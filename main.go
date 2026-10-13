package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sophic00/sybil/internal/api"
	"github.com/sophic00/sybil/internal/capture"
	"github.com/sophic00/sybil/internal/config"
	"github.com/sophic00/sybil/internal/db"
	"github.com/sophic00/sybil/internal/parser"
	"github.com/sophic00/sybil/internal/risk"
	"github.com/sophic00/sybil/internal/stream"
	"github.com/sophic00/sybil/internal/telemetry"
	"github.com/sophic00/sybil/internal/tlshello"

	"github.com/redis/go-redis/v9"
)

func main() {
	cfg := config.Parse()
	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	registry := telemetry.NewRegistry(cfg.Capture.Backend, cfg.Capture.Interface)

	// One Redis client is shared by the API store, the risk stats store and the
	// JA4 lookup cache. Startup failure is degraded, not fatal: capture keeps
	// running and healthz/metrics report the outage so an operator can fix it
	// while the sensor still records traffic.
	rdb, closeRedis := openRedisClient(ctx, cfg.Risk, registry)
	defer closeRedis()

	apiStore := newAPIStore(rdb, cfg.Risk)

	closeHTTPServer, err := startHTTPServer(ctx, cfg.Observability, registry, apiStore)
	if err != nil {
		log.Fatal(err)
	}
	defer closeHTTPServer()

	threatScorer, closeThreatScorer := newThreatScorer(rdb, cfg.Risk, registry)
	defer closeThreatScorer()
	breaker := newRedisCircuit(registry, redisFailureThreshold, redisCooldown)

	var helloOnce sync.Once
	onHello := func(hello *tlshello.Hello) {
		helloOnce.Do(func() {
			if cfg.Output.HelloOutPath != "" {
				if err := os.WriteFile(cfg.Output.HelloOutPath, hello.RecordBytes, 0o644); err != nil {
					log.Printf("write hello output: %v", err)
				}
			}
			if cfg.Output.ExitAfterHello {
				cancel()
			}
		})
	}

	processor := stream.NewProcessor(stream.Options{
		MatchPort: cfg.Capture.MatchPort,
		OnEvent: func(event stream.Event) {
			if event.Hello == nil {
				return
			}

			eventStart := time.Now()
			observedAt := eventStart.UTC()
			registry.RecordEvent(event)
			printHelloEvent(event)
			if threatScorer != nil && breaker.allow(time.Now()) {
				// The breaker is closed (or a cooldown probe is due). While it is
				// open this block is skipped so capture is never blocked by
				// failing Redis round trips; healthz reports degraded instead.
				assessmentStart := time.Now()
				assessment, err := assessClientHello(ctx, threatScorer, event, observedAt)
				registry.ObserveDuration("assessment", time.Since(assessmentStart))
				if err != nil {
					log.Printf("risk assessment failed for %s: %v", event.JA4.Fingerprint, err)
					breaker.failure(time.Now())
				} else if assessment != nil {
					breaker.success()
					registry.RecordAssessment(*assessment)
					if apiStore != nil {
						if observation, ok := api.BuildObservation(event, assessment, observedAt); ok {
							if err := apiStore.Record(ctx, observation); err != nil {
								log.Printf("api persistence failed for %s: %v", observation.JA4Fingerprint, err)
								breaker.failure(time.Now())
							}
						}
					}
				}
			}
			onHello(event.Hello)
			registry.ObserveDuration("event", time.Since(eventStart))
		},
		OnExtractError: func(err error) {
			kind := "parse_error"
			if errors.Is(err, tlshello.ErrBufferLimit) {
				kind = "buffer_limit"
			}
			registry.Inc("sybil_tls_extract_errors_total", telemetry.Labels{"kind": kind})
		},
	})
	// Flush at shutdown so hellos still buffered in half-open streams are
	// not dropped when capture stops.
	defer processor.FlushAll()

	source, err := capture.Open(cfg.Capture)
	if err != nil {
		log.Fatal(err)
	}
	defer source.Close()

	fmt.Printf("Capturing TCP on %s using %s backend... (Ctrl+C to stop)\n", cfg.Capture.Interface, cfg.Capture.Backend)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(time.Second * 1)
	defer ticker.Stop()

	go func() {
		<-sig
		cancel()
	}()

	var lastLostSamples, lastMalformedSamples uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Periodically flush old streams to trigger reassembly
			processor.FlushOlderThan(time.Now().Add(-time.Second * 3))
			// The eBPF backend reports dropped/malformed samples through
			// counters instead of per-batch errors, so publish deltas here
			// and keep a busy interface from flooding the logs.
			if lost := source.LostSamples(); lost > lastLostSamples {
				registry.Add("sybil_capture_errors_total", telemetry.Labels{"kind": "lost_samples"}, float64(lost-lastLostSamples))
				lastLostSamples = lost
			}
			if malformed := source.MalformedSamples(); malformed > lastMalformedSamples {
				registry.Add("sybil_capture_errors_total", telemetry.Labels{"kind": "malformed_samples"}, float64(malformed-lastMalformedSamples))
				lastMalformedSamples = malformed
			}
			// libpcap keeps its own kernel counters; publish deltas so receive
			// and drop behavior is visible on the dashboards. eBPF sources do
			// not expose these and the call is a no-op for them.
			if stats, ok := source.Stats(); ok {
				registry.RecordCaptureStats(telemetry.CaptureStats{
					Received:  stats.Received,
					Dropped:   stats.Dropped,
					IfDropped: stats.IfDropped,
				})
			}
		default:
			packet, err := source.NextPacket(ctx)
			if err != nil {
				if errors.Is(err, capture.ErrClosed) || errors.Is(err, context.Canceled) {
					return
				}
				registry.RecordCaptureError(err)
				log.Printf("capture read failed: %v", err)
				continue
			}
			registry.RecordCapturePacket()
			processor.ProcessPacket(packet)
		}
	}
}

func newAPIStore(rdb *redis.Client, cfg config.Risk) api.Store {
	if rdb == nil {
		return nil
	}
	return api.NewRedisStore(rdb, cfg.KeyPrefix)
}

func newThreatScorer(rdb *redis.Client, cfg config.Risk, registry *telemetry.Registry) (*risk.Scorer, func()) {
	if rdb == nil {
		return nil, func() {}
	}

	riskCfg := risk.DefaultConfig()
	riskCfg.UseHostFallback = cfg.UseHostFallback
	if cfg.DelayThreshold >= 0 {
		riskCfg.DelayThreshold = cfg.DelayThreshold
	}
	if cfg.RateLimitThresh >= 0 {
		riskCfg.RateLimitThreshold = cfg.RateLimitThresh
	}
	if cfg.ChallengeThresh >= 0 {
		riskCfg.ChallengeThreshold = cfg.ChallengeThresh
	}
	if cfg.BlockThresh >= 0 {
		riskCfg.BlockThreshold = cfg.BlockThresh
	}

	var store risk.StatsStore = risk.NewRedisStore(rdb, cfg.KeyPrefix)
	if registry != nil {
		store = registry.WrapStatsStore(store)
	}

	var lookup risk.LookupClient
	closeFns := []func(){}
	switch {
	case cfg.JA4DBURL != "":
		dbLookup, closeDB, err := risk.NewLibSQLLookupClient(db.SQLiteConfig{
			Driver:    "libsql",
			DSN:       cfg.JA4DBURL,
			AuthToken: cfg.JA4DBAuthToken,
		})
		if err != nil {
			// Behavioral scoring still works without enrichment, and the shared
			// Redis client is owned by main (not this function), so a libSQL
			// failure no longer leaks it or takes the sensor down.
			log.Printf("ja4 libsql lookup unavailable: %v; continuing without enrichment", err)
			return risk.NewScorer(store, nil, riskCfg), func() {}
		}
		closeFns = append(closeFns, closeDB)
		lookup = dbLookup
	case cfg.JA4LookupURL != "":
		lookup = risk.NewHTTPLookupClient(cfg.JA4LookupURL, &http.Client{Timeout: cfg.JA4LookupTimeout})
	}
	if lookup != nil {
		var observer risk.LookupObserver
		if registry != nil {
			observer = registry
		}
		lookup = risk.NewCachedLookupClient(lookup, rdb, cfg.KeyPrefix, cfg.JA4CacheTTL, observer)
	}

	return risk.NewScorer(store, lookup, riskCfg), func() {
		for i := len(closeFns) - 1; i >= 0; i-- {
			closeFns[i]()
		}
	}
}

const (
	redisFailureThreshold = 3
	redisCooldown         = 30 * time.Second
)

// openRedisClient dials and pings Redis with bounded retry/backoff, then
// returns a single shared client plus its close function. A failure is logged
// and reported through the sybil_redis_up gauge / healthz, not fatal: the
// sensor degrades to capture-only mode instead of refusing to start.
func openRedisClient(ctx context.Context, cfg config.Risk, registry *telemetry.Registry) (*redis.Client, func()) {
	if strings.TrimSpace(cfg.RedisAddr) == "" {
		return nil, func() {}
	}

	attempts := cfg.RedisConnectAttempts
	if attempts < 1 {
		attempts = 1
	}
	backoff := 500 * time.Millisecond

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		rdb, err := db.OpenRedis(ctx, db.RedisConfig{
			Addr:         cfg.RedisAddr,
			Password:     cfg.RedisPassword,
			DB:           cfg.RedisDB,
			DialTimeout:  cfg.RedisDialTimeout,
			ReadTimeout:  cfg.RedisReadTimeout,
			WriteTimeout: cfg.RedisWriteTimeout,
			PoolTimeout:  cfg.RedisPoolTimeout,
			PoolSize:     cfg.RedisPoolSize,
			MinIdleConns: cfg.RedisMinIdleConns,
		})
		if err == nil {
			if registry != nil {
				registry.SetRedisUp(true)
			}
			return rdb, func() { _ = rdb.Close() }
		}
		lastErr = err
		if attempt == attempts {
			break
		}
		select {
		case <-ctx.Done():
			if registry != nil {
				registry.SetRedisUp(false)
			}
			log.Printf("redis connect canceled at %s: %v; continuing in capture-only mode", cfg.RedisAddr, ctx.Err())
			return nil, func() {}
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > 8*time.Second {
			backoff = 8 * time.Second
		}
	}

	if registry != nil {
		registry.SetRedisUp(false)
	}
	log.Printf("redis unavailable at %s after %d attempt(s): %v; continuing in capture-only mode (risk scoring and API endpoints disabled)", cfg.RedisAddr, attempts, lastErr)
	return nil, func() {}
}

// redisCircuit is a small breaker around the shared Redis client. Repeated
// runtime failures (for example Redis restarting under load) trip it open; the
// capture loop then stops calling assess/persist for a cooldown period and
// healthz reports degraded instead of every hello paying a failing round
// trip. One probe is allowed after the cooldown (half-open); a success closes
// the breaker and restores sybil_redis_up.
type redisCircuit struct {
	registry  *telemetry.Registry
	threshold int
	cooldown  time.Duration

	mu        sync.Mutex
	failures  int
	openUntil time.Time
	degraded  bool
}

func newRedisCircuit(registry *telemetry.Registry, threshold int, cooldown time.Duration) *redisCircuit {
	if threshold < 1 {
		threshold = 1
	}
	return &redisCircuit{registry: registry, threshold: threshold, cooldown: cooldown}
}

func (c *redisCircuit) allow(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.openUntil.IsZero() {
		return true
	}
	return !now.Before(c.openUntil)
}

func (c *redisCircuit) success() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures = 0
	c.openUntil = time.Time{}
	if c.degraded {
		c.degraded = false
		if c.registry != nil {
			c.registry.SetRedisUp(true)
		}
	}
}

func (c *redisCircuit) failure(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures++
	if c.failures < c.threshold {
		return
	}
	c.openUntil = now.Add(c.cooldown)
	if !c.degraded {
		c.degraded = true
		if c.registry != nil {
			c.registry.SetRedisUp(false)
		}
	}
}

func printHelloEvent(event stream.Event) {
	fmt.Printf("\n--- Detected TLS %s (%s:%s -> %s:%s) ---\n",
		event.Hello.Type, event.NetFlow.Src(), event.TransportFlow.Src(), event.NetFlow.Dst(), event.TransportFlow.Dst())
	fmt.Printf("record_bytes=%d handshake_bytes=%d stream_offset=%d\n",
		len(event.Hello.RecordBytes), len(event.Hello.HandshakeBytes), event.Hello.StreamOffset)
	fmt.Println(hex.Dump(event.Hello.RecordBytes))

	if event.Hello.Type != tlshello.ClientHello {
		return
	}

	if event.ParseError != nil {
		fmt.Printf("ClientHello parse error: %v\n", event.ParseError)
		return
	}

	fields := event.Fields
	fmt.Println("Parsed ClientHello Fields:")
	fmt.Printf("  protocol            : %s\n", fields.Protocol)
	fmt.Printf("  tls_version         : %s\n", parser.TLSVersionString(fields.TLSVersion))
	fmt.Printf("  record_version      : %s\n", parser.TLSVersionString(fields.RecordVersion))
	fmt.Printf("  hello_version       : %s\n", parser.TLSVersionString(fields.HelloVersion))
	fmt.Printf("  sni_type            : %s\n", fields.SNIType)
	fmt.Printf("  sni_hostname        : %s\n", fields.SNIHost)
	fmt.Printf("  cipher_count        : %d\n", fields.CipherCount)
	fmt.Printf("  extension_count     : %d\n", fields.ExtensionCount)
	fmt.Printf("  alpn_first          : %s\n", fields.FirstALPN)

	if event.FingerprintError != nil {
		fmt.Printf("JA4 build error: %v\n", event.FingerprintError)
		return
	}

	ja4 := event.JA4
	fmt.Printf("  ja4_a               : %s\n", ja4.A)
	fmt.Printf("  ja4_b               : %s\n", ja4.B)
	fmt.Printf("  ja4_c               : %s\n", ja4.C)
	fmt.Printf("JA4: %s\n", ja4.Fingerprint)
}

func assessClientHello(ctx context.Context, threatScorer *risk.Scorer, event stream.Event, observedAt time.Time) (*risk.Assessment, error) {
	if threatScorer == nil || event.Fields == nil || event.JA4 == nil {
		return nil, nil
	}

	// A ClientHello exposes only the SNI host, never the encrypted HTTP path,
	// so Endpoint is intentionally left empty: the scorer falls back to
	// host-level and then per-source-IP resource diversity.
	assessment, err := threatScorer.Assess(ctx, risk.Observation{
		JA4:       event.JA4.Fingerprint,
		SourceIP:  event.NetFlow.Src().String(),
		Hostname:  event.Fields.SNIHost,
		Timestamp: observedAt,
	})
	if err != nil {
		return nil, err
	}

	// Advisory only: this label is printed and persisted for operators/API
	// consumers, but nothing on the capture path enforces it.
	fmt.Printf("Threat Score: %d/100 action=%s", assessment.Score, assessment.Action)
	if assessment.Delay > 0 {
		fmt.Printf(" delay=%s", assessment.Delay)
	}
	fmt.Println()
	for _, component := range assessment.Components {
		fmt.Printf("  %-20s %2d/%-2d %s\n", component.Name+":", component.Score, component.Weight, component.Detail)
	}
	if assessment.LookupError != "" {
		fmt.Printf("  lookup_error         %s\n", assessment.LookupError)
	}
	if assessment.Lookup != nil {
		fmt.Printf("  identity_class       %s\n", assessment.Summary.IdentityClass)
		fmt.Printf("  reputation_state     %s\n", assessment.Summary.ReputationState)
		fmt.Printf("  app_family           %s\n", assessment.Summary.ApplicationFamily)
		fmt.Printf("  os_family            %s\n", assessment.Summary.OSFamily)
	}
	return &assessment, nil
}

func startHTTPServer(ctx context.Context, cfg config.Observability, registry *telemetry.Registry, apiStore api.Store) (func(), error) {
	if strings.TrimSpace(cfg.HTTPAddr) == "" || registry == nil {
		return func() {}, nil
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", registry.Handler())
	mux.Handle("/healthz", registry.HealthHandler())
	api.RegisterRoutes(mux, apiStore)

	server := &http.Server{
		Addr:    cfg.HTTPAddr,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("observability server failed: %v", err)
		}
	}()

	fmt.Printf("Observability server listening on %s\n", cfg.HTTPAddr)
	return func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}, nil
}
