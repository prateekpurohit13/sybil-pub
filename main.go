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
)

func main() {
	cfg := config.Parse()
	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	registry := telemetry.NewRegistry(cfg.Capture.Backend, cfg.Capture.Interface)
	apiStore, closeAPIStore, err := newAPIStore(ctx, cfg.Risk)
	if err != nil {
		log.Fatal(err)
	}
	defer closeAPIStore()

	closeHTTPServer, err := startHTTPServer(ctx, cfg.Observability, registry, apiStore)
	if err != nil {
		log.Fatal(err)
	}
	defer closeHTTPServer()

	threatScorer, closeThreatScorer, err := newThreatScorer(ctx, cfg.Risk, registry)
	if err != nil {
		log.Fatal(err)
	}
	defer closeThreatScorer()

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
			assessmentStart := time.Now()
			assessment, err := assessClientHello(ctx, threatScorer, event, observedAt)
			registry.ObserveDuration("assessment", time.Since(assessmentStart))
			if err != nil {
				log.Printf("risk assessment failed for %s: %v", event.JA4.Fingerprint, err)
			} else if assessment != nil {
				registry.RecordAssessment(*assessment)
				if apiStore != nil {
					if observation, ok := api.BuildObservation(event, assessment, observedAt); ok {
						if err := apiStore.Record(ctx, observation); err != nil {
							log.Printf("api persistence failed for %s: %v", observation.JA4Fingerprint, err)
						}
					}
				}
			}
			onHello(event.Hello)
			registry.ObserveDuration("event", time.Since(eventStart))
		},
	})

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

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Periodically flush old streams to trigger reassembly
			processor.FlushOlderThan(time.Now().Add(-time.Second * 3))
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

func newAPIStore(ctx context.Context, cfg config.Risk) (api.Store, func(), error) {
	if cfg.RedisAddr == "" {
		return nil, func() {}, nil
	}

	rdb, err := db.OpenRedis(ctx, db.RedisConfig{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	if err != nil {
		return nil, func() {}, err
	}

	return api.NewRedisStore(rdb, cfg.KeyPrefix), func() {
		_ = rdb.Close()
	}, nil
}

func newThreatScorer(ctx context.Context, cfg config.Risk, registry *telemetry.Registry) (*risk.Scorer, func(), error) {
	if cfg.RedisAddr == "" {
		return nil, func() {}, nil
	}

	rdb, err := db.OpenRedis(ctx, db.RedisConfig{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	if err != nil {
		return nil, func() {}, err
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
	closeFns := []func(){func() { _ = rdb.Close() }}
	switch {
	case cfg.JA4DBURL != "":
		dbLookup, closeDB, err := risk.NewLibSQLLookupClient(db.SQLiteConfig{
			Driver:    "libsql",
			DSN:       cfg.JA4DBURL,
			AuthToken: cfg.JA4DBAuthToken,
		})
		if err != nil {
			return nil, func() {}, err
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
	}, nil
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

	assessment, err := threatScorer.Assess(ctx, risk.Observation{
		JA4:       event.JA4.Fingerprint,
		SourceIP:  event.NetFlow.Src().String(),
		Hostname:  event.Fields.SNIHost,
		Timestamp: observedAt,
	})
	if err != nil {
		return nil, err
	}

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
