package config

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	BackendPCAP = "pcap"
	BackendEBPF = "ebpf"

	// DefaultHTTPAddr binds the observability surface to loopback only. The
	// /api endpoints expose source/destination IPs, JA4 fingerprints and
	// threat history, so exposing them to the network must be an explicit
	// operator decision (e.g. -http-addr :9090).
	DefaultHTTPAddr = "127.0.0.1:9090"

	// Default server timeouts bound how long a slow or stalled client can
	// hold a connection (slowloris) and how long a handler may take.
	DefaultHTTPReadHeaderTimeout = 5 * time.Second
	DefaultHTTPReadTimeout       = 10 * time.Second
	DefaultHTTPWriteTimeout      = 10 * time.Second
	DefaultHTTPIdleTimeout       = 60 * time.Second
)

type Config struct {
	Capture       Capture
	Output        Output
	Risk          Risk
	Observability Observability
}

type Capture struct {
	Backend   string
	Interface string
	MatchPort uint
}

type Output struct {
	HelloOutPath   string
	ExitAfterHello bool
}

type Risk struct {
	RedisAddr        string
	RedisPassword    string
	RedisDB          int
	KeyPrefix        string
	JA4LookupURL     string
	JA4LookupTimeout time.Duration
	JA4DBURL         string
	JA4DBAuthToken   string
	JA4CacheTTL      time.Duration
	UseHostFallback  bool
	DelayThreshold   int
	RateLimitThresh  int
	ChallengeThresh  int
	BlockThresh      int

	// Redis connection tuning for the single shared client.
	RedisDialTimeout     time.Duration
	RedisReadTimeout     time.Duration
	RedisWriteTimeout    time.Duration
	RedisPoolTimeout     time.Duration
	RedisPoolSize        int
	RedisMinIdleConns    int
	RedisConnectAttempts int
}

type Observability struct {
	HTTPAddr string
	// HTTPToken, when non-empty, requires "Authorization: Bearer <token>"
	// on the /api endpoints so the dashboard data is not world-readable.
	HTTPToken string
	// HTTPCORSOrigins is the exact allowlist of browser origins permitted to
	// read /api cross-origin. Empty means same-origin only; "*" is rejected
	// because a wildcard would re-expose the API to any web page.
	HTTPCORSOrigins []string

	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
}

func defaultObservability() Observability {
	return Observability{
		HTTPAddr:          DefaultHTTPAddr,
		HTTPToken:         os.Getenv("SYBIL_HTTP_TOKEN"),
		ReadHeaderTimeout: DefaultHTTPReadHeaderTimeout,
		ReadTimeout:       DefaultHTTPReadTimeout,
		WriteTimeout:      DefaultHTTPWriteTimeout,
		IdleTimeout:       DefaultHTTPIdleTimeout,
	}
}

func Parse() Config {
	var cfg Config

	flag.StringVar(&cfg.Capture.Backend, "backend", BackendPCAP, "Capture backend: pcap or ebpf")
	flag.StringVar(&cfg.Capture.Interface, "iface", "lo", "Interface to attach XDP program to")
	flag.UintVar(&cfg.Capture.MatchPort, "port", 0, "Only inspect TCP traffic where either source or destination port matches")

	flag.StringVar(&cfg.Output.HelloOutPath, "hello-out", "", "Write the first detected TLS hello record bytes to this file")
	flag.BoolVar(&cfg.Output.ExitAfterHello, "exit-after-hello", false, "Exit after the first matching TLS hello is detected")

	flag.StringVar(&cfg.Risk.RedisAddr, "redis-addr", "", "Redis address for live JA4 risk scoring")
	flag.StringVar(&cfg.Risk.RedisPassword, "redis-password", strings.TrimSpace(os.Getenv("SYBIL_REDIS_PASSWORD")), "Redis password for live JA4 risk scoring (default $SYBIL_REDIS_PASSWORD; prefer the env var, flags are visible in ps)")
	flag.IntVar(&cfg.Risk.RedisDB, "redis-db", 0, "Redis database for live JA4 risk scoring")
	flag.StringVar(&cfg.Risk.KeyPrefix, "risk-key-prefix", "sybil:risk", "Redis key prefix for live JA4 risk scoring")
	flag.DurationVar(&cfg.Risk.RedisDialTimeout, "redis-dial-timeout", 5*time.Second, "Timeout for dialing Redis")
	flag.DurationVar(&cfg.Risk.RedisReadTimeout, "redis-read-timeout", 3*time.Second, "Timeout for Redis reads")
	flag.DurationVar(&cfg.Risk.RedisWriteTimeout, "redis-write-timeout", 3*time.Second, "Timeout for Redis writes")
	flag.DurationVar(&cfg.Risk.RedisPoolTimeout, "redis-pool-timeout", 4*time.Second, "Timeout waiting for a pooled Redis connection")
	flag.IntVar(&cfg.Risk.RedisPoolSize, "redis-pool-size", 32, "Maximum Redis connection pool size")
	flag.IntVar(&cfg.Risk.RedisMinIdleConns, "redis-min-idle-conns", 2, "Minimum idle Redis connections to keep warm")
	flag.IntVar(&cfg.Risk.RedisConnectAttempts, "redis-connect-attempts", 3, "Startup Redis connect attempts before degrading to capture-only mode")
	flag.StringVar(&cfg.Risk.JA4LookupURL, "ja4-lookup-url", "", "Optional JA4 lookup URL or template. Use %s to inject the URL-escaped JA4 fingerprint")
	flag.DurationVar(&cfg.Risk.JA4LookupTimeout, "ja4-lookup-timeout", 2*time.Second, "Timeout for external JA4 enrichment lookups")
	flag.StringVar(&cfg.Risk.JA4DBURL, "ja4-db-url", strings.TrimSpace(os.Getenv("DB_URL")), "Optional libSQL/Turso URL for JA4 enrichment (default $DB_URL)")
	flag.StringVar(&cfg.Risk.JA4DBAuthToken, "ja4-db-auth-token", strings.TrimSpace(os.Getenv("AUTH_TOKEN")), "Optional auth token for the JA4 libSQL/Turso database (default $AUTH_TOKEN; prefer the env var, flags are visible in ps)")
	flag.DurationVar(&cfg.Risk.JA4CacheTTL, "ja4-cache-ttl", 30*time.Minute, "Redis TTL for cached JA4 enrichment lookups")
	flag.BoolVar(&cfg.Risk.UseHostFallback, "risk-use-host-fallback", true, "Use SNI host as a weaker diversity signal when the real endpoint path is unavailable")
	flag.IntVar(&cfg.Risk.DelayThreshold, "risk-delay-threshold", -1, "Optional override for delay threshold (default scorer config when negative)")
	flag.IntVar(&cfg.Risk.RateLimitThresh, "risk-rate-limit-threshold", -1, "Optional override for rate-limit threshold (default scorer config when negative)")
	flag.IntVar(&cfg.Risk.ChallengeThresh, "risk-challenge-threshold", -1, "Optional override for challenge threshold (default scorer config when negative)")
	flag.IntVar(&cfg.Risk.BlockThresh, "risk-block-threshold", -1, "Optional override for block threshold (default scorer config when negative)")
	obs := defaultObservability()
	flag.StringVar(&obs.HTTPAddr, "http-addr", obs.HTTPAddr, "HTTP listen address for /metrics, /healthz and /api; defaults to loopback only, pass :9090 to expose on all interfaces; empty disables the server")
	flag.StringVar(&obs.HTTPToken, "http-token", obs.HTTPToken, "Optional bearer token required on /api endpoints (default $SYBIL_HTTP_TOKEN); empty leaves /api unauthenticated")
	flag.Func("http-cors-origins", "Comma-separated exact browser origins allowed to read /api cross-origin (default none: same-origin only; wildcard not supported)", func(raw string) error {
		origins, err := parseCORSOrigins(raw)
		if err != nil {
			return err
		}
		obs.HTTPCORSOrigins = origins
		return nil
	})
	flag.DurationVar(&obs.ReadHeaderTimeout, "http-read-header-timeout", obs.ReadHeaderTimeout, "Maximum time to read request headers")
	flag.DurationVar(&obs.ReadTimeout, "http-read-timeout", obs.ReadTimeout, "Maximum time to read the whole request")
	flag.DurationVar(&obs.WriteTimeout, "http-write-timeout", obs.WriteTimeout, "Maximum time to write a response")
	flag.DurationVar(&obs.IdleTimeout, "http-idle-timeout", obs.IdleTimeout, "Maximum keep-alive idle time between requests")

	flag.Parse()

	cfg.Observability = obs
	return cfg
}

// parseCORSOrigins splits and normalizes a comma-separated origin allowlist.
// A wildcard is refused rather than silently honored: the previous behavior
// (Access-Control-Allow-Origin: *) let any web page read the API.
func parseCORSOrigins(raw string) ([]string, error) {
	var origins []string
	seen := make(map[string]struct{})
	for _, part := range strings.Split(raw, ",") {
		origin := strings.TrimSpace(part)
		if origin == "" {
			continue
		}
		if origin == "*" {
			return nil, fmt.Errorf("wildcard CORS origin is not supported; list explicit origins instead")
		}
		if _, ok := seen[origin]; ok {
			continue
		}
		seen[origin] = struct{}{}
		origins = append(origins, origin)
	}
	return origins, nil
}

func (c Config) Validate() error {
	switch c.Capture.Backend {
	case BackendPCAP, BackendEBPF:
		return nil
	default:
		return fmt.Errorf("invalid -backend %q (expected %s or %s)", c.Capture.Backend, BackendPCAP, BackendEBPF)
	}
}
