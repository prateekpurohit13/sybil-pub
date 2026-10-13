package config

import (
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
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

	// Default risk action thresholds. They mirror risk.DefaultConfig in
	// internal/risk/scorer.go; validateThresholds needs them to check the
	// ordering even when only some -risk-*-threshold overrides are set. Keep
	// the two in sync (config deliberately does not import risk so that flag
	// validation stays dependency-free).
	defaultDelayThreshold     = 70
	defaultRateLimitThreshold = 80
	defaultChallengeThreshold = 90
	defaultBlockThreshold     = 95
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
	flag.StringVar(&cfg.Capture.Interface, "iface", "lo", "Interface to capture on (pcap) or to attach the XDP program to (ebpf)")
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
		// Accept a trailing slash but store the origin exactly as a browser
		// sends it, so the allowlist comparison in the API middleware matches.
		origin = strings.TrimSuffix(origin, "/")
		if err := validateCORSOrigin(origin); err != nil {
			return nil, err
		}
		if _, ok := seen[origin]; ok {
			continue
		}
		seen[origin] = struct{}{}
		origins = append(origins, origin)
	}
	return origins, nil
}

// validateCORSOrigin requires an absolute http(s) origin without a path,
// query, fragment or userinfo. A malformed entry would otherwise fail open
// (never match) or produce an invalid header value.
func validateCORSOrigin(origin string) error {
	parsed, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("invalid CORS origin %q: %w", origin, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("invalid CORS origin %q: scheme must be http or https", origin)
	}
	if parsed.Host == "" {
		return fmt.Errorf("invalid CORS origin %q: missing host", origin)
	}
	if parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return fmt.Errorf("invalid CORS origin %q: use scheme://host[:port] without a path, query or fragment", origin)
	}
	return nil
}

// validateLookupURL accepts an http(s) URL, optionally containing the %s
// placeholder used to inject the JA4 fingerprint. The placeholder is
// substituted before parsing because url.Parse rejects "%s" as an invalid
// escape in a path.
func validateLookupURL(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("-ja4-lookup-url must not be blank")
	}
	parsed, err := url.Parse(strings.ReplaceAll(trimmed, "%s", "ja4"))
	if err != nil {
		return fmt.Errorf("invalid -ja4-lookup-url %q: %w", raw, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("invalid -ja4-lookup-url %q: scheme must be http or https", raw)
	}
	if parsed.Host == "" {
		return fmt.Errorf("invalid -ja4-lookup-url %q: missing host", raw)
	}
	return nil
}

// validateListenAddr checks that -http-addr is a host:port pair whose port is
// in range. It deliberately does not resolve the host: a name that is not
// resolvable at flag time may still be valid at listen time.
func validateListenAddr(addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%q is not a valid host:port: %w", addr, err)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("%q has an invalid port %q (expected 0-65535)", addr, port)
	}
	return nil
}

// validateThresholds applies the -risk-*-threshold overrides on top of the
// scorer defaults and requires the effective values to be strictly
// increasing. deriveAction checks block, then challenge, then rate-limit, then
// delay, so an out-of-order threshold silently makes the earlier action
// unreachable instead of failing at startup.
func validateThresholds(risk Risk) error {
	effective := [4]int{
		defaultDelayThreshold,
		defaultRateLimitThreshold,
		defaultChallengeThreshold,
		defaultBlockThreshold,
	}
	overrides := [4]int{risk.DelayThreshold, risk.RateLimitThresh, risk.ChallengeThresh, risk.BlockThresh}
	for i, override := range overrides {
		if override >= 0 {
			effective[i] = override
		}
	}
	for i := 1; i < len(effective); i++ {
		if effective[i-1] >= effective[i] {
			return fmt.Errorf(
				"risk thresholds must be strictly increasing (delay < rate-limit < challenge < block) after applying -risk-*-threshold overrides; got delay=%d rate-limit=%d challenge=%d block=%d",
				effective[0], effective[1], effective[2], effective[3],
			)
		}
	}
	return nil
}

// Validate rejects configurations that would otherwise fail late in the
// capture/scoring path (where the error is harder to attribute to a flag) or
// that silently disable an action the operator asked for.
func (c Config) Validate() error {
	switch c.Capture.Backend {
	case BackendPCAP, BackendEBPF:
	default:
		return fmt.Errorf("invalid -backend %q (expected %s or %s)", c.Capture.Backend, BackendPCAP, BackendEBPF)
	}

	if strings.TrimSpace(c.Capture.Interface) == "" {
		return fmt.Errorf("-iface must not be empty")
	}

	// MatchPort is a uint because libpcap/XDP ports are unsigned; a value
	// above 65535 would be rejected deep in capture.Open (or wrap inside the
	// XDP port map) rather than at flag time.
	if c.Capture.MatchPort > 65535 {
		return fmt.Errorf("-port %d is out of range (0-65535)", c.Capture.MatchPort)
	}

	if err := validateThresholds(c.Risk); err != nil {
		return err
	}

	if c.Risk.RedisDB < 0 {
		return fmt.Errorf("-redis-db must be >= 0, got %d", c.Risk.RedisDB)
	}
	if c.Risk.RedisPoolSize < 1 {
		return fmt.Errorf("-redis-pool-size must be >= 1, got %d", c.Risk.RedisPoolSize)
	}
	if c.Risk.RedisMinIdleConns < 0 {
		return fmt.Errorf("-redis-min-idle-conns must be >= 0, got %d", c.Risk.RedisMinIdleConns)
	}
	if c.Risk.RedisConnectAttempts < 1 {
		return fmt.Errorf("-redis-connect-attempts must be >= 1, got %d", c.Risk.RedisConnectAttempts)
	}

	for _, d := range []struct {
		name  string
		value time.Duration
	}{
		{"-redis-dial-timeout", c.Risk.RedisDialTimeout},
		{"-redis-read-timeout", c.Risk.RedisReadTimeout},
		{"-redis-write-timeout", c.Risk.RedisWriteTimeout},
		{"-redis-pool-timeout", c.Risk.RedisPoolTimeout},
		{"-ja4-lookup-timeout", c.Risk.JA4LookupTimeout},
		{"-ja4-cache-ttl", c.Risk.JA4CacheTTL},
		{"-http-read-header-timeout", c.Observability.ReadHeaderTimeout},
		{"-http-read-timeout", c.Observability.ReadTimeout},
		{"-http-write-timeout", c.Observability.WriteTimeout},
		{"-http-idle-timeout", c.Observability.IdleTimeout},
	} {
		if d.value <= 0 {
			return fmt.Errorf("%s must be positive, got %s", d.name, d.value)
		}
	}

	if c.Risk.JA4LookupURL != "" {
		if err := validateLookupURL(c.Risk.JA4LookupURL); err != nil {
			return err
		}
	}

	for _, origin := range c.Observability.HTTPCORSOrigins {
		if err := validateCORSOrigin(origin); err != nil {
			return err
		}
	}

	// An empty -http-addr disables the observability server (and /api), which
	// is a supported deployment; only validate the address when it is set.
	if strings.TrimSpace(c.Observability.HTTPAddr) != "" {
		if err := validateListenAddr(c.Observability.HTTPAddr); err != nil {
			return fmt.Errorf("invalid -http-addr: %w", err)
		}
	}

	return nil
}
