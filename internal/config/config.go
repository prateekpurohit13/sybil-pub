package config

import (
	"flag"
	"fmt"
	"os"
	"time"
)

const (
	BackendPCAP = "pcap"
	BackendEBPF = "ebpf"
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
}

type Observability struct {
	HTTPAddr string
}

func Parse() Config {
	var cfg Config

	flag.StringVar(&cfg.Capture.Backend, "backend", BackendPCAP, "Capture backend: pcap or ebpf")
	flag.StringVar(&cfg.Capture.Interface, "iface", "lo", "Interface to attach XDP program to")
	flag.UintVar(&cfg.Capture.MatchPort, "port", 0, "Only inspect TCP traffic where either source or destination port matches")

	flag.StringVar(&cfg.Output.HelloOutPath, "hello-out", "", "Write the first detected TLS hello record bytes to this file")
	flag.BoolVar(&cfg.Output.ExitAfterHello, "exit-after-hello", false, "Exit after the first matching TLS hello is detected")

	flag.StringVar(&cfg.Risk.RedisAddr, "redis-addr", "", "Redis address for live JA4 risk scoring")
	flag.StringVar(&cfg.Risk.RedisPassword, "redis-password", "", "Redis password for live JA4 risk scoring")
	flag.IntVar(&cfg.Risk.RedisDB, "redis-db", 0, "Redis database for live JA4 risk scoring")
	flag.StringVar(&cfg.Risk.KeyPrefix, "risk-key-prefix", "sybil:risk", "Redis key prefix for live JA4 risk scoring")
	flag.StringVar(&cfg.Risk.JA4LookupURL, "ja4-lookup-url", "", "Optional JA4 lookup URL or template. Use %s to inject the URL-escaped JA4 fingerprint")
	flag.DurationVar(&cfg.Risk.JA4LookupTimeout, "ja4-lookup-timeout", 2*time.Second, "Timeout for external JA4 enrichment lookups")
	flag.StringVar(&cfg.Risk.JA4DBURL, "ja4-db-url", os.Getenv("DB_URL"), "Optional libSQL/Turso URL for JA4 enrichment")
	flag.StringVar(&cfg.Risk.JA4DBAuthToken, "ja4-db-auth-token", os.Getenv("AUTH_TOKEN"), "Optional auth token for the JA4 libSQL/Turso database")
	flag.DurationVar(&cfg.Risk.JA4CacheTTL, "ja4-cache-ttl", 30*time.Minute, "Redis TTL for cached JA4 enrichment lookups")
	flag.BoolVar(&cfg.Risk.UseHostFallback, "risk-use-host-fallback", true, "Use SNI host as a weaker diversity signal when the real endpoint path is unavailable")
	flag.IntVar(&cfg.Risk.DelayThreshold, "risk-delay-threshold", -1, "Optional override for delay threshold (default scorer config when negative)")
	flag.IntVar(&cfg.Risk.RateLimitThresh, "risk-rate-limit-threshold", -1, "Optional override for rate-limit threshold (default scorer config when negative)")
	flag.IntVar(&cfg.Risk.ChallengeThresh, "risk-challenge-threshold", -1, "Optional override for challenge threshold (default scorer config when negative)")
	flag.IntVar(&cfg.Risk.BlockThresh, "risk-block-threshold", -1, "Optional override for block threshold (default scorer config when negative)")
	flag.StringVar(&cfg.Observability.HTTPAddr, "http-addr", ":9090", "HTTP listen address for /metrics and /healthz; empty disables the server")

	flag.Parse()

	return cfg
}

func (c Config) Validate() error {
	switch c.Capture.Backend {
	case BackendPCAP, BackendEBPF:
		return nil
	default:
		return fmt.Errorf("invalid -backend %q (expected %s or %s)", c.Capture.Backend, BackendPCAP, BackendEBPF)
	}
}
