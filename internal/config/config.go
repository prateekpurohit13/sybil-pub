package config

import (
	"flag"
	"fmt"
	"time"
)

const (
	BackendPCAP = "pcap"
	BackendEBPF = "ebpf"
)

type Config struct {
	Capture Capture
	Output  Output
	Risk    Risk
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
	UseHostFallback  bool
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
	flag.BoolVar(&cfg.Risk.UseHostFallback, "risk-use-host-fallback", true, "Use SNI host as a weaker diversity signal when the real endpoint path is unavailable")

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
