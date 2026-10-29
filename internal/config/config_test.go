package config

import (
	"strings"
	"testing"
	"time"
)

func TestDefaultObservabilityBindsLoopbackOnly(t *testing.T) {
	obs := defaultObservability()
	if obs.HTTPAddr != DefaultHTTPAddr {
		t.Fatalf("HTTPAddr = %q, want %q", obs.HTTPAddr, DefaultHTTPAddr)
	}
	if obs.HTTPAddr != "127.0.0.1:9090" {
		t.Fatalf("HTTPAddr = %q, want 127.0.0.1:9090", obs.HTTPAddr)
	}
	if obs.HTTPToken != "" {
		t.Fatalf("HTTPToken = %q, want empty when SYBIL_HTTP_TOKEN is unset", obs.HTTPToken)
	}
	if len(obs.HTTPCORSOrigins) != 0 {
		t.Fatalf("HTTPCORSOrigins = %v, want none (same-origin only)", obs.HTTPCORSOrigins)
	}
}

func TestDefaultObservabilityTimeouts(t *testing.T) {
	obs := defaultObservability()
	cases := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"read-header", obs.ReadHeaderTimeout, 5 * time.Second},
		{"read", obs.ReadTimeout, 10 * time.Second},
		{"write", obs.WriteTimeout, 10 * time.Second},
		{"idle", obs.IdleTimeout, 60 * time.Second},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s timeout = %s, want %s", tc.name, tc.got, tc.want)
		}
		if tc.got <= 0 {
			t.Errorf("%s timeout must be positive to bound slow clients", tc.name)
		}
	}
}

func TestDefaultObservabilityTokenFromEnv(t *testing.T) {
	t.Setenv("SYBIL_HTTP_TOKEN", "env-token")
	if got := defaultObservability().HTTPToken; got != "env-token" {
		t.Fatalf("HTTPToken = %q, want env-token", got)
	}
}

func TestParseCORSOrigins(t *testing.T) {
	t.Run("trims and dedupes", func(t *testing.T) {
		got, err := parseCORSOrigins(" https://a.example, https://b.example ,https://a.example,")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"https://a.example", "https://b.example"}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("got %v, want %v", got, want)
			}
		}
	})

	t.Run("empty means same-origin only", func(t *testing.T) {
		got, err := parseCORSOrigins("  ,  ")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("got %v, want none", got)
		}
	})

	t.Run("wildcard rejected", func(t *testing.T) {
		if _, err := parseCORSOrigins("*"); err == nil {
			t.Fatal("expected wildcard origin to be rejected")
		}
		if _, err := parseCORSOrigins("https://a.example,*"); err == nil {
			t.Fatal("expected wildcard in list to be rejected")
		}
	})

	t.Run("trailing slash normalized", func(t *testing.T) {
		got, err := parseCORSOrigins("https://a.example/")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 || got[0] != "https://a.example" {
			t.Fatalf("got %v, want [https://a.example]", got)
		}
	})

	t.Run("malformed origins rejected", func(t *testing.T) {
		for _, raw := range []string{
			"a.example",
			"https://",
			"ftp://a.example",
			"https://a.example/path",
			"https://a.example?x=1",
			"https://user@a.example",
		} {
			if _, err := parseCORSOrigins(raw); err == nil {
				t.Errorf("expected %q to be rejected", raw)
			}
		}
	})
}

// validConfig returns a minimal configuration that Validate accepts. Tests
// mutate one field at a time to isolate the rule under test.
func validConfig() Config {
	return Config{
		Capture: Capture{Backend: BackendPCAP, Interface: "lo"},
		Risk: Risk{
			RedisDialTimeout:     5 * time.Second,
			RedisReadTimeout:     3 * time.Second,
			RedisWriteTimeout:    3 * time.Second,
			RedisPoolTimeout:     4 * time.Second,
			RedisPoolSize:        32,
			RedisMinIdleConns:    2,
			RedisConnectAttempts: 3,
			JA4LookupTimeout:     2 * time.Second,
			JA4CacheTTL:          30 * time.Minute,
			DelayThreshold:       -1,
			RateLimitThresh:      -1,
			ChallengeThresh:      -1,
			BlockThresh:          -1,
		},
		Observability: defaultObservability(),
	}
}

func TestValidateAcceptsDefaults(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatalf("default config should validate, got %v", err)
	}
}

func TestValidateAcceptsBoundaryValues(t *testing.T) {
	cfg := validConfig()
	cfg.Capture.MatchPort = 65535
	cfg.Risk.RedisDB = 0
	cfg.Risk.JA4LookupURL = "https://lookup.example/api/%s"
	cfg.Observability.HTTPCORSOrigins = []string{"http://localhost:3000", "https://[::1]:8443"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("boundary config should validate, got %v", err)
	}

	// An empty -http-addr disables the server and must stay valid.
	disabled := validConfig()
	disabled.Observability.HTTPAddr = ""
	if err := disabled.Validate(); err != nil {
		t.Fatalf("disabled observability server should validate, got %v", err)
	}
}

func TestValidateRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{
			name:   "unknown backend",
			mutate: func(c *Config) { c.Capture.Backend = "af_packet" },
			want:   "-backend",
		},
		{
			name:   "empty iface",
			mutate: func(c *Config) { c.Capture.Interface = "  " },
			want:   "-iface",
		},
		{
			name:   "port above 65535",
			mutate: func(c *Config) { c.Capture.MatchPort = 65536 },
			want:   "-port",
		},
		{
			name: "delay above block",
			mutate: func(c *Config) {
				c.Risk.DelayThreshold = 90
				c.Risk.BlockThresh = 70
			},
			want: "strictly increasing",
		},
		{
			name: "rate equal to challenge",
			mutate: func(c *Config) {
				c.Risk.RateLimitThresh = 85
				c.Risk.ChallengeThresh = 85
			},
			want: "strictly increasing",
		},
		{
			name:   "delay override hides default block",
			mutate: func(c *Config) { c.Risk.DelayThreshold = 96 },
			want:   "strictly increasing",
		},
		{
			name:   "negative redis db",
			mutate: func(c *Config) { c.Risk.RedisDB = -1 },
			want:   "-redis-db",
		},
		{
			name:   "zero pool size",
			mutate: func(c *Config) { c.Risk.RedisPoolSize = 0 },
			want:   "-redis-pool-size",
		},
		{
			name:   "zero connect attempts",
			mutate: func(c *Config) { c.Risk.RedisConnectAttempts = 0 },
			want:   "-redis-connect-attempts",
		},
		{
			name:   "zero redis dial timeout",
			mutate: func(c *Config) { c.Risk.RedisDialTimeout = 0 },
			want:   "-redis-dial-timeout",
		},
		{
			name:   "negative ja4 cache ttl",
			mutate: func(c *Config) { c.Risk.JA4CacheTTL = -time.Second },
			want:   "-ja4-cache-ttl",
		},
		{
			name:   "address without port",
			mutate: func(c *Config) { c.Observability.HTTPAddr = "127.0.0.1" },
			want:   "-http-addr",
		},
		{
			name:   "address with out-of-range port",
			mutate: func(c *Config) { c.Observability.HTTPAddr = "127.0.0.1:70000" },
			want:   "-http-addr",
		},
		{
			name:   "zero http read timeout",
			mutate: func(c *Config) { c.Observability.ReadTimeout = 0 },
			want:   "-http-read-timeout",
		},
		{
			name:   "lookup url bad scheme",
			mutate: func(c *Config) { c.Risk.JA4LookupURL = "ftp://lookup.example" },
			want:   "-ja4-lookup-url",
		},
		{
			name:   "lookup url missing host",
			mutate: func(c *Config) { c.Risk.JA4LookupURL = "not a url" },
			want:   "-ja4-lookup-url",
		},
		{
			name:   "cors origin with path",
			mutate: func(c *Config) { c.Observability.HTTPCORSOrigins = []string{"https://a.example/path"} },
			want:   "CORS",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected error mentioning %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}
