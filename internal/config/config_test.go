package config

import (
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
}
