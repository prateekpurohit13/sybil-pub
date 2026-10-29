package db

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestOpenRedisRejectsEmptyAddr(t *testing.T) {
	if _, err := OpenRedis(context.Background(), RedisConfig{}); err == nil {
		t.Fatal("expected an error for an empty address")
	}
}

func TestOpenRedisAppliesTimeoutsAndPings(t *testing.T) {
	mr := miniredis.RunT(t)

	client, err := OpenRedis(context.Background(), RedisConfig{
		Addr:         mr.Addr(),
		DialTimeout:  2 * time.Second,
		ReadTimeout:  1500 * time.Millisecond,
		WriteTimeout: 1500 * time.Millisecond,
		PoolTimeout:  3 * time.Second,
		PoolSize:     7,
		MinIdleConns: 1,
		MaxRetries:   1,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	opts := client.Options()
	if opts.DialTimeout != 2*time.Second {
		t.Errorf("DialTimeout = %s, want 2s", opts.DialTimeout)
	}
	if opts.ReadTimeout != 1500*time.Millisecond {
		t.Errorf("ReadTimeout = %s, want 1.5s", opts.ReadTimeout)
	}
	if opts.WriteTimeout != 1500*time.Millisecond {
		t.Errorf("WriteTimeout = %s, want 1.5s", opts.WriteTimeout)
	}
	if opts.PoolTimeout != 3*time.Second {
		t.Errorf("PoolTimeout = %s, want 3s", opts.PoolTimeout)
	}
	if opts.PoolSize != 7 {
		t.Errorf("PoolSize = %d, want 7", opts.PoolSize)
	}
	if opts.MinIdleConns != 1 {
		t.Errorf("MinIdleConns = %d, want 1", opts.MinIdleConns)
	}
	if opts.MaxRetries != 1 {
		t.Errorf("MaxRetries = %d, want 1", opts.MaxRetries)
	}

	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

// TestOpenRedisDefaultOptionsAreBounded guards against someone dropping the
// defaults and reviving the unbounded-timeout behavior a wedged Redis would
// turn into a capture-path stall.
func TestOpenRedisDefaultOptionsAreBounded(t *testing.T) {
	mr := miniredis.RunT(t)

	client, err := OpenRedis(context.Background(), RedisConfig{Addr: mr.Addr()})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	opts := client.Options()
	if opts.DialTimeout <= 0 || opts.ReadTimeout <= 0 || opts.WriteTimeout <= 0 || opts.PoolTimeout <= 0 {
		t.Fatalf("expected all timeouts to be positive, got dial=%s read=%s write=%s pool=%s",
			opts.DialTimeout, opts.ReadTimeout, opts.WriteTimeout, opts.PoolTimeout)
	}
	if opts.PoolSize <= 0 || opts.MinIdleConns <= 0 {
		t.Fatalf("expected a bounded warm pool, got pool=%d minIdle=%d", opts.PoolSize, opts.MinIdleConns)
	}
}
