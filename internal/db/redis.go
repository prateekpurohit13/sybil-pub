package db

import (
	"context"
	"fmt"
	"strings"
	"time"

	redis "github.com/redis/go-redis/v9"
)

type RedisConfig struct {
	Addr     string
	Password string
	DB       int

	// Connection tuning. Zero values fall back to defaultRedisOptions so
	// callers that only set Addr/Password/DB keep working while still getting
	// bounded dial/read/write timeouts and a connection pool instead of the
	// go-redis defaults plus an unbounded ping.
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	PoolTimeout  time.Duration
	PoolSize     int
	MinIdleConns int
	MaxRetries   int
}

// defaultRedisOptions returns a conservative baseline for a sensor that
// shares one client between the capture hot path and the HTTP API. Timeouts
// are deliberately finite so a wedged Redis cannot pin a capture goroutine
// forever, and the pool is bounded so a slow server cannot fan out connections.
func defaultRedisOptions() *redis.Options {
	return &redis.Options{
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolTimeout:  4 * time.Second,
		PoolSize:     32,
		MinIdleConns: 2,
		MaxRetries:   2,
	}
}

func OpenRedis(ctx context.Context, cfg RedisConfig) (*redis.Client, error) {
	addr := strings.TrimSpace(cfg.Addr)
	if addr == "" {
		return nil, fmt.Errorf("missing redis address")
	}

	opts := defaultRedisOptions()
	opts.Addr = addr
	opts.Password = cfg.Password
	opts.DB = cfg.DB
	if cfg.DialTimeout > 0 {
		opts.DialTimeout = cfg.DialTimeout
	}
	if cfg.ReadTimeout > 0 {
		opts.ReadTimeout = cfg.ReadTimeout
	}
	if cfg.WriteTimeout > 0 {
		opts.WriteTimeout = cfg.WriteTimeout
	}
	if cfg.PoolTimeout > 0 {
		opts.PoolTimeout = cfg.PoolTimeout
	}
	if cfg.PoolSize > 0 {
		opts.PoolSize = cfg.PoolSize
	}
	if cfg.MinIdleConns > 0 {
		opts.MinIdleConns = cfg.MinIdleConns
	}
	if cfg.MaxRetries > 0 {
		opts.MaxRetries = cfg.MaxRetries
	}

	client := redis.NewClient(opts)
	if err := client.Ping(ctx).Err(); err != nil {
		// Close before returning so a failed startup (including the retry loop
		// in main) cannot leak the client's background reconnect goroutines.
		_ = client.Close()
		return nil, fmt.Errorf("redis ping failed: %w", err)
	}

	return client, nil
}
