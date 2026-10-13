package risk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type LookupEvent struct {
	Source   string
	Result   string
	Duration time.Duration
}

type LookupObserver interface {
	ObserveLookup(LookupEvent)
}

type LookupObserverFunc func(LookupEvent)

func (f LookupObserverFunc) ObserveLookup(event LookupEvent) {
	f(event)
}

type CachedLookupClient struct {
	client   LookupClient
	redis    redis.Cmdable
	keyFn    func(string) string
	ttl      time.Duration
	observer LookupObserver

	// inflight deduplicates concurrent origin lookups for the same JA4. The
	// cache absorbs repeated fingerprints, but a burst of identical JA4s can
	// all miss the cache before the first response is written, and nothing in
	// Redis prevents N identical libSQL/HTTP requests from being issued at
	// once. Followers wait for the leader's result instead.
	inflightMu sync.Mutex
	inflight   map[string]*inflightLookup
}

// inflightLookup is one origin lookup shared by every concurrent caller for
// the same cache key. Followers wait on done and then read the leader's
// record/err, so the enrichment backend sees a single request per JA4 burst.
type inflightLookup struct {
	done   chan struct{}
	record *FingerprintRecord
	err    error
}

type cachedLookupEntry struct {
	Status string             `json:"status"`
	Record *FingerprintRecord `json:"record,omitempty"`
}

func NewCachedLookupClient(client LookupClient, redisClient redis.Cmdable, prefix string, ttl time.Duration, observer LookupObserver) *CachedLookupClient {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	trimmedPrefix := strings.Trim(strings.TrimSpace(prefix), ":")
	return &CachedLookupClient{
		client: client,
		redis:  redisClient,
		ttl:    ttl,
		keyFn: func(ja4 string) string {
			if trimmedPrefix == "" {
				return fmt.Sprintf("sybil:lookup:%s", ja4)
			}
			return fmt.Sprintf("%s:lookup:%s", trimmedPrefix, ja4)
		},
		observer: observer,
	}
}

func (c *CachedLookupClient) Lookup(ctx context.Context, ja4 string) (*FingerprintRecord, error) {
	if c == nil || c.client == nil || c.redis == nil {
		if c != nil && c.client != nil {
			return c.client.Lookup(ctx, ja4)
		}
		return nil, nil
	}

	trimmed := strings.TrimSpace(ja4)
	cacheKey := c.keyFn(trimmed)
	cacheStart := time.Now()
	cachedValue, err := c.redis.Get(ctx, cacheKey).Result()
	switch {
	case err == nil:
		c.observe("cache", "hit", time.Since(cacheStart))
		var entry cachedLookupEntry
		if decodeErr := json.Unmarshal([]byte(cachedValue), &entry); decodeErr != nil {
			c.observe("cache", "error", 0)
			break
		}
		if entry.Status == "not_found" {
			return nil, ErrFingerprintNotFound
		}
		if entry.Record == nil {
			return nil, nil
		}
		return entry.Record, nil
	case errors.Is(err, redis.Nil):
		c.observe("cache", "miss", time.Since(cacheStart))
	default:
		c.observe("cache", "error", time.Since(cacheStart))
	}

	flight, leader := c.beginFlight(cacheKey)
	if !leader {
		// A lookup for this JA4 is already in flight. Wait for its result
		// instead of issuing a duplicate enrichment request.
		c.observe("singleflight", "joined", 0)
		joinStart := time.Now()
		select {
		case <-flight.done:
			c.observe("singleflight", "done", time.Since(joinStart))
			return flight.record, flight.err
		case <-ctx.Done():
			c.observe("singleflight", "canceled", time.Since(joinStart))
			return nil, ctx.Err()
		}
	}

	record, lookupErr := c.lookupOrigin(ctx, trimmed, cacheKey)
	c.finishFlight(cacheKey, flight, record, lookupErr)
	return record, lookupErr
}

// lookupOrigin performs one origin lookup and writes the cache entry. Only
// the single-flight leader calls it.
func (c *CachedLookupClient) lookupOrigin(ctx context.Context, ja4, cacheKey string) (*FingerprintRecord, error) {
	originStart := time.Now()
	record, lookupErr := c.client.Lookup(ctx, ja4)
	switch {
	case errors.Is(lookupErr, ErrFingerprintNotFound):
		c.observe("origin", "miss", time.Since(originStart))
		c.writeCache(ctx, cacheKey, cachedLookupEntry{Status: "not_found"})
		return nil, lookupErr
	case lookupErr != nil:
		c.observe("origin", "error", time.Since(originStart))
		return nil, lookupErr
	case record == nil:
		c.observe("origin", "miss", time.Since(originStart))
		c.writeCache(ctx, cacheKey, cachedLookupEntry{Status: "empty"})
		return nil, nil
	default:
		c.observe("origin", "hit", time.Since(originStart))
		c.writeCache(ctx, cacheKey, cachedLookupEntry{Status: "hit", Record: record})
		return record, nil
	}
}

// beginFlight registers the caller as the leader for key, or returns the
// existing in-flight lookup when one is already running. leader is true only
// for the caller that registered the flight.
func (c *CachedLookupClient) beginFlight(key string) (flight *inflightLookup, leader bool) {
	c.inflightMu.Lock()
	defer c.inflightMu.Unlock()
	if c.inflight == nil {
		c.inflight = make(map[string]*inflightLookup)
	}
	if existing, ok := c.inflight[key]; ok {
		return existing, false
	}
	flight = &inflightLookup{done: make(chan struct{})}
	c.inflight[key] = flight
	return flight, true
}

// finishFlight publishes the leader's result to every waiter and removes the
// flight. Waiters read record/err after <-done, which is ordered after the
// writes below by the channel close.
func (c *CachedLookupClient) finishFlight(key string, flight *inflightLookup, record *FingerprintRecord, err error) {
	c.inflightMu.Lock()
	delete(c.inflight, key)
	flight.record = record
	flight.err = err
	c.inflightMu.Unlock()
	close(flight.done)
}

func (c *CachedLookupClient) writeCache(ctx context.Context, key string, entry cachedLookupEntry) {
	if c == nil || c.redis == nil {
		return
	}
	payload, err := json.Marshal(entry)
	if err != nil {
		c.observe("cache", "error", 0)
		return
	}
	if err := c.redis.SetEx(ctx, key, payload, c.ttl).Err(); err != nil {
		c.observe("cache", "error", 0)
		return
	}
	c.observe("cache", "set", 0)
}

func (c *CachedLookupClient) observe(source, result string, duration time.Duration) {
	if c == nil || c.observer == nil {
		return
	}
	c.observer.ObserveLookup(LookupEvent{
		Source:   source,
		Result:   result,
		Duration: duration,
	})
}
