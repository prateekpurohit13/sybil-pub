package risk

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// blockingLookup is a LookupClient that holds every origin call until release
// is closed, so concurrent lookups can be forced to overlap deterministically.
type blockingLookup struct {
	calls   atomic.Int64
	started chan struct{}
	release chan struct{}
	record  *FingerprintRecord
	err     error
}

func newBlockingLookup(record *FingerprintRecord) *blockingLookup {
	return &blockingLookup{
		started: make(chan struct{}, 16),
		release: make(chan struct{}),
		record:  record,
	}
}

func (b *blockingLookup) Lookup(ctx context.Context, _ string) (*FingerprintRecord, error) {
	b.calls.Add(1)
	select {
	case b.started <- struct{}{}:
	default:
	}
	select {
	case <-b.release:
		return b.record, b.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func newCachedLookupTestClient(t *testing.T, origin LookupClient, observer LookupObserver) *CachedLookupClient {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return NewCachedLookupClient(origin, client, "test", time.Minute, observer)
}

// TestCachedLookupSingleFlightDeduplicatesBurst pins the fix for identical JA4
// bursts: while one origin lookup is in flight, every concurrent miss for the
// same fingerprint joins it instead of issuing another libSQL/HTTP request.
func TestCachedLookupSingleFlightDeduplicatesBurst(t *testing.T) {
	record := &FingerprintRecord{Application: "curl", JA4Fingerprint: "t13d1516h2"}
	origin := newBlockingLookup(record)

	joined := make(chan struct{}, 16)
	observer := LookupObserverFunc(func(event LookupEvent) {
		if event.Source == "singleflight" && event.Result == "joined" {
			select {
			case joined <- struct{}{}:
			default:
			}
		}
	})
	cached := newCachedLookupTestClient(t, origin, observer)

	const callers = 8
	results := make(chan *FingerprintRecord, callers)
	errs := make(chan error, callers)

	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			record, err := cached.Lookup(context.Background(), "t13d1516h2")
			results <- record
			errs <- err
		}()
	}

	// Wait for the leader to reach the origin, then for every follower to join
	// the in-flight lookup before releasing it. Followers cannot complete
	// before release, so this ordering is deterministic.
	select {
	case <-origin.started:
	case <-time.After(2 * time.Second):
		t.Fatal("origin lookup never started")
	}
	for i := 0; i < callers-1; i++ {
		select {
		case <-joined:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d of %d followers joined the in-flight lookup", i, callers-1)
		}
	}
	close(origin.release)
	wg.Wait()
	close(results)
	close(errs)

	for result := range results {
		if result == nil || result.Application != "curl" {
			t.Fatalf("lookup result = %+v, want the shared curl record", result)
		}
	}
	for err := range errs {
		if err != nil {
			t.Fatalf("lookup error = %v, want nil", err)
		}
	}
	if got := origin.calls.Load(); got != 1 {
		t.Fatalf("origin calls = %d, want 1", got)
	}

	// The leader's cache write makes the next lookup a cache hit; still no
	// second origin call.
	if _, err := cached.Lookup(context.Background(), "t13d1516h2"); err != nil {
		t.Fatalf("warm cache lookup: %v", err)
	}
	if got := origin.calls.Load(); got != 1 {
		t.Fatalf("origin calls after cache hit = %d, want 1", got)
	}
}

// TestCachedLookupSingleFlightFollowerHonorsContext verifies a follower with an
// expiring per-event deadline returns instead of waiting forever on the leader.
func TestCachedLookupSingleFlightFollowerHonorsContext(t *testing.T) {
	record := &FingerprintRecord{Application: "curl"}
	origin := newBlockingLookup(record)
	cached := newCachedLookupTestClient(t, origin, nil)

	leaderDone := make(chan error, 1)
	go func() {
		_, err := cached.Lookup(context.Background(), "ja4-burst")
		leaderDone <- err
	}()

	select {
	case <-origin.started:
	case <-time.After(2 * time.Second):
		t.Fatal("origin lookup never started")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := cached.Lookup(ctx, "ja4-burst"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("follower error = %v, want context.DeadlineExceeded", err)
	}
	if got := origin.calls.Load(); got != 1 {
		t.Fatalf("origin calls = %d, want 1 (the follower must not hit the origin)", got)
	}

	close(origin.release)
	if err := <-leaderDone; err != nil {
		t.Fatalf("leader lookup: %v", err)
	}
}
