package worker

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPoolProcessesAllJobs(t *testing.T) {
	const jobs = 100
	var processed atomic.Int64

	pool := New[int](context.Background(), Options[int]{
		Workers:   4,
		QueueSize: 128,
		Timeout:   time.Second,
		Handler: func(context.Context, int) {
			processed.Add(1)
		},
	})

	for i := 0; i < jobs; i++ {
		if !pool.TrySubmit(i) {
			t.Fatalf("job %d rejected with an empty queue", i)
		}
	}
	pool.Close()

	if got := processed.Load(); got != jobs {
		t.Fatalf("processed = %d, want %d", got, jobs)
	}
	if got := pool.Dropped(); got != 0 {
		t.Fatalf("dropped = %d, want 0", got)
	}

	// Submitting after Close must be rejected and counted, never panic on a
	// closed channel.
	if pool.TrySubmit(jobs) {
		t.Fatal("submit after Close succeeded")
	}
	if got := pool.Dropped(); got != 1 {
		t.Fatalf("dropped after closed submit = %d, want 1", got)
	}
}

func TestPoolDropsWhenShardQueueIsFull(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	var onDrop atomic.Int64

	pool := New[int](context.Background(), Options[int]{
		Workers:   1,
		QueueSize: 2,
		ShardOf:   func(int) uint64 { return 0 },
		Handler: func(context.Context, int) {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-release
		},
		OnDrop: func() { onDrop.Add(1) },
	})

	accepted := 0
	rejected := 0
	for i := 0; i < 50; i++ {
		if pool.TrySubmit(i) {
			accepted++
		} else {
			rejected++
		}
	}

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("handler never started")
	}
	if rejected == 0 {
		t.Fatalf("expected drops once the queue filled, accepted all %d jobs", accepted)
	}
	if got := pool.Dropped(); got != uint64(rejected) {
		t.Fatalf("Dropped() = %d, want %d", got, rejected)
	}
	if got := onDrop.Load(); got != int64(rejected) {
		t.Fatalf("OnDrop called %d times, want %d", got, rejected)
	}

	close(release)
	pool.Close()
}

func TestPoolBoundsHandlerWithTimeout(t *testing.T) {
	ctxErr := make(chan error, 1)

	pool := New[int](context.Background(), Options[int]{
		Workers:   1,
		QueueSize: 1,
		Timeout:   20 * time.Millisecond,
		Handler: func(ctx context.Context, _ int) {
			<-ctx.Done()
			ctxErr <- ctx.Err()
		},
	})

	if !pool.TrySubmit(1) {
		t.Fatal("submit failed")
	}

	select {
	case err := <-ctxErr:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("handler context error = %v, want DeadlineExceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler was not cancelled by the per-job timeout")
	}
	pool.Close()
}

func TestPoolKeepsShardOrder(t *testing.T) {
	const jobs = 200

	var mu sync.Mutex
	var got []int

	pool := New[int](context.Background(), Options[int]{
		Workers:   8,
		QueueSize: 2048,
		ShardOf:   func(value int) uint64 { return uint64(value % 2) },
		Handler: func(_ context.Context, value int) {
			mu.Lock()
			got = append(got, value)
			mu.Unlock()
		},
	})

	for i := 0; i < jobs; i++ {
		if !pool.TrySubmit(i) {
			t.Fatalf("unexpected drop at job %d", i)
		}
	}
	pool.Close()

	if len(got) != jobs {
		t.Fatalf("processed %d jobs, want %d", len(got), jobs)
	}
	// Each shard maps to exactly one worker, which consumes its channel FIFO.
	next := map[int]int{0: 0, 1: 1}
	for _, value := range got {
		if next[value%2] != value {
			t.Fatalf("shard %d out of order: got %d, want %d", value%2, value, next[value%2])
		}
		next[value%2] += 2
	}
}

func TestPoolCloseCancelsSlowDrain(t *testing.T) {
	started := make(chan struct{}, 1)

	pool := New[int](context.Background(), Options[int]{
		Workers:      1,
		QueueSize:    1,
		DrainTimeout: 30 * time.Millisecond,
		Handler: func(ctx context.Context, _ int) {
			select {
			case started <- struct{}{}:
			default:
			}
			<-ctx.Done()
		},
	})
	if !pool.TrySubmit(1) {
		t.Fatal("submit failed")
	}
	<-started

	done := make(chan struct{})
	go func() {
		pool.Close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return after the drain timeout")
	}
}
