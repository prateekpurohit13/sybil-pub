// Package worker provides a bounded worker pool used to move per-event work
// (risk scoring, lookup enrichment, persistence) off the packet capture
// goroutine.
//
// The submit path is deliberately non-blocking: packet capture must never
// stall behind Redis, libSQL, or an enrichment HTTP call. When a shard's queue
// is full the job is dropped and counted instead of applying backpressure to
// the capture loop, which would otherwise back up the pcap/kernel buffers.
package worker

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Options configures a Pool.
type Options[T any] struct {
	// Workers is the number of goroutines processing jobs. Values below 1 are
	// treated as 1.
	Workers int
	// QueueSize is the total number of jobs that may wait across all shards.
	// It is divided evenly between workers. Values below 1 are treated as 1.
	QueueSize int
	// Timeout bounds each job: the handler receives a context that is
	// cancelled after Timeout. Values <= 0 disable the per-job deadline.
	Timeout time.Duration
	// DrainTimeout bounds how long Close waits for queued jobs before it
	// cancels in-flight handlers. Values <= 0 default to 5s.
	DrainTimeout time.Duration
	// ShardOf selects the worker for a job. Jobs with the same shard value are
	// processed by the same worker in submission order, which lets callers
	// keep per-key state serialized without a global lock. A nil ShardOf
	// spreads jobs round-robin across workers.
	ShardOf func(T) uint64
	// Handler processes one job. It must honor context cancellation, because
	// Pool.Close cancels the context to unblock a slow drain.
	Handler func(context.Context, T)
	// OnDrop, when set, is called once for each job rejected because its queue
	// was full.
	OnDrop func()
}

// Pool is a bounded, sharded worker pool. It is safe for concurrent use.
type Pool[T any] struct {
	ctx          context.Context
	cancel       context.CancelFunc
	timeout      time.Duration
	drainTimeout time.Duration
	shardOf      func(T) uint64
	handler      func(context.Context, T)
	onDrop       func()

	jobs []chan T
	rr   atomic.Uint64

	wg        sync.WaitGroup
	mu        sync.RWMutex
	closed    bool
	closeOnce sync.Once
	dropped   atomic.Uint64
}

// New starts a pool with the given options. The parent context cancels every
// in-flight and future job; Close stops the workers and waits for the queues
// to drain (bounded by DrainTimeout).
func New[T any](parent context.Context, opts Options[T]) *Pool[T] {
	workers := opts.Workers
	if workers < 1 {
		workers = 1
	}
	if workers > 64 {
		workers = 64
	}
	queue := opts.QueueSize
	if queue < 1 {
		queue = 1
	}
	perWorker := (queue + workers - 1) / workers
	if perWorker < 1 {
		perWorker = 1
	}
	drain := opts.DrainTimeout
	if drain <= 0 {
		drain = 5 * time.Second
	}

	ctx, cancel := context.WithCancel(parent)
	p := &Pool[T]{
		ctx:          ctx,
		cancel:       cancel,
		timeout:      opts.Timeout,
		drainTimeout: drain,
		shardOf:      opts.ShardOf,
		handler:      opts.Handler,
		onDrop:       opts.OnDrop,
		jobs:         make([]chan T, workers),
	}
	for i := range p.jobs {
		p.jobs[i] = make(chan T, perWorker)
		p.wg.Add(1)
		go p.run(p.jobs[i])
	}
	return p
}

// TrySubmit enqueues a job on the worker selected by ShardOf (or round-robin
// when ShardOf is nil). It never blocks: if that worker's queue is full, the
// job is dropped, counted, and false is returned.
func (p *Pool[T]) TrySubmit(job T) bool {
	if p == nil || p.handler == nil {
		return false
	}

	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		p.countDrop()
		return false
	}
	select {
	case p.jobs[p.workerIndex(job)] <- job:
		p.mu.RUnlock()
		return true
	default:
		p.mu.RUnlock()
		p.countDrop()
		return false
	}
}

// Dropped reports how many jobs were rejected because their queue was full or
// the pool was already closed.
func (p *Pool[T]) Dropped() uint64 {
	if p == nil {
		return 0
	}
	return p.dropped.Load()
}

// Close stops accepting jobs, signals the workers to finish their queues, and
// waits up to DrainTimeout. If the drain is still running after the timeout,
// in-flight handler contexts are cancelled and any queued jobs are discarded.
func (p *Pool[T]) Close() {
	if p == nil {
		return
	}
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		for _, jobs := range p.jobs {
			close(jobs)
		}
		p.mu.Unlock()

		done := make(chan struct{})
		go func() {
			p.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(p.drainTimeout):
			// Handlers that honor their context unblock immediately; the
			// worker loop then discards whatever is still queued.
			p.cancel()
			<-done
		}
		p.cancel()
	})
}

func (p *Pool[T]) workerIndex(job T) int {
	if len(p.jobs) == 1 {
		return 0
	}
	if p.shardOf == nil {
		return int(p.rr.Add(1)-1) % len(p.jobs)
	}
	return int(p.shardOf(job) % uint64(len(p.jobs)))
}

func (p *Pool[T]) run(jobs <-chan T) {
	defer p.wg.Done()
	for job := range jobs {
		if p.ctx.Err() != nil {
			continue
		}
		ctx, cancel := p.jobContext()
		p.handler(ctx, job)
		cancel()
	}
}

func (p *Pool[T]) jobContext() (context.Context, context.CancelFunc) {
	if p.timeout > 0 {
		return context.WithTimeout(p.ctx, p.timeout)
	}
	return context.WithCancel(p.ctx)
}

func (p *Pool[T]) countDrop() {
	p.dropped.Add(1)
	if p.onDrop != nil {
		p.onDrop()
	}
}
