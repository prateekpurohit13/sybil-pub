package risk

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisStore struct {
	client redis.Cmdable
	prefix string
}

func NewRedisStore(client redis.Cmdable, prefix string) *RedisStore {
	return &RedisStore{
		client: client,
		prefix: strings.Trim(strings.TrimSpace(prefix), ":"),
	}
}

func (s *RedisStore) Record(ctx context.Context, obs Observation, cfg Config) (LiveStats, error) {
	now := obs.Timestamp.UTC()
	pairKey := obs.pairKey()
	resource, resourceKind := resolveResource(obs, cfg.UseHostFallback)

	statsKey := s.key(pairKey, "stats")
	resourceKey := s.key(pairKey, "resources")
	minuteKey := s.key(pairKey, "minutes")
	hourKey := s.key(pairKey, "hours")

	bucketSeconds := cfg.BucketSeconds
	if bucketSeconds <= 0 {
		bucketSeconds = 60
	}
	bucketDuration := time.Duration(bucketSeconds) * time.Second
	minuteBucket := strconv.FormatInt(now.Truncate(bucketDuration).Unix(), 10)
	hourBucket := strconv.FormatInt(now.Truncate(time.Hour).Unix(), 10)
	retention := cfg.HourWindow + 24*time.Hour

	pipe := s.client.TxPipeline()
	totalCmd := pipe.HIncrBy(ctx, statsKey, "total_requests", 1)
	pipe.HSet(ctx, statsKey, "last_seen_unix", now.Unix())
	pipe.HSetNX(ctx, statsKey, "first_seen_unix", now.Unix())
	if resource != "" {
		pipe.HSet(ctx, resourceKey, resource, now.Unix())
	}
	pipe.HIncrBy(ctx, minuteKey, minuteBucket, 1)
	pipe.HIncrBy(ctx, hourKey, hourBucket, 1)
	pipe.Expire(ctx, statsKey, retention)
	pipe.Expire(ctx, resourceKey, cfg.ResourceWindow+time.Hour)
	pipe.Expire(ctx, minuteKey, cfg.MinuteWindow+time.Hour)
	pipe.Expire(ctx, hourKey, cfg.HourWindow+time.Hour)
	statsCmd := pipe.HGetAll(ctx, statsKey)
	resourceCmd := pipe.HGetAll(ctx, resourceKey)
	minuteCmd := pipe.HGetAll(ctx, minuteKey)
	hourCmd := pipe.HGetAll(ctx, hourKey)
	if _, err := pipe.Exec(ctx); err != nil {
		return LiveStats{}, err
	}

	firstSeen := unixFromMap(statsCmd.Val(), "first_seen_unix")
	lastSeen := unixFromMap(statsCmd.Val(), "last_seen_unix")

	cutoffResources := now.Add(-cfg.ResourceWindow).Unix()
	cutoffMinutes := now.Add(-cfg.MinuteWindow).Truncate(bucketDuration).Unix()
	cutoffHours := now.Add(-cfg.HourWindow).Truncate(time.Hour).Unix()

	uniqueResources, staleResources := countFreshResources(resourceCmd.Val(), cutoffResources)
	minuteCounts, windowRequests, staleMinutes := collectBuckets(minuteCmd.Val(), cutoffMinutes)
	hourCounts, _, staleHours := collectBuckets(hourCmd.Val(), cutoffHours)

	if len(staleResources) > 0 || len(staleMinutes) > 0 || len(staleHours) > 0 {
		cleanup := s.client.TxPipeline()
		if len(staleResources) > 0 {
			cleanup.HDel(ctx, resourceKey, staleResources...)
		}
		if len(staleMinutes) > 0 {
			cleanup.HDel(ctx, minuteKey, staleMinutes...)
		}
		if len(staleHours) > 0 {
			cleanup.HDel(ctx, hourKey, staleHours...)
		}
		_, _ = cleanup.Exec(ctx)
	}

	peakMinute := int64(0)
	for _, count := range minuteCounts {
		if count > peakMinute {
			peakMinute = count
		}
	}

	medianMinute := median(minuteCounts)
	peakToMedian := 0.0
	if medianMinute > 0 {
		peakToMedian = float64(peakMinute) / medianMinute
	}

	activeBuckets := len(minuteCounts)
	activeMinutes := float64(activeBuckets) * float64(bucketSeconds) / 60.0
	rpm := 0.0
	if activeMinutes > 0 {
		rpm = float64(windowRequests) / activeMinutes
	}

	return LiveStats{
		PairKey:           pairKey,
		ResourceKind:      resourceKind,
		WindowRequests:    windowRequests,
		TotalRequests:     totalCmd.Val(),
		ActiveBuckets:     activeBuckets,
		BucketSeconds:     bucketSeconds,
		RequestsPerMinute: rpm,
		UniqueResources:   uniqueResources,
		MinuteCounts:      minuteCounts,
		HourCounts:        hourCounts,
		PeakMinuteCount:   peakMinute,
		MedianMinuteCount: medianMinute,
		PeakToMedianRatio: peakToMedian,
		FirstSeen:         firstSeen,
		LastSeen:          lastSeen,
	}, nil
}

func (s *RedisStore) key(pairKey, suffix string) string {
	if s.prefix == "" {
		return fmt.Sprintf("sybil:risk:%s:%s", pairKey, suffix)
	}
	return fmt.Sprintf("%s:%s:%s", s.prefix, pairKey, suffix)
}

func unixFromMap(values map[string]string, field string) time.Time {
	raw := strings.TrimSpace(values[field])
	if raw == "" {
		return time.Time{}
	}
	parsed, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || parsed <= 0 {
		return time.Time{}
	}
	return time.Unix(parsed, 0).UTC()
}

func countFreshResources(values map[string]string, cutoff int64) (int, []string) {
	total := 0
	stale := make([]string, 0)
	for field, raw := range values {
		lastSeen, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || lastSeen < cutoff {
			stale = append(stale, field)
			continue
		}
		total++
	}
	return total, stale
}

func collectBuckets(values map[string]string, cutoff int64) ([]int64, int64, []string) {
	type bucket struct {
		ts    int64
		count int64
	}

	series := make([]bucket, 0, len(values))
	stale := make([]string, 0)
	total := int64(0)

	for field, raw := range values {
		ts, err := strconv.ParseInt(field, 10, 64)
		if err != nil || ts < cutoff {
			stale = append(stale, field)
			continue
		}

		count, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || count <= 0 {
			stale = append(stale, field)
			continue
		}

		series = append(series, bucket{ts: ts, count: count})
		total += count
	}

	sort.Slice(series, func(i, j int) bool {
		return series[i].ts < series[j].ts
	})

	counts := make([]int64, 0, len(series))
	for _, point := range series {
		counts = append(counts, point.count)
	}

	return counts, total, stale
}
