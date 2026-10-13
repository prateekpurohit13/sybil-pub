package risk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// maxResourceFieldLen caps the resource value stored as a hash field. DNS
// names are limited to 253 characters; endpoint paths are not, so a peer
// controlling the request target could otherwise force a multi-kilobyte field
// (and the matching HGetAll balloon) per observation.
const maxResourceFieldLen = 253

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
	resource = clampResource(resource)

	statsKey := s.key(pairKey, "stats")
	resourceKey := s.key(pairKey, "resources")
	minuteKey := s.key(pairKey, "minutes")
	hourKey := s.key(pairKey, "hours")

	minuteBucket := strconv.FormatInt(now.Truncate(time.Minute).Unix(), 10)
	hourBucket := strconv.FormatInt(now.Truncate(time.Hour).Unix(), 10)

	// Retention budget: each (pair, suffix) key costs one key while a pair is
	// active. Stale buckets are HDel'd on the next record, so these TTLs only
	// decide how long an idle pair lingers. Keep them just past the scoring
	// window instead of the old stats 48h / minute+resource 2h / hour 25h
	// layout, which kept idle-pair keys alive well beyond the data they could
	// still serve.
	statsRetention := cfg.HourWindow + 2*time.Hour
	resourceRetention := cfg.ResourceWindow + 15*time.Minute
	minuteRetention := cfg.MinuteWindow + 15*time.Minute
	hourRetention := cfg.HourWindow + time.Hour

	pipe := s.client.TxPipeline()
	totalCmd := pipe.HIncrBy(ctx, statsKey, "total_requests", 1)
	pipe.HSet(ctx, statsKey, "last_seen_unix", now.Unix())
	pipe.HSetNX(ctx, statsKey, "first_seen_unix", now.Unix())
	if resource != "" {
		pipe.HSet(ctx, resourceKey, resource, now.Unix())
	}
	pipe.HIncrBy(ctx, minuteKey, minuteBucket, 1)
	pipe.HIncrBy(ctx, hourKey, hourBucket, 1)
	pipe.Expire(ctx, statsKey, statsRetention)
	pipe.Expire(ctx, resourceKey, resourceRetention)
	pipe.Expire(ctx, minuteKey, minuteRetention)
	pipe.Expire(ctx, hourKey, hourRetention)
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
	cutoffMinutes := now.Add(-cfg.MinuteWindow).Truncate(time.Minute).Unix()
	cutoffHours := now.Add(-cfg.HourWindow).Truncate(time.Hour).Unix()

	uniqueResources, staleResources := countFreshResources(resourceCmd.Val(), cutoffResources)
	minuteCounts, windowRequests, staleMinutes := collectBuckets(minuteCmd.Val(), cutoffMinutes)
	hourCounts, _, staleHours := collectBuckets(hourCmd.Val(), cutoffHours)

	// Best-effort cleanup of buckets that fell out of the window. This is safe
	// without MULTI because the capture loop calls Record serially: a field
	// read as stale cannot be refreshed concurrently, so the HDel cannot drop
	// a live count. If Record ever gains parallel writers, replace this with a
	// Lua script or WATCH-based prune; it is deliberately not in MULTI today
	// to keep the hot path to one round trip.
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

	activeMinutes := len(minuteCounts)
	rpm := 0.0
	if activeMinutes > 0 {
		rpm = float64(windowRequests) / float64(activeMinutes)
	}

	return LiveStats{
		PairKey:           pairKey,
		ResourceKind:      resourceKind,
		WindowRequests:    windowRequests,
		TotalRequests:     totalCmd.Val(),
		ActiveMinutes:     activeMinutes,
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

// key builds a Redis key from the observation pair key. The pair key is
// hashed rather than embedded raw because it is "<JA4>|<source IP>": raw
// IPv6 addresses contain colons and arbitrary separators, and the pair key
// feeds Redis key names where unbounded/ambiguous components would make key
// scanning and sharding fragile. The full pair key is still returned in
// LiveStats for display.
func (s *RedisStore) key(pairKey, suffix string) string {
	segment := pairKeySegment(pairKey)
	if s.prefix == "" {
		return fmt.Sprintf("sybil:risk:%s:%s", segment, suffix)
	}
	return fmt.Sprintf("%s:%s:%s", s.prefix, segment, suffix)
}

func pairKeySegment(pairKey string) string {
	sum := sha256.Sum256([]byte(pairKey))
	return "pair:" + hex.EncodeToString(sum[:12])
}

// clampResource bounds attacker-controlled resource values (mostly SNI hosts,
// but endpoint paths from custom callers too) to the DNS name limit so a hash
// field can never balloon.
func clampResource(resource string) string {
	if len(resource) <= maxResourceFieldLen {
		return resource
	}
	runes := []rune(resource)
	if len(runes) <= maxResourceFieldLen {
		return resource
	}
	return string(runes[:maxResourceFieldLen])
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
