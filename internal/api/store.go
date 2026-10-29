package api

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// Retention and bounding rules for this Redis store. Every key class is
// bounded by a function of traffic rate rather than process uptime, so a
// headless sensor whose dashboard endpoints are never polled cannot grow
// Redis without limit:
//
//	api:stats:total            one hash, 4 fixed verdict fields, no TTL needed
//	api:stats:hour:<unix>      1 key/hour, TTL 48h                     -> 48 keys
//	api:requests:recent        list trimmed to defaultRecentLimit
//	api:request:<id>           1 key/request, TTL 25h                 -> 25h * rate
//	api:requests:top_threats   zset rank-capped at maxTopThreats (writes evict
//	                           the weakest scores), so it is bounded even when
//	                           /api/requests/top-threats is never scraped
//	api:fingerprints:*         counts/scores/display/labels/kinds/last_seen keys
//	                           carry a 48h TTL refreshed on write, plus an
//	                           amortized last-seen prune and a maxFingerprints
//	                           rank cap on the counts zset
//	api:fingerprints:hour:<ts> count+score hash per hour bucket, TTL 2h; the
//	                           last-hour endpoints read the current and previous
//	                           bucket instead of scanning every request payload
const (
	defaultRecentLimit = 10
	defaultTopLimit    = 10

	// requestRetention must stay >= 24h (top-threat age cutoff) and >= the
	// last-hour read window so request payloads outlive their zset entries.
	requestRetention = 25 * time.Hour
	// hourRetention covers the 24h timeseries query plus one hour of clock
	// skew, so Timeseries(now) can always read a full day of buckets.
	hourRetention = 48 * time.Hour
	// fingerprintRetention is how long an inactive fingerprint's aggregate
	// fields survive. The TTL is refreshed on every write, so pruning by
	// last-seen is what actually bounds cardinality under continuous traffic;
	// the TTL is the backstop for a prefix that stops receiving writes.
	fingerprintRetention = 48 * time.Hour
	// fingerprintHourRetention keeps the current and previous hourly counter
	// buckets for the last-hour endpoints; 2h covers the window plus the
	// bucket boundary.
	fingerprintHourRetention = 2 * time.Hour

	// maxTopThreats caps the by-score threat zset. defaultTopLimit is the
	// dashboard page size, so this leaves ~100 pages of headroom.
	maxTopThreats = 1000
	// maxFingerprints caps the number of distinct fingerprints kept in the
	// all-time common-fingerprint aggregate.
	maxFingerprints = 10000
	// fingerprintPruneInterval amortizes the O(stale) last-seen prune across
	// records: one prune per N Record calls, so hot-path overhead is ~1/N.
	fingerprintPruneInterval = 256

	fingerprintTopScoreBase = 1_000_000_0000
	// Per-hour bucket hash fields are prefixed so count and score-sum can
	// share one hash key (and therefore one TTL) per hour.
	fingerprintCountFieldPrefix = "c:"
	fingerprintScoreFieldPrefix = "s:"
)

type RedisStore struct {
	client redis.Cmdable
	prefix string

	// recordCount drives the amortized fingerprint prune. Record is called
	// from the single capture goroutine today; atomic keeps the counter safe
	// if writes are ever parallelized.
	recordCount atomic.Int64
}

func NewRedisStore(client redis.Cmdable, prefix string) *RedisStore {
	return &RedisStore{
		client: client,
		prefix: strings.Trim(strings.TrimSpace(prefix), ":"),
	}
}

func (s *RedisStore) Record(ctx context.Context, obs RequestObservation) error {
	if strings.TrimSpace(obs.JA4Fingerprint) == "" {
		return fmt.Errorf("missing ja4 fingerprint")
	}
	if obs.Timestamp.IsZero() {
		obs.Timestamp = time.Now().UTC()
	} else {
		obs.Timestamp = obs.Timestamp.UTC()
	}
	if strings.TrimSpace(obs.Fingerprint) == "" {
		obs.Fingerprint = obs.JA4Fingerprint
	}
	if strings.TrimSpace(obs.FingerprintKind) == "" {
		obs.FingerprintKind = "ja4"
	}
	if obs.Label == "" {
		obs.Label = "Unknown JA4 Client"
	}

	id, err := s.client.Incr(ctx, s.key("api", "requests", "seq")).Result()
	if err != nil {
		return err
	}

	request := TLSRequest{
		ID:               id,
		Timestamp:        obs.Timestamp,
		SourceIP:         obs.SourceIP,
		DestinationIP:    obs.DestinationIP,
		JA3Hash:          obs.JA4Fingerprint,
		Fingerprint:      obs.Fingerprint,
		ThreatScore:      obs.ThreatScore,
		Verdict:          normalizeVerdict(obs.Verdict),
		MatchedSignature: obs.MatchedSignature,
		FingerprintKind:  obs.FingerprintKind,
		JA4Fingerprint:   obs.JA4Fingerprint,
	}

	payload, err := json.Marshal(request)
	if err != nil {
		return err
	}

	hourKey := s.hourKey(obs.Timestamp)
	fingerprintHourKey := s.fingerprintHourKey(obs.Timestamp)
	requestKey := s.key("api", "request", strconv.FormatInt(id, 10))
	recentKey := s.key("api", "requests", "recent")
	threatKey := s.key("api", "requests", "top_threats")
	countsKey := s.key("api", "fingerprints", "counts")
	scoresKey := s.key("api", "fingerprints", "scores")
	displayKey := s.key("api", "fingerprints", "display")
	labelsKey := s.key("api", "fingerprints", "labels")
	kindsKey := s.key("api", "fingerprints", "kinds")
	lastSeenKey := s.key("api", "fingerprints", "last_seen")
	memberID := strconv.FormatInt(id, 10)
	verdict := normalizeVerdict(obs.Verdict)

	pipe := s.client.TxPipeline()
	pipe.HIncrBy(ctx, s.key("api", "stats", "total"), "total", 1)
	pipe.HIncrBy(ctx, s.key("api", "stats", "total"), verdict, 1)

	pipe.HIncrBy(ctx, hourKey, "total", 1)
	pipe.HIncrBy(ctx, hourKey, verdict, 1)
	pipe.Expire(ctx, hourKey, hourRetention)

	pipe.LPush(ctx, recentKey, payload)
	pipe.LTrim(ctx, recentKey, 0, defaultRecentLimit-1)

	pipe.Set(ctx, requestKey, payload, requestRetention)
	pipe.ZAdd(ctx, threatKey, redis.Z{
		Score:  topThreatScore(request.ThreatScore, obs.Timestamp),
		Member: memberID,
	})
	// Keep only the strongest maxTopThreats entries. The rank cap makes the
	// zset memory-bound even when /api/requests/top-threats is never polled,
	// which is what let the old time-keyed zset grow with every request.
	pipe.ZRemRangeByRank(ctx, threatKey, 0, -(maxTopThreats + 1))

	pipe.ZIncrBy(ctx, countsKey, 1, obs.JA4Fingerprint)
	pipe.HIncrBy(ctx, scoresKey, obs.JA4Fingerprint, int64(obs.ThreatScore))
	pipe.HSet(ctx, displayKey, obs.JA4Fingerprint, obs.Fingerprint)
	pipe.HSet(ctx, labelsKey, obs.JA4Fingerprint, obs.Label)
	pipe.HSet(ctx, kindsKey, obs.JA4Fingerprint, obs.FingerprintKind)
	pipe.ZAdd(ctx, lastSeenKey, redis.Z{
		Score:  float64(obs.Timestamp.Unix()),
		Member: obs.JA4Fingerprint,
	})
	for _, key := range []string{countsKey, scoresKey, displayKey, labelsKey, kindsKey, lastSeenKey} {
		pipe.Expire(ctx, key, fingerprintRetention)
	}

	// Per-hour buckets power the last-hour endpoints with a bounded read:
	// two HGetAll calls instead of ZRangeByScore(+inf) across every request
	// in the window plus one MGET per request ID.
	pipe.HIncrBy(ctx, fingerprintHourKey, fingerprintCountFieldPrefix+obs.JA4Fingerprint, 1)
	pipe.HIncrBy(ctx, fingerprintHourKey, fingerprintScoreFieldPrefix+obs.JA4Fingerprint, int64(obs.ThreatScore))
	pipe.Expire(ctx, fingerprintHourKey, fingerprintHourRetention)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return err
	}

	// Prune inactive fingerprints periodically, not on every record: the scan
	// is O(stale fields) and amortizing it keeps the hot path cheap.
	if s.recordCount.Add(1)%fingerprintPruneInterval == 0 {
		_ = s.pruneFingerprints(ctx, obs.Timestamp)
	}
	return nil
}

func (s *RedisStore) TotalStats(ctx context.Context) (TotalStats, error) {
	values, err := s.client.HGetAll(ctx, s.key("api", "stats", "total")).Result()
	if err != nil {
		return TotalStats{}, err
	}
	return TotalStats{
		Total:      parseInt64(values["total"]),
		Malicious:  parseInt64(values["malicious"]),
		Suspicious: parseInt64(values["suspicious"]),
		Clean:      parseInt64(values["clean"]),
	}, nil
}

func (s *RedisStore) Timeseries(ctx context.Context, now time.Time) ([]TimeseriesEntry, error) {
	now = now.UTC().Truncate(time.Hour)
	start := now.Add(-23 * time.Hour)

	pipe := s.client.Pipeline()
	cmds := make([]*redis.MapStringStringCmd, 0, 24)
	timestamps := make([]time.Time, 0, 24)
	for ts := start; !ts.After(now); ts = ts.Add(time.Hour) {
		timestamps = append(timestamps, ts)
		cmds = append(cmds, pipe.HGetAll(ctx, s.hourKey(ts)))
	}
	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		return nil, err
	}

	series := make([]TimeseriesEntry, 0, len(cmds))
	for idx, cmd := range cmds {
		values := cmd.Val()
		ts := timestamps[idx]
		series = append(series, TimeseriesEntry{
			Timestamp:  ts,
			Hour:       ts.Format("15:04"),
			Total:      parseInt64(values["total"]),
			Clean:      parseInt64(values["clean"]),
			Suspicious: parseInt64(values["suspicious"]),
			Malicious:  parseInt64(values["malicious"]),
		})
	}
	return series, nil
}

func (s *RedisStore) RecentRequests(ctx context.Context, limit int) ([]TLSRequest, error) {
	if limit <= 0 {
		limit = defaultRecentLimit
	}

	values, err := s.client.LRange(ctx, s.key("api", "requests", "recent"), 0, int64(limit-1)).Result()
	if err != nil {
		return nil, err
	}

	out := make([]TLSRequest, 0, len(values))
	for _, raw := range values {
		request, ok := decodeRequest(raw)
		if !ok {
			continue
		}
		out = append(out, request)
	}
	return out, nil
}

func (s *RedisStore) TopThreats(ctx context.Context, limit int, now time.Time) ([]TLSRequest, error) {
	if limit <= 0 {
		limit = defaultTopLimit
	}
	if limit > maxTopThreats {
		limit = maxTopThreats
	}

	ids, err := s.client.ZRevRange(ctx, s.key("api", "requests", "top_threats"), 0, int64(limit-1)).Result()
	if err != nil {
		return nil, err
	}
	return s.loadRequestsByID(ctx, ids)
}

func (s *RedisStore) TopCommonFingerprints(ctx context.Context, limit int) ([]FingerprintEntry, error) {
	if limit <= 0 {
		limit = defaultTopLimit
	}

	ranked, err := s.client.ZRevRangeWithScores(ctx, s.key("api", "fingerprints", "counts"), 0, int64(limit-1)).Result()
	if err != nil {
		return nil, err
	}
	if len(ranked) == 0 {
		return []FingerprintEntry{}, nil
	}

	fields := make([]string, 0, len(ranked))
	for _, member := range ranked {
		fingerprint, _ := member.Member.(string)
		fields = append(fields, fingerprint)
	}

	pipe := s.client.Pipeline()
	scoreCmd := pipe.HMGet(ctx, s.key("api", "fingerprints", "scores"), fields...)
	displayCmd := pipe.HMGet(ctx, s.key("api", "fingerprints", "display"), fields...)
	labelCmd := pipe.HMGet(ctx, s.key("api", "fingerprints", "labels"), fields...)
	kindCmd := pipe.HMGet(ctx, s.key("api", "fingerprints", "kinds"), fields...)
	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		return nil, err
	}

	out := make([]FingerprintEntry, 0, len(ranked))
	for idx, member := range ranked {
		fingerprint, _ := member.Member.(string)
		count := int64(math.Round(member.Score))
		totalScore := parseAnyInt64(scoreCmd.Val()[idx])
		display := stringValue(displayCmd.Val()[idx])
		if display == "" {
			display = fingerprint
		}
		label := stringValue(labelCmd.Val()[idx])
		if label == "" {
			label = "Unknown JA4 Client"
		}
		kind := stringValue(kindCmd.Val()[idx])
		if kind == "" {
			kind = "ja4"
		}
		avg := 0
		if count > 0 {
			avg = int(math.Round(float64(totalScore) / float64(count)))
		}
		out = append(out, FingerprintEntry{
			JA3Hash:         fingerprint,
			Fingerprint:     display,
			Count:           count,
			AvgThreatScore:  avg,
			Label:           label,
			FingerprintKind: kind,
			JA4Fingerprint:  fingerprint,
		})
	}

	return out, nil
}

func (s *RedisStore) FrequentFingerprintsLastHour(ctx context.Context, now time.Time, minCount int64) (FrequentFingerprintsSummary, error) {
	if minCount <= 0 {
		minCount = 2
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	stats, err := s.fingerprintStatsLastHour(ctx, now)
	if err != nil {
		return FrequentFingerprintsSummary{}, err
	}

	count := int64(0)
	for _, entry := range stats {
		if entry.Count >= minCount {
			count++
		}
	}

	return FrequentFingerprintsSummary{
		WindowMinutes: 60,
		MinCount:      minCount,
		Count:         count,
		EvaluatedAt:   now,
	}, nil
}

func (s *RedisStore) TopFingerprintsLastHour(ctx context.Context, now time.Time, limit int) ([]FingerprintEntry, error) {
	if limit <= 0 {
		limit = defaultTopLimit
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	stats, err := s.fingerprintStatsLastHour(ctx, now)
	if err != nil {
		return nil, err
	}
	if len(stats) == 0 {
		return []FingerprintEntry{}, nil
	}

	entries := make([]FingerprintEntry, 0, len(stats))
	for _, entry := range stats {
		entries = append(entries, entry)
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Count == entries[j].Count {
			if entries[i].AvgThreatScore == entries[j].AvgThreatScore {
				return entries[i].JA4Fingerprint < entries[j].JA4Fingerprint
			}
			return entries[i].AvgThreatScore > entries[j].AvgThreatScore
		}
		return entries[i].Count > entries[j].Count
	})

	if len(entries) > limit {
		entries = entries[:limit]
	}
	return entries, nil
}

// fingerprintStatsLastHour aggregates the current and previous per-hour
// fingerprint buckets. The read is bounded by the number of distinct
// fingerprints observed in those two buckets, independent of request volume,
// unlike the old implementation which fetched every request ID in the window
// and MGET'd each payload.
//
// The window is bucket-aligned rather than an exact trailing 60 minutes: at
// 10:05 it covers 09:00-11:00. Callers report WindowMinutes=60 and treat this
// as "recent fingerprints"; the per-bucket counters expire after
// fingerprintHourRetention so Redis memory stays bounded.
func (s *RedisStore) fingerprintStatsLastHour(ctx context.Context, now time.Time) (map[string]FingerprintEntry, error) {
	current := now.UTC().Truncate(time.Hour)
	keys := []string{s.fingerprintHourKey(current), s.fingerprintHourKey(current.Add(-time.Hour))}

	pipe := s.client.Pipeline()
	cmds := make([]*redis.MapStringStringCmd, 0, len(keys))
	for _, key := range keys {
		cmds = append(cmds, pipe.HGetAll(ctx, key))
	}
	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		return nil, err
	}

	counts := make(map[string]int64)
	totalScores := make(map[string]int64)
	for _, cmd := range cmds {
		for field, raw := range cmd.Val() {
			switch {
			case strings.HasPrefix(field, fingerprintCountFieldPrefix):
				fingerprint := strings.TrimPrefix(field, fingerprintCountFieldPrefix)
				counts[fingerprint] += parseInt64(raw)
			case strings.HasPrefix(field, fingerprintScoreFieldPrefix):
				fingerprint := strings.TrimPrefix(field, fingerprintScoreFieldPrefix)
				totalScores[fingerprint] += parseInt64(raw)
			}
		}
	}
	if len(counts) == 0 {
		return map[string]FingerprintEntry{}, nil
	}

	fields := make([]string, 0, len(counts))
	for fingerprint := range counts {
		fields = append(fields, fingerprint)
	}
	sort.Strings(fields)

	metaPipe := s.client.Pipeline()
	displayCmd := metaPipe.HMGet(ctx, s.key("api", "fingerprints", "display"), fields...)
	labelCmd := metaPipe.HMGet(ctx, s.key("api", "fingerprints", "labels"), fields...)
	kindCmd := metaPipe.HMGet(ctx, s.key("api", "fingerprints", "kinds"), fields...)
	if _, err := metaPipe.Exec(ctx); err != nil && err != redis.Nil {
		return nil, err
	}

	stats := make(map[string]FingerprintEntry, len(counts))
	for idx, fingerprint := range fields {
		count := counts[fingerprint]
		if count <= 0 {
			continue
		}

		display := strings.TrimSpace(stringValue(displayCmd.Val()[idx]))
		if display == "" {
			display = fingerprint
		}
		label := strings.TrimSpace(stringValue(labelCmd.Val()[idx]))
		if label == "" {
			label = "Unknown JA4 Client"
		}
		kind := strings.TrimSpace(stringValue(kindCmd.Val()[idx]))
		if kind == "" {
			kind = "ja4"
		}

		avg := 0
		if count > 0 {
			avg = int(math.Round(float64(totalScores[fingerprint]) / float64(count)))
		}

		stats[fingerprint] = FingerprintEntry{
			JA3Hash:         fingerprint,
			Fingerprint:     display,
			Count:           count,
			AvgThreatScore:  avg,
			Label:           label,
			FingerprintKind: kind,
			JA4Fingerprint:  fingerprint,
		}
	}

	return stats, nil
}

func (s *RedisStore) loadRequestsByID(ctx context.Context, ids []string) ([]TLSRequest, error) {
	if len(ids) == 0 {
		return []TLSRequest{}, nil
	}

	keys := make([]string, 0, len(ids))
	for _, id := range ids {
		keys = append(keys, s.key("api", "request", id))
	}

	values, err := s.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, err
	}

	out := make([]TLSRequest, 0, len(values))
	stale := make([]string, 0)
	for idx, raw := range values {
		if raw == nil {
			stale = append(stale, ids[idx])
			continue
		}
		request, ok := decodeRequest(stringValue(raw))
		if !ok {
			stale = append(stale, ids[idx])
			continue
		}
		out = append(out, request)
	}

	if len(stale) > 0 {
		_, _ = s.client.ZRem(ctx, s.key("api", "requests", "top_threats"), toMembers(stale)...).Result()
	}

	return out, nil
}

// pruneFingerprints removes aggregate fields for fingerprints whose last-seen
// timestamp is older than fingerprintRetention. The caller invokes it every
// fingerprintPruneInterval records so the ZRangeByScore scan is amortized;
// key TTLs alone cannot bound cardinality because every Record refreshes the
// shared key TTL while old fields stay inside it.
func (s *RedisStore) pruneFingerprints(ctx context.Context, now time.Time) error {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	cutoff := now.Add(-fingerprintRetention).Unix()

	countsKey := s.key("api", "fingerprints", "counts")
	scoresKey := s.key("api", "fingerprints", "scores")
	displayKey := s.key("api", "fingerprints", "display")
	labelsKey := s.key("api", "fingerprints", "labels")
	kindsKey := s.key("api", "fingerprints", "kinds")
	lastSeenKey := s.key("api", "fingerprints", "last_seen")

	stale, err := s.client.ZRangeByScore(ctx, lastSeenKey, &redis.ZRangeBy{
		Min: "-inf",
		Max: strconv.FormatInt(cutoff, 10),
	}).Result()
	if err != nil && err != redis.Nil {
		return err
	}

	pipe := s.client.TxPipeline()
	if len(stale) > 0 {
		members := toMembers(stale)
		pipe.ZRem(ctx, countsKey, members...)
		pipe.HDel(ctx, scoresKey, stale...)
		pipe.HDel(ctx, displayKey, stale...)
		pipe.HDel(ctx, labelsKey, stale...)
		pipe.HDel(ctx, kindsKey, stale...)
		pipe.ZRem(ctx, lastSeenKey, members...)
	}
	// Hard backstop: keep the most-seen maxFingerprints entries even if they
	// are all still fresh. Meta fields for rank-evicted members are dropped by
	// the next last-seen prune.
	pipe.ZRemRangeByRank(ctx, countsKey, 0, -(maxFingerprints + 1))
	_, err = pipe.Exec(ctx)
	return err
}

func (s *RedisStore) hourKey(ts time.Time) string {
	return s.key("api", "stats", "hour", strconv.FormatInt(ts.UTC().Truncate(time.Hour).Unix(), 10))
}

func (s *RedisStore) fingerprintHourKey(ts time.Time) string {
	return s.key("api", "fingerprints", "hour", strconv.FormatInt(ts.UTC().Truncate(time.Hour).Unix(), 10))
}

func (s *RedisStore) key(parts ...string) string {
	base := strings.Trim(strings.TrimSpace(s.prefix), ":")
	if base == "" {
		base = "sybil:risk"
	}
	return base + ":" + strings.Join(parts, ":")
}

func topThreatScore(score int, ts time.Time) float64 {
	return float64(score)*fingerprintTopScoreBase + float64(ts.UTC().Unix())
}

func normalizeVerdict(verdict string) string {
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "malicious":
		return "malicious"
	case "suspicious":
		return "suspicious"
	default:
		return "clean"
	}
}

func decodeRequest(raw string) (TLSRequest, bool) {
	var request TLSRequest
	if err := json.Unmarshal([]byte(raw), &request); err != nil {
		return TLSRequest{}, false
	}
	return request, true
}

func parseInt64(raw string) int64 {
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0
	}
	return value
}

func parseAnyInt64(raw any) int64 {
	switch value := raw.(type) {
	case nil:
		return 0
	case string:
		return parseInt64(value)
	case []byte:
		return parseInt64(string(value))
	case int64:
		return value
	case int:
		return int64(value)
	case float64:
		return int64(math.Round(value))
	default:
		return 0
	}
}

func stringValue(raw any) string {
	switch value := raw.(type) {
	case nil:
		return ""
	case string:
		return value
	case []byte:
		return string(value)
	default:
		return fmt.Sprint(value)
	}
}

func toMembers(values []string) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}
