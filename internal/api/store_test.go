package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestRedisStore(t *testing.T) (*RedisStore, *miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return NewRedisStore(client, "test"), mr, client
}

func testObservation(ts time.Time, ja4 string, score int) RequestObservation {
	return RequestObservation{
		Timestamp:       ts,
		SourceIP:        "203.0.113.9",
		JA4Fingerprint:  ja4,
		Fingerprint:     "display-" + ja4,
		FingerprintKind: "ja4",
		ThreatScore:     score,
		Verdict:         "suspicious",
		Label:           "Chrome",
	}
}

// TestRecordSetsTTLsOnBoundedKeys pins the retention contract: every key class
// that can be minted per request/fingerprint has a TTL, so a sensor that stops
// receiving traffic drains Redis instead of leaving the last state forever.
func TestRecordSetsTTLsOnBoundedKeys(t *testing.T) {
	store, mr, _ := newTestRedisStore(t)
	now := time.Now().UTC()

	if err := store.Record(context.Background(), testObservation(now, "ja4-a", 42)); err != nil {
		t.Fatalf("record: %v", err)
	}

	for _, key := range []string{
		store.key("api", "request", "1"),
		store.hourKey(now),
		store.key("api", "fingerprints", "counts"),
		store.key("api", "fingerprints", "scores"),
		store.key("api", "fingerprints", "display"),
		store.key("api", "fingerprints", "labels"),
		store.key("api", "fingerprints", "kinds"),
		store.key("api", "fingerprints", "last_seen"),
		store.fingerprintHourKey(now),
	} {
		if ttl := mr.TTL(key); ttl <= 0 {
			t.Errorf("expected positive TTL for %s, got %s", key, ttl)
		}
	}
}

// TestRecordCapsTopThreatsByRank verifies the zset stays bounded even when the
// dashboard never polls TopThreats, which is the headless-growth case.
func TestRecordCapsTopThreatsByRank(t *testing.T) {
	store, _, client := newTestRedisStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	for i := 0; i < maxTopThreats+25; i++ {
		if err := store.Record(ctx, testObservation(now.Add(time.Duration(i)*time.Millisecond), "ja4-cap", i%100)); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	card, err := client.ZCard(ctx, store.key("api", "requests", "top_threats")).Result()
	if err != nil {
		t.Fatalf("zcard: %v", err)
	}
	if card != maxTopThreats {
		t.Fatalf("top_threats cardinality = %d, want %d", card, maxTopThreats)
	}
}

// TestFingerprintStatsLastHourReadsHourBucketsOnly proves the last-hour
// endpoints no longer scan the per-request zset/payloads: it deletes every
// request key and the threat zset before querying and still expects the
// per-hour counters to answer.
func TestFingerprintStatsLastHourReadsHourBucketsOnly(t *testing.T) {
	store, _, client := newTestRedisStore(t)
	ctx := context.Background()

	// Anchor "now" mid-hour so the -40m records fall in the previous hourly
	// bucket and the -10m record falls in the current one.
	now := time.Now().UTC().Truncate(time.Hour).Add(30 * time.Minute)
	older := now.Add(-40 * time.Minute)

	for _, obs := range []RequestObservation{
		testObservation(older, "ja4-hour", 10),
		testObservation(older.Add(time.Minute), "ja4-hour", 20),
		testObservation(now.Add(-10*time.Minute), "ja4-hour", 30),
		testObservation(now.Add(-3*time.Hour), "ja4-old", 90),
	} {
		if err := store.Record(ctx, obs); err != nil {
			t.Fatalf("record: %v", err)
		}
	}

	requestKeys, err := client.Keys(ctx, store.key("api", "request", "*")).Result()
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	if err := client.Del(ctx, requestKeys...).Err(); err != nil {
		t.Fatalf("delete request payloads: %v", err)
	}
	if err := client.Del(ctx, store.key("api", "requests", "top_threats")).Err(); err != nil {
		t.Fatalf("delete threat zset: %v", err)
	}

	entries, err := store.TopFingerprintsLastHour(ctx, now, 10)
	if err != nil {
		t.Fatalf("top last hour: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1 (%+v)", len(entries), entries)
	}
	entry := entries[0]
	if entry.JA4Fingerprint != "ja4-hour" || entry.Count != 3 || entry.AvgThreatScore != 20 {
		t.Fatalf("unexpected entry: %+v", entry)
	}
	if entry.Label != "Chrome" || entry.Fingerprint != "display-ja4-hour" {
		t.Fatalf("metadata lost in bucket rewrite: %+v", entry)
	}

	summary, err := store.FrequentFingerprintsLastHour(ctx, now, 3)
	if err != nil {
		t.Fatalf("frequent last hour: %v", err)
	}
	if summary.Count != 1 {
		t.Fatalf("frequent count = %d, want 1", summary.Count)
	}
	summary, err = store.FrequentFingerprintsLastHour(ctx, now, 4)
	if err != nil {
		t.Fatalf("frequent last hour high min: %v", err)
	}
	if summary.Count != 0 {
		t.Fatalf("frequent count = %d, want 0 for minCount 4", summary.Count)
	}
}

// TestPruneFingerprintsRemovesInactiveMembers covers the amortized last-seen
// prune that key TTLs alone cannot provide (the shared key TTL is refreshed on
// every write while old fields stay inside it).
func TestPruneFingerprintsRemovesInactiveMembers(t *testing.T) {
	store, _, client := newTestRedisStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := store.Record(ctx, testObservation(now.Add(-49*time.Hour), "ja4-stale", 10)); err != nil {
		t.Fatalf("record stale: %v", err)
	}
	if err := store.Record(ctx, testObservation(now, "ja4-fresh", 10)); err != nil {
		t.Fatalf("record fresh: %v", err)
	}

	if err := store.pruneFingerprints(ctx, now); err != nil {
		t.Fatalf("prune: %v", err)
	}

	countsKey := store.key("api", "fingerprints", "counts")
	if _, err := client.ZScore(ctx, countsKey, "ja4-stale").Result(); !errors.Is(err, redis.Nil) {
		t.Fatalf("stale fingerprint still in counts zset: %v", err)
	}
	if _, err := client.ZScore(ctx, countsKey, "ja4-fresh").Result(); err != nil {
		t.Fatalf("fresh fingerprint missing from counts zset: %v", err)
	}
	exists, err := client.HExists(ctx, store.key("api", "fingerprints", "display"), "ja4-stale").Result()
	if err != nil {
		t.Fatalf("hexists: %v", err)
	}
	if exists {
		t.Fatal("stale fingerprint meta field survived prune")
	}
}

// TestTopThreatsDropsExpiredPayloads keeps the read path self-healing when a
// request payload TTL expires before its zset member does.
func TestTopThreatsDropsExpiredPayloads(t *testing.T) {
	store, _, client := newTestRedisStore(t)
	ctx := context.Background()

	if err := store.Record(ctx, testObservation(time.Now().UTC(), "ja4-top", 80)); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := client.Del(ctx, store.key("api", "request", "1")).Err(); err != nil {
		t.Fatalf("delete payload: %v", err)
	}

	got, err := store.TopThreats(ctx, 10, time.Now().UTC())
	if err != nil {
		t.Fatalf("top threats: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no live top threats, got %+v", got)
	}
	card, err := client.ZCard(ctx, store.key("api", "requests", "top_threats")).Result()
	if err != nil {
		t.Fatalf("zcard: %v", err)
	}
	if card != 0 {
		t.Fatalf("stale member left in top_threats, card=%d", card)
	}
}
