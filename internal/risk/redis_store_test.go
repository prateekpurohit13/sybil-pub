package risk

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newRiskTestStore(t *testing.T) (*RedisStore, *miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return NewRedisStore(client, "test"), mr, client
}

// TestKeyHashesPairSegment pins the raw-IPv6 fix: the pair key never lands in
// a Redis key name, so colons (and any other separator) in the address cannot
// make key names ambiguous, and long fingerprints/IPs cannot grow keys.
func TestKeyHashesPairSegment(t *testing.T) {
	store := NewRedisStore(nil, "test")

	key := store.key("t13d1516h2_8daaf6152771_02713d6af862|2001:db8::1", "stats")
	if strings.Contains(key, "2001:db8") {
		t.Fatalf("pair key leaked raw into redis key: %q", key)
	}
	if strings.Contains(key, "|") {
		t.Fatalf("pair separator leaked raw into redis key: %q", key)
	}
	if !strings.HasPrefix(key, "test:pair:") {
		t.Fatalf("unexpected key shape: %q", key)
	}
	if key != store.key("t13d1516h2_8daaf6152771_02713d6af862|2001:db8::1", "stats") {
		t.Fatal("pair key segment is not deterministic")
	}
	if key == store.key("t13d1516h2_8daaf6152771_02713d6af862|2001:db8::2", "stats") {
		t.Fatal("different source IPs hashed to the same key segment")
	}
}

// TestRecordClampsResourceField covers the SNI/endpoint attacker-length field
// fix: a 500-byte resource is stored as at most 253 runes.
func TestRecordClampsResourceField(t *testing.T) {
	store, _, client := newRiskTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	obs := Observation{
		JA4:       "ja4",
		SourceIP:  "203.0.113.9",
		Hostname:  strings.Repeat("a", 500),
		Timestamp: now,
	}
	if _, err := store.Record(ctx, obs, DefaultConfig()); err != nil {
		t.Fatalf("record: %v", err)
	}

	fields, err := client.HKeys(ctx, store.key(obs.pairKey(), "resources")).Result()
	if err != nil {
		t.Fatalf("hkeys: %v", err)
	}
	if len(fields) != 1 {
		t.Fatalf("resource fields = %d, want 1", len(fields))
	}
	if got := len([]rune(fields[0])); got != maxResourceFieldLen {
		t.Fatalf("resource field length = %d, want %d", got, maxResourceFieldLen)
	}
}

// TestRecordSetsRetentionTTLs checks the shortened per-pair retention budget:
// idle pairs drain after the scoring window instead of lingering for 48h.
func TestRecordSetsRetentionTTLs(t *testing.T) {
	store, mr, _ := newRiskTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	obs := Observation{
		JA4:       "ja4",
		SourceIP:  "203.0.113.9",
		Hostname:  "example.com",
		Timestamp: now,
	}
	if _, err := store.Record(ctx, obs, DefaultConfig()); err != nil {
		t.Fatalf("record: %v", err)
	}

	for _, suffix := range []string{"stats", "resources", "minutes", "hours"} {
		if ttl := mr.TTL(store.key(obs.pairKey(), suffix)); ttl <= 0 {
			t.Errorf("expected positive TTL for %s key, got %s", suffix, ttl)
		}
	}
}

// TestRecordPrunesStaleBuckets keeps the existing bounded-hash behavior
// covered after the retention changes.
func TestRecordPrunesStaleBuckets(t *testing.T) {
	store, _, client := newRiskTestStore(t)
	ctx := context.Background()
	cfg := DefaultConfig()
	now := time.Now().UTC()

	old := Observation{
		JA4:       "ja4",
		SourceIP:  "203.0.113.9",
		Hostname:  "old.example",
		Timestamp: now.Add(-25 * time.Hour),
	}
	if _, err := store.Record(ctx, old, cfg); err != nil {
		t.Fatalf("record old: %v", err)
	}
	fresh := Observation{
		JA4:       "ja4",
		SourceIP:  "203.0.113.9",
		Hostname:  "new.example",
		Timestamp: now,
	}
	if _, err := store.Record(ctx, fresh, cfg); err != nil {
		t.Fatalf("record fresh: %v", err)
	}

	pairKey := fresh.pairKey()
	oldMinute := strconv.FormatInt(old.Timestamp.Truncate(time.Minute).Unix(), 10)
	oldHour := strconv.FormatInt(old.Timestamp.Truncate(time.Hour).Unix(), 10)

	checks := []struct {
		key   string
		field string
		want  bool
	}{
		{key: store.key(pairKey, "minutes"), field: oldMinute, want: false},
		{key: store.key(pairKey, "hours"), field: oldHour, want: false},
		{key: store.key(pairKey, "resources"), field: "old.example", want: false},
		{key: store.key(pairKey, "resources"), field: "new.example", want: true},
	}
	for _, check := range checks {
		exists, err := client.HExists(ctx, check.key, check.field).Result()
		if err != nil {
			t.Fatalf("hexists %s/%s: %v", check.key, check.field, err)
		}
		if exists != check.want {
			t.Errorf("HExists(%s, %s) = %t, want %t", check.key, check.field, exists, check.want)
		}
	}
}
