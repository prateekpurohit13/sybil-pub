package telemetry

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sophic00/sybil/internal/fingerprint"
	"github.com/sophic00/sybil/internal/parser"
	"github.com/sophic00/sybil/internal/stream"
	"github.com/sophic00/sybil/internal/tlshello"
)

// seriesValue finds the rendered sample for metric whose line contains every
// label fragment and returns its value. Fragments are matched as substrings so
// callers do not have to reproduce the deterministic label ordering.
func seriesValue(rendered, metric string, labelFragments ...string) (float64, bool) {
	for _, line := range strings.Split(rendered, "\n") {
		if !strings.HasPrefix(line, metric) {
			continue
		}
		if rest := line[len(metric):]; rest != "" && rest[0] != '{' && rest[0] != ' ' {
			continue
		}
		matched := true
		for _, fragment := range labelFragments {
			if !strings.Contains(line, fragment) {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		value, err := strconv.ParseFloat(fields[len(fields)-1], 64)
		if err != nil {
			continue
		}
		return value, true
	}
	return 0, false
}

func TestMetricSeriesCardinalityIsBounded(t *testing.T) {
	r := NewRegistry("pcap", "eth0")

	const extra = 250
	total := maxSeriesPerMetric + extra
	for i := 0; i < total; i++ {
		r.Inc("sybil_ja4_fingerprints_total", Labels{
			"ja4": fmt.Sprintf("t13d1516h2_%012d_%012d", i, i),
		})
	}

	state := r.metrics["sybil_ja4_fingerprints_total"]
	if got := len(state.series); got > maxSeriesPerMetric+1 {
		t.Fatalf("series grew to %d, want at most %d (including overflow)", got, maxSeriesPerMetric+1)
	}
	if state.lru.Len() > maxSeriesPerMetric {
		t.Fatalf("LRU holds %d series, want at most %d", state.lru.Len(), maxSeriesPerMetric)
	}

	// Eviction folds values into the overflow bucket, so no increments are
	// lost from the aggregate total.
	aggregate := 0.0
	for _, series := range state.series {
		aggregate += series.value
	}
	if aggregate != float64(total) {
		t.Fatalf("aggregate counter = %v, want %d", aggregate, total)
	}

	rendered := r.render()
	if got, ok := seriesValue(rendered, "sybil_ja4_fingerprints_total", `ja4="other"`); !ok || got != extra {
		t.Errorf(`overflow series ja4="other" = %v (present=%v), want %d`, got, ok, extra)
	}
	if got, ok := seriesValue(rendered, seriesDroppedMetric, `reason="overflow"`); !ok || got != extra {
		t.Errorf(`%s{reason="overflow"} = %v (present=%v), want %d`, seriesDroppedMetric, got, ok, extra)
	}
}

func TestUnknownMetricIsCountedNotCreated(t *testing.T) {
	r := NewRegistry("pcap", "eth0")
	labels := Labels{"k": "v"}
	r.Inc("sybil_not_registered_total", labels)
	r.Add("sybil_not_registered_total", labels, 5)
	r.Set("sybil_not_registered_total", labels, 5)
	r.Observe("sybil_not_registered_total", labels, 5)

	if _, exists := r.metrics["sybil_not_registered_total"]; exists {
		t.Fatal("observation for an unregistered metric created a throwaway series")
	}
	if got := r.dropped[dropReasonUnknown]; got != 4 {
		t.Fatalf("unknown-metric drops = %d, want 4", got)
	}
	rendered := r.render()
	if got, ok := seriesValue(rendered, seriesDroppedMetric, `reason="unknown_metric"`); !ok || got != 4 {
		t.Errorf(`%s{reason="unknown_metric"} = %v (present=%v), want 4`, seriesDroppedMetric, got, ok)
	}
}

func TestLRUEvictionKeepsHotSeries(t *testing.T) {
	r := NewRegistry("pcap", "eth0")
	hot := Labels{"ja4": "t13d1516h2_deadbeefdead_beefdeadbeef"}

	for i := 0; i < maxSeriesPerMetric; i++ {
		r.Inc("sybil_ja4_fingerprints_total", Labels{"ja4": fmt.Sprintf("cold_%012d_000000000000", i)})
	}
	for i := 0; i < maxSeriesPerMetric; i++ {
		r.Inc("sybil_ja4_fingerprints_total", hot)
		r.Inc("sybil_ja4_fingerprints_total", Labels{"ja4": fmt.Sprintf("flood_%012d_000000000000", i)})
	}

	key, _ := canonicalLabels(hot)
	if _, ok := r.metrics["sybil_ja4_fingerprints_total"].series[key]; !ok {
		t.Fatal("hot series was evicted despite being touched between evictions")
	}
}

func TestHistogramOverflowFoldsCountAndSum(t *testing.T) {
	r := NewRegistry("pcap", "eth0")

	total := maxSeriesPerMetric + 10
	for i := 0; i < total; i++ {
		r.Observe("sybil_risk_component_score", Labels{
			"component": fmt.Sprintf("c%d", i),
		}, 5)
	}

	state := r.metrics["sybil_risk_component_score"]
	if got := len(state.series); got > maxSeriesPerMetric+1 {
		t.Fatalf("histogram series grew to %d, want at most %d", got, maxSeriesPerMetric+1)
	}
	var count uint64
	var sum float64
	for _, series := range state.series {
		count += series.count
		sum += series.sum
	}
	if count != uint64(total) {
		t.Fatalf("histogram count = %d, want %d", count, total)
	}
	if sum != float64(total)*5 {
		t.Fatalf("histogram sum = %v, want %v", sum, float64(total)*5)
	}
}

func TestHistogramInfinityBucketMatchesCount(t *testing.T) {
	r := NewRegistry("pcap", "eth0")
	r.Observe("sybil_lookup_duration_seconds", Labels{"source": "cache"}, 0.002)
	r.Observe("sybil_lookup_duration_seconds", Labels{"source": "cache"}, 10)

	rendered := r.render()
	if got, ok := seriesValue(rendered, "sybil_lookup_duration_seconds_bucket", `source="cache"`, `le="+Inf"`); !ok || got != 2 {
		t.Errorf("+Inf bucket = %v (present=%v), want 2", got, ok)
	}
	if got, ok := seriesValue(rendered, "sybil_lookup_duration_seconds_count", `source="cache"`); !ok || got != 2 {
		t.Errorf("count = %v (present=%v), want 2", got, ok)
	}
	if got, ok := seriesValue(rendered, "sybil_lookup_duration_seconds_sum", `source="cache"`); !ok || got != 10.002 {
		t.Errorf("sum = %v (present=%v), want 10.002", got, ok)
	}
}

func TestObserveDurationRecordsZeroAndIgnoresNegative(t *testing.T) {
	r := NewRegistry("pcap", "eth0")
	r.ObserveDuration("assessment", 0)
	r.ObserveDuration("assessment", -time.Millisecond)

	rendered := r.render()
	if got, ok := seriesValue(rendered, "sybil_processing_duration_seconds_count", `stage="assessment"`); !ok || got != 1 {
		t.Errorf("count = %v (present=%v), want 1 (zero-duration observation counted)", got, ok)
	}
	if got, ok := seriesValue(rendered, "sybil_processing_duration_seconds_bucket", `stage="assessment"`, `le="+Inf"`); !ok || got != 1 {
		t.Errorf("+Inf bucket = %v (present=%v), want 1", got, ok)
	}
}

func TestRecordCaptureStatsPublishesDeltas(t *testing.T) {
	r := NewRegistry("pcap", "eth0")
	r.RecordCaptureStats(CaptureStats{Received: 100, Dropped: 2, IfDropped: 1})
	r.RecordCaptureStats(CaptureStats{Received: 150, Dropped: 2, IfDropped: 3})

	rendered := r.render()
	for metric, want := range map[string]float64{
		"sybil_capture_pcap_received_total":  150,
		"sybil_capture_pcap_dropped_total":   2,
		"sybil_capture_pcap_ifdropped_total": 3,
	} {
		if got, ok := seriesValue(rendered, metric); !ok || got != want {
			t.Errorf("%s = %v (present=%v), want %v", metric, got, ok, want)
		}
	}

	// A counter below the previous baseline (interface reopen) must not mint
	// a negative or wrap-around delta.
	r.RecordCaptureStats(CaptureStats{Received: 10})
	rendered = r.render()
	if got, _ := seriesValue(rendered, "sybil_capture_pcap_received_total"); got != 150 {
		t.Errorf("received after reset = %v, want 150", got)
	}
}

func TestSanitizeLabelValueCollapsesUnderscoreRuns(t *testing.T) {
	tests := []struct {
		in       string
		fallback string
		want     string
	}{
		{"a___b", "unknown", "a_b"},
		{"a____b", "unknown", "a_b"},
		{"__weird__value__", "unknown", "weird_value"},
		{"MiXeD / Value", "unknown", "mixed_value"},
		{"!!!", "unknown", "unknown"},
		{"", "unknown", "unknown"},
		{strings.Repeat("a", 50), "unknown", strings.Repeat("a", 40)},
		{"evil--ja4-_value", "unknown", "evil_ja4_value"},
	}
	for _, tc := range tests {
		got := sanitizeLabelValue(tc.in, tc.fallback)
		if got != tc.want {
			t.Errorf("sanitizeLabelValue(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if strings.Contains(got, "__") {
			t.Errorf("sanitizeLabelValue(%q) = %q still contains a double underscore", tc.in, got)
		}
	}
}

func TestNormalizeALPNIsBounded(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", "none"},
		{"h2", "h2"},
		{"h2c", "h2"},
		{"http/1.1", "http1"},
		{"h3-29", "h3"},
		{"grpc", "grpc"},
		{"stun.turn", "stun"},
		{"evil-attacker-minted-protocol", "other"},
		{"%$#@!", "other"},
	}
	for _, tc := range tests {
		if got := normalizeALPN(tc.in); got != tc.want {
			t.Errorf("normalizeALPN(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRecordEventBoundsALPNCardinality(t *testing.T) {
	r := NewRegistry("pcap", "eth0")
	const events = 1000
	for i := 0; i < events; i++ {
		r.RecordEvent(stream.Event{
			Hello:  &tlshello.Hello{Type: tlshello.ClientHello},
			Fields: &parser.ClientHelloFields{FirstALPN: fmt.Sprintf("attacker-%d", i), SNIHost: "example.com"},
			JA4:    &fingerprint.JA4{Fingerprint: "t13d1516h2_000000000000_000000000000"},
		})
	}

	state := r.metrics["sybil_tls_alpn_total"]
	if got := len(state.series); got != 1 {
		t.Fatalf("sybil_tls_alpn_total has %d series after %d distinct ALPN values, want 1", got, events)
	}
	key, _ := canonicalLabels(Labels{"alpn": "other"})
	series, ok := state.series[key]
	if !ok || series.value != events {
		t.Fatalf("alpn=other series = %+v (present=%v), want value %d", series, ok, events)
	}
}

func TestConcurrentObserveAndRender(t *testing.T) {
	r := NewRegistry("pcap", "eth0")
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				r.Inc("sybil_ja4_fingerprints_total", Labels{"ja4": fmt.Sprintf("w%d_%012d_000000000000", worker, i)})
				r.ObserveDuration("assessment", time.Duration(i)*time.Microsecond)
				if i%10 == 0 {
					_ = r.render()
				}
			}
		}(worker)
	}
	wg.Wait()
}
