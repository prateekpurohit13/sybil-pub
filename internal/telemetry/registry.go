package telemetry

import (
	"container/list"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sophic00/sybil/internal/parser"
	"github.com/sophic00/sybil/internal/risk"
	"github.com/sophic00/sybil/internal/stream"
)

type Labels map[string]string

type metricKind string

const (
	counterKind   metricKind = "counter"
	gaugeKind     metricKind = "gauge"
	histogramKind metricKind = "histogram"
)

const (
	// maxSeriesPerMetric bounds the number of distinct label sets retained for
	// a single metric. Once the cap is reached the least recently observed
	// series is evicted and folded into an "other" overflow series, so an
	// attacker minting unique JA4 fingerprints, ALPN values or any other
	// label cannot grow the registry without bound. A bounded registry keeps
	// scrape rendering predictable and prevents the OOM this used to allow.
	maxSeriesPerMetric = 5000

	// overflowLabelValue is the label value used by the per-metric overflow
	// series (for example ja4="other"). Every value of an evicted series' label
	// set is replaced with this value and the evicted counters are folded into
	// the overflow series, so aggregate rates stay correct.
	overflowLabelValue = "other"

	// seriesDroppedMetric counts series evictions and observations sent to
	// unregistered metrics. It is rendered from Registry.dropped rather than
	// stored as ordinary series to avoid recursive locking.
	seriesDroppedMetric = "sybil_metrics_series_dropped_total"
	dropReasonOverflow  = "overflow"
	dropReasonUnknown   = "unknown_metric"

	// unknownMetricLogInterval throttles the "unregistered metric" warning so
	// a buggy or hostile call path cannot flood the logs.
	unknownMetricLogInterval = time.Minute
)

type metricDef struct {
	help    string
	kind    metricKind
	buckets []float64
}

type metricSeries struct {
	key     string
	labels  Labels
	value   float64
	buckets []uint64
	count   uint64
	sum     float64

	// lruElem is this series' element in metricState.lru. It is nil for the
	// per-metric overflow series, which is never evicted.
	lruElem *list.Element
}

type metricState struct {
	def    metricDef
	series map[string]*metricSeries

	// lru orders series by last observation, most recently used first. The
	// overflow series is intentionally not tracked here.
	lru *list.List

	// overflowKey is the series key of the per-metric overflow bucket, if one
	// has been created. It is never evicted.
	overflowKey string
}

type Registry struct {
	started time.Time

	mu      sync.RWMutex
	metrics map[string]*metricState

	// dropped counts evicted series and observations sent to unregistered
	// metrics, keyed by reason. It is rendered as seriesDroppedMetric.
	dropped map[string]uint64

	// capture* remember the last cumulative libpcap counters so
	// RecordCaptureStats can publish deltas.
	captureReceived  uint64
	captureDropped   uint64
	captureIfDropped uint64

	// redisUp is -1 until the process first reports Redis state (no Redis
	// configured), 0 when the shared client is unreachable (capture-only
	// degraded mode), and 1 when it is reachable.
	redisUp atomic.Int32

	logMu         sync.Mutex
	unknownLogged map[string]time.Time
}

func NewRegistry(backend, iface string) *Registry {
	r := &Registry{
		started:       time.Now(),
		metrics:       make(map[string]*metricState),
		dropped:       make(map[string]uint64),
		unknownLogged: make(map[string]time.Time),
	}
	r.redisUp.Store(-1)

	r.registerGauge("sybil_runtime_info", "Static runtime metadata for the active Sybil process", nil)
	r.registerCounter("sybil_capture_packets_total", "Packets delivered to the stream processor")
	r.registerCounter("sybil_capture_errors_total", "Capture read errors by kind")
	r.registerCounter("sybil_tls_hellos_total", "Detected TLS hello messages by type")
	r.registerCounter("sybil_tls_extract_errors_total", "TLS hello extraction failures by kind")
	r.registerCounter("sybil_client_hello_parse_total", "ClientHello parse results")
	r.registerCounter("sybil_ja4_build_total", "JA4 build results")
	r.registerCounter("sybil_tls_versions_total", "Observed ClientHello TLS versions")
	r.registerCounter("sybil_tls_alpn_total", "Observed ALPN families")
	r.registerCounter("sybil_tls_sni_total", "Observed SNI presence")
	r.registerCounter("sybil_ja4_fingerprints_total", "Observed JA4 fingerprints from parsed ClientHello events")
	r.registerCounter("sybil_lookup_requests_total", "JA4 enrichment lookup requests by source and result")
	r.registerHistogram("sybil_lookup_duration_seconds", "JA4 enrichment lookup durations", []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5})
	r.registerCounter("sybil_identity_events_total", "Enriched JA4 identity classes and families")
	r.registerCounter("sybil_risk_assessments_total", "Risk assessment actions by band and identity")
	r.registerHistogram("sybil_risk_score", "Distribution of Sybil risk scores", []float64{5, 10, 20, 30, 40, 50, 60, 70, 80, 90, 95, 100})
	r.registerHistogram("sybil_risk_component_score", "Distribution of component scores", []float64{1, 2, 4, 6, 8, 10, 12, 15, 20, 25, 30})
	r.registerHistogram("sybil_processing_duration_seconds", "Pipeline processing durations", []float64{0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1})
	r.registerCounter("sybil_redis_record_total", "Redis-backed stats store outcomes")
	r.registerHistogram("sybil_redis_record_duration_seconds", "Redis-backed stats store durations", []float64{0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1})
	r.registerGauge("sybil_redis_up", "Whether the shared Redis client is reachable (1) or the sensor is in capture-only degraded mode (0)", nil)
	r.registerCounter("sybil_scoring_dropped_total", "Per-event risk scoring/persistence jobs dropped because the bounded worker queue was full")
	r.registerCounter(seriesDroppedMetric, "Metric series and observations dropped because a metric exceeded its cardinality limit or was not registered")
	r.registerCounter("sybil_capture_pcap_received_total", "Packets received by the libpcap backend (kernel counter)")
	r.registerCounter("sybil_capture_pcap_dropped_total", "Packets dropped by libpcap because its kernel buffer was full")
	r.registerCounter("sybil_capture_pcap_ifdropped_total", "Packets dropped by the interface before reaching libpcap")
	r.registerGauge("sybil_uptime_seconds", "Process uptime in seconds", nil)

	r.Set("sybil_runtime_info", Labels{
		"backend": sanitizeLabelValue(backend, "unknown"),
		"iface":   sanitizeLabelValue(iface, "unknown"),
	}, 1)

	return r
}

func (r *Registry) ObserveLookup(event risk.LookupEvent) {
	labels := Labels{
		"source": sanitizeLabelValue(event.Source, "unknown"),
		"result": sanitizeLabelValue(event.Result, "unknown"),
	}
	r.Inc("sybil_lookup_requests_total", labels)
	// Only events with a measured duration update the histogram; the cache
	// write path emits a zero duration to mean "not measured", and counting
	// those would skew lookup latency low.
	if event.Duration > 0 {
		r.Observe("sybil_lookup_duration_seconds", labels, event.Duration.Seconds())
	}
}

func (r *Registry) WrapStatsStore(next risk.StatsStore) risk.StatsStore {
	if r == nil || next == nil {
		return next
	}
	return statsStore{next: next, registry: r}
}

type statsStore struct {
	next     risk.StatsStore
	registry *Registry
}

func (s statsStore) Record(ctx context.Context, obs risk.Observation, cfg risk.Config) (risk.LiveStats, error) {
	start := time.Now()
	stats, err := s.next.Record(ctx, obs, cfg)
	labels := Labels{"status": "success"}
	if err != nil {
		labels["status"] = "error"
	}
	s.registry.Inc("sybil_redis_record_total", labels)
	s.registry.Observe("sybil_redis_record_duration_seconds", labels, time.Since(start).Seconds())
	return stats, err
}

func (r *Registry) RecordCapturePacket() {
	r.Inc("sybil_capture_packets_total", nil)
}

func (r *Registry) RecordCaptureError(err error) {
	if err == nil {
		return
	}
	kind := "read_error"
	switch {
	case strings.Contains(strings.ToLower(err.Error()), "lost"):
		kind = "lost_samples"
	case strings.Contains(strings.ToLower(err.Error()), "closed"):
		kind = "closed"
	}
	r.Inc("sybil_capture_errors_total", Labels{"kind": kind})
}

// CaptureStats holds the cumulative kernel packet counters reported by a
// capture source that exposes libpcap statistics.
type CaptureStats struct {
	Received  uint64
	Dropped   uint64
	IfDropped uint64
}

// RecordCaptureStats publishes libpcap kernel counters. The caller passes the
// cumulative values from the capture source on each poll; the registry stores
// deltas and exposes monotonic counters.
func (r *Registry) RecordCaptureStats(stats CaptureStats) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.addLocked("sybil_capture_pcap_received_total", nil, deltaUint64(&r.captureReceived, stats.Received))
	r.addLocked("sybil_capture_pcap_dropped_total", nil, deltaUint64(&r.captureDropped, stats.Dropped))
	r.addLocked("sybil_capture_pcap_ifdropped_total", nil, deltaUint64(&r.captureIfDropped, stats.IfDropped))
}

// deltaUint64 returns cur-last and advances last. A counter smaller than the
// previous value (for example after the interface is reopened) resets the
// baseline and contributes no delta.
func deltaUint64(last *uint64, cur uint64) float64 {
	if cur < *last {
		*last = cur
		return 0
	}
	delta := cur - *last
	*last = cur
	return float64(delta)
}

func (r *Registry) RecordEvent(event stream.Event) {
	if event.Hello == nil {
		return
	}
	r.Inc("sybil_tls_hellos_total", Labels{"type": helloTypeLabel(event.Hello.Type.String())})
	if event.Hello.Type != 0x01 {
		return
	}

	parseStatus := "success"
	if event.ParseError != nil {
		parseStatus = "error"
	}
	r.Inc("sybil_client_hello_parse_total", Labels{"status": parseStatus})

	fingerprintStatus := "success"
	if event.FingerprintError != nil {
		fingerprintStatus = "error"
	}
	r.Inc("sybil_ja4_build_total", Labels{"status": fingerprintStatus})

	if event.Fields == nil {
		return
	}

	if event.JA4 != nil && strings.TrimSpace(event.JA4.Fingerprint) != "" {
		r.Inc("sybil_ja4_fingerprints_total", Labels{
			"ja4": normalizeJA4FingerprintLabel(event.JA4.Fingerprint),
		})
	}

	r.Inc("sybil_tls_versions_total", Labels{
		"version": normalizeVersion(parser.TLSVersionString(event.Fields.TLSVersion)),
	})
	r.Inc("sybil_tls_alpn_total", Labels{
		"alpn": normalizeALPN(event.Fields.FirstALPN),
	})
	sniState := "missing"
	if strings.TrimSpace(event.Fields.SNIHost) != "" {
		sniState = "present"
	}
	r.Inc("sybil_tls_sni_total", Labels{"state": sniState})
}

func (r *Registry) RecordAssessment(assessment risk.Assessment) {
	labels := Labels{
		"action":           sanitizeLabelValue(string(assessment.Action), "unknown"),
		"band":             scoreBand(assessment.Score),
		"identity_class":   sanitizeLabelValue(assessment.Summary.IdentityClass, "unknown"),
		"reputation_state": sanitizeLabelValue(assessment.Summary.ReputationState, "unknown"),
		"resource_kind":    sanitizeLabelValue(assessment.Stats.ResourceKind, "unknown"),
	}
	r.Inc("sybil_risk_assessments_total", labels)
	r.Observe("sybil_risk_score", Labels{
		"identity_class": sanitizeLabelValue(assessment.Summary.IdentityClass, "unknown"),
	}, float64(assessment.Score))

	r.Inc("sybil_identity_events_total", Labels{
		"identity_class":   sanitizeLabelValue(assessment.Summary.IdentityClass, "unknown"),
		"reputation_state": sanitizeLabelValue(assessment.Summary.ReputationState, "unknown"),
		"application":      sanitizeLabelValue(assessment.Summary.ApplicationFamily, "unknown"),
		"library":          sanitizeLabelValue(assessment.Summary.LibraryFamily, "unknown"),
		"os":               sanitizeLabelValue(assessment.Summary.OSFamily, "unknown"),
		"device":           sanitizeLabelValue(assessment.Summary.DeviceClass, "unknown"),
		"verified":         strconv.FormatBool(assessment.Lookup != nil && assessment.Lookup.Verified),
	})

	for _, component := range assessment.Components {
		r.Observe("sybil_risk_component_score", Labels{
			"component": sanitizeLabelValue(component.Name, "unknown"),
		}, float64(component.Score))
	}
}

func (r *Registry) ObserveDuration(stage string, duration time.Duration) {
	// Negative durations indicate a clock problem and are ignored. Zero is a
	// legitimate (sub-resolution) observation and is recorded, so the
	// histogram count and +Inf bucket cover every completed stage.
	if duration < 0 {
		return
	}
	r.Observe("sybil_processing_duration_seconds", Labels{
		"stage": sanitizeLabelValue(stage, "unknown"),
	}, duration.Seconds())
}

// SetRedisUp records whether the single shared Redis client is reachable. It
// backs the sybil_redis_up gauge and the /healthz degraded status so a Redis
// outage is visible to operators instead of silently disabling risk scoring.
func (r *Registry) SetRedisUp(up bool) {
	if r == nil {
		return
	}
	value := int32(0)
	if up {
		value = 1
	}
	r.redisUp.Store(value)
	r.Set("sybil_redis_up", nil, float64(value))
}

func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(r.render()))
	})
}

func (r *Registry) HealthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		payload := map[string]any{
			"status":  "ok",
			"uptime":  time.Since(r.started).String(),
			"started": r.started.UTC().Format(time.RFC3339),
		}
		switch r.redisUp.Load() {
		case 1:
			payload["redis"] = "up"
		case 0:
			payload["redis"] = "down"
			payload["status"] = "degraded"
		}
		w.Header().Set("Content-Type", "application/json")
		data, _ := json.Marshal(payload)
		_, _ = w.Write(data)
	})
}

func (r *Registry) render() string {
	r.Set("sybil_uptime_seconds", nil, time.Since(r.started).Seconds())

	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.metrics))
	for name := range r.metrics {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, name := range names {
		state := r.metrics[name]
		fmt.Fprintf(&b, "# HELP %s %s\n", name, state.def.help)
		fmt.Fprintf(&b, "# TYPE %s %s\n", name, state.def.kind)

		keys := make([]string, 0, len(state.series))
		for key := range state.series {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		for _, key := range keys {
			series := state.series[key]
			switch state.def.kind {
			case counterKind, gaugeKind:
				fmt.Fprintf(&b, "%s%s %s\n", name, formatLabels(series.labels), formatFloat(series.value))
			case histogramKind:
				cumulative := uint64(0)
				for idx, bucket := range state.def.buckets {
					cumulative += series.buckets[idx]
					fmt.Fprintf(&b, "%s_bucket%s %d\n", name, formatLabels(withLE(series.labels, bucket)), cumulative)
				}
				fmt.Fprintf(&b, "%s_bucket%s %d\n", name, formatLabels(withInf(series.labels)), series.count)
				fmt.Fprintf(&b, "%s_sum%s %s\n", name, formatLabels(series.labels), formatFloat(series.sum))
				fmt.Fprintf(&b, "%s_count%s %d\n", name, formatLabels(series.labels), series.count)
			}
		}

		// Dropped series and unknown-metric observations are tracked in plain
		// counters; synthesize them here so the help/type lines above stay
		// correct and no recursive locking is needed while recording drops.
		if name == seriesDroppedMetric {
			reasons := make([]string, 0, len(r.dropped))
			for reason := range r.dropped {
				reasons = append(reasons, reason)
			}
			sort.Strings(reasons)
			for _, reason := range reasons {
				fmt.Fprintf(&b, "%s{reason=%q} %d\n", name, reason, r.dropped[reason])
			}
		}
	}

	return b.String()
}

func (r *Registry) registerCounter(name, help string) {
	r.register(name, metricDef{help: help, kind: counterKind})
}

func (r *Registry) registerGauge(name, help string, _ []float64) {
	r.register(name, metricDef{help: help, kind: gaugeKind})
}

func (r *Registry) registerHistogram(name, help string, buckets []float64) {
	r.register(name, metricDef{help: help, kind: histogramKind, buckets: append([]float64(nil), buckets...)})
}

func (r *Registry) register(name string, def metricDef) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.metrics[name] = &metricState{
		def:    def,
		series: make(map[string]*metricSeries),
		lru:    list.New(),
	}
}

func (r *Registry) Inc(name string, labels Labels) {
	r.Add(name, labels, 1)
}

func (r *Registry) Add(name string, labels Labels, delta float64) {
	r.mu.Lock()
	series, ok := r.getSeriesLocked(name, labels)
	if ok {
		series.value += delta
	} else {
		r.countDroppedLocked(dropReasonUnknown)
	}
	r.mu.Unlock()
	if !ok {
		r.logUnknownMetric(name)
	}
}

func (r *Registry) Set(name string, labels Labels, value float64) {
	r.mu.Lock()
	series, ok := r.getSeriesLocked(name, labels)
	if ok {
		series.value = value
	} else {
		r.countDroppedLocked(dropReasonUnknown)
	}
	r.mu.Unlock()
	if !ok {
		r.logUnknownMetric(name)
	}
}

func (r *Registry) Observe(name string, labels Labels, value float64) {
	r.mu.Lock()
	state, known := r.metrics[name]
	if !known {
		r.countDroppedLocked(dropReasonUnknown)
		r.mu.Unlock()
		r.logUnknownMetric(name)
		return
	}
	series, ok := r.getSeriesLocked(name, labels)
	if !ok {
		// Unreachable while the metric exists, but keep the write path safe
		// and loud instead of writing into a throwaway series.
		r.countDroppedLocked(dropReasonUnknown)
		r.mu.Unlock()
		r.logUnknownMetric(name)
		return
	}
	if state.def.kind != histogramKind {
		series.value = value
		r.mu.Unlock()
		return
	}
	series.count++
	series.sum += value
	for idx, bucket := range state.def.buckets {
		if value <= bucket {
			series.buckets[idx]++
			break
		}
	}
	r.mu.Unlock()
}

// getSeriesLocked returns the series for name/labels, creating it if needed.
// It reports false for a metric that was never registered: such observations
// are counted as dropped and logged instead of being written into a throwaway
// series (which silently discarded the increment). Callers must hold r.mu.
func (r *Registry) getSeriesLocked(name string, labels Labels) (*metricSeries, bool) {
	state, ok := r.metrics[name]
	if !ok {
		return nil, false
	}
	key, normalized := canonicalLabels(labels)
	if series, ok := state.series[key]; ok {
		if series.lruElem != nil {
			state.lru.MoveToFront(series.lruElem)
		}
		return series, true
	}
	if state.lru.Len() >= maxSeriesPerMetric {
		state.evictLocked(r)
	}
	series := &metricSeries{key: key, labels: normalized}
	if state.def.kind == histogramKind {
		series.buckets = make([]uint64, len(state.def.buckets))
	}
	state.series[key] = series
	series.lruElem = state.lru.PushFront(series)
	return series, true
}

// addLocked records a delta for an already-registered metric without logging.
// Callers must hold r.mu.
func (r *Registry) addLocked(name string, labels Labels, delta float64) {
	series, ok := r.getSeriesLocked(name, labels)
	if !ok {
		r.countDroppedLocked(dropReasonUnknown)
		return
	}
	series.value += delta
}

// countDroppedLocked records a dropped observation or an evicted series.
// Callers must hold r.mu.
func (r *Registry) countDroppedLocked(reason string) {
	if r.dropped == nil {
		r.dropped = make(map[string]uint64)
	}
	r.dropped[reason]++
}

// logUnknownMetric warns that an observation was sent to a metric that was
// never registered. Warnings are throttled per metric so a hot unregistered
// label path cannot flood the logs.
func (r *Registry) logUnknownMetric(name string) {
	r.logMu.Lock()
	if r.unknownLogged == nil {
		r.unknownLogged = make(map[string]time.Time)
	}
	last, seen := r.unknownLogged[name]
	now := time.Now()
	if seen && now.Sub(last) < unknownMetricLogInterval {
		r.logMu.Unlock()
		return
	}
	r.unknownLogged[name] = now
	r.logMu.Unlock()
	log.Printf("telemetry: dropped observation for unregistered metric %q; register it before use", name)
}

// evictLocked removes the least recently observed series and folds it into
// the metric's overflow series. Callers must hold r.mu.
func (s *metricState) evictLocked(r *Registry) {
	for s.lru.Len() > 0 {
		elem := s.lru.Back()
		s.lru.Remove(elem)
		evicted := elem.Value.(*metricSeries)
		evicted.lruElem = nil
		if s.overflowKey != "" && evicted.key == s.overflowKey {
			continue
		}
		delete(s.series, evicted.key)
		overflow := s.overflowLocked(evicted.labels)
		overflow.value += evicted.value
		if s.def.kind == histogramKind {
			overflow.count += evicted.count
			overflow.sum += evicted.sum
			for i := range overflow.buckets {
				overflow.buckets[i] += evicted.buckets[i]
			}
		}
		r.countDroppedLocked(dropReasonOverflow)
		return
	}
}

// overflowLocked returns the overflow series for the metric's label shape,
// creating it on first use. All label values are replaced with
// overflowLabelValue so the bucket is easy to spot in dashboards. Callers
// must hold r.mu.
func (s *metricState) overflowLocked(labels Labels) *metricSeries {
	other := make(Labels, len(labels))
	for name := range labels {
		other[name] = overflowLabelValue
	}
	key, normalized := canonicalLabels(other)
	if series, ok := s.series[key]; ok {
		s.overflowKey = key
		return series
	}
	series := &metricSeries{key: key, labels: normalized}
	if s.def.kind == histogramKind {
		series.buckets = make([]uint64, len(s.def.buckets))
	}
	s.series[key] = series
	s.overflowKey = key
	return series
}

func canonicalLabels(labels Labels) (string, Labels) {
	if len(labels) == 0 {
		return "", nil
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	normalized := make(Labels, len(labels))
	var b strings.Builder
	for _, key := range keys {
		value := sanitizeLabelValue(labels[key], "unknown")
		normalized[key] = value
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(value)
		b.WriteByte(',')
	}
	return b.String(), normalized
}

func formatLabels(labels Labels) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf(`%s="%s"`, key, escapeLabel(labels[key])))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func withLE(labels Labels, bucket float64) Labels {
	out := copyLabels(labels)
	out["le"] = formatFloat(bucket)
	return out
}

func withInf(labels Labels) Labels {
	out := copyLabels(labels)
	out["le"] = "+Inf"
	return out
}

func copyLabels(labels Labels) Labels {
	if len(labels) == 0 {
		return Labels{}
	}
	out := make(Labels, len(labels)+1)
	for key, value := range labels {
		out[key] = value
	}
	return out
}

func escapeLabel(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	return strings.ReplaceAll(value, `"`, `\"`)
}

func sanitizeLabelValue(value, fallback string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return fallback
	}
	// Collapse runs of invalid characters to a single '_' in one pass. A
	// single strings.ReplaceAll("__", "_") is not enough: on a run of four
	// underscores it only halves the run ("a____b" -> "a__b"), and repeated
	// scraping/persistence of such values could still split series.
	var b strings.Builder
	b.Grow(len(value))
	lastUnderscore := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastUnderscore = false
		default:
			if lastUnderscore {
				continue
			}
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return fallback
	}
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}

func formatFloat(value float64) string {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return "0"
	}
	return strconv.FormatFloat(value, 'f', -1, 64)
}

func normalizeVersion(version string) string {
	version = strings.TrimSpace(version)
	if version == "" {
		return "unknown"
	}
	return strings.ReplaceAll(version, ".", "_")
}

// knownALPNFamilies maps well-known ALPN protocol identifiers to a small,
// bounded set of label values. Any identifier outside this set is reported as
// "other" so a peer cannot mint unbounded sybil_tls_alpn_total series.
var knownALPNFamilies = map[string]string{
	"http/0.9":           "http1",
	"grpc":               "grpc",
	"grpc-exp":           "grpc",
	"spdy/2":             "spdy",
	"spdy/3":             "spdy",
	"spdy/3.1":           "spdy",
	"quic":               "quic",
	"doq":                "doq",
	"dot":                "dot",
	"coap":               "coap",
	"co":                 "co",
	"mqtt":               "mqtt",
	"stun.turn":          "stun",
	"stun.nat-discovery": "stun",
	"webrtc":             "webrtc",
	"c-webrtc":           "webrtc",
	"ftp":                "ftp",
	"imap":               "imap",
	"pop3":               "pop3",
	"smtp":               "smtp",
	"ssh":                "ssh",
	"irc":                "irc",
	"xmpp-client":        "xmpp",
	"xmpp-server":        "xmpp",
	"acme-tls/1":         "acme-tls",
}

func normalizeALPN(alpn string) string {
	alpn = strings.TrimSpace(strings.ToLower(alpn))
	switch {
	case alpn == "":
		return "none"
	case strings.HasPrefix(alpn, "h2"):
		return "h2"
	case strings.HasPrefix(alpn, "http/1"):
		return "http1"
	case strings.HasPrefix(alpn, "h3"):
		return "h3"
	}
	if family, ok := knownALPNFamilies[alpn]; ok {
		return family
	}
	return "other"
}

func normalizeJA4FingerprintLabel(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return "unknown"
	}
	if len(value) > 128 {
		value = value[:128]
	}
	return value
}

func scoreBand(score int) string {
	switch {
	case score >= 95:
		return "critical"
	case score >= 80:
		return "high"
	case score >= 70:
		return "elevated"
	case score >= 40:
		return "medium"
	default:
		return "low"
	}
}

func helloTypeLabel(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "client hello":
		return "client"
	case "server hello":
		return "server"
	default:
		return sanitizeLabelValue(value, "unknown")
	}
}
