package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
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

type metricDef struct {
	help    string
	kind    metricKind
	buckets []float64
}

type metricSeries struct {
	labels  Labels
	value   float64
	buckets []uint64
	count   uint64
	sum     float64
}

type metricState struct {
	def    metricDef
	series map[string]*metricSeries
}

type Registry struct {
	started time.Time

	mu      sync.RWMutex
	metrics map[string]*metricState
}

func NewRegistry(backend, iface string) *Registry {
	r := &Registry{
		started: time.Now(),
		metrics: make(map[string]*metricState),
	}

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
	if duration <= 0 {
		return
	}
	r.Observe("sybil_processing_duration_seconds", Labels{
		"stage": sanitizeLabelValue(stage, "unknown"),
	}, duration.Seconds())
}

func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(r.render()))
	})
}

func (r *Registry) HealthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		payload, _ := json.Marshal(map[string]any{
			"status":  "ok",
			"uptime":  time.Since(r.started).String(),
			"started": r.started.UTC().Format(time.RFC3339),
		})
		_, _ = w.Write(payload)
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
	}
}

func (r *Registry) Inc(name string, labels Labels) {
	r.Add(name, labels, 1)
}

func (r *Registry) Add(name string, labels Labels, delta float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	series := r.getSeriesLocked(name, labels)
	series.value += delta
}

func (r *Registry) Set(name string, labels Labels, value float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	series := r.getSeriesLocked(name, labels)
	series.value = value
}

func (r *Registry) Observe(name string, labels Labels, value float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.metrics[name]
	if !ok {
		return
	}
	series := r.getSeriesLocked(name, labels)
	if state.def.kind != histogramKind {
		series.value = value
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
}

func (r *Registry) getSeriesLocked(name string, labels Labels) *metricSeries {
	state, ok := r.metrics[name]
	if !ok {
		return &metricSeries{}
	}
	key, normalized := canonicalLabels(labels)
	series, ok := state.series[key]
	if ok {
		return series
	}
	series = &metricSeries{
		labels: normalized,
	}
	if state.def.kind == histogramKind {
		series.buckets = make([]uint64, len(state.def.buckets))
	}
	state.series[key] = series
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
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	out = strings.ReplaceAll(out, "__", "_")
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
	default:
		return sanitizeLabelValue(alpn, "other")
	}
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
