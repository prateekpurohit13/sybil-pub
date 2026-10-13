package risk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

var ErrFingerprintNotFound = errors.New("fingerprint not found")

type StatsStore interface {
	Record(ctx context.Context, obs Observation, cfg Config) (LiveStats, error)
}

type LookupClient interface {
	Lookup(ctx context.Context, ja4 string) (*FingerprintRecord, error)
}

type LookupFunc func(ctx context.Context, ja4 string) (*FingerprintRecord, error)

func (f LookupFunc) Lookup(ctx context.Context, ja4 string) (*FingerprintRecord, error) {
	return f(ctx, ja4)
}

type Config struct {
	// MinuteWindow is the lookback/retention window for the per-minute bucket
	// series, despite the name (default 1h). Each bucket still aggregates one
	// wall-clock minute; the window only decides how many buckets are kept.
	MinuteWindow time.Duration
	// ResourceWindow bounds how long a resource value counts as fresh.
	ResourceWindow time.Duration
	// HourWindow is the retention for the hourly rollup. HourCounts is
	// currently informational only; scoring consumes the minute series.
	HourWindow         time.Duration
	UseHostFallback    bool
	WeightEndpoint     int
	WeightVelocity     int
	WeightBurstiness   int
	WeightReputation   int
	DelayThreshold     int
	RateLimitThreshold int
	ChallengeThreshold int
	BlockThreshold     int
	DelayBase          time.Duration
	DelayCeiling       time.Duration
}

func DefaultConfig() Config {
	return Config{
		MinuteWindow:       time.Hour,
		ResourceWindow:     time.Hour,
		HourWindow:         24 * time.Hour,
		UseHostFallback:    true,
		WeightEndpoint:     30,
		WeightVelocity:     30,
		WeightBurstiness:   25,
		WeightReputation:   15,
		DelayThreshold:     70,
		RateLimitThreshold: 80,
		ChallengeThreshold: 90,
		BlockThreshold:     95,
		DelayBase:          200 * time.Millisecond,
		DelayCeiling:       500 * time.Millisecond,
	}
}

type Observation struct {
	JA4       string
	SourceIP  string
	Endpoint  string
	Hostname  string
	Timestamp time.Time
}

func (o Observation) pairKey() string {
	return o.JA4 + "|" + o.SourceIP
}

type FingerprintRecord struct {
	Application          string `json:"application"`
	Library              string `json:"library"`
	Device               string `json:"device"`
	OS                   string `json:"os"`
	UserAgentString      string `json:"user_agent_string"`
	CertificateAuthority string `json:"certificate_authority"`
	Verified             bool   `json:"verified"`
	Notes                string `json:"notes"`
	JA4Fingerprint       string `json:"ja4_fingerprint"`
	JA4FingerprintString string `json:"ja4_fingerprint_string"`
	JA4SFingerprint      string `json:"ja4s_fingerprint"`
	JA4HFingerprint      string `json:"ja4h_fingerprint"`
	JA4XFingerprint      string `json:"ja4x_fingerprint"`
	JA4TFingerprint      string `json:"ja4t_fingerprint"`
	JA4TSFingerprint     string `json:"ja4ts_fingerprint"`
	JA4TScanFingerprint  string `json:"ja4tscan_fingerprint"`
}

type LiveStats struct {
	PairKey        string
	ResourceKind   string
	WindowRequests int64
	TotalRequests  int64
	ActiveMinutes  int
	// RequestsPerMinute is requests / active minutes, i.e. intensity while the
	// client was active. The store never zero-fills idle minutes, so a slow
	// drip that is only active in a few minutes of the hour reads the same as
	// a sustained burst compressed into those minutes. Burstiness (newest
	// minute vs trailing baseline) separates the two; see scoreBurstiness.
	RequestsPerMinute float64
	UniqueResources   int
	MinuteCounts      []int64
	// HourCounts is populated by the store but not consumed by scoring yet.
	HourCounts        []int64
	PeakMinuteCount   int64
	MedianMinuteCount float64
	PeakToMedianRatio float64
	FirstSeen         time.Time
	LastSeen          time.Time
}

type ScoreComponent struct {
	Name   string
	Score  int
	Weight int
	Detail string
}

// Action is the advisory mitigation label attached to an assessment. Sybil is
// a passive sniffer: it prints and persists this label, but nothing on the
// capture path enforces it (the eBPF/XDP path always passes packets). Wiring
// actions into a proxy, firewall, or XDP verdict is explicitly left to the
// operator; do not read "block" as an enforced drop.
type Action string

const (
	ActionAllow     Action = "allow"
	ActionDelay     Action = "delay"
	ActionRateLimit Action = "rate_limit"
	ActionChallenge Action = "challenge"
	ActionBlock     Action = "block"
)

type Assessment struct {
	PairKey     string
	Score       int
	Action      Action
	Delay       time.Duration
	Components  []ScoreComponent
	Stats       LiveStats
	Lookup      *FingerprintRecord
	Summary     FingerprintSummary
	LookupError string
}

type Scorer struct {
	store  StatsStore
	lookup LookupClient
	config Config
	now    func() time.Time
}

func NewScorer(store StatsStore, lookup LookupClient, cfg Config) *Scorer {
	return &Scorer{
		store:  store,
		lookup: lookup,
		config: cfg,
		now:    time.Now,
	}
}

func (s *Scorer) Assess(ctx context.Context, obs Observation) (Assessment, error) {
	if strings.TrimSpace(obs.JA4) == "" {
		return Assessment{}, errors.New("missing ja4 fingerprint")
	}
	if strings.TrimSpace(obs.SourceIP) == "" {
		return Assessment{}, errors.New("missing source ip")
	}
	if obs.Timestamp.IsZero() {
		obs.Timestamp = s.now()
	}

	stats, err := s.store.Record(ctx, obs, s.config)
	if err != nil {
		return Assessment{}, fmt.Errorf("record live stats: %w", err)
	}

	var (
		record    *FingerprintRecord
		lookupErr error
	)
	if s.lookup != nil {
		record, lookupErr = s.lookup.Lookup(ctx, obs.JA4)
		if record != nil && record.JA4Fingerprint == "" {
			record.JA4Fingerprint = obs.JA4
		}
	}
	summary := SummarizeFingerprint(record, lookupErr, s.lookup != nil)

	components := []ScoreComponent{
		scoreResourceDiversity(stats, s.config),
		scoreVelocity(stats, s.config),
		scoreBurstiness(stats, s.config),
		scoreReputation(summary, record, lookupErr, s.lookup != nil, s.config),
	}

	raw := 0
	for _, component := range components {
		raw += component.Score
	}
	raw = clampInt(raw, 0, 100)

	// Renormalize against the maximum score the visible signal set can earn.
	// Host-only SNI and per-source-IP fallbacks earn less of the endpoint
	// weight, so without this the documented thresholds (and therefore
	// rate_limit/challenge/block) would be unreachable in the sniffer flow.
	// 100 means "as risky as observable evidence allows".
	total := raw
	if achievable := achievableMax(stats.ResourceKind, s.lookup != nil, s.config); achievable > 0 {
		total = clampInt(int(math.Round(float64(raw)*100.0/achievable)), 0, 100)
	}

	action, delay := deriveAction(total, s.config)
	assessment := Assessment{
		PairKey:    stats.PairKey,
		Score:      total,
		Action:     action,
		Delay:      delay,
		Components: components,
		Stats:      stats,
		Lookup:     record,
		Summary:    summary,
	}
	if lookupErr != nil {
		assessment.LookupError = lookupErr.Error()
	}

	return assessment, nil
}

func scoreResourceDiversity(stats LiveStats, cfg Config) ScoreComponent {
	component := ScoreComponent{
		Name:   "resource_diversity",
		Weight: cfg.WeightEndpoint,
		Detail: "no endpoint-level signal collected yet",
	}

	if stats.UniqueResources == 0 || stats.WindowRequests == 0 {
		return component
	}

	// Keep the declared weight (30) for every resource kind and attenuate the
	// earnable risk by visibility confidence. Host fallback used to halve both
	// the cap (to 15) and the reported weight, which combined with the raw
	// sum put every action above "delay" permanently out of reach in the
	// sniffer flow. Confidence-based attenuation keeps host/SNI evidence
	// weaker than a real endpoint path without making it a dead letter.
	confidence := resourceConfidence(stats.ResourceKind)
	maxWeight := float64(cfg.WeightEndpoint) * confidence

	uniqueFactor := 1.0 - clampFloat((float64(stats.UniqueResources)-1.0)/9.0, 0, 1)
	coverage := float64(stats.UniqueResources) / float64(stats.WindowRequests)
	coverageFactor := 1.0 - clampFloat(coverage/0.35, 0, 1)
	signalStrength := clampFloat(float64(stats.WindowRequests)/20.0, 0.35, 1)
	risk := (0.7 * uniqueFactor) + (0.3 * coverageFactor)

	component.Score = clampInt(int(math.Round(maxWeight*signalStrength*risk)), 0, cfg.WeightEndpoint)
	component.Detail = fmt.Sprintf("%d unique %s values across %d requests in %d active minute(s) (visibility confidence %.2f)",
		stats.UniqueResources, stats.ResourceKind, stats.WindowRequests, stats.ActiveMinutes, confidence)
	return component
}

func scoreVelocity(stats LiveStats, cfg Config) ScoreComponent {
	component := ScoreComponent{
		Name:   "velocity",
		Weight: cfg.WeightVelocity,
		Detail: "insufficient request history",
	}

	rpm := stats.RequestsPerMinute
	component.Detail = fmt.Sprintf("%.1f requests/min across %d active minute(s)", rpm, stats.ActiveMinutes)

	if rpm <= 10 {
		return component
	}

	weight := cfg.WeightVelocity
	switch {
	case rpm <= 20:
		component.Score = lerpInt(0, weight/3, (rpm-10)/10)
	case rpm <= 50:
		component.Score = lerpInt(weight/3, int(math.Round(float64(weight)*0.60)), (rpm-20)/30)
	case rpm <= 200:
		component.Score = lerpInt(int(math.Round(float64(weight)*0.60)), int(math.Round(float64(weight)*0.90)), (rpm-50)/150)
	default:
		component.Score = lerpInt(int(math.Round(float64(weight)*0.90)), weight, clampFloat((rpm-200)/200, 0, 1))
	}

	return component
}

const (
	// burstMinRequests filters sampling noise: below this there is not enough
	// traffic for a minute-level spike to be meaningful.
	burstMinRequests = 10
	// burstBaselineBuckets is how many preceding active minutes form the
	// trailing baseline the newest minute is compared against.
	burstBaselineBuckets = 5
)

func scoreBurstiness(stats LiveStats, cfg Config) ScoreComponent {
	component := ScoreComponent{
		Name:   "burstiness",
		Weight: cfg.WeightBurstiness,
		Detail: "not enough minute buckets to measure bursts",
	}

	buckets := len(stats.MinuteCounts)
	if buckets == 0 || stats.WindowRequests < burstMinRequests {
		return component
	}

	// The newest bucket is the minute that contains this observation (the
	// store sorted buckets ascending and just incremented the current one).
	// Compare it against the median of the preceding active minutes instead of
	// requiring three buckets: a single-minute spike was previously scored 0,
	// which made burstiness silently unenforced for short demo/attack bursts.
	current := stats.MinuteCounts[buckets-1]
	start := buckets - 1 - burstBaselineBuckets
	if start < 0 {
		start = 0
	}
	baseline := median(stats.MinuteCounts[start : buckets-1])
	if baseline < 1 {
		// First observed minute (or all-zero neighbours): floor the baseline
		// at one request/minute so a solo hot minute is a spike rather than
		// an undefined ratio.
		baseline = 1
	}

	spikeRatio := float64(current) / baseline
	mean, stdev := meanAndStdDev(stats.MinuteCounts)
	cv := 0.0
	if mean > 0 {
		cv = stdev / mean
	}

	spikeFactor := clampFloat(math.Log2(math.Max(spikeRatio, 1))/5, 0, 1)
	cvFactor := clampFloat(cv/2.5, 0, 1)
	// A solo bucket is a fully observed concentration (all window traffic in
	// one minute), so it gets full confidence. Ramp 2-4 buckets from 0.625 to
	// 0.875 instead of collapsing to the old 0.4 floor that buried short
	// bursts below the action bands.
	confidence := 1.0
	if buckets > 1 && buckets < 5 {
		confidence = 0.5 + 0.125*float64(buckets-1)
	}

	component.Score = clampInt(int(math.Round(float64(cfg.WeightBurstiness)*confidence*((0.65*spikeFactor)+(0.35*cvFactor)))), 0, cfg.WeightBurstiness)
	component.Detail = fmt.Sprintf("current minute %d vs trailing median %.1f (%.2fx) across %d minute bucket(s)", current, baseline, spikeRatio, buckets)
	return component
}

func scoreReputation(summary FingerprintSummary, record *FingerprintRecord, lookupErr error, lookupEnabled bool, cfg Config) ScoreComponent {
	component := ScoreComponent{
		Name:   "fingerprint_reputation",
		Weight: cfg.WeightReputation,
	}

	switch {
	case errors.Is(lookupErr, ErrFingerprintNotFound):
		component.Score = cfg.WeightReputation / 2
		component.Detail = "fingerprint missing from reputation DB"
		return component
	case lookupErr != nil:
		component.Detail = "reputation lookup failed; ignoring static signal"
		return component
	case !lookupEnabled:
		component.Detail = "reputation lookup not configured"
		return component
	case record == nil:
		component.Score = cfg.WeightReputation / 2
		component.Detail = "fingerprint missing from reputation DB"
		return component
	}

	scoreRatio := 0.35
	switch summary.IdentityClass {
	case "verified_browser":
		scoreRatio = 0.0
	case "browser":
		scoreRatio = 0.12
	case "verified_known":
		scoreRatio = 0.10
	case "mobile_app":
		scoreRatio = 0.18
	case "vpn":
		scoreRatio = 0.40
	case "automation":
		scoreRatio = 0.55
	case "malware_like":
		scoreRatio = 0.90
	case "known_unverified":
		scoreRatio = 0.70
	default:
		scoreRatio = 0.50
	}

	if record.Verified && scoreRatio > 0.10 {
		scoreRatio -= 0.10
	}
	if strings.TrimSpace(record.Library) != "" && scoreRatio > 0.05 {
		scoreRatio -= 0.05
	}
	if strings.TrimSpace(record.Notes) != "" && summary.IdentityClass != "malware_like" {
		scoreRatio += 0.05
	}
	scoreRatio = clampFloat(scoreRatio, 0, 1)

	component.Score = clampInt(int(math.Round(float64(cfg.WeightReputation)*scoreRatio)), 0, cfg.WeightReputation)
	component.Detail = fmt.Sprintf("identity=%s reputation=%s verified=%t",
		summary.IdentityClass, summary.ReputationState, record.Verified)
	return component
}

func deriveAction(score int, cfg Config) (Action, time.Duration) {
	switch {
	case score >= cfg.BlockThreshold:
		return ActionBlock, 0
	case score >= cfg.ChallengeThreshold:
		return ActionChallenge, 0
	case score >= cfg.RateLimitThreshold:
		return ActionRateLimit, 0
	case score >= cfg.DelayThreshold:
		step := time.Duration(score-cfg.DelayThreshold) * 25 * time.Millisecond
		delay := cfg.DelayBase + step
		if delay > cfg.DelayCeiling {
			delay = cfg.DelayCeiling
		}
		return ActionDelay, delay
	default:
		return ActionAllow, 0
	}
}

type HTTPLookupClient struct {
	urlTemplate string
	client      *http.Client
}

func NewHTTPLookupClient(urlTemplate string, client *http.Client) *HTTPLookupClient {
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second}
	}
	return &HTTPLookupClient{
		urlTemplate: strings.TrimSpace(urlTemplate),
		client:      client,
	}
}

func (c *HTTPLookupClient) Lookup(ctx context.Context, ja4 string) (*FingerprintRecord, error) {
	if strings.TrimSpace(c.urlTemplate) == "" {
		return nil, nil
	}

	targetURL := c.urlTemplate
	if strings.Contains(targetURL, "%s") {
		targetURL = fmt.Sprintf(targetURL, url.QueryEscape(ja4))
	} else {
		separator := "?"
		if strings.Contains(targetURL, "?") {
			separator = "&"
		}
		targetURL += separator + "ja4=" + url.QueryEscape(ja4)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create lookup request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute lookup request: %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrFingerprintNotFound
	case resp.StatusCode >= http.StatusBadRequest:
		return nil, fmt.Errorf("lookup returned status %d", resp.StatusCode)
	}

	var record FingerprintRecord
	if err := json.NewDecoder(resp.Body).Decode(&record); err != nil {
		return nil, fmt.Errorf("decode lookup response: %w", err)
	}
	if record.JA4Fingerprint == "" {
		record.JA4Fingerprint = ja4
	}
	return &record, nil
}

const (
	resourceKindEndpoint = "endpoint"
	resourceKindHost     = "host"
	// resourceKindSourceIP is the last-resort destination bucket used when
	// neither an HTTP path nor an SNI host is visible (or host fallback is
	// disabled).
	resourceKindSourceIP = "source_ip"
)

// Visibility confidence applied to resource observations. A real endpoint
// path is full-strength. SNI is destination-level, not path-level evidence,
// so it earns 75% of the diversity weight; a per-source-IP bucket says only
// "one opaque destination", so it earns 50%.
const (
	hostFallbackConfidence     = 0.75
	sourceIPFallbackConfidence = 0.50
)

// resolveResource picks the strongest destination resource visible to the
// sensor: endpoint path > SNI host (when allowed) > per-source-IP bucket. The
// final fallback deliberately returns a synthetic, non-empty resource so
// diversity reads "one opaque destination" instead of silently scoring zero
// (a missing resource used to skip the resource hash entirely and cap
// SNI-less traffic below the rate_limit band).
func resolveResource(obs Observation, useHostFallback bool) (string, string) {
	if endpoint := strings.TrimSpace(obs.Endpoint); endpoint != "" {
		return endpoint, resourceKindEndpoint
	}
	if useHostFallback {
		if host := strings.TrimSpace(obs.Hostname); host != "" {
			return host, resourceKindHost
		}
	}
	if sourceIP := strings.TrimSpace(obs.SourceIP); sourceIP != "" {
		return "ip:" + sourceIP, resourceKindSourceIP
	}
	return "", ""
}

// resourceConfidence maps a resource kind to the fraction of the endpoint
// weight it can earn. Unknown/legacy kinds keep full weight so custom stores
// are not penalized.
func resourceConfidence(kind string) float64 {
	switch kind {
	case resourceKindHost:
		return hostFallbackConfidence
	case resourceKindSourceIP:
		return sourceIPFallbackConfidence
	default:
		return 1.0
	}
}

// achievableMax returns the highest score the current signal set could earn.
// The raw component sum is expressed as a percentage of this ceiling so the
// documented action thresholds stay reachable when only weaker signals are
// visible. The reputation weight joins the denominator only when an
// enrichment lookup is configured: an unenriched sensor is normalized
// against behavior alone, while an enabled-but-erroring lookup keeps the
// weight in the denominator so an outage cannot inflate scores.
func achievableMax(resourceKind string, lookupEnabled bool, cfg Config) float64 {
	max := float64(cfg.WeightEndpoint) * resourceConfidence(resourceKind)
	max += float64(cfg.WeightVelocity)
	max += float64(cfg.WeightBurstiness)
	if lookupEnabled {
		max += float64(cfg.WeightReputation)
	}
	return max
}

func meanAndStdDev(values []int64) (float64, float64) {
	if len(values) == 0 {
		return 0, 0
	}

	total := 0.0
	for _, value := range values {
		total += float64(value)
	}
	mean := total / float64(len(values))
	if len(values) == 1 {
		return mean, 0
	}

	variance := 0.0
	for _, value := range values {
		diff := float64(value) - mean
		variance += diff * diff
	}
	variance /= float64(len(values))
	return mean, math.Sqrt(variance)
}

func median(values []int64) float64 {
	if len(values) == 0 {
		return 0
	}
	copied := append([]int64(nil), values...)
	sort.Slice(copied, func(i, j int) bool { return copied[i] < copied[j] })
	mid := len(copied) / 2
	if len(copied)%2 == 0 {
		return float64(copied[mid-1]+copied[mid]) / 2
	}
	return float64(copied[mid])
}

func lerpInt(minValue, maxValue int, ratio float64) int {
	ratio = clampFloat(ratio, 0, 1)
	return int(math.Round(float64(minValue) + (float64(maxValue-minValue) * ratio)))
}

func clampInt(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func clampFloat(value, minValue, maxValue float64) float64 {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}
