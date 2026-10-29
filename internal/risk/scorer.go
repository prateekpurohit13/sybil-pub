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
	MinuteWindow       time.Duration
	ResourceWindow     time.Duration
	HourWindow         time.Duration
	BucketSeconds      int
	BurstMinBuckets    int
	BurstMinRequests   int64
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
		BucketSeconds:      60,
		BurstMinBuckets:    3,
		BurstMinRequests:   10,
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

// DemoConfig returns the fast demo preset: short buckets, a short window and
// lower action thresholds. It must not be used for production triage.
func DemoConfig() Config {
	cfg := DefaultConfig()
	cfg.MinuteWindow = 2 * time.Minute
	cfg.ResourceWindow = 10 * time.Minute
	cfg.HourWindow = time.Hour
	cfg.BucketSeconds = 5
	cfg.BurstMinBuckets = 2
	cfg.BurstMinRequests = 5
	cfg.DelayThreshold = 30
	cfg.RateLimitThreshold = 45
	cfg.ChallengeThreshold = 55
	cfg.BlockThreshold = 70
	return cfg
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
	PairKey           string
	ResourceKind      string
	WindowRequests    int64
	TotalRequests     int64
	ActiveBuckets     int
	BucketSeconds     int
	RequestsPerMinute float64
	UniqueResources   int
	MinuteCounts      []int64
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

	total := 0
	for _, component := range components {
		total += component.Score
	}
	total = clampInt(total, 0, 100)

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

	maxWeight := cfg.WeightEndpoint
	if stats.ResourceKind == "host" {
		maxWeight = int(math.Round(float64(maxWeight) * 0.5))
	}

	uniqueFactor := 1.0 - clampFloat((float64(stats.UniqueResources)-1.0)/9.0, 0, 1)
	coverage := float64(stats.UniqueResources) / float64(stats.WindowRequests)
	coverageFactor := 1.0 - clampFloat(coverage/0.35, 0, 1)
	signalStrength := clampFloat(float64(stats.WindowRequests)/20.0, 0.35, 1)
	risk := (0.7 * uniqueFactor) + (0.3 * coverageFactor)

	component.Score = clampInt(int(math.Round(float64(maxWeight)*signalStrength*risk)), 0, maxWeight)
	component.Weight = maxWeight
	component.Detail = fmt.Sprintf("%d unique %s values across %d requests in %d active %ds bucket(s)",
		stats.UniqueResources, stats.ResourceKind, stats.WindowRequests, stats.ActiveBuckets, stats.BucketSeconds)
	return component
}

func scoreVelocity(stats LiveStats, cfg Config) ScoreComponent {
	component := ScoreComponent{
		Name:   "velocity",
		Weight: cfg.WeightVelocity,
		Detail: "insufficient request history",
	}

	rpm := stats.RequestsPerMinute
	component.Detail = fmt.Sprintf("%.1f requests/min across %d active %ds bucket(s)", rpm, stats.ActiveBuckets, stats.BucketSeconds)

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

func scoreBurstiness(stats LiveStats, cfg Config) ScoreComponent {
	component := ScoreComponent{
		Name:   "burstiness",
		Weight: cfg.WeightBurstiness,
		Detail: "not enough minute buckets to measure bursts",
	}

	minBuckets := cfg.BurstMinBuckets
	if minBuckets <= 0 {
		minBuckets = 3
	}
	minRequests := cfg.BurstMinRequests
	if minRequests <= 0 {
		minRequests = 10
	}
	if len(stats.MinuteCounts) < minBuckets || stats.WindowRequests < minRequests {
		return component
	}

	median := stats.MedianMinuteCount
	if median < 1 {
		median = 1
	}
	spikeRatio := float64(stats.PeakMinuteCount) / median
	mean, stdev := meanAndStdDev(stats.MinuteCounts)
	cv := 0.0
	if mean > 0 {
		cv = stdev / mean
	}

	spikeFactor := clampFloat(math.Log2(math.Max(spikeRatio, 1))/5, 0, 1)
	cvFactor := clampFloat(cv/2.5, 0, 1)
	confidence := clampFloat(float64(len(stats.MinuteCounts))/5, 0.4, 1)

	component.Score = clampInt(int(math.Round(float64(cfg.WeightBurstiness)*confidence*((0.65*spikeFactor)+(0.35*cvFactor)))), 0, cfg.WeightBurstiness)
	component.Detail = fmt.Sprintf("peak/median %.2fx over %d minute buckets", spikeRatio, len(stats.MinuteCounts))
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

func resolveResource(obs Observation, useHostFallback bool) (string, string) {
	if endpoint := strings.TrimSpace(obs.Endpoint); endpoint != "" {
		return endpoint, "endpoint"
	}
	if useHostFallback {
		if host := strings.TrimSpace(obs.Hostname); host != "" {
			return host, "host"
		}
	}
	return "", ""
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
