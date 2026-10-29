package risk

import (
	"context"
	"errors"
	"testing"
	"time"
)

type stubStore struct {
	stats LiveStats
	err   error
}

func (s stubStore) Record(context.Context, Observation, Config) (LiveStats, error) {
	if s.err != nil {
		return LiveStats{}, s.err
	}
	return s.stats, nil
}

func TestScorerHighRiskSingleEndpointBurst(t *testing.T) {
	cfg := DefaultConfig()
	scorer := NewScorer(
		stubStore{stats: LiveStats{
			PairKey:           "ja4|1.2.3.4",
			ResourceKind:      "endpoint",
			WindowRequests:    600,
			TotalRequests:     900,
			ActiveMinutes:     3,
			RequestsPerMinute: 200,
			UniqueResources:   1,
			MinuteCounts:      []int64{20, 20, 560},
			HourCounts:        []int64{600},
			PeakMinuteCount:   560,
			MedianMinuteCount: 20,
			PeakToMedianRatio: 28,
		}},
		LookupFunc(func(context.Context, string) (*FingerprintRecord, error) {
			return &FingerprintRecord{
				JA4Fingerprint:  "ja4",
				UserAgentString: "Mozilla/5.0",
				Verified:        false,
			}, nil
		}),
		cfg,
	)

	assessment, err := scorer.Assess(context.Background(), Observation{
		JA4:      "ja4",
		SourceIP: "1.2.3.4",
	})
	if err != nil {
		t.Fatalf("Assess returned error: %v", err)
	}

	if assessment.Score < 80 {
		t.Fatalf("expected high-risk score, got %d", assessment.Score)
	}
	if assessment.Action != ActionRateLimit && assessment.Action != ActionChallenge && assessment.Action != ActionBlock {
		t.Fatalf("expected stronger mitigation, got %s", assessment.Action)
	}
}

func TestScorerLowRiskVerifiedDiverseTraffic(t *testing.T) {
	cfg := DefaultConfig()
	scorer := NewScorer(
		stubStore{stats: LiveStats{
			PairKey:           "ja4|5.6.7.8",
			ResourceKind:      "endpoint",
			WindowRequests:    20,
			TotalRequests:     80,
			ActiveMinutes:     5,
			RequestsPerMinute: 4,
			UniqueResources:   8,
			MinuteCounts:      []int64{4, 4, 4, 4, 4},
			HourCounts:        []int64{20},
			PeakMinuteCount:   4,
			MedianMinuteCount: 4,
			PeakToMedianRatio: 1,
			FirstSeen:         time.Now().Add(-2 * time.Hour),
			LastSeen:          time.Now(),
		}},
		LookupFunc(func(context.Context, string) (*FingerprintRecord, error) {
			return &FingerprintRecord{
				JA4Fingerprint:  "ja4",
				Application:     "Chrome",
				Device:          "Desktop",
				OS:              "macOS",
				UserAgentString: "Mozilla/5.0",
				Verified:        true,
			}, nil
		}),
		cfg,
	)

	assessment, err := scorer.Assess(context.Background(), Observation{
		JA4:      "ja4",
		SourceIP: "5.6.7.8",
	})
	if err != nil {
		t.Fatalf("Assess returned error: %v", err)
	}

	if assessment.Score > 20 {
		t.Fatalf("expected low-risk score, got %d", assessment.Score)
	}
	if assessment.Action != ActionAllow {
		t.Fatalf("expected allow action, got %s", assessment.Action)
	}
}

func TestHostFallbackCarriesLessWeightThanEndpointSignal(t *testing.T) {
	cfg := DefaultConfig()

	endpointAssessment, err := NewScorer(
		stubStore{stats: LiveStats{
			PairKey:           "ja4|1.1.1.1",
			ResourceKind:      "endpoint",
			WindowRequests:    100,
			ActiveMinutes:     4,
			RequestsPerMinute: 25,
			UniqueResources:   1,
			MinuteCounts:      []int64{25, 25, 25, 25},
			PeakMinuteCount:   25,
			MedianMinuteCount: 25,
		}},
		nil,
		cfg,
	).Assess(context.Background(), Observation{JA4: "ja4", SourceIP: "1.1.1.1"})
	if err != nil {
		t.Fatalf("endpoint assessment failed: %v", err)
	}

	hostAssessment, err := NewScorer(
		stubStore{stats: LiveStats{
			PairKey:           "ja4|1.1.1.1",
			ResourceKind:      "host",
			WindowRequests:    100,
			ActiveMinutes:     4,
			RequestsPerMinute: 25,
			UniqueResources:   1,
			MinuteCounts:      []int64{25, 25, 25, 25},
			PeakMinuteCount:   25,
			MedianMinuteCount: 25,
		}},
		nil,
		cfg,
	).Assess(context.Background(), Observation{JA4: "ja4", SourceIP: "1.1.1.1"})
	if err != nil {
		t.Fatalf("host assessment failed: %v", err)
	}

	if endpointAssessment.Components[0].Score <= hostAssessment.Components[0].Score {
		t.Fatalf("expected endpoint diversity weight to exceed host fallback, got endpoint=%d host=%d",
			endpointAssessment.Components[0].Score, hostAssessment.Components[0].Score)
	}
}

func TestScorerPropagatesStoreError(t *testing.T) {
	scorer := NewScorer(stubStore{err: errors.New("redis down")}, nil, DefaultConfig())

	_, err := scorer.Assess(context.Background(), Observation{
		JA4:      "ja4",
		SourceIP: "1.2.3.4",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func componentByName(assessment Assessment, name string) ScoreComponent {
	for _, component := range assessment.Components {
		if component.Name == name {
			return component
		}
	}
	return ScoreComponent{}
}

func TestResolveResourceNeverReturnsEmptyForKnownSourceIP(t *testing.T) {
	tests := []struct {
		name            string
		obs             Observation
		useHostFallback bool
		wantKind        string
	}{
		{
			name:            "endpoint path wins",
			obs:             Observation{Endpoint: "/api/v1", Hostname: "example.com", SourceIP: "203.0.113.5"},
			useHostFallback: true,
			wantKind:        resourceKindEndpoint,
		},
		{
			name:            "sni host fallback",
			obs:             Observation{Hostname: "example.com", SourceIP: "203.0.113.5"},
			useHostFallback: true,
			wantKind:        resourceKindHost,
		},
		{
			name:            "sni-less per-source-ip fallback",
			obs:             Observation{SourceIP: "203.0.113.5"},
			useHostFallback: true,
			wantKind:        resourceKindSourceIP,
		},
		{
			name:            "host fallback disabled still buckets by source ip",
			obs:             Observation{Hostname: "example.com", SourceIP: "203.0.113.5"},
			useHostFallback: false,
			wantKind:        resourceKindSourceIP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource, kind := resolveResource(tt.obs, tt.useHostFallback)
			if kind != tt.wantKind {
				t.Fatalf("expected kind %q, got %q", tt.wantKind, kind)
			}
			if resource == "" {
				t.Fatal("expected a non-empty resource so diversity is not silently zero")
			}
		})
	}
}

func TestSingleBucketSpikeFiresBurstinessAndReachesRateLimit(t *testing.T) {
	cfg := DefaultConfig()
	assessment, err := NewScorer(
		stubStore{stats: LiveStats{
			PairKey:           "ja4|9.9.9.9",
			ResourceKind:      resourceKindHost,
			WindowRequests:    500,
			TotalRequests:     500,
			ActiveMinutes:     1,
			RequestsPerMinute: 500,
			UniqueResources:   1,
			MinuteCounts:      []int64{500},
			PeakMinuteCount:   500,
			MedianMinuteCount: 500,
		}},
		LookupFunc(func(context.Context, string) (*FingerprintRecord, error) {
			return &FingerprintRecord{JA4Fingerprint: "ja4", Application: "curl"}, nil
		}),
		cfg,
	).Assess(context.Background(), Observation{JA4: "ja4", SourceIP: "9.9.9.9", Hostname: "example.com"})
	if err != nil {
		t.Fatalf("Assess returned error: %v", err)
	}

	if burst := componentByName(assessment, "burstiness"); burst.Score == 0 {
		t.Fatalf("expected a single-minute spike to score burstiness, got %+v", burst)
	}
	if assessment.Score < cfg.RateLimitThreshold {
		t.Fatalf("expected single-host burst+automation to reach rate_limit band, got score=%d action=%s", assessment.Score, assessment.Action)
	}
	switch assessment.Action {
	case ActionRateLimit, ActionChallenge, ActionBlock:
	default:
		t.Fatalf("expected rate_limit or stronger, got %s", assessment.Action)
	}
}

func TestSustainedHostMalwareReachesBlock(t *testing.T) {
	cfg := DefaultConfig()
	assessment, err := NewScorer(
		stubStore{stats: LiveStats{
			PairKey:           "ja4|198.51.100.9",
			ResourceKind:      resourceKindHost,
			WindowRequests:    2500,
			TotalRequests:     2500,
			ActiveMinutes:     5,
			RequestsPerMinute: 500,
			UniqueResources:   1,
			MinuteCounts:      []int64{10, 10, 10, 10, 2460},
			PeakMinuteCount:   2460,
			MedianMinuteCount: 10,
		}},
		LookupFunc(func(context.Context, string) (*FingerprintRecord, error) {
			return &FingerprintRecord{JA4Fingerprint: "ja4", Application: "Cobalt Strike Beacon"}, nil
		}),
		cfg,
	).Assess(context.Background(), Observation{JA4: "ja4", SourceIP: "198.51.100.9", Hostname: "example.com"})
	if err != nil {
		t.Fatalf("Assess returned error: %v", err)
	}

	if assessment.Score < cfg.ChallengeThreshold {
		t.Fatalf("expected sustained host+malware to reach challenge/block band, got score=%d action=%s", assessment.Score, assessment.Action)
	}
	if assessment.Action != ActionChallenge && assessment.Action != ActionBlock {
		t.Fatalf("expected challenge or block, got %s", assessment.Action)
	}
	if assessment.Summary.IdentityClass != "malware_like" {
		t.Fatalf("expected malware_like identity, got %s", assessment.Summary.IdentityClass)
	}
}

// TestDocumentedBlockReachableAcrossResourceKinds pins the fix for the old
// ceiling: host-only (SNI) and SNI-less (per-source-IP) visibility used to
// top out at ~85 and ~70 raw points, so the 90/95 actions and the malicious
// verdict were unreachable. With confidence-weighted diversity and
// normalization against the achievable maximum, worst-case attack-shaped
// traffic can reach block in every resource mode.
func TestDocumentedBlockReachableAcrossResourceKinds(t *testing.T) {
	cfg := DefaultConfig()
	for _, kind := range []string{resourceKindEndpoint, resourceKindHost, resourceKindSourceIP} {
		t.Run(kind, func(t *testing.T) {
			assessment, err := NewScorer(
				stubStore{stats: LiveStats{
					PairKey:           "ja4|192.0.2.10",
					ResourceKind:      kind,
					WindowRequests:    2500,
					TotalRequests:     2500,
					ActiveMinutes:     5,
					RequestsPerMinute: 500,
					UniqueResources:   1,
					MinuteCounts:      []int64{10, 10, 10, 10, 2460},
					PeakMinuteCount:   2460,
					MedianMinuteCount: 10,
				}},
				LookupFunc(func(context.Context, string) (*FingerprintRecord, error) {
					return &FingerprintRecord{JA4Fingerprint: "ja4", Application: "Cobalt Strike Beacon"}, nil
				}),
				cfg,
			).Assess(context.Background(), Observation{JA4: "ja4", SourceIP: "192.0.2.10"})
			if err != nil {
				t.Fatalf("Assess returned error: %v", err)
			}
			if assessment.Score < cfg.BlockThreshold || assessment.Action != ActionBlock {
				t.Fatalf("expected block for %s resource kind, got score=%d action=%s", kind, assessment.Score, assessment.Action)
			}
		})
	}
}

func TestBenignHostTrafficStaysAllow(t *testing.T) {
	cfg := DefaultConfig()
	assessment, err := NewScorer(
		stubStore{stats: LiveStats{
			PairKey:           "ja4|203.0.113.77",
			ResourceKind:      resourceKindHost,
			WindowRequests:    20,
			TotalRequests:     20,
			ActiveMinutes:     5,
			RequestsPerMinute: 4,
			UniqueResources:   8,
			MinuteCounts:      []int64{4, 4, 4, 4, 4},
			PeakMinuteCount:   4,
			MedianMinuteCount: 4,
		}},
		LookupFunc(func(context.Context, string) (*FingerprintRecord, error) {
			return &FingerprintRecord{JA4Fingerprint: "ja4", Application: "Google Chrome", Verified: true}, nil
		}),
		cfg,
	).Assess(context.Background(), Observation{JA4: "ja4", SourceIP: "203.0.113.77", Hostname: "www.example.com"})
	if err != nil {
		t.Fatalf("Assess returned error: %v", err)
	}

	if assessment.Action != ActionAllow {
		t.Fatalf("expected benign host traffic to stay allow, got score=%d action=%s", assessment.Score, assessment.Action)
	}
}

func TestDemoBurstReachesChallengeThreshold(t *testing.T) {
	cfg := DemoConfig()
	scorer := NewScorer(
		stubStore{stats: LiveStats{
			PairKey:           "ja4|1.2.3.4",
			ResourceKind:      "host",
			WindowRequests:    110,
			TotalRequests:     110,
			ActiveBuckets:     3,
			BucketSeconds:     5,
			RequestsPerMinute: 440,
			UniqueResources:   1,
			MinuteCounts:      []int64{5, 5, 100},
			PeakMinuteCount:   100,
			MedianMinuteCount: 5,
			PeakToMedianRatio: 20,
		}},
		nil,
		cfg,
	)

	assessment, err := scorer.Assess(context.Background(), Observation{
		JA4:      "ja4",
		SourceIP: "1.2.3.4",
	})
	if err != nil {
		t.Fatalf("Assess returned error: %v", err)
	}
	if assessment.Score < cfg.ChallengeThreshold {
		t.Fatalf("demo burst score = %d, want >= %d: %+v", assessment.Score, cfg.ChallengeThreshold, assessment.Components)
	}
}

func TestDemoC2ReachesBlockThreshold(t *testing.T) {
	cfg := DemoConfig()
	scorer := NewScorer(
		stubStore{stats: LiveStats{
			PairKey:           "c2|1.2.3.4",
			ResourceKind:      "host",
			WindowRequests:    220,
			TotalRequests:     220,
			ActiveBuckets:     5,
			BucketSeconds:     5,
			RequestsPerMinute: 528,
			UniqueResources:   1,
			MinuteCounts:      []int64{5, 5, 5, 5, 200},
			PeakMinuteCount:   200,
			MedianMinuteCount: 5,
			PeakToMedianRatio: 40,
		}},
		LookupFunc(func(context.Context, string) (*FingerprintRecord, error) {
			return &FingerprintRecord{Notes: "c2 beacon lab fixture; malware_like"}, nil
		}),
		cfg,
	)

	assessment, err := scorer.Assess(context.Background(), Observation{
		JA4:      "c2",
		SourceIP: "1.2.3.4",
	})
	if err != nil {
		t.Fatalf("Assess returned error: %v", err)
	}
	if assessment.Score < 80 {
		t.Fatalf("demo C2 score = %d, want >= 80: %+v", assessment.Score, assessment.Components)
	}
	if assessment.Action != ActionBlock {
		t.Fatalf("demo C2 action = %s, want %s", assessment.Action, ActionBlock)
	}
}
