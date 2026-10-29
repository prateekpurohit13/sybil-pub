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
			ActiveBuckets:     3,
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
			ActiveBuckets:     5,
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
			ActiveBuckets:     4,
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
			ActiveBuckets:     4,
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

func TestBurstinessRespectsDemoMinimums(t *testing.T) {
	stats := LiveStats{
		WindowRequests:    51,
		ActiveBuckets:     2,
		BucketSeconds:     5,
		MinuteCounts:      []int64{1, 50},
		PeakMinuteCount:   50,
		MedianMinuteCount: 1,
	}

	defaults := scoreBurstiness(stats, DefaultConfig())
	if defaults.Score != 0 {
		t.Fatalf("default burst minimum should ignore two buckets, got %d", defaults.Score)
	}

	demo := DefaultConfig()
	demo.BurstMinBuckets = 2
	demo.BurstMinRequests = 5
	fast := scoreBurstiness(stats, demo)
	if fast.Score == 0 {
		t.Fatal("demo burst minimum should score a two-bucket spike")
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
