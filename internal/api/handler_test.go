package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sophic00/sybil/internal/risk"
)

type fakeStore struct {
	total       TotalStats
	timeseries  []TimeseriesEntry
	recent      []TLSRequest
	topThreats  []TLSRequest
	topCommon   []FingerprintEntry
	frequent    FrequentFingerprintsSummary
	topLastHour []FingerprintEntry
	readErr     error
	recordCalls int
}

func (f *fakeStore) Record(context.Context, RequestObservation) error {
	f.recordCalls++
	return nil
}

func (f *fakeStore) TotalStats(context.Context) (TotalStats, error) {
	return f.total, f.readErr
}

func (f *fakeStore) Timeseries(context.Context, time.Time) ([]TimeseriesEntry, error) {
	return f.timeseries, f.readErr
}

func (f *fakeStore) RecentRequests(context.Context, int) ([]TLSRequest, error) {
	return f.recent, f.readErr
}

func (f *fakeStore) TopThreats(context.Context, int, time.Time) ([]TLSRequest, error) {
	return f.topThreats, f.readErr
}

func (f *fakeStore) TopCommonFingerprints(context.Context, int) ([]FingerprintEntry, error) {
	return f.topCommon, f.readErr
}

func (f *fakeStore) FrequentFingerprintsLastHour(context.Context, time.Time, int64) (FrequentFingerprintsSummary, error) {
	return f.frequent, f.readErr
}

func (f *fakeStore) TopFingerprintsLastHour(context.Context, time.Time, int) ([]FingerprintEntry, error) {
	return f.topLastHour, f.readErr
}

func TestRegisterRoutesTotalStats(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, &fakeStore{
		total: TotalStats{Total: 10, Clean: 8, Suspicious: 1, Malicious: 1},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/stats/total", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
	// Hardened default: same-origin only, so no wildcard CORS header and no
	// allow-origin echo without an explicit allowlist.
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("expected no CORS header by default, got %q", got)
	}

	var payload TotalStats
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if payload.Total != 10 || payload.Clean != 8 || payload.Suspicious != 1 || payload.Malicious != 1 {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestRegisterRoutesStoreUnavailable(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/requests/recent", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
}

func TestRegisterRoutesLastHourEndpoints(t *testing.T) {
	mux := http.NewServeMux()
	now := time.Now().UTC()
	RegisterRoutes(mux, &fakeStore{
		frequent: FrequentFingerprintsSummary{
			WindowMinutes: 60,
			MinCount:      2,
			Count:         3,
			EvaluatedAt:   now,
		},
		topLastHour: []FingerprintEntry{{
			JA4Fingerprint: "t13d1516h2_8daaf6152771_02713d6af862",
			Count:          12,
		}},
	})

	for _, tc := range []struct {
		path string
		code int
	}{
		{path: "/api/fingerprints/frequent-last-hour", code: http.StatusOK},
		{path: "/api/fingerprints/top-last-hour", code: http.StatusOK},
	} {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != tc.code {
				t.Fatalf("unexpected status for %s: %d", tc.path, rec.Code)
			}
		})
	}
}

func TestVerdictFromAssessment(t *testing.T) {
	cases := []struct {
		name       string
		assessment risk.Assessment
		want       string
	}{
		{
			name: "clean",
			assessment: risk.Assessment{
				Score:  20,
				Action: risk.ActionAllow,
			},
			want: "clean",
		},
		{
			name: "suspicious",
			assessment: risk.Assessment{
				Score:  78,
				Action: risk.ActionRateLimit,
			},
			want: "suspicious",
		},
		{
			name: "malicious",
			assessment: risk.Assessment{
				Score:  95,
				Action: risk.ActionBlock,
			},
			want: "malicious",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := verdictFromAssessment(tc.assessment); got != tc.want {
				t.Fatalf("unexpected verdict: got %q want %q", got, tc.want)
			}
		})
	}
}

func TestFingerprintLabelPrefersLookupIdentity(t *testing.T) {
	assessment := &risk.Assessment{
		Summary: risk.FingerprintSummary{
			ApplicationFamily: "chrome",
			OSFamily:          "windows",
		},
		Lookup: &risk.FingerprintRecord{
			Application: "Chrome 120+",
			OS:          "Windows",
		},
	}

	if got := fingerprintLabel(assessment); got != "Chrome 120+ (Windows)" {
		t.Fatalf("unexpected label: %q", got)
	}
}

func newHardenedMux(store Store, opts Options) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterRoutesWithOptions(mux, store, opts)
	return mux
}

func TestCORSAllowlistOnlyEchoesListedOrigins(t *testing.T) {
	const allowed = "https://dash.example"
	mux := newHardenedMux(&fakeStore{}, Options{AllowedOrigins: []string{allowed, "*"}})

	t.Run("allowed origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/stats/total", nil)
		req.Header.Set("Origin", allowed)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected status: %d", rec.Code)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != allowed {
			t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, allowed)
		}
		if got := rec.Header().Get("Vary"); got != "Origin" {
			t.Fatalf("Vary = %q, want Origin", got)
		}
	})

	t.Run("unlisted origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/stats/total", nil)
		req.Header.Set("Origin", "https://evil.example")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected status: %d", rec.Code)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("unlisted origin got CORS header %q", got)
		}
	})

	t.Run("wildcard entry never emitted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/stats/total", nil)
		req.Header.Set("Origin", "https://other.example")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if got := rec.Header().Get("Access-Control-Allow-Origin"); got == "*" {
			t.Fatalf("wildcard CORS header must never be emitted")
		}
	})

	t.Run("preflight", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/stats/total", nil)
		req.Header.Set("Origin", allowed)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("unexpected preflight status: %d", rec.Code)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != allowed {
			t.Fatalf("preflight Access-Control-Allow-Origin = %q, want %q", got, allowed)
		}
	})
}

func TestBearerTokenAuth(t *testing.T) {
	const token = "s3cret-token"
	mux := newHardenedMux(&fakeStore{}, Options{Token: token})

	request := func(t *testing.T, header string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/stats/total", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	t.Run("missing header", func(t *testing.T) {
		rec := request(t, "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
		if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
			t.Fatalf("WWW-Authenticate = %q, want Bearer", got)
		}
		if !strings.Contains(rec.Body.String(), "unauthorized") {
			t.Fatalf("unexpected body: %s", rec.Body.String())
		}
	})

	t.Run("wrong token", func(t *testing.T) {
		if rec := request(t, "Bearer nope"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("correct token", func(t *testing.T) {
		if rec := request(t, "Bearer "+token); rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("case-insensitive scheme", func(t *testing.T) {
		if rec := request(t, "bearer "+token); rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("preflight exempt from auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/stats/total", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", rec.Code)
		}
	})
}

func TestBearerTokenDisabledWhenEmpty(t *testing.T) {
	mux := newHardenedMux(&fakeStore{}, Options{})
	req := httptest.NewRequest(http.MethodGet, "/api/stats/total", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestAPIErrorBodyIsGeneric(t *testing.T) {
	internal := errors.New("redis dial tcp 10.0.0.5:6379: connection refused")
	mux := newHardenedMux(&fakeStore{readErr: internal}, Options{})

	req := httptest.NewRequest(http.MethodGet, "/api/stats/total", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if payload["error"] != "internal error" {
		t.Fatalf("error = %q, want internal error", payload["error"])
	}
	if strings.Contains(rec.Body.String(), "redis") || strings.Contains(rec.Body.String(), "10.0.0.5") {
		t.Fatalf("internal detail leaked in body: %s", rec.Body.String())
	}
}

func TestAPIErrorBodyTimeoutIsGeneric(t *testing.T) {
	mux := newHardenedMux(&fakeStore{readErr: context.DeadlineExceeded}, Options{})

	req := httptest.NewRequest(http.MethodGet, "/api/stats/total", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestTimeout {
		t.Fatalf("status = %d, want 408", rec.Code)
	}
	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if payload["error"] != "request timeout" {
		t.Fatalf("error = %q, want request timeout", payload["error"])
	}
}

func TestAPIErrorIsLoggedButNotEchoed(t *testing.T) {
	// The 500 path must not echo err.Error() the way the old handler did.
	mux := newHardenedMux(&fakeStore{readErr: errors.New("WRITEABLE-SECRET-KEY")}, Options{})
	req := httptest.NewRequest(http.MethodGet, "/api/requests/recent", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), "WRITEABLE-SECRET-KEY") {
		t.Fatalf("raw error leaked: %s", rec.Body.String())
	}
}
