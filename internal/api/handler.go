package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"
)

// Options is the access policy applied to the /api routes.
type Options struct {
	// AllowedOrigins is the exact set of browser origins allowed to read
	// /api cross-origin. Empty means same-origin only: no CORS header is
	// emitted. A wildcard entry is ignored rather than honored.
	AllowedOrigins []string
	// Token, when non-empty, requires "Authorization: Bearer <token>" on
	// every /api request. Preflight OPTIONS requests are exempt because
	// browsers do not attach credentials to them.
	Token string
}

// RegisterRoutes installs the read-only /api routes with the hardened
// default policy: same-origin only, no bearer token.
func RegisterRoutes(mux *http.ServeMux, store Store) {
	RegisterRoutesWithOptions(mux, store, Options{})
}

// RegisterRoutesWithOptions installs the read-only /api routes behind a CORS
// allowlist and optional bearer-token authentication.
func RegisterRoutesWithOptions(mux *http.ServeMux, store Store, opts Options) {
	if mux == nil {
		return
	}

	cors := newCORSPolicy(opts.AllowedOrigins)
	routes := []struct {
		path string
		fn   routeFunc
	}{
		{"/api/stats/total", func(r *http.Request) (any, error) {
			return store.TotalStats(r.Context())
		}},
		{"/api/stats/timeseries", func(r *http.Request) (any, error) {
			return store.Timeseries(r.Context(), time.Now())
		}},
		{"/api/requests/recent", func(r *http.Request) (any, error) {
			return store.RecentRequests(r.Context(), defaultRecentLimit)
		}},
		{"/api/requests/top-threats", func(r *http.Request) (any, error) {
			return store.TopThreats(r.Context(), defaultTopLimit, time.Now())
		}},
		{"/api/fingerprints/top-common", func(r *http.Request) (any, error) {
			return store.TopCommonFingerprints(r.Context(), defaultTopLimit)
		}},
		{"/api/fingerprints/frequent-last-hour", func(r *http.Request) (any, error) {
			return store.FrequentFingerprintsLastHour(r.Context(), time.Now(), 2)
		}},
		{"/api/fingerprints/top-last-hour", func(r *http.Request) (any, error) {
			return store.TopFingerprintsLastHour(r.Context(), time.Now(), 10)
		}},
	}
	for _, route := range routes {
		mux.Handle(route.path, guard(cors, opts.Token, apiHandler(store, route.fn)))
	}
}

type routeFunc func(r *http.Request) (any, error)

// guard applies the CORS policy first (so browsers can read error statuses)
// and then bearer-token authentication.
func guard(cors corsPolicy, token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cors.apply(w, r)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if !authorized(r, token) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func apiHandler(store Store, fn routeFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if store == nil {
			writeError(w, http.StatusServiceUnavailable, "api store unavailable")
			return
		}

		payload, err := fn(r)
		if err != nil {
			status := http.StatusInternalServerError
			message := "internal error"
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				status = http.StatusRequestTimeout
				message = "request timeout"
			}
			// Log the detail server-side (Redis key names, addresses) and
			// return a generic body so internals do not leak to the caller.
			log.Printf("api %s: %v", r.URL.Path, err)
			writeError(w, status, message)
			return
		}
		writeJSON(w, http.StatusOK, payload)
	})
}

// authorized performs a constant-time bearer-token check. An empty configured
// token disables authentication.
func authorized(r *http.Request, token string) bool {
	if token == "" {
		return true
	}
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return false
	}
	provided := strings.TrimSpace(header[len(prefix):])
	return subtle.ConstantTimeCompare([]byte(provided), []byte(token)) == 1
}

// corsPolicy is an exact-match origin allowlist.
type corsPolicy struct {
	origins map[string]struct{}
}

func newCORSPolicy(origins []string) corsPolicy {
	set := make(map[string]struct{}, len(origins))
	for _, origin := range origins {
		origin = strings.TrimSpace(origin)
		if origin == "" || origin == "*" {
			continue
		}
		set[origin] = struct{}{}
	}
	return corsPolicy{origins: set}
}

// apply echoes the request origin only when it is explicitly allowed. It never
// emits a wildcard, and Vary: Origin keeps caches from serving one origin's
// response to another.
func (c corsPolicy) apply(w http.ResponseWriter, r *http.Request) {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return
	}
	w.Header().Add("Vary", "Origin")
	if _, ok := c.origins[origin]; !ok {
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
