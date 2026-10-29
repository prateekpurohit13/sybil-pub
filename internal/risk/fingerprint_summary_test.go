package risk

import (
	"errors"
	"testing"
)

// TestSummarizeFingerprintIdentity guards the identity precedence and the
// token-boundary matching that keeps real browsers (e.g. "Google Chrome")
// from being mislabeled as automation because of short substrings such as
// "go" or "java".
func TestSummarizeFingerprintIdentity(t *testing.T) {
	const (
		chromeWinUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
		chromeLinUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
		chromeMobUA = "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
		safariUA    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
		firefoxUA   = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
	)

	tests := []struct {
		name           string
		record         *FingerprintRecord
		wantIdentity   string
		wantReputation string
		wantAppFamily  string
		wantLibFamily  string
	}{
		{
			name: "verified Google Chrome with BoringSSL stays verified browser",
			record: &FingerprintRecord{
				Application: "Google Chrome", Library: "BoringSSL", OS: "Windows",
				Device: "Desktop", UserAgentString: chromeWinUA, Verified: true,
			},
			wantIdentity: "verified_browser", wantReputation: "verified",
			wantAppFamily: "chrome", wantLibFamily: "boringssl",
		},
		{
			name: "verified Google Chrome linked against OpenSSL stays verified browser",
			record: &FingerprintRecord{
				Application: "Google Chrome", Library: "OpenSSL", OS: "Linux",
				Device: "Desktop", UserAgentString: chromeLinUA, Verified: true,
			},
			wantIdentity: "verified_browser", wantReputation: "verified",
			wantAppFamily: "chrome", wantLibFamily: "openssl",
		},
		{
			name: "unverified Chrome is a browser, not automation",
			record: &FingerprintRecord{
				Application: "Chrome", Library: "BoringSSL", OS: "Windows",
				Device: "Desktop", UserAgentString: chromeWinUA,
			},
			wantIdentity: "browser", wantReputation: "known_unverified",
			wantAppFamily: "chrome", wantLibFamily: "boringssl",
		},
		{
			name: "Firefox with NSS stays verified browser",
			record: &FingerprintRecord{
				Application: "Firefox", Library: "NSS", OS: "Linux",
				Device: "Desktop", UserAgentString: firefoxUA, Verified: true,
			},
			wantIdentity: "verified_browser", wantReputation: "verified",
			wantAppFamily: "firefox", wantLibFamily: "nss",
		},
		{
			name: "Safari with JavaScriptCore library is not java automation",
			record: &FingerprintRecord{
				Application: "Safari", Library: "JavaScriptCore", OS: "macOS",
				Device: "Desktop", UserAgentString: safariUA, Verified: true,
			},
			wantIdentity: "verified_browser", wantReputation: "verified",
			wantAppFamily: "safari", wantLibFamily: "other",
		},
		{
			name: "Javascript application is not java automation",
			record: &FingerprintRecord{
				Application: "Javascript", Library: "JavaScriptCore", UserAgentString: "",
			},
			wantIdentity: "known_unverified", wantReputation: "known_unverified",
			wantAppFamily: "other", wantLibFamily: "other",
		},
		{
			name: "Google application is not go automation",
			record: &FingerprintRecord{
				Application: "Google", Device: "Desktop", OS: "Linux",
			},
			wantIdentity: "known_unverified", wantReputation: "known_unverified",
			wantAppFamily: "other", wantLibFamily: "unknown",
		},
		{
			name: "curl with OpenSSL is automation",
			record: &FingerprintRecord{
				Application: "curl", Library: "OpenSSL", Device: "Server",
				OS: "Linux", UserAgentString: "curl/8.4.0",
			},
			wantIdentity: "automation", wantReputation: "known_unverified",
			wantAppFamily: "curl", wantLibFamily: "openssl",
		},
		{
			name: "python-requests is automation",
			record: &FingerprintRecord{
				Application: "python-requests", Library: "OpenSSL", Device: "Server",
				OS: "Linux", UserAgentString: "python-requests/2.31.0",
			},
			wantIdentity: "automation", wantReputation: "known_unverified",
			wantAppFamily: "python", wantLibFamily: "openssl",
		},
		{
			name: "Go-http-client is automation",
			record: &FingerprintRecord{
				Application: "Go-http-client", Library: "Go", Device: "Server",
				OS: "Linux", UserAgentString: "Go-http-client/1.1",
			},
			wantIdentity: "automation", wantReputation: "known_unverified",
			wantAppFamily: "go", wantLibFamily: "go_tls",
		},
		{
			name: "Java client is automation",
			record: &FingerprintRecord{
				Application: "Java/17.0.9", Library: "Java", UserAgentString: "Java/17.0.9",
			},
			wantIdentity: "automation", wantReputation: "known_unverified",
			wantAppFamily: "java", wantLibFamily: "java_tls",
		},
		{
			name: "OkHttp library alone is automation",
			record: &FingerprintRecord{
				Application: "okhttp", Library: "OkHttp",
			},
			wantIdentity: "automation", wantReputation: "known_unverified",
			wantAppFamily: "java", wantLibFamily: "java_tls",
		},
		{
			name: "curl UA outranks a browser-like application value",
			record: &FingerprintRecord{
				Application: "Google Chrome", UserAgentString: "curl/8.4.0",
			},
			wantIdentity: "automation", wantReputation: "known_unverified",
			wantAppFamily: "chrome", wantLibFamily: "unknown",
		},
		{
			name: "rustls library alone is not automation evidence",
			record: &FingerprintRecord{
				Application: "", Library: "rustls",
			},
			wantIdentity: "known_unverified", wantReputation: "known_unverified",
			wantAppFamily: "unknown", wantLibFamily: "rustls",
		},
		{
			name: "OpenSSL library alone is not automation evidence",
			record: &FingerprintRecord{
				Application: "", Library: "OpenSSL",
			},
			wantIdentity: "known_unverified", wantReputation: "known_unverified",
			wantAppFamily: "unknown", wantLibFamily: "openssl",
		},
		{
			name: "WireGuard is vpn",
			record: &FingerprintRecord{
				Application: "WireGuard", Device: "Desktop", OS: "Linux",
			},
			wantIdentity: "vpn", wantReputation: "known_unverified",
			wantAppFamily: "vpn", wantLibFamily: "unknown",
		},
		{
			name: "mobile browser is classified as mobile app",
			record: &FingerprintRecord{
				Application: "Chrome Mobile", Device: "Mobile", OS: "Android",
				UserAgentString: chromeMobUA,
			},
			wantIdentity: "mobile_app", wantReputation: "known_unverified",
			wantAppFamily: "chrome", wantLibFamily: "unknown",
		},
		{
			name: "malware_like outranks automation",
			record: &FingerprintRecord{
				Application: "curl", UserAgentString: "curl/8.4.0",
				Notes: "C2 beacon observed",
			},
			wantIdentity: "malware_like", wantReputation: "suspicious",
			wantAppFamily: "curl", wantLibFamily: "unknown",
		},
		{
			name: "automation outranks vpn",
			record: &FingerprintRecord{
				Application: "WireGuard", Library: "Go",
			},
			wantIdentity: "automation", wantReputation: "known_unverified",
			wantAppFamily: "vpn", wantLibFamily: "go_tls",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SummarizeFingerprint(tt.record, nil, true)
			if got.IdentityClass != tt.wantIdentity {
				t.Errorf("IdentityClass = %q, want %q", got.IdentityClass, tt.wantIdentity)
			}
			if got.ReputationState != tt.wantReputation {
				t.Errorf("ReputationState = %q, want %q", got.ReputationState, tt.wantReputation)
			}
			if got.ApplicationFamily != tt.wantAppFamily {
				t.Errorf("ApplicationFamily = %q, want %q", got.ApplicationFamily, tt.wantAppFamily)
			}
			if got.LibraryFamily != tt.wantLibFamily {
				t.Errorf("LibraryFamily = %q, want %q", got.LibraryFamily, tt.wantLibFamily)
			}
		})
	}
}

func TestSummarizeFingerprintLookupFallbacks(t *testing.T) {
	record := &FingerprintRecord{Application: "Google Chrome", Library: "BoringSSL"}

	got := SummarizeFingerprint(record, errors.New("lookup boom"), true)
	if got.IdentityClass != "unknown" || got.ReputationState != "lookup_error" {
		t.Fatalf("lookup error summary = %+v, want unknown/lookup_error", got)
	}

	got = SummarizeFingerprint(record, nil, false)
	if got.IdentityClass != "unknown" || got.ReputationState != "lookup_disabled" {
		t.Fatalf("lookup disabled summary = %+v, want unknown/lookup_disabled", got)
	}

	got = SummarizeFingerprint(nil, nil, true)
	if got.IdentityClass != "unknown" || got.ReputationState != "unknown" {
		t.Fatalf("nil record summary = %+v, want unknown/unknown", got)
	}
}

func TestContainsWord(t *testing.T) {
	tests := []struct {
		value     string
		candidate string
		want      bool
	}{
		{"google chrome", "go", false},
		{"google", "go", false},
		{"django", "go", false},
		{"go", "go", true},
		{"go-http-client/1.1", "go", true},
		{"big go client", "go", true},
		{"javascript", "java", false},
		{"javascriptcore", "java", false},
		{"java/17.0.9", "java", true},
		{"openjdk", "jdk", false},
		{"okhttp", "http", false},
	}
	for _, tt := range tests {
		if got := containsWord(tt.value, tt.candidate); got != tt.want {
			t.Errorf("containsWord(%q, %q) = %t, want %t", tt.value, tt.candidate, got, tt.want)
		}
	}
}

// TestVerifiedChromeReputationScore is the regression test for the reported
// bug: "Google Chrome" was classified as automation (scoreRatio 0.55) and
// scored 8 of 15 reputation points instead of 0 as a verified browser.
func TestVerifiedChromeReputationScore(t *testing.T) {
	record := &FingerprintRecord{
		Application:     "Google Chrome",
		Library:         "BoringSSL",
		OS:              "Windows",
		Device:          "Desktop",
		UserAgentString: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		Verified:        true,
	}
	summary := SummarizeFingerprint(record, nil, true)
	if summary.IdentityClass != "verified_browser" {
		t.Fatalf("IdentityClass = %q, want verified_browser", summary.IdentityClass)
	}

	component := scoreReputation(summary, record, nil, true, DefaultConfig())
	if component.Score != 0 {
		t.Fatalf("reputation component = %+v, want score 0", component)
	}
}
