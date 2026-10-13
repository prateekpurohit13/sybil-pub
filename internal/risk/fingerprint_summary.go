package risk

import "strings"

type FingerprintSummary struct {
	IdentityClass     string
	ReputationState   string
	ApplicationFamily string
	LibraryFamily     string
	OSFamily          string
	DeviceClass       string
}

func SummarizeFingerprint(record *FingerprintRecord, lookupErr error, lookupEnabled bool) FingerprintSummary {
	if lookupErr != nil {
		return FingerprintSummary{
			IdentityClass:     "unknown",
			ReputationState:   "lookup_error",
			ApplicationFamily: "unknown",
			LibraryFamily:     "unknown",
			OSFamily:          "unknown",
			DeviceClass:       "unknown",
		}
	}
	if !lookupEnabled {
		return FingerprintSummary{
			IdentityClass:     "unknown",
			ReputationState:   "lookup_disabled",
			ApplicationFamily: "unknown",
			LibraryFamily:     "unknown",
			OSFamily:          "unknown",
			DeviceClass:       "unknown",
		}
	}
	if record == nil {
		return FingerprintSummary{
			IdentityClass:     "unknown",
			ReputationState:   "unknown",
			ApplicationFamily: "unknown",
			LibraryFamily:     "unknown",
			OSFamily:          "unknown",
			DeviceClass:       "unknown",
		}
	}

	app := strings.ToLower(strings.TrimSpace(record.Application))
	lib := strings.ToLower(strings.TrimSpace(record.Library))
	device := strings.ToLower(strings.TrimSpace(record.Device))
	osName := strings.ToLower(strings.TrimSpace(record.OS))
	ua := strings.ToLower(strings.TrimSpace(record.UserAgentString))
	notes := strings.ToLower(strings.TrimSpace(record.Notes))

	summary := FingerprintSummary{
		ApplicationFamily: classifyApplicationFamily(app, ua, notes),
		LibraryFamily:     classifyLibraryFamily(lib, ua),
		OSFamily:          classifyOSFamily(osName, ua),
		DeviceClass:       classifyDeviceClass(device, ua),
		ReputationState:   "known_unverified",
		IdentityClass:     "known_unverified",
	}

	if record.Verified {
		summary.ReputationState = "verified"
		summary.IdentityClass = "verified_known"
	}

	// Identity precedence, highest first. Exactly one branch wins, so the
	// result no longer depends on the order of independent if statements:
	//
	//   malware_like > automation > vpn > mobile_app >
	//   verified_browser/browser > verified_known/known_unverified
	//
	// malware_like wins outright: known C2/loader fingerprints must never be
	// softened by another signal. automation outranks browser because a
	// curated client signature (curl, python-requests, Go-http-client, ...)
	// is stronger evidence than a browser-like app/UA value; conversely a
	// browser no longer becomes automation just because its name or TLS
	// library contains a short token such as "go". vpn sits below automation
	// (a VPN tunnel is not scripted traffic) but above plain mobile/browser.
	// mobile_app is checked before browser to preserve the existing handling
	// of mobile browsers/runtimes. verified_status only chooses between the
	// browser/known variants; it never overrides a stronger signal.
	switch {
	case isMalwareLike(app, notes):
		summary.IdentityClass = "malware_like"
		summary.ReputationState = "suspicious"
	case isAutomation(app, lib, ua):
		summary.IdentityClass = "automation"
	case isVPN(app, notes):
		summary.IdentityClass = "vpn"
	case isMobileApp(summary.DeviceClass, app, ua):
		summary.IdentityClass = "mobile_app"
	case isBrowser(app, ua):
		if record.Verified {
			summary.IdentityClass = "verified_browser"
		} else {
			summary.IdentityClass = "browser"
		}
	}

	return summary
}

func classifyApplicationFamily(app, ua, notes string) string {
	switch {
	case containsAny(app, "chrome", "chromium") || containsAny(ua, "chrome/", "chromium"):
		return "chrome"
	case containsAny(app, "firefox") || containsAny(ua, "firefox/"):
		return "firefox"
	case containsAny(app, "safari") || containsAny(ua, "safari/"):
		return "safari"
	case containsAny(app, "edge") || containsAny(ua, "edg/"):
		return "edge"
	case containsAny(app, "curl") || containsAny(ua, "curl/"):
		return "curl"
	case containsAny(app, "python") || containsAny(ua, "python", "requests"):
		return "python"
	case containsWord(app, "go") || containsAny(app, "golang") || containsAny(ua, "go-http-client"):
		return "go"
	case containsWord(app, "java") || containsAny(app, "okhttp", "jdk", "jre") ||
		containsWord(ua, "java") || containsAny(ua, "okhttp"):
		return "java"
	case containsAny(app, "node") || containsAny(ua, "node", "axios"):
		return "node"
	case containsAny(app, "powershell", "wget"):
		return "cli"
	case containsAny(app, "vpn", "wireguard", "openvpn") || containsAny(notes, "vpn"):
		return "vpn"
	case containsAny(app, "android", "ios"):
		return "mobile"
	case app == "":
		return "unknown"
	default:
		return "other"
	}
}

func classifyLibraryFamily(lib, ua string) string {
	switch {
	case containsAny(lib, "boringssl"):
		return "boringssl"
	case containsAny(lib, "openssl"):
		return "openssl"
	case containsAny(lib, "schannel"):
		return "schannel"
	case containsAny(lib, "nss"):
		return "nss"
	case containsAny(lib, "rustls"):
		return "rustls"
	case containsWord(lib, "go") || containsAny(lib, "golang") || containsAny(ua, "go-http-client"):
		return "go_tls"
	case containsWord(lib, "java") || containsAny(lib, "okhttp", "jdk", "jre") ||
		containsWord(ua, "java") || containsAny(ua, "okhttp"):
		return "java_tls"
	case lib == "":
		return "unknown"
	default:
		return "other"
	}
}

func classifyOSFamily(osName, ua string) string {
	switch {
	case containsAny(osName, "windows") || containsAny(ua, "windows"):
		return "windows"
	case containsAny(osName, "mac", "darwin") || containsAny(ua, "mac os x"):
		return "macos"
	case containsAny(osName, "linux") || containsAny(ua, "linux"):
		return "linux"
	case containsAny(osName, "ios") || containsAny(ua, "iphone", "ipad", "ios"):
		return "ios"
	case containsAny(osName, "android") || containsAny(ua, "android"):
		return "android"
	case osName == "":
		return "unknown"
	default:
		return "other"
	}
}

func classifyDeviceClass(device, ua string) string {
	switch {
	case containsAny(device, "mobile", "phone", "tablet") || containsAny(ua, "mobile"):
		return "mobile"
	case containsAny(device, "desktop", "laptop"):
		return "desktop"
	case containsAny(device, "server", "vm"):
		return "server"
	case containsAny(device, "iot", "printer", "embedded"):
		return "embedded"
	case device == "":
		return "unknown"
	default:
		return "other"
	}
}

func isBrowser(app, ua string) bool {
	return containsAny(app, "chrome", "chromium", "firefox", "safari", "edge", "opera") ||
		containsAny(ua, "chrome/", "firefox/", "safari/", "edg/", "opr/")
}

// isAutomation reports whether the record describes a scripted HTTP client
// rather than a human-driven application.
//
// Short, ambiguous tokens are matched on word boundaries: "go" must not match
// "Google Chrome", "golang", or "Django", and "java" must not match
// "Javascript"/"JavaScriptCore". Distinctive client names ("curl",
// "python", "okhttp", ...) keep substring matching so variants such as
// "python-requests" and "libcurl" still match.
//
// Generic TLS stacks (OpenSSL, BoringSSL, rustls, Schannel, NSS) are
// deliberately NOT automation evidence: browsers and scripted clients share
// them, so a browser fingerprint linked against OpenSSL/BoringSSL/rustls must
// stay a browser. True automation that uses those stacks is already
// identified through its application/UA (curl, python-requests, ...).
func isAutomation(app, lib, ua string) bool {
	return containsAny(app, "curl", "wget", "python", "requests", "httpx", "okhttp", "node", "golang", "powershell", "bot", "aiohttp", "scrapy", "libwww") ||
		containsWord(app, "go", "java", "jdk", "jre") ||
		containsAny(lib, "curl", "wget", "python", "requests", "httpx", "okhttp", "golang", "aiohttp") ||
		containsWord(lib, "go", "java", "jdk", "jre") ||
		containsAny(ua, "curl/", "python", "go-http-client", "okhttp", "axios", "wget", "powershell", "aiohttp", "scrapy", "libwww") ||
		containsWord(ua, "java", "jdk", "jre")
}

func isVPN(app, notes string) bool {
	return containsAny(app, "vpn", "wireguard", "openvpn", "tailscale", "surfshark", "nordvpn", "softether") ||
		containsAny(notes, "vpn", "proxy")
}

func isMobileApp(deviceClass, app, ua string) bool {
	return deviceClass == "mobile" || containsAny(app, "android", "ios") || containsAny(ua, "cfnetwork", "dalvik")
}

func isMalwareLike(app, notes string) bool {
	return containsAny(app, "malware", "cobalt strike", "sliver", "icedid", "qakbot", "pikabot", "darkgate", "lumma", "evilginx") ||
		containsAny(notes, "malware", "dropper", "c2", "beacon")
}

func containsAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if candidate != "" && strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}

// containsWord reports whether value contains candidate delimited by
// non-alphanumeric characters (or the string boundaries). Inputs are expected
// to be lower-cased already. Unlike containsAny it prevents "go" from
// matching "Google" and "java" from matching "Javascript".
func containsWord(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		from := 0
		for {
			idx := strings.Index(value[from:], candidate)
			if idx < 0 {
				break
			}
			start := from + idx
			end := start + len(candidate)
			leadingOK := start == 0 || !isTokenByte(candidate[0]) || !isTokenByte(value[start-1])
			trailingOK := end == len(value) || !isTokenByte(candidate[len(candidate)-1]) || !isTokenByte(value[end])
			if leadingOK && trailingOK {
				return true
			}
			from = start + 1
		}
	}
	return false
}

// isTokenByte reports whether b can be part of an alphanumeric word token.
// Inputs are already lower-cased, so only lower-case letters and digits count.
func isTokenByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}
