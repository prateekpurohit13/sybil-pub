package fingerprint

import (
	"testing"

	"github.com/sophic00/sybil/internal/parser"
)

func TestBuildJA4FoxIOCanonicalExample(t *testing.T) {
	fields := &parser.ClientHelloFields{
		Protocol:       "t",
		TLSVersion:     0x0304,
		SNIType:        "d",
		FirstALPN:      "h2",
		CipherCount:    15,
		ExtensionCount: 16,
		CipherSuites: []uint16{
			0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
			0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
		},
		Extensions: []uint16{
			0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d,
			0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
		},
		SignatureAlgorithms: []uint16{
			0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
		},
	}

	ja4, err := BuildJA4(fields)
	if err != nil {
		t.Fatalf("BuildJA4: %v", err)
	}

	const want = "t13d1516h2_8daaf6152771_e5627efa2ab1"
	if ja4.Fingerprint != want {
		t.Fatalf("unexpected fingerprint\n got: %s\nwant: %s", ja4.Fingerprint, want)
	}
	if ja4.BlobC != "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601" {
		t.Fatalf("unexpected c blob: %s", ja4.BlobC)
	}
}

func TestNormalizeALPN(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"", "00"},
		{"h2", "h2"},
		{"h3", "h3"},
		{"http/1.1", "h1"},
		{"H2", "h2"},
		{"x", "xx"},
		{"\xab", "ab"},
		{"\xab\xcd", "ad"},
		{"\x20\x61", "21"},
		{"\x30\xab", "3b"},
		{"\x61\x20", "60"},
		{"\x30\x31\xab\xcd", "3d"},
		{"\x30\xab\xcd\x31", "01"},
	}

	for _, tc := range cases {
		if got := normalizeALPN(tc.input); got != tc.want {
			t.Errorf("normalizeALPN(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestBuildJA4_ACountsAndVersions(t *testing.T) {
	cases := []struct {
		name     string
		version  uint16
		ciphers  int
		exts     int
		wantPart string
	}{
		{"tls13", 0x0304, 15, 16, "t13d1516h2"},
		{"tls12", 0x0303, 3, 4, "t12d0304h2"},
		{"tls11", 0x0302, 3, 4, "t11d0304h2"},
		{"tls10", 0x0301, 3, 4, "t10d0304h2"},
		{"ssl3", 0x0300, 3, 4, "ts3d0304h2"},
		{"unknown", 0x1234, 3, 4, "t00d0304h2"},
		{"count clamp", 0x0304, 100, 120, "t13d9999h2"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ja4, err := BuildJA4(&parser.ClientHelloFields{
				Protocol:       "t",
				TLSVersion:     tc.version,
				SNIType:        "d",
				FirstALPN:      "h2",
				CipherCount:    tc.ciphers,
				ExtensionCount: tc.exts,
			})
			if err != nil {
				t.Fatalf("BuildJA4: %v", err)
			}
			if ja4.A != tc.wantPart {
				t.Fatalf("A = %q, want %q", ja4.A, tc.wantPart)
			}
		})
	}
}

func TestBuildJA4EmptyHashes(t *testing.T) {
	ja4, err := BuildJA4(&parser.ClientHelloFields{
		Protocol:   "t",
		TLSVersion: 0x0304,
		SNIType:    "i",
	})
	if err != nil {
		t.Fatalf("BuildJA4: %v", err)
	}

	if ja4.B != emptyHash || ja4.C != emptyHash {
		t.Fatalf("empty lists must use %s, got B=%s C=%s", emptyHash, ja4.B, ja4.C)
	}
	if ja4.Fingerprint != "t13i000000_000000000000_000000000000" {
		t.Fatalf("unexpected fingerprint: %s", ja4.Fingerprint)
	}
}

func TestBuildJA4ExcludesSNIAndALPNFromC(t *testing.T) {
	base := &parser.ClientHelloFields{
		Protocol:            "t",
		TLSVersion:          0x0304,
		SNIType:             "d",
		FirstALPN:           "h2",
		Extensions:          []uint16{0x001b, 0x0000, 0x0010, 0x002b},
		SignatureAlgorithms: []uint16{0x0403},
	}
	withoutTraffic := *base
	withoutTraffic.Extensions = []uint16{0x001b, 0x002b}

	first, err := BuildJA4(base)
	if err != nil {
		t.Fatalf("BuildJA4: %v", err)
	}
	second, err := BuildJA4(&withoutTraffic)
	if err != nil {
		t.Fatalf("BuildJA4: %v", err)
	}
	if first.C != second.C {
		t.Fatalf("SNI/ALPN must not change JA4_c: %s vs %s", first.C, second.C)
	}
}
