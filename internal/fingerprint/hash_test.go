package fingerprint

import (
	"strings"
	"testing"

	"github.com/sophic00/sybil/internal/parser"
)

// foxioCanonicalFields mirrors the worked example in the FoxIO JA4
// specification (technical_details/JA4.md).
func foxioCanonicalFields() *parser.ClientHelloFields {
	return &parser.ClientHelloFields{
		Protocol:       "t",
		TLSVersion:     0x0304,
		SNIType:        "d",
		CipherCount:    15,
		ExtensionCount: 16,
		FirstALPN:      "h2",
		CipherSuites: []uint16{
			0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
			0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
		},
		Extensions: []uint16{
			0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d,
			0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
		},
		SignatureAlgorithms: []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601},
	}
}

// TestBuildJA4FoxIOCanonical checks the full reference vector from
// technical_details/JA4.md, including the underscore delimiter between the
// sorted extension list and the signature algorithms in JA4_c.
func TestBuildJA4FoxIOCanonical(t *testing.T) {
	got, err := BuildJA4(foxioCanonicalFields())
	if err != nil {
		t.Fatalf("BuildJA4: %v", err)
	}

	if got.A != "t13d1516h2" {
		t.Errorf("A = %q, want %q", got.A, "t13d1516h2")
	}
	if got.B != "8daaf6152771" {
		t.Errorf("B = %q, want %q", got.B, "8daaf6152771")
	}
	if got.C != "e5627efa2ab1" {
		t.Errorf("C = %q, want %q", got.C, "e5627efa2ab1")
	}
	if got.Fingerprint != "t13d1516h2_8daaf6152771_e5627efa2ab1" {
		t.Errorf("Fingerprint = %q, want %q", got.Fingerprint, "t13d1516h2_8daaf6152771_e5627efa2ab1")
	}

	wantBlobB := "002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"
	if got.BlobB != wantBlobB {
		t.Errorf("BlobB = %q, want %q", got.BlobB, wantBlobB)
	}

	wantBlobC := "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01" +
		"_0403,0804,0401,0503,0805,0501,0806,0601"
	if got.BlobC != wantBlobC {
		t.Errorf("BlobC = %q, want %q", got.BlobC, wantBlobC)
	}
}

// TestBuildJA4ExtensionsWithoutSignatures checks that the JA4_c input ends
// without a trailing underscore when no signature algorithms are present.
func TestBuildJA4ExtensionsWithoutSignatures(t *testing.T) {
	fields := foxioCanonicalFields()
	fields.SignatureAlgorithms = nil

	got, err := BuildJA4(fields)
	if err != nil {
		t.Fatalf("BuildJA4: %v", err)
	}

	wantBlobC := "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01"
	if got.BlobC != wantBlobC {
		t.Errorf("BlobC = %q, want %q", got.BlobC, wantBlobC)
	}
	if got.C != "6d807ffa2a79" {
		t.Errorf("C = %q, want %q", got.C, "6d807ffa2a79")
	}
	if strings.Contains(got.BlobC, "_") {
		t.Errorf("BlobC = %q, must not contain an underscore without signatures", got.BlobC)
	}
}

// TestBuildJA4EmptyLists checks the literal 000000000000 rule for empty
// cipher and extension lists (never sha256("") = e3b0c44298fc).
func TestBuildJA4EmptyLists(t *testing.T) {
	got, err := BuildJA4(&parser.ClientHelloFields{Protocol: "t", TLSVersion: 0x0303})
	if err != nil {
		t.Fatalf("BuildJA4: %v", err)
	}

	if got.A != "t12i000000" {
		t.Errorf("A = %q, want %q", got.A, "t12i000000")
	}
	if got.B != emptyBlobHash || got.C != emptyBlobHash {
		t.Errorf("B, C = %q, %q; want %q, %q", got.B, got.C, emptyBlobHash, emptyBlobHash)
	}
	if got.BlobB != "" || got.BlobC != "" {
		t.Errorf("BlobB, BlobC = %q, %q; want empty", got.BlobB, got.BlobC)
	}
	if got.Fingerprint != "t12i000000_000000000000_000000000000" {
		t.Errorf("Fingerprint = %q", got.Fingerprint)
	}
	if got.B == "e3b0c44298fc" || got.C == "e3b0c44298fc" {
		t.Error("empty lists must not hash the empty string")
	}
}

// TestBuildJA4GREASEOnlyLists checks that GREASE-only lists collapse to the
// literal empty hash as well.
func TestBuildJA4GREASEOnlyLists(t *testing.T) {
	got, err := BuildJA4(&parser.ClientHelloFields{
		Protocol:   "t",
		TLSVersion: 0x0304,
		CipherSuites: []uint16{
			0x0a0a, 0x1a1a,
		},
		Extensions: []uint16{
			0x0a0a, 0x2a2a, 0x0000, 0x0010,
		},
	})
	if err != nil {
		t.Fatalf("BuildJA4: %v", err)
	}
	if got.BlobB != "" || got.BlobC != "" {
		t.Errorf("BlobB, BlobC = %q, %q; want empty after GREASE/SNI/ALPN filtering", got.BlobB, got.BlobC)
	}
	if got.B != emptyBlobHash || got.C != emptyBlobHash {
		t.Errorf("B, C = %q, %q; want %q, %q", got.B, got.C, emptyBlobHash, emptyBlobHash)
	}
}

// TestBuildJA4EmptyExtensionsWithSignatures pins the spec rule that an empty
// sorted extension list always yields the literal JA4_c value.
func TestBuildJA4EmptyExtensionsWithSignatures(t *testing.T) {
	got, err := BuildJA4(&parser.ClientHelloFields{
		Protocol:            "t",
		TLSVersion:          0x0304,
		SignatureAlgorithms: []uint16{0x0403},
	})
	if err != nil {
		t.Fatalf("BuildJA4: %v", err)
	}
	if got.BlobC != "" || got.C != emptyBlobHash {
		t.Errorf("BlobC, C = %q, %q; want empty, %q", got.BlobC, got.C, emptyBlobHash)
	}
}

// TestBuildJA4GREASEFilteringAndExclusion verifies GREASE stripping plus the
// removal of SNI (0x0000) and ALPN (0x0010) from the JA4_c extension list.
func TestBuildJA4GREASEFilteringAndExclusion(t *testing.T) {
	got, err := BuildJA4(&parser.ClientHelloFields{
		Protocol:            "t",
		TLSVersion:          0x0303,
		SNIType:             "d",
		FirstALPN:           "h2",
		CipherCount:         1,
		ExtensionCount:      3,
		CipherSuites:        []uint16{0x0a0a, 0x1301, 0x1a1a},
		Extensions:          []uint16{0x0a0a, 0x0000, 0x0010, 0x000d, 0x2a2a},
		SignatureAlgorithms: []uint16{0x0403},
	})
	if err != nil {
		t.Fatalf("BuildJA4: %v", err)
	}

	if got.BlobB != "1301" {
		t.Errorf("BlobB = %q, want %q", got.BlobB, "1301")
	}
	if got.BlobC != "000d_0403" {
		t.Errorf("BlobC = %q, want %q", got.BlobC, "000d_0403")
	}
	if got.Fingerprint != "t12d0103h2_0f2cb44170f4_79c50902419d" {
		t.Errorf("Fingerprint = %q, want %q", got.Fingerprint, "t12d0103h2_0f2cb44170f4_79c50902419d")
	}
}

// TestBuildJA4SignatureOrderPreserved checks signature algorithms are hashed
// in wire order, while ciphers and extensions are sorted.
func TestBuildJA4SignatureOrderPreserved(t *testing.T) {
	fields := foxioCanonicalFields()
	fields.SignatureAlgorithms = []uint16{0x0804, 0x0403}

	got, err := BuildJA4(fields)
	if err != nil {
		t.Fatalf("BuildJA4: %v", err)
	}
	if !strings.HasSuffix(got.BlobC, "_0804,0403") {
		t.Errorf("BlobC = %q, want suffix %q (wire order)", got.BlobC, "_0804,0403")
	}
	if strings.HasSuffix(got.BlobC, "_0403,0804") {
		t.Errorf("BlobC = %q, signature algorithms must not be sorted", got.BlobC)
	}
}

func TestNormalizeALPN(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", "00"},
		{"h2", "h2", "h2"},
		{"http/1.1", "http/1.1", "h1"},
		{"single alphanumeric", "x", "xx"},
		{"single non-alphanumeric", "\xab", "ab"},
		{"non-ascii pair", "\xab\xcd", "ad"},
		{"space", "\x20", "20"},
		{"space then alnum", "\x20\x61", "21"},
		{"alnum then non-ascii", "\x30\xab", "3b"},
		{"alnum then space", "\x61\x20", "60"},
		{"non-ascii in middle only", "\x30\x31\xab\xcd", "3d"},
		{"non-ascii in middle only 2", "\x30\xab\xcd\x31", "01"},
		{"preserve case", "H2", "H2"},
		{"nul byte", "\x00", "00"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeALPN(tc.in); got != tc.want {
				t.Errorf("normalizeALPN(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestTLSVersionCode(t *testing.T) {
	cases := map[uint16]string{
		0x0304: "13",
		0x0303: "12",
		0x0302: "11",
		0x0301: "10",
		0x0300: "s3",
		0x0002: "s2",
		0xfeff: "d1",
		0xfefd: "d2",
		0xfefc: "d3",
		0x0000: "00",
		0x0305: "00",
		0x1234: "00",
	}
	for in, want := range cases {
		if got := tlsVersionCode(in); got != want {
			t.Errorf("tlsVersionCode(0x%04x) = %q, want %q", in, got, want)
		}
	}
}

func TestCountFieldClamp(t *testing.T) {
	cases := []struct {
		in   int
		want string
	}{
		{0, "00"},
		{9, "09"},
		{99, "99"},
		{100, "99"},
		{12345, "99"},
		{-1, "00"},
	}
	for _, tc := range cases {
		if got := countField(tc.in); got != tc.want {
			t.Errorf("countField(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}

	got, err := BuildJA4(&parser.ClientHelloFields{
		Protocol:       "t",
		TLSVersion:     0x0304,
		SNIType:        "d",
		FirstALPN:      "h2",
		CipherCount:    150,
		ExtensionCount: 12345,
	})
	if err != nil {
		t.Fatalf("BuildJA4: %v", err)
	}
	if got.A != "t13d9999h2" {
		t.Errorf("A = %q, want %q (counts clamped to 99)", got.A, "t13d9999h2")
	}
}

func TestBuildASNIMarker(t *testing.T) {
	base := parser.ClientHelloFields{
		Protocol:       "t",
		TLSVersion:     0x0304,
		CipherCount:    1,
		ExtensionCount: 1,
	}
	if got := buildA(&base); got != "t13i010100" {
		t.Errorf("no SNI: buildA = %q, want %q", got, "t13i010100")
	}
	base.SNIType = "d"
	if got := buildA(&base); got != "t13d010100" {
		t.Errorf("SNI: buildA = %q, want %q", got, "t13d010100")
	}
	base.SNIType = "bogus"
	if got := buildA(&base); got != "t13i010100" {
		t.Errorf("bogus SNI type: buildA = %q, want %q", got, "t13i010100")
	}
}

func TestHashBlobEmptyLiteral(t *testing.T) {
	if got := hashBlob(""); got != emptyBlobHash {
		t.Errorf("hashBlob(\"\") = %q, want %q", got, emptyBlobHash)
	}
	if got := hashBlob("13"); got != "3fdba35f04dc" {
		t.Errorf("hashBlob(\"13\") = %q, want %q", got, "3fdba35f04dc")
	}
	if got := hash12(""); got != "e3b0c44298fc" {
		t.Errorf("hash12(\"\") = %q, want %q", got, "e3b0c44298fc")
	}
}

// --- parser integration -------------------------------------------------

type testExtension struct {
	id   uint16
	data []byte
}

func buildClientHelloPayload(t *testing.T, version uint16, ciphers []uint16, exts []testExtension) []byte {
	t.Helper()

	body := []byte{byte(version >> 8), byte(version)}
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session id length
	body = append(body, byte(len(ciphers)*2>>8), byte(len(ciphers)*2))
	for _, c := range ciphers {
		body = append(body, byte(c>>8), byte(c))
	}
	body = append(body, 0x01, 0x00) // compression: null

	var extBlock []byte
	for _, e := range exts {
		extBlock = append(extBlock, byte(e.id>>8), byte(e.id), byte(len(e.data)>>8), byte(len(e.data)))
		extBlock = append(extBlock, e.data...)
	}
	body = append(body, byte(len(extBlock)>>8), byte(len(extBlock)))
	body = append(body, extBlock...)

	handshake := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)

	record := []byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}
	return append(record, handshake...)
}

func sniExtension(host string) testExtension {
	h := []byte(host)
	entry := append([]byte{0x00}, byte(len(h)>>8), byte(len(h)))
	entry = append(entry, h...)
	data := append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)
	return testExtension{id: 0x0000, data: data}
}

// TestParseClientHelloSNITypePresence verifies end to end that JA4_a uses
// "d" purely on SNI extension presence. An IPv6 literal is not a plausible
// hostname, yet the extension is present, so the marker must be "d".
func TestParseClientHelloSNITypePresence(t *testing.T) {
	payload := buildClientHelloPayload(t, 0x0303, []uint16{0x1301}, []testExtension{sniExtension("2001:db8::1")})
	fields, err := parser.ParseClientHello(payload)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if fields.SNIType != "d" {
		t.Errorf("SNIType = %q, want %q for present SNI extension", fields.SNIType, "d")
	}
	if fields.SNIHost != "" {
		t.Errorf("SNIHost = %q, want empty for IP-literal hostname", fields.SNIHost)
	}
	got, err := BuildJA4(fields)
	if err != nil {
		t.Fatalf("BuildJA4: %v", err)
	}
	if got.A != "t12d010100" {
		t.Errorf("A = %q, want %q", got.A, "t12d010100")
	}

	payload = buildClientHelloPayload(t, 0x0303, []uint16{0x1301}, nil)
	fields, err = parser.ParseClientHello(payload)
	if err != nil {
		t.Fatalf("ParseClientHello (no SNI): %v", err)
	}
	if fields.SNIType != "i" {
		t.Errorf("SNIType = %q, want %q without SNI extension", fields.SNIType, "i")
	}
	got, err = BuildJA4(fields)
	if err != nil {
		t.Fatalf("BuildJA4 (no SNI): %v", err)
	}
	if got.A != "t12i010000" {
		t.Errorf("A = %q, want %q", got.A, "t12i010000")
	}
}

// TestBuildJA4FromParsedClientHello exercises parser -> BuildJA4 for a
// well-formed handshake with SNI, ALPN, supported_versions and signature
// algorithms.
func TestBuildJA4FromParsedClientHello(t *testing.T) {
	alpnData := []byte{0x00, 0x03, 0x02, 'h', '2'}            // list len 3, "h2"
	supportedVersions := []byte{0x04, 0x03, 0x04, 0x03, 0x03} // TLS 1.3, TLS 1.2
	sigAlgs := []byte{0x00, 0x04, 0x04, 0x03, 0x08, 0x04}     // ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256

	payload := buildClientHelloPayload(t, 0x0303, []uint16{0x1301, 0x002f}, []testExtension{
		sniExtension("example.com"),
		{id: 0x0010, data: alpnData},
		{id: 0x002b, data: supportedVersions},
		{id: 0x000d, data: sigAlgs},
	})
	fields, err := parser.ParseClientHello(payload)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	got, err := BuildJA4(fields)
	if err != nil {
		t.Fatalf("BuildJA4: %v", err)
	}
	if got.A != "t13d0204h2" {
		t.Errorf("A = %q, want %q", got.A, "t13d0204h2")
	}
	if got.BlobB != "002f,1301" {
		t.Errorf("BlobB = %q, want %q", got.BlobB, "002f,1301")
	}
	if got.BlobC != "000d,002b_0403,0804" {
		t.Errorf("BlobC = %q, want %q", got.BlobC, "000d,002b_0403,0804")
	}
}
