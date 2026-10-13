package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/sophic00/sybil/internal/parser"
)

// emptyBlobHash is the literal JA4_b / JA4_c value used when the hashed
// input list is empty, per the FoxIO JA4 specification. The reference
// explicitly avoids a sha256("") of e3b0c44298fc for these fields.
const emptyBlobHash = "000000000000"

// JA4 represents the three JA4 parts and the combined fingerprint string.
type JA4 struct {
	A string
	B string
	C string

	Fingerprint string

	// Useful for debugging and test validation.
	BlobB string
	BlobC string
}

// BuildJA4 constructs JA4 fingerprint parts from parsed ClientHello fields.
//
// It follows the FoxIO JA4 specification:
//   - JA4_b is the truncated SHA-256 of the GREASE-filtered cipher suites
//     sorted in hex order, comma delimited.
//   - JA4_c is the truncated SHA-256 of the GREASE-filtered extension list
//     (sorted, with SNI and ALPN removed), followed by the signature
//     algorithms in wire order; the two lists are delimited by an
//     underscore.
//   - Empty cipher and empty extension lists hash to the literal
//     "000000000000" instead of a hash of the empty string.
func BuildJA4(fields *parser.ClientHelloFields) (JA4, error) {
	if fields == nil {
		return JA4{}, fmt.Errorf("nil clienthello fields")
	}

	a := buildA(fields)

	ciphers := make([]uint16, 0, len(fields.CipherSuites))
	for _, c := range fields.CipherSuites {
		if !isGREASEValue(c) {
			ciphers = append(ciphers, c)
		}
	}
	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })
	blobB := buildHexBlob(ciphers)
	b := hashBlob(blobB)

	ext := make([]uint16, 0, len(fields.Extensions))
	for _, e := range fields.Extensions {
		if isGREASEValue(e) || e == 0x0000 || e == 0x0010 {
			continue
		}
		ext = append(ext, e)
	}
	sort.Slice(ext, func(i, j int) bool { return ext[i] < ext[j] })

	sigs := make([]uint16, 0, len(fields.SignatureAlgorithms))
	for _, s := range fields.SignatureAlgorithms {
		if !isGREASEValue(s) {
			sigs = append(sigs, s)
		}
	}
	// Keep signature algorithms in wire order (no sorting), per spec.

	extBlob := buildHexBlob(ext)
	sigBlob := buildHexBlob(sigs)

	blobC := extBlob
	if extBlob == "" {
		// Spec: if there are no extensions in the sorted list, JA4_c is
		// the literal empty hash (regardless of any signature algorithms).
		blobC = ""
	} else if sigBlob != "" {
		// Sorted extensions and signature algorithms are delimited by an
		// underscore in the JA4_c hash input.
		blobC = extBlob + "_" + sigBlob
	}
	c := hashBlob(blobC)

	return JA4{
		A:           a,
		B:           b,
		C:           c,
		Fingerprint: a + "_" + b + "_" + c,
		BlobB:       blobB,
		BlobC:       blobC,
	}, nil
}

func buildA(fields *parser.ClientHelloFields) string {
	proto := fields.Protocol
	if proto == "" {
		proto = "t"
	}

	sniType := fields.SNIType
	if sniType != "d" {
		sniType = "i"
	}

	return proto +
		tlsVersionCode(fields.TLSVersion) +
		sniType +
		countField(fields.CipherCount) +
		countField(fields.ExtensionCount) +
		normalizeALPN(fields.FirstALPN)
}

// tlsVersionCode maps the effective ClientHello version to the JA4_a
// two-character code from the FoxIO specification.
func tlsVersionCode(v uint16) string {
	switch v {
	case 0x0304:
		return "13" // TLS 1.3
	case 0x0303:
		return "12" // TLS 1.2
	case 0x0302:
		return "11" // TLS 1.1
	case 0x0301:
		return "10" // TLS 1.0
	case 0x0300:
		return "s3" // SSL 3.0
	case 0x0002:
		return "s2" // SSL 2.0
	case 0xfeff:
		return "d1" // DTLS 1.0
	case 0xfefd:
		return "d2" // DTLS 1.2
	case 0xfefc:
		return "d3" // DTLS 1.3
	default:
		return "00"
	}
}

// countField renders the two-character count fields. Per spec the value is
// clamped to 99 so JA4_a keeps its fixed-width layout.
func countField(n int) string {
	if n < 0 {
		n = 0
	}
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}

// normalizeALPN encodes the first ALPN value for JA4_a:
//   - no/empty value => "00"
//   - otherwise the first and last ASCII alphanumeric characters
//     (a single character is used as both)
//   - if either end byte is not ASCII alphanumeric, the first and last
//     characters of the hex representation of the whole value instead.
func normalizeALPN(s string) string {
	if s == "" {
		return "00"
	}
	b := []byte(s)
	first, last := b[0], b[len(b)-1]
	if isASCIIAlphanumeric(first) && isASCIIAlphanumeric(last) {
		return string([]byte{first, last})
	}
	hexStr := hex.EncodeToString(b)
	return string([]byte{hexStr[0], hexStr[len(hexStr)-1]})
}

func isASCIIAlphanumeric(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
}

func buildHexBlob(values []uint16) string {
	if len(values) == 0 {
		return ""
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, fmt.Sprintf("%04x", v))
	}
	return strings.Join(out, ",")
}

// hashBlob returns the literal empty hash for an empty blob, otherwise the
// first 12 hex characters of its SHA-256 digest.
func hashBlob(input string) string {
	if input == "" {
		return emptyBlobHash
	}
	return hash12(input)
}

func hash12(input string) string {
	sum := sha256.Sum256([]byte(input))
	hexStr := hex.EncodeToString(sum[:])
	if len(hexStr) < 12 {
		return hexStr
	}
	return hexStr[:12]
}

func isGREASEValue(v uint16) bool {
	if (v & 0x0F0F) != 0x0A0A {
		return false
	}
	return (v >> 8) == (v & 0xFF)
}
