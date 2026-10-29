package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/sophic00/sybil/internal/parser"
)

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
func BuildJA4(fields *parser.ClientHelloFields) (JA4, error) {
	if fields == nil {
		return JA4{}, fmt.Errorf("nil clienthello fields")
	}

	a := buildA(fields)

	ciphers := copySlice(fields.CipherSuites)
	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })
	blobB := buildHexBlob(ciphers)
	b := emptyHash
	if blobB != "" {
		b = hash12(blobB)
	}

	ext := make([]uint16, 0, len(fields.Extensions))
	for _, e := range fields.Extensions {
		if isGREASEValue(e) || e == 0x0000 || e == 0x0010 {
			continue
		}
		ext = append(ext, e)
	}
	sort.Slice(ext, func(i, j int) bool { return ext[i] < ext[j] })

	sigs := copySlice(fields.SignatureAlgorithms)
	// Keep signature algorithms in wire order (no sorting).

	extBlob := buildHexBlob(ext)
	sigBlob := buildHexBlob(sigs)
	blobC := extBlob
	if extBlob != "" && sigBlob != "" {
		blobC = extBlob + "_" + sigBlob
	}
	c := emptyHash
	if extBlob != "" {
		c = hash12(blobC)
	}

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

	alpn := normalizeALPN(fields.FirstALPN)

	return fmt.Sprintf("%s%s%s%02d%02d%s", proto, tlsVersionTag(fields.TLSVersion), sniType,
		clampCount(fields.CipherCount), clampCount(fields.ExtensionCount), alpn)
}

const emptyHash = "000000000000"

func tlsVersionTag(version uint16) string {
	switch version {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	default:
		return "00"
	}
}

func clampCount(count int) int {
	if count < 0 {
		return 0
	}
	if count > 99 {
		return 99
	}
	return count
}

// normalizeALPN returns the first and last character of the first ALPN value.
// Non-alphanumeric edges use the first and last character of the hex encoding,
// matching the FoxIO JA4 specification.
func normalizeALPN(alpn string) string {
	if alpn == "" {
		return "00"
	}

	raw := []byte(alpn)
	first := raw[0]
	last := raw[len(raw)-1]
	if isASCIIAlnum(first) && isASCIIAlnum(last) {
		return strings.ToLower(string([]byte{first, last}))
	}

	encoded := hex.EncodeToString(raw)
	return string([]byte{encoded[0], encoded[len(encoded)-1]})
}

func isASCIIAlnum(value byte) bool {
	return (value >= '0' && value <= '9') ||
		(value >= 'A' && value <= 'Z') ||
		(value >= 'a' && value <= 'z')
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

func hash12(input string) string {
	sum := sha256.Sum256([]byte(input))
	hexStr := hex.EncodeToString(sum[:])
	if len(hexStr) < 12 {
		return hexStr
	}
	return hexStr[:12]
}

func copySlice(in []uint16) []uint16 {
	out := make([]uint16, len(in))
	copy(out, in)
	return out
}

func isGREASEValue(v uint16) bool {
	if (v & 0x0F0F) != 0x0A0A {
		return false
	}
	return (v >> 8) == (v & 0xFF)
}
