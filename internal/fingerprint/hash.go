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
	b := hash12(blobB)

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
		blobC = extBlob + "," + sigBlob
	} else if sigBlob != "" {
		blobC = sigBlob
	}
	c := hash12(blobC)

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

	version := "00"
	switch fields.TLSVersion {
	case 0x0303:
		version = "12"
	case 0x0304:
		version = "13"
	}

	sniType := fields.SNIType
	if sniType != "d" {
		sniType = "i"
	}

	alpn := normalizeALPN(fields.FirstALPN)

	return fmt.Sprintf("%s%s%s%02d%02d%s", proto, version, sniType, fields.CipherCount, fields.ExtensionCount, alpn)
}

func normalizeALPN(s string) string {
	if s == "" {
		return "00"
	}
	v := strings.ToLower(s)
	if len(v) >= 2 {
		return v[:2]
	}
	return v + "0"
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
