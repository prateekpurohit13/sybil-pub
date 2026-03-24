package parser

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/cryptobyte"
)

// ClientHelloFields contains the parsed values needed for your TLS
// fingerprinting pipeline. This parser only extracts fields; it does not hash.
type ClientHelloFields struct {
	Protocol string // "t" for TCP in the current pipeline

	// TLS versions:
	// RecordVersion: TLS record-layer version from the outer wrapper.
	// HelloVersion: legacy_version inside ClientHello.
	// TLSVersion: effective client capability, prefers ext 43 if present.
	RecordVersion uint16
	HelloVersion  uint16
	TLSVersion    uint16

	// SNI metadata:
	// SNIType is "d" when hostname exists, else "i".
	SNIType string
	SNIHost string

	// ALPN metadata: first protocol string from ext 16, empty if absent.
	FirstALPN string

	// GREASE-filtered lists used by later stages.
	CipherSuites        []uint16
	Extensions          []uint16
	SignatureAlgorithms []uint16

	CipherCount    int
	ExtensionCount int
}

// isGREASEValue checks whether val is an RFC 8701 GREASE value.
func isGREASEValue(val uint16) bool {
	if (val & 0x0F0F) != 0x0A0A {
		return false
	}
	return (val >> 8) == (val & 0xFF)
}

// ParseClientHello parses a single TLS record containing a ClientHello and
// returns the field values required by your next stages.
func ParseClientHello(payload []byte) (*ClientHelloFields, error) {
	if len(payload) < 5 {
		return nil, errors.New("payload too short for tls record")
	}

	input := cryptobyte.String(payload)
	info := &ClientHelloFields{
		Protocol: "t",
		SNIType:  "i", // default: no valid hostname in SNI
	}

	// 1) TLS record header
	var recordType uint8
	var recordVersion uint16
	var recordLen uint16
	if !input.ReadUint8(&recordType) || !input.ReadUint16(&recordVersion) || !input.ReadUint16(&recordLen) {
		return nil, errors.New("incomplete tls record header")
	}
	info.RecordVersion = recordVersion

	if recordType != 0x16 {
		return nil, errors.New("packet is not a handshake record")
	}

	if int(recordLen) > len(payload)-5 {
		return nil, errors.New("tls record length exceeds payload")
	}

	// Handshake bytes (inside this TLS record)
	if len(input) < int(recordLen) {
		return nil, errors.New("handshake payload truncated")
	}
	handshakeData := input[:recordLen]

	// 2) Handshake header
	var msgType uint8
	if !handshakeData.ReadUint8(&msgType) {
		return nil, errors.New("missing handshake type")
	}
	if msgType != 0x01 {
		return nil, errors.New("handshake is not a Client Hello")
	}

	hsLen, ok := readUint24(&handshakeData)
	if !ok {
		return nil, errors.New("missing handshake length")
	}
	if int(hsLen) > len(handshakeData) {
		return nil, errors.New("clienthello length exceeds record")
	}

	var helloBody cryptobyte.String
	helloBody = handshakeData[:hsLen]
	handshakeData = handshakeData[hsLen:]

	// 3) Core ClientHello fields
	var helloVersion uint16
	if !helloBody.ReadUint16(&helloVersion) {
		return nil, errors.New("missing version field")
	}
	info.HelloVersion = helloVersion
	info.TLSVersion = helloVersion // overridden by ext 43 when present

	// random[32]
	if !helloBody.Skip(32) {
		return nil, errors.New("missing random bytes")
	}

	// session_id
	var sessionID cryptobyte.String
	if !helloBody.ReadUint8LengthPrefixed(&sessionID) {
		return nil, errors.New("missing session id")
	}

	// cipher_suites
	var cipherStream cryptobyte.String
	if !helloBody.ReadUint16LengthPrefixed(&cipherStream) {
		return nil, errors.New("missing cipher suite list")
	}
	if len(cipherStream)%2 != 0 {
		return nil, errors.New("malformed cipher suite vector")
	}

	for !cipherStream.Empty() {
		var suiteID uint16
		if !cipherStream.ReadUint16(&suiteID) {
			return nil, errors.New("malformed cipher suite entry")
		}
		if !isGREASEValue(suiteID) {
			info.CipherSuites = append(info.CipherSuites, suiteID)
		}
	}
	info.CipherCount = len(info.CipherSuites)

	// compression_methods
	var compression cryptobyte.String
	if !helloBody.ReadUint8LengthPrefixed(&compression) {
		return nil, errors.New("missing compression field")
	}

	// Extensions may be absent in some odd/old handshakes.
	if helloBody.Empty() {
		info.ExtensionCount = 0
		return info, nil
	}

	var extensionsBlock cryptobyte.String
	if !helloBody.ReadUint16LengthPrefixed(&extensionsBlock) {
		return nil, errors.New("malformed extension block")
	}

	for !extensionsBlock.Empty() {
		var extID uint16
		var extContent cryptobyte.String
		if !extensionsBlock.ReadUint16(&extID) || !extensionsBlock.ReadUint16LengthPrefixed(&extContent) {
			return nil, errors.New("malformed extension entry")
		}

		if !isGREASEValue(extID) {
			info.Extensions = append(info.Extensions, extID)
		}

		// Parse extension-specific content required by your objective.
		switch extID {
		case 0: // server_name
			var nameList cryptobyte.String
			if extContent.ReadUint16LengthPrefixed(&nameList) {
				for !nameList.Empty() {
					var nameKind uint8
					var hostname cryptobyte.String
					if !nameList.ReadUint8(&nameKind) || !nameList.ReadUint16LengthPrefixed(&hostname) {
						break
					}
					if nameKind == 0 && len(hostname) > 0 {
						host := string(hostname)
						if isLikelyHostname(host) {
							info.SNIHost = host
							info.SNIType = "d"
						}
						break
					}
				}
			}

		case 13: // signature_algorithms
			var sigStream cryptobyte.String
			if extContent.ReadUint16LengthPrefixed(&sigStream) {
				if len(sigStream)%2 != 0 {
					return nil, errors.New("malformed signature algorithms vector")
				}
				for !sigStream.Empty() {
					var sigID uint16
					if !sigStream.ReadUint16(&sigID) {
						return nil, errors.New("malformed signature algorithm entry")
					}
					if !isGREASEValue(sigID) {
						info.SignatureAlgorithms = append(info.SignatureAlgorithms, sigID)
					}
				}
			}

		case 16: // alpn
			var alpnList cryptobyte.String
			if extContent.ReadUint16LengthPrefixed(&alpnList) && !alpnList.Empty() {
				var primaryProto cryptobyte.String
				if alpnList.ReadUint8LengthPrefixed(&primaryProto) {
					info.FirstALPN = string(primaryProto)
				}
			}

		case 43: // supported_versions
			var versionList cryptobyte.String
			if extContent.ReadUint8LengthPrefixed(&versionList) {
				if len(versionList)%2 != 0 {
					return nil, errors.New("malformed supported versions vector")
				}

				var highestVer uint16
				for !versionList.Empty() {
					var v uint16
					if !versionList.ReadUint16(&v) {
						return nil, errors.New("malformed supported versions entry")
					}
					if !isGREASEValue(v) && v > highestVer {
						highestVer = v
					}
				}
				if highestVer != 0 {
					info.TLSVersion = highestVer
				}
			}
		}
	}

	info.ExtensionCount = len(info.Extensions)

	return info, nil
}

// DeconstructTlsClientHello is kept as a compatibility wrapper.
func DeconstructTlsClientHello(payload []byte) (*ClientHelloFields, error) {
	return ParseClientHello(payload)
}

func readUint24(s *cryptobyte.String) (uint32, bool) {
	var b0, b1, b2 uint8
	if !s.ReadUint8(&b0) || !s.ReadUint8(&b1) || !s.ReadUint8(&b2) {
		return 0, false
	}
	return uint32(b0)<<16 | uint32(b1)<<8 | uint32(b2), true
}

func isLikelyHostname(host string) bool {
	if host == "" || len(host) > 253 || !utf8.ValidString(host) {
		return false
	}
	if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	if strings.Contains(host, " ") {
		return false
	}
	// Keep this light: if it's an IP literal, treat as non-domain.
	for _, r := range host {
		if r == ':' {
			return false
		}
	}
	return true
}

// TLSVersionString prints versions like 0x0304 as "1.3" when known.
func TLSVersionString(v uint16) string {
	switch v {
	case 0x0301:
		return "1.0"
	case 0x0302:
		return "1.1"
	case 0x0303:
		return "1.2"
	case 0x0304:
		return "1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
