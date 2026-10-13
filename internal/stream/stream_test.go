package stream

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/google/gopacket/tcpassembly"
)

// streamTestClientHello builds a minimal ClientHello handshake message with
// SNI, supported_versions and ALPN extensions so the parser can produce a JA4.
func streamTestClientHello(t *testing.T) []byte {
	t.Helper()

	body := []byte{0x03, 0x03} // legacy_version: TLS 1.2
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)                   // session_id length
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites
	body = append(body, 0x01, 0x00)             // compression: null

	var extensions []byte
	appendExtension := func(id uint16, payload []byte) {
		extensions = binary.BigEndian.AppendUint16(extensions, id)
		extensions = binary.BigEndian.AppendUint16(extensions, uint16(len(payload)))
		extensions = append(extensions, payload...)
	}

	host := []byte("example.com")
	sni := binary.BigEndian.AppendUint16(nil, uint16(len(host)+3))
	sni = append(sni, 0x00)
	sni = binary.BigEndian.AppendUint16(sni, uint16(len(host)))
	sni = append(sni, host...)
	appendExtension(0x0000, sni)
	appendExtension(0x002b, []byte{0x02, 0x03, 0x04})           // supported_versions: TLS 1.3
	appendExtension(0x0010, []byte{0x00, 0x03, 0x02, 'h', '2'}) // ALPN: h2

	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)

	handshake := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(handshake, body...)
}

// streamTestRecordStream splits a handshake message across two TLS records.
func streamTestRecordStream(handshake []byte, firstPayload int) []byte {
	if firstPayload <= 0 || firstPayload >= len(handshake) {
		firstPayload = len(handshake) / 2
	}

	var out []byte
	for _, chunk := range [][]byte{handshake[:firstPayload], handshake[firstPayload:]} {
		out = append(out, 0x16, 0x03, 0x03, byte(len(chunk)>>8), byte(len(chunk)))
		out = append(out, chunk...)
	}
	return out
}

// TestStreamParsesMultiRecordClientHello is a regression test for ClientHellos
// that span multiple TLS records: the stream must parse the defragmented
// handshake bytes rather than erroring out on the first record.
func TestStreamParsesMultiRecordClientHello(t *testing.T) {
	handshake := streamTestClientHello(t)
	record := streamTestRecordStream(handshake, 13)

	var events []Event
	s := &tlsStream{
		onEvent: func(event Event) { events = append(events, event) },
	}
	s.Reassembled([]tcpassembly.Reassembly{{
		Bytes: record,
		Seen:  time.Unix(1_700_000_000, 0),
	}})

	if len(events) != 1 {
		t.Fatalf("emitted %d events, want 1", len(events))
	}

	event := events[0]
	if event.Hello == nil || event.Hello.Type != 0x01 {
		t.Fatalf("event hello = %+v, want a ClientHello", event.Hello)
	}
	if event.ParseError != nil {
		t.Fatalf("ParseError = %v, want nil", event.ParseError)
	}
	if event.FingerprintError != nil {
		t.Fatalf("FingerprintError = %v, want nil", event.FingerprintError)
	}
	if event.Fields == nil || event.JA4 == nil {
		t.Fatalf("fields/JA4 missing: fields=%+v ja4=%+v", event.Fields, event.JA4)
	}
	if event.JA4.A != "t13d0103h2" {
		t.Errorf("JA4_a = %q, want %q", event.JA4.A, "t13d0103h2")
	}
	if event.Fields.RecordVersion != 0x0303 {
		t.Errorf("RecordVersion = 0x%04x, want 0x0303", event.Fields.RecordVersion)
	}
}
