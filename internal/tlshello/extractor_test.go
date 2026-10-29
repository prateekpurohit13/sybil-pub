package tlshello

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
	"github.com/sophic00/sybil/internal/parser"
)

func TestExtractorMatchesTLSStreamAndTShark(t *testing.T) {
	if _, err := exec.LookPath("tshark"); err != nil {
		t.Skip("tshark is required for this accuracy test")
	}

	testCases := []struct {
		name     string
		min      uint16
		max      uint16
		segments []int
	}{
		{
			name:     "tls12_fragmented",
			min:      tls.VersionTLS12,
			max:      tls.VersionTLS12,
			segments: []int{1, 2, 3, 5, 8, 13, 21, 34, 55},
		},
		{
			name:     "tls13_fragmented",
			min:      tls.VersionTLS13,
			max:      tls.VersionTLS13,
			segments: []int{2, 1, 7, 11, 19, 23, 29, 31, 37},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			want := captureClientHello(t, &tls.Config{
				ServerName:         "example.com",
				NextProtos:         []string{"h2", "http/1.1"},
				MinVersion:         tc.min,
				MaxVersion:         tc.max,
				InsecureSkipVerify: true,
			})

			frames := buildTCPFlow(t, want, tc.segments)
			got := extractFromFrames(t, frames)
			if got.Type != ClientHello {
				t.Fatalf("extractor recovered %s, want %s", got.Type, ClientHello)
			}
			if !bytes.Equal(got.RecordBytes, want) {
				t.Fatalf("extractor bytes differ from source ClientHello\nwant=%x\ngot=%x", want, got.RecordBytes)
			}

			pcapPath := writePCAP(t, frames)
			ref := tsharkClientHello(t, pcapPath)
			if !bytes.Equal(ref, want) {
				t.Fatalf("tshark bytes differ from source ClientHello\nwant=%x\nref=%x", want, ref)
			}
			if !bytes.Equal(got.RecordBytes, ref) {
				t.Fatalf("extractor bytes differ from tshark\nref=%x\ngot=%x", ref, got.RecordBytes)
			}
		})
	}
}

func captureClientHello(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()

	clientConn, serverConn := net.Pipe()

	errCh := make(chan error, 1)
	go func() {
		defer clientConn.Close()
		client := tls.Client(clientConn, cfg)
		_ = client.SetDeadline(time.Now().Add(2 * time.Second))
		errCh <- client.Handshake()
	}()

	var stream bytes.Buffer
	buf := make([]byte, 2048)
	if err := serverConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	for {
		n, err := serverConn.Read(buf)
		if n > 0 {
			stream.Write(buf[:n])
			_ = serverConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		}

		if err == nil {
			continue
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			break
		}
		if errors.Is(err, io.EOF) {
			break
		}
		t.Fatalf("read client hello: %v", err)
	}

	serverConn.Close()
	<-errCh

	if stream.Len() == 0 {
		t.Fatal("captured empty TLS stream")
	}
	if stream.Bytes()[0] != 0x16 {
		t.Fatalf("captured stream does not begin with a TLS handshake record: %x", stream.Bytes())
	}

	return append([]byte(nil), stream.Bytes()...)
}

func buildTCPFlow(t *testing.T, payload []byte, segmentSizes []int) [][]byte {
	t.Helper()

	clientMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	serverMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	clientIP := net.IPv4(192, 0, 2, 1)
	serverIP := net.IPv4(192, 0, 2, 2)
	clientPort := layers.TCPPort(42424)
	serverPort := layers.TCPPort(443)

	clientSeq := uint32(1000)
	serverSeq := uint32(9000)

	var frames [][]byte
	frames = append(frames, serializeTCPPacket(t, clientMAC, serverMAC, clientIP, serverIP, clientPort, serverPort, clientSeq, 0, true, false, false, nil))
	frames = append(frames, serializeTCPPacket(t, serverMAC, clientMAC, serverIP, clientIP, serverPort, clientPort, serverSeq, clientSeq+1, true, true, false, nil))
	frames = append(frames, serializeTCPPacket(t, clientMAC, serverMAC, clientIP, serverIP, clientPort, serverPort, clientSeq+1, serverSeq+1, false, true, false, nil))
	clientSeq++
	serverSeq++

	for _, segment := range splitPayload(payload, segmentSizes) {
		frames = append(frames, serializeTCPPacket(t, clientMAC, serverMAC, clientIP, serverIP, clientPort, serverPort, clientSeq, serverSeq, false, true, true, segment))
		clientSeq += uint32(len(segment))
		frames = append(frames, serializeTCPPacket(t, serverMAC, clientMAC, serverIP, clientIP, serverPort, clientPort, serverSeq, clientSeq, false, true, false, nil))
	}

	return frames
}

func splitPayload(payload []byte, sizes []int) [][]byte {
	var segments [][]byte
	offset := 0

	for _, size := range sizes {
		if offset >= len(payload) {
			break
		}
		if size > len(payload)-offset {
			size = len(payload) - offset
		}
		segments = append(segments, append([]byte(nil), payload[offset:offset+size]...))
		offset += size
	}

	if offset < len(payload) {
		segments = append(segments, append([]byte(nil), payload[offset:]...))
	}

	return segments
}

func serializeTCPPacket(
	t *testing.T,
	srcMAC, dstMAC net.HardwareAddr,
	srcIP, dstIP net.IP,
	srcPort, dstPort layers.TCPPort,
	seq, ack uint32,
	syn, ackFlag, psh bool,
	payload []byte,
) []byte {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	tcp := &layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     seq,
		Ack:     ack,
		SYN:     syn,
		ACK:     ackFlag,
		PSH:     psh,
		Window:  64240,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set checksum network layer: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth,
		ip,
		tcp,
		gopacket.Payload(payload),
	); err != nil {
		t.Fatalf("serialize packet: %v", err)
	}

	return append([]byte(nil), buf.Bytes()...)
}

type helloCollectorFactory struct {
	results chan *Hello
}

func (f *helloCollectorFactory) New(netFlow, transport gopacket.Flow) tcpassembly.Stream {
	return &helloCollectorStream{results: f.results}
}

type helloCollectorStream struct {
	extractor Extractor
	results   chan *Hello
	done      bool
}

func (s *helloCollectorStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	if s.done {
		return
	}

	for _, reassembly := range reassemblies {
		hello, err := s.extractor.Feed(reassembly.Bytes)
		if err != nil {
			s.done = true
			return
		}
		if hello == nil {
			continue
		}

		s.results <- hello
		s.done = true
		return
	}
}

func (s *helloCollectorStream) ReassemblyComplete() {}

func extractFromFrames(t *testing.T, frames [][]byte) *Hello {
	t.Helper()

	results := make(chan *Hello, 1)
	pool := tcpassembly.NewStreamPool(&helloCollectorFactory{results: results})
	assembler := tcpassembly.NewAssembler(pool)
	base := time.Unix(1_700_000_000, 0)

	for i, frame := range frames {
		packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}

		ip := ipLayer.(*layers.IPv4)
		tcp := tcpLayer.(*layers.TCP)
		assembler.AssembleWithTimestamp(ip.NetworkFlow(), tcp, base.Add(time.Duration(i)*time.Millisecond))
	}

	assembler.FlushAll()

	select {
	case hello := <-results:
		return hello
	default:
		t.Fatal("extractor did not recover a TLS hello from the packet stream")
		return nil
	}
}

func writePCAP(t *testing.T, frames [][]byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "clienthello.pcap")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pcap: %v", err)
	}
	defer file.Close()

	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}

	base := time.Unix(1_700_000_000, 0)
	for i, frame := range frames {
		info := gopacket.CaptureInfo{
			Timestamp:     base.Add(time.Duration(i) * time.Millisecond),
			CaptureLength: len(frame),
			Length:        len(frame),
		}
		if err := writer.WritePacket(info, frame); err != nil {
			t.Fatalf("write pcap packet: %v", err)
		}
	}

	return path
}

func tsharkClientHello(t *testing.T, pcapPath string) []byte {
	t.Helper()

	var stderr bytes.Buffer
	cmd := exec.Command(
		"tshark",
		"-2",
		"-r", pcapPath,
		"-d", "tcp.port==443,tls",
		"-o", "tcp.desegment_tcp_streams:TRUE",
		"-o", "tls.desegment_ssl_records:TRUE",
		"-Y", "tls.handshake.type == 1",
		"-T", "fields",
		"-e", "tcp.reassembled.data",
		"-e", "tcp.payload",
	)
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("tshark failed: %v\nstderr=%s", err, stderr.String())
	}

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}

		for _, field := range strings.Split(line, "\t") {
			if strings.TrimSpace(field) == "" {
				continue
			}

			decoded, err := decodeHexField(field)
			if err == nil && len(decoded) > 0 {
				return decoded
			}
		}
	}

	t.Fatalf("tshark did not emit a client hello payload\nstdout=%s\nstderr=%s", out, stderr.String())
	return nil
}

func decodeHexField(field string) ([]byte, error) {
	clean := strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9':
			return r
		case r >= 'a' && r <= 'f':
			return r
		case r >= 'A' && r <= 'F':
			return r
		default:
			return -1
		}
	}, field)

	if clean == "" {
		return nil, nil
	}

	return hex.DecodeString(clean)
}

// buildClientHelloHandshake synthesizes a minimal, well-formed ClientHello
// handshake message (type byte + 3-byte length + body) that the production
// parser and JA4 builder accept. Record-layer tests can then split it across
// records without needing a real TLS stack or tshark.
func buildClientHelloHandshake(t *testing.T) []byte {
	t.Helper()

	body := []byte{0x03, 0x03}               // legacy_version: TLS 1.2
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session_id length
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00) // compression: null

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

// buildRecordStream splits a handshake message at the given payload offsets
// and wraps each chunk in its own TLS handshake record. Splits that do not
// make progress are ignored, and any remainder always lands in a final
// record.
func buildRecordStream(handshake []byte, splits ...int) []byte {
	var out []byte
	emit := func(chunk []byte) {
		out = append(out, 0x16, 0x03, 0x03, byte(len(chunk)>>8), byte(len(chunk)))
		out = append(out, chunk...)
	}

	offset := 0
	for _, split := range splits {
		if split <= offset || split >= len(handshake) {
			continue
		}
		emit(handshake[offset:split])
		offset = split
	}
	emit(handshake[offset:])
	return out
}

func requireParsedClientHello(t *testing.T, handshake []byte, recordVersion uint16) {
	t.Helper()

	fields, err := parser.ParseClientHelloHandshake(handshake, recordVersion)
	if err != nil {
		t.Fatalf("ParseClientHelloHandshake: %v", err)
	}
	if fields.RecordVersion != recordVersion {
		t.Errorf("RecordVersion = 0x%04x, want 0x%04x", fields.RecordVersion, recordVersion)
	}
	if fields.TLSVersion != 0x0304 {
		t.Errorf("TLSVersion = 0x%04x, want TLS 1.3 (0x0304)", fields.TLSVersion)
	}
	if fields.SNIType != "d" || fields.SNIHost != "example.com" {
		t.Errorf("SNI = (%q, %q), want (\"d\", \"example.com\")", fields.SNIType, fields.SNIHost)
	}
	if fields.FirstALPN != "h2" {
		t.Errorf("FirstALPN = %q, want %q", fields.FirstALPN, "h2")
	}
	if fields.CipherCount != 1 || fields.ExtensionCount != 3 {
		t.Errorf("counts = (%d, %d), want (1, 3)", fields.CipherCount, fields.ExtensionCount)
	}
}

// TestExtractorMultiRecordHello covers a ClientHello whose message body spans
// two TLS records. The extractor must defragment the record payloads, and the
// parser must accept both the defragmented handshake and the original
// multi-record byte stream.
func TestExtractorMultiRecordHello(t *testing.T) {
	handshake := buildClientHelloHandshake(t)
	stream := buildRecordStream(handshake, 13)

	var extractor Extractor
	hello, err := extractor.Feed(stream)
	if err != nil {
		t.Fatalf("Feed: %v", err)
	}
	if hello == nil {
		t.Fatal("extractor did not recover the multi-record ClientHello")
	}
	if hello.Type != ClientHello {
		t.Fatalf("extractor recovered %s, want %s", hello.Type, ClientHello)
	}
	if hello.StreamOffset != 0 {
		t.Errorf("StreamOffset = %d, want 0", hello.StreamOffset)
	}
	if hello.RecordVersion != 0x0303 {
		t.Errorf("RecordVersion = 0x%04x, want 0x0303", hello.RecordVersion)
	}
	if !bytes.Equal(hello.HandshakeBytes, handshake) {
		t.Fatalf("HandshakeBytes differ from source handshake\nwant=%x\ngot=%x", handshake, hello.HandshakeBytes)
	}
	if !bytes.Equal(hello.RecordBytes, stream) {
		t.Fatalf("RecordBytes differ from source record stream\nwant=%x\ngot=%x", stream, hello.RecordBytes)
	}

	requireParsedClientHello(t, hello.HandshakeBytes, hello.RecordVersion)

	// The record-aware parser must defragment the same multi-record bytes.
	fields, err := parser.ParseClientHello(stream)
	if err != nil {
		t.Fatalf("ParseClientHello(multi-record): %v", err)
	}
	if fields.RecordVersion != 0x0303 || fields.SNIHost != "example.com" || fields.FirstALPN != "h2" {
		t.Errorf("ParseClientHello(multi-record) = %+v", fields)
	}
}

// TestExtractorSplitHandshakeHeaderAcrossRecords covers the case where the
// 4-byte handshake header itself is split across TLS records.
func TestExtractorSplitHandshakeHeaderAcrossRecords(t *testing.T) {
	handshake := buildClientHelloHandshake(t)

	for _, split := range []int{1, 2, 3} {
		stream := buildRecordStream(handshake, split)

		var extractor Extractor
		hello, err := extractor.Feed(stream)
		if err != nil {
			t.Errorf("split %d: Feed: %v", split, err)
			continue
		}
		if hello == nil {
			t.Errorf("split %d: extractor did not recover the ClientHello", split)
			continue
		}
		if !bytes.Equal(hello.HandshakeBytes, handshake) {
			t.Errorf("split %d: HandshakeBytes differ\nwant=%x\ngot=%x", split, handshake, hello.HandshakeBytes)
		}
	}
}

// TestExtractorTruncatesRecordBytesToConsumedHandshake verifies that bytes
// following the handshake message inside its final record do not leak into
// RecordBytes.
func TestExtractorTruncatesRecordBytesToConsumedHandshake(t *testing.T) {
	handshake := buildClientHelloHandshake(t)
	record := buildRecordStream(handshake)

	// Append trailing bytes and extend the declared record length to cover
	// them, imitating a record that carries more than the ClientHello.
	trailing := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	padded := append(append([]byte(nil), record...), trailing...)
	binary.BigEndian.PutUint16(padded[3:5], uint16(len(padded)-5))

	var extractor Extractor
	hello, err := extractor.Feed(padded)
	if err != nil {
		t.Fatalf("Feed: %v", err)
	}
	if hello == nil {
		t.Fatal("extractor did not recover the ClientHello")
	}
	if !bytes.Equal(hello.HandshakeBytes, handshake) {
		t.Fatalf("HandshakeBytes differ\nwant=%x\ngot=%x", handshake, hello.HandshakeBytes)
	}
	// RecordBytes keeps the original (now over-long) record header but
	// stops where the handshake message ends.
	wantRecordBytes := padded[:5+len(handshake)]
	if !bytes.Equal(hello.RecordBytes, wantRecordBytes) {
		t.Fatalf("RecordBytes over-include trailing record bytes\nwant=%x\ngot=%x", wantRecordBytes, hello.RecordBytes)
	}
	requireParsedClientHello(t, hello.HandshakeBytes, hello.RecordVersion)
}

// TestExtractorSkipsFalsePositiveCandidate verifies that an incomplete header
// that merely looks like a TLS record does not hide a complete ClientHello
// that follows it in the buffer.
func TestExtractorSkipsFalsePositiveCandidate(t *testing.T) {
	handshake := buildClientHelloHandshake(t)
	real := buildRecordStream(handshake)
	// Claims a 0x4000-byte record that never arrives.
	bogus := []byte{0x16, 0x03, 0x03, 0x40, 0x00}
	stream := append(append([]byte(nil), bogus...), real...)

	var extractor Extractor
	hello, err := extractor.Feed(stream)
	if err != nil {
		t.Fatalf("Feed: %v", err)
	}
	if hello == nil {
		t.Fatal("extractor was blocked by a false-positive record header")
	}
	if hello.StreamOffset != len(bogus) {
		t.Errorf("StreamOffset = %d, want %d (the real record)", hello.StreamOffset, len(bogus))
	}
	if !bytes.Equal(hello.HandshakeBytes, handshake) {
		t.Fatalf("HandshakeBytes differ\nwant=%x\ngot=%x", handshake, hello.HandshakeBytes)
	}
}

// TestExtractorMultiRecordHelloThroughTCP runs the same multi-record
// ClientHello through gopacket TCP reassembly with arbitrary segment
// boundaries.
func TestExtractorMultiRecordHelloThroughTCP(t *testing.T) {
	handshake := buildClientHelloHandshake(t)
	stream := buildRecordStream(handshake, 13)

	frames := buildTCPFlow(t, stream, []int{1, 3, 5, 8, 13, 21, 34})
	hello := extractFromFrames(t, frames)
	if hello == nil || hello.Type != ClientHello {
		t.Fatalf("extractor recovered %v, want %s", hello, ClientHello)
	}
	if !bytes.Equal(hello.HandshakeBytes, handshake) {
		t.Fatalf("HandshakeBytes differ\nwant=%x\ngot=%x", handshake, hello.HandshakeBytes)
	}
}

// TestExtractorFinishRecoversHelloBehindPendingCandidate covers the final
// flush scan: data observed after the last Feed call must still be scanned
// when the stream is closed.
func TestExtractorFinishRecoversHelloBehindPendingCandidate(t *testing.T) {
	handshake := buildClientHelloHandshake(t)
	real := buildRecordStream(handshake)
	bogus := []byte{0x16, 0x03, 0x03, 0x40, 0x00}

	var extractor Extractor
	hello, err := extractor.Feed(bogus)
	if err != nil || hello != nil {
		t.Fatalf("Feed(bogus) = (%v, %v), want (nil, nil)", hello, err)
	}

	// Simulate bytes buffered before a final flush without a preceding scan.
	extractor.buf = append(extractor.buf, real...)

	hello = extractor.Finish()
	if hello == nil {
		t.Fatal("Finish did not recover the buffered ClientHello")
	}
	if !bytes.Equal(hello.HandshakeBytes, handshake) {
		t.Fatalf("HandshakeBytes differ\nwant=%x\ngot=%x", handshake, hello.HandshakeBytes)
	}
	if extractor.Finish() != nil {
		t.Fatal("Finish returned a hello twice")
	}
}
