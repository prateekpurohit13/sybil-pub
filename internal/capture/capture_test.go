package capture

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sophic00/sybil/internal/config"
)

var testPayload = []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00}

// buildTestFrame serializes a minimal Ethernet/IPv4/TCP frame carrying a TLS
// record header, mirroring what the XDP program emits for a ClientHello.
func buildTestFrame(t *testing.T) []byte {
	t.Helper()

	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IP{10, 0, 0, 1},
		DstIP:    net.IP{10, 0, 0, 2},
	}
	tcp := layers.TCP{
		SrcPort: 49152,
		DstPort: 443,
		Seq:     1,
		SYN:     true,
	}
	if err := tcp.SetNetworkLayerForChecksum(&ip); err != nil {
		t.Fatalf("set network layer: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, gopacket.Payload(testPayload)); err != nil {
		t.Fatalf("serialize test frame: %v", err)
	}
	return buf.Bytes()
}

// encodeTestSample prepends the fixed metadata prefix the XDP program writes.
func encodeTestSample(t *testing.T, frame []byte) []byte {
	t.Helper()

	if len(frame) > ebpfCaptureLimit {
		t.Fatalf("test frame is %d bytes, above the %d-byte capture limit", len(frame), ebpfCaptureLimit)
	}
	sample := make([]byte, ebpfSamplePrefixLen+len(frame))
	binary.NativeEndian.PutUint32(sample[:ebpfSamplePrefixLen], ebpfSampleMarker)
	copy(sample[ebpfSamplePrefixLen:], frame)
	return sample
}

func TestDecodeEBPFSampleParsesRawFrame(t *testing.T) {
	frame := buildTestFrame(t)
	sample := encodeTestSample(t, frame)
	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	packet, err := decodeEBPFSample(sample, ts)
	if err != nil {
		t.Fatalf("decodeEBPFSample() error = %v", err)
	}
	if packet.ErrorLayer() != nil {
		t.Fatalf("unexpected decode error: %v", packet.ErrorLayer().Error())
	}
	if got := packet.Metadata().Timestamp; !got.Equal(ts) {
		t.Fatalf("timestamp = %v, want %v", got, ts)
	}
	if packet.Layer(layers.LayerTypeIPv4) == nil {
		t.Fatal("missing IPv4 layer")
	}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		t.Fatal("missing TCP layer")
	}
	tcp := tcpLayer.(*layers.TCP)
	if tcp.SrcPort != 49152 || tcp.DstPort != 443 {
		t.Fatalf("ports = %d->%d, want 49152->443", tcp.SrcPort, tcp.DstPort)
	}
	if got := len(tcp.Payload); got != len(testPayload) {
		t.Fatalf("payload length = %d, want %d", got, len(testPayload))
	}
}

func TestDecodeEBPFSampleLegacyPrefix(t *testing.T) {
	// The previous XDP program wrote a zero metadata prefix. Keep accepting it
	// so a mixed deployment still captures packets.
	frame := buildTestFrame(t)
	sample := make([]byte, ebpfSamplePrefixLen+len(frame))
	copy(sample[ebpfSamplePrefixLen:], frame)

	packet, err := decodeEBPFSample(sample, time.Now())
	if err != nil {
		t.Fatalf("decodeEBPFSample() error = %v", err)
	}
	if packet.Layer(layers.LayerTypeTCP) == nil {
		t.Fatal("missing TCP layer")
	}
}

func TestDecodeEBPFSampleTrimsPerfRingTrailingGarbage(t *testing.T) {
	frame := buildTestFrame(t)
	// The kernel perf ring can append up to 7 garbage bytes per sample; IP
	// length decoding must keep them out of the TCP payload.
	sample := encodeTestSample(t, frame)
	sample = append(sample, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02)

	packet, err := decodeEBPFSample(sample, time.Now())
	if err != nil {
		t.Fatalf("decodeEBPFSample() error = %v", err)
	}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		t.Fatal("missing TCP layer")
	}
	if got := len(tcpLayer.(*layers.TCP).Payload); got != len(testPayload) {
		t.Fatalf("payload length = %d, want %d (trailing garbage leaked into payload)", got, len(testPayload))
	}
}

func TestDecodeEBPFSampleRejectsMalformedSamples(t *testing.T) {
	cases := map[string][]byte{
		"empty":           {},
		"partial prefix":  {0x53, 0x42, 0x59},
		"marker only":     encodeTestSample(t, nil)[:ebpfSamplePrefixLen],
		"legacy dummy":    {0x00, 0x00, 0x00, 0x00},
		"frame too short": encodeTestSample(t, make([]byte, minEBPFSampleLen-1)),
		"unknown prefix":  append([]byte{0xef, 0xbe, 0xad, 0xde}, buildTestFrame(t)...),
	}

	for name, raw := range cases {
		packet, err := decodeEBPFSample(raw, time.Now())
		if !errors.Is(err, errEBPFMalformedSample) {
			t.Fatalf("%s: err = %v, want errEBPFMalformedSample", name, err)
		}
		if packet != nil {
			t.Fatalf("%s: packet = %v, want nil", name, packet)
		}
	}
}

func TestHandleEBPFSampleCountsMalformed(t *testing.T) {
	s := &Source{}

	if _, ok := s.handleEBPFSample([]byte{0x00, 0x00, 0x00, 0x00}); ok {
		t.Fatal("legacy dummy sample should be rejected")
	}
	if got := s.MalformedSamples(); got != 1 {
		t.Fatalf("malformed samples = %d, want 1", got)
	}

	packet, ok := s.handleEBPFSample(encodeTestSample(t, buildTestFrame(t)))
	if !ok || packet == nil {
		t.Fatal("valid frame should be accepted")
	}
	if got := s.MalformedSamples(); got != 1 {
		t.Fatalf("malformed samples = %d, want 1 after valid frame", got)
	}
}

func TestDecodeEBPFSampleCountsTruncatedFrame(t *testing.T) {
	frame := buildTestFrame(t)
	sample := encodeTestSample(t, frame[:20]) // Ethernet + partial IPv4 header.

	if _, ok := (&Source{}).handleEBPFSample(sample); ok {
		t.Fatal("truncated frame should be rejected")
	}
}

func TestNextPacketEBPFHonorsContext(t *testing.T) {
	s := &Source{backend: config.BackendEBPF, perfPackets: make(chan ebpfSample)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := s.NextPacket(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("NextPacket() error = %v, want context.Canceled", err)
	}
}

func TestNextPacketEBPFReturnsPublishedPacket(t *testing.T) {
	s := &Source{backend: config.BackendEBPF, perfPackets: make(chan ebpfSample, 1)}
	packet := gopacket.NewPacket(buildTestFrame(t), layers.LayerTypeEthernet, gopacket.Default)
	s.perfPackets <- ebpfSample{packet: packet}

	got, err := s.NextPacket(context.Background())
	if err != nil {
		t.Fatalf("NextPacket() error = %v", err)
	}
	if got != packet {
		t.Fatal("NextPacket() did not return the published packet")
	}
}

func TestNextPacketEBPFReturnsErrClosed(t *testing.T) {
	s := &Source{backend: config.BackendEBPF, perfPackets: make(chan ebpfSample)}
	close(s.perfPackets)

	if _, err := s.NextPacket(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("NextPacket() error = %v, want ErrClosed", err)
	}
}

func TestOpenRejectsInvalidMatchPort(t *testing.T) {
	_, err := Open(config.Capture{Backend: config.BackendPCAP, Interface: "lo", MatchPort: 70000})
	if err == nil {
		t.Fatal("Open() accepted an out-of-range match port")
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	s := &Source{perfStop: make(chan struct{})}
	if err := s.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}
