package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/sophic00/sybil/internal/fingerprint"
	"github.com/sophic00/sybil/internal/parser"
)

func TestRunDirectLookup(t *testing.T) {
	datasetPath := filepath.Join("..", "..", "datasets", "ja4plus-mapping.csv")
	result, err := run(context.Background(), options{
		datasetPath: datasetPath,
		ja4Inputs: []string{
			"t13d1516h2_8daaf6152771_02713d6af862",
			"t13d000000_000000000000_000000000000",
		},
		strict: true,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if result.Summary.DirectLookups != 2 || result.Summary.Exact != 1 || result.Summary.Unknown != 1 {
		t.Fatalf("unexpected summary: %+v", result.Summary)
	}
	if !result.StrictFailure {
		t.Fatal("expected strict failure for the unknown fingerprint")
	}
	if result.Dataset.UniqueJA4 != 32 {
		t.Fatalf("unexpected dataset stats: %+v", result.Dataset)
	}
	if result.Observations[0].Matches[0].Application != "Chromium Browser" {
		t.Fatalf("unexpected match: %+v", result.Observations[0].Matches)
	}
}

func TestRunPCAPMatchesDataset(t *testing.T) {
	hello := captureClientHello(t)
	fields, err := parser.ParseClientHello(hello)
	if err != nil {
		t.Fatalf("parse captured client hello: %v", err)
	}
	ja4, err := fingerprint.BuildJA4(fields)
	if err != nil {
		t.Fatalf("build ja4: %v", err)
	}
	if !strings.HasPrefix(ja4.Fingerprint, "t13d") {
		t.Fatalf("expected TLS 1.3 with domain SNI, got %s", ja4.Fingerprint)
	}

	dir := t.TempDir()
	datasetPath := filepath.Join(dir, "dataset.csv")
	contents := fmt.Sprintf(`Application,Library,Device,OS,ja4,ja4s,ja4h,ja4x,ja4t,ja4tscan,Notes
Test Client,Test Library,,,`+"%s"+`,,,,,,fixture
`, ja4.Fingerprint)
	if err := os.WriteFile(datasetPath, []byte(contents), 0o644); err != nil {
		t.Fatalf("write dataset: %v", err)
	}

	pcapPath := writeClientHelloPCAP(t, hello)
	result, err := run(context.Background(), options{
		datasetPath: datasetPath,
		pcapPath:    pcapPath,
		strict:      true,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if result.Summary.ClientHellos != 1 || result.Summary.Exact != 1 {
		t.Fatalf("unexpected summary: %+v", result.Summary)
	}
	if result.StrictFailure {
		t.Fatal("expected strict pass")
	}

	item := result.Observations[0]
	if item.JA4 != ja4.Fingerprint {
		t.Fatalf("ja4 = %q, want %q", item.JA4, ja4.Fingerprint)
	}
	if item.SNI != "example.com" {
		t.Fatalf("sni = %q", item.SNI)
	}
	if item.SourceIP != "192.0.2.1" || item.DestinationIP != "192.0.2.2" {
		t.Fatalf("unexpected flow: %+v", item)
	}
	if item.SourcePort != "42424" || item.DestinationPort != "443" {
		t.Fatalf("unexpected ports: %+v", item)
	}
	if len(item.Matches) != 1 || item.Matches[0].Application != "Test Client" {
		t.Fatalf("unexpected matches: %+v", item.Matches)
	}
}

func captureClientHello(t *testing.T) []byte {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer clientConn.Close()

		client := tls.Client(clientConn, &tls.Config{
			ServerName:         "example.com",
			NextProtos:         []string{"h2", "http/1.1"},
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
		})
		_ = client.SetDeadline(time.Now().Add(2 * time.Second))
		_ = client.Handshake()
	}()

	var stream []byte
	buffer := make([]byte, 4096)
	deadline := time.Now().Add(2 * time.Second)
	for {
		_ = serverConn.SetReadDeadline(deadline)
		n, err := serverConn.Read(buffer)
		if n > 0 {
			stream = append(stream, buffer[:n]...)
		}
		if len(stream) >= 5 {
			recordLen := int(stream[3])<<8 | int(stream[4])
			if len(stream) >= 5+recordLen {
				break
			}
		}
		if err != nil {
			break
		}
	}
	_ = serverConn.Close()
	<-done

	if len(stream) < 5 || stream[0] != 0x16 {
		t.Fatalf("did not capture a ClientHello: %x", stream)
	}
	return stream
}

func writeClientHelloPCAP(t *testing.T, payload []byte) string {
	t.Helper()

	frames := buildTCPFrames(payload)
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
	for index, frame := range frames {
		info := gopacket.CaptureInfo{
			Timestamp:     base.Add(time.Duration(index) * time.Millisecond),
			CaptureLength: len(frame),
			Length:        len(frame),
		}
		if err := writer.WritePacket(info, frame); err != nil {
			t.Fatalf("write packet: %v", err)
		}
	}
	return path
}

func buildTCPFrames(payload []byte) [][]byte {
	clientMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	serverMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	clientIP := net.IPv4(192, 0, 2, 1)
	serverIP := net.IPv4(192, 0, 2, 2)

	clientSeq := uint32(1000)
	serverSeq := uint32(9000)

	frames := [][]byte{
		serializeTCPFrame(clientMAC, serverMAC, clientIP, serverIP, 42424, 443, clientSeq, 0, true, false, false, nil),
		serializeTCPFrame(serverMAC, clientMAC, serverIP, clientIP, 443, 42424, serverSeq, clientSeq+1, true, true, false, nil),
		serializeTCPFrame(clientMAC, serverMAC, clientIP, serverIP, 42424, 443, clientSeq+1, serverSeq+1, false, true, false, nil),
	}
	clientSeq++
	serverSeq++

	frames = append(frames,
		serializeTCPFrame(clientMAC, serverMAC, clientIP, serverIP, 42424, 443, clientSeq, serverSeq, false, true, true, payload),
		serializeTCPFrame(serverMAC, clientMAC, serverIP, clientIP, 443, 42424, serverSeq, clientSeq+uint32(len(payload)), false, true, false, nil),
	)
	return frames
}

func serializeTCPFrame(
	srcMAC, dstMAC net.HardwareAddr,
	srcIP, dstIP net.IP,
	srcPort, dstPort layers.TCPPort,
	seq, ack uint32,
	syn, ackFlag, psh bool,
	payload []byte,
) []byte {
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
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buffer := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip, tcp, gopacket.Payload(payload),
	)
	return append([]byte(nil), buffer.Bytes()...)
}

func TestPrintReportContainsSummary(t *testing.T) {
	datasetPath := filepath.Join("..", "..", "datasets", "ja4plus-mapping.csv")
	result, err := run(context.Background(), options{
		datasetPath: datasetPath,
		ja4Inputs:   []string{"t13d1516h2_8daaf6152771_02713d6af862"},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	var output strings.Builder
	printReport(&output, result)
	text := output.String()
	if !strings.Contains(text, "Chromium Browser") || !strings.Contains(text, "exact=1") {
		t.Fatalf("unexpected report output:\n%s", text)
	}
}
