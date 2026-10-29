// Package capture provides packet sources for the Sybil pipeline.
//
// Two backends are supported:
//
//   - "pcap": libpcap on the configured interface. The TCP filter (and the
//     optional -port filter) is installed in the kernel as a pcap BPF filter.
//
//   - "ebpf": an XDP program (see ebpf/xdp_tcp.c) attached to the configured
//     interface. The program passes frames through to the kernel stack and
//     emits raw IPv4/IPv6 TCP Ethernet frames to userspace through a perf ring
//     buffer, truncated to ebpfCaptureLimit bytes. The TCP filter (and the
//     optional -port filter) runs inside the XDP program, so non-TCP traffic
//     never reaches the perf ring. The program is attached in driver (native)
//     mode when the interface supports it and falls back to generic (SKB) XDP
//     mode otherwise (loopback, veth, tunnels, ...); in generic mode capture
//     still works, it just runs later in the networking path.
//
// eBPF perf samples have a fixed 4-byte metadata prefix (SAMPLE_MARKER in
// ebpf/xdp_tcp.c; the previous program wrote zero there) followed by the raw
// Ethernet frame starting at the Ethernet header. Packet bytes are appended by
// the kernel using the BPF_F_CTXLEN_MASK half of bpf_perf_event_output's flags
// argument, which is the supported way for an XDP program to emit packet data
// (the helper's data argument may not point into the packet). Samples that are
// prefix-only or shorter than an Ethernet header (including the 4-byte dummy
// samples the previous program produced) are counted as malformed and logged at
// a throttled rate instead of being silently dropped.
package capture

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	projectebpf "github.com/sophic00/sybil/ebpf"
	"github.com/sophic00/sybil/internal/config"
)

var ErrClosed = errors.New("capture source closed")

const backendPCAPFile = "pcap-file"

// OpenOffline reads packets from a pcap/pcapng file using libpcap.
func OpenOffline(path string, matchPort uint) (*Source, error) {
	src := &Source{backend: backendPCAPFile}
	if err := src.openPCAPFile(path, matchPort); err != nil {
		_ = src.Close()
		return nil, err
	}
	return src, nil
}

const (
	// ebpfCaptureLimit mirrors MAX_CAPTURE_LEN in ebpf/xdp_tcp.c. The XDP
	// program asks the kernel to append at most this many frame bytes to each
	// perf sample.
	ebpfCaptureLimit = 2048

	// ebpfSamplePrefixLen is the fixed metadata prefix (SAMPLE_MARKER in
	// ebpf/xdp_tcp.c) that precedes the Ethernet frame in every perf sample.
	ebpfSamplePrefixLen = 4

	// ebpfSampleMarker mirrors SAMPLE_MARKER in ebpf/xdp_tcp.c.
	ebpfSampleMarker = 0x53594231 // "SYB1"

	// legacyEBPFSamplePrefix is the zero prefix written by the previous XDP
	// program; it is still accepted so a stale object does not break capture.
	legacyEBPFSamplePrefix = 0

	// minEBPFSampleLen is sizeof(struct ethhdr): the fewest bytes gopacket
	// needs to start decoding an Ethernet frame.
	minEBPFSampleLen = 14

	// ebpfLogInterval throttles "lost samples" and "malformed sample" log
	// lines so that a full ring buffer or a hostile sender cannot flood the
	// logs. Counters are always updated; only logging is sampled.
	ebpfLogInterval = 5 * time.Second
)

// errEBPFMalformedSample indicates a perf sample that could not be turned into
// an Ethernet frame (prefix-only, unknown prefix, or a frame shorter than an
// Ethernet header).
var errEBPFMalformedSample = errors.New("malformed ebpf perf sample")

type Source struct {
	backend string
	rd      *perf.Reader
	source  *gopacket.PacketSource
	// pcapHandle is the live libpcap handle (pcap backend only); it backs
	// Stats() so kernel receive/drop counters can be published as deltas.
	pcapHandle *pcap.Handle
	closers    []io.Closer

	// perfPackets is fed by the reader goroutine for the eBPF backend and
	// selected on together with ctx in NextPacket. perfStop is closed by Close
	// to unblock the goroutine if it is waiting to publish.
	perfPackets chan ebpfSample
	perfStop    chan struct{}
	closeOnce   sync.Once

	lostSamples      atomic.Uint64
	malformedSamples atomic.Uint64
	lastLostLog      atomic.Int64
	lastMalformedLog atomic.Int64
}

type ebpfSample struct {
	packet gopacket.Packet
	err    error
}

func Open(cfg config.Capture) (*Source, error) {
	if cfg.MatchPort > 65535 {
		return nil, fmt.Errorf("match port %d is out of range (0-65535)", cfg.MatchPort)
	}

	src := &Source{backend: cfg.Backend}

	var err error
	switch cfg.Backend {
	case config.BackendEBPF:
		err = src.openEBPF(cfg)
	case config.BackendPCAP:
		err = src.openPCAP(cfg)
	default:
		err = fmt.Errorf("unsupported capture backend %q", cfg.Backend)
	}
	if err != nil {
		_ = src.Close()
		return nil, err
	}

	return src, nil
}

// NextPacket returns the next captured packet. For the eBPF backend the read
// is driven by a dedicated goroutine (see readEBPF) so that cancellation is
// honored even while no packets are flowing; the pcap backend selects on
// ctx.Done directly.
func (s *Source) NextPacket(ctx context.Context) (gopacket.Packet, error) {
	switch s.backend {
	case config.BackendEBPF:
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case sample, ok := <-s.perfPackets:
			if !ok {
				return nil, ErrClosed
			}
			if sample.err != nil {
				return nil, sample.err
			}
			return sample.packet, nil
		}
	case config.BackendPCAP, backendPCAPFile:
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case packet, ok := <-s.source.Packets():
			if !ok {
				return nil, ErrClosed
			}
			return packet, nil
		}
	default:
		return nil, fmt.Errorf("unsupported capture backend %q", s.backend)
	}
}

// Close releases the backend resources. It is safe to call more than once.
func (s *Source) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		// Unblock the perf reader goroutine before closing the reader it may
		// be blocked in.
		if s.perfStop != nil {
			close(s.perfStop)
		}

		var errs []error
		for i := len(s.closers) - 1; i >= 0; i-- {
			if err := s.closers[i].Close(); err != nil {
				errs = append(errs, err)
			}
		}
		closeErr = errors.Join(errs...)
	})
	return closeErr
}

// LostSamples reports how many perf samples the kernel dropped because the
// userspace ring buffer was full (eBPF backend only; always 0 for pcap). It is
// safe to call while capture is running.
func (s *Source) LostSamples() uint64 {
	return s.lostSamples.Load()
}

// MalformedSamples reports how many eBPF perf samples were rejected by the
// userspace decoder (shorter than an Ethernet header, or undecodable).
func (s *Source) MalformedSamples() uint64 {
	return s.malformedSamples.Load()
}

// Stats holds the cumulative kernel packet counters reported by libpcap.
type Stats struct {
	Received  uint64
	Dropped   uint64
	IfDropped uint64
}

// Stats returns the live libpcap counters (packets received, dropped because
// libpcap's kernel buffer was full, and dropped by the interface). ok is false
// for backends without libpcap statistics. The values are cumulative for the
// lifetime of the handle, so callers should publish deltas.
func (s *Source) Stats() (Stats, bool) {
	if s.pcapHandle == nil {
		return Stats{}, false
	}
	stats, err := s.pcapHandle.Stats()
	if err != nil {
		return Stats{}, false
	}
	return Stats{
		Received:  uint64(stats.PacketsReceived),
		Dropped:   uint64(stats.PacketsDropped),
		IfDropped: uint64(stats.PacketsIfDropped),
	}, true
}

func (s *Source) openEBPF(cfg config.Capture) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock: %w", err)
	}

	var objs projectebpf.XdpTcpObjects
	if err := projectebpf.LoadXdpTcpObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading objects: %w", err)
	}
	s.closers = append(s.closers, &objs)

	// 0 means "every TCP port"; the XDP program treats it as no filter.
	if err := objs.PortConfig.Update(uint32(0), uint32(cfg.MatchPort), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("configure XDP port filter: %w", err)
	}

	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return fmt.Errorf("lookup interface %q: %w", cfg.Interface, err)
	}

	// Prefer driver (native) mode, which runs before the stack allocates an
	// skb. Loopback, veth and other virtual interfaces only support generic
	// (SKB) XDP, so fall back rather than failing capture.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpTcpParser,
		Interface: iface.Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		l, err = link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpTcpParser,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			return fmt.Errorf("attaching XDP: %w", err)
		}
	}
	s.closers = append(s.closers, l)

	rd, err := perf.NewReader(objs.Events, osPageSize()*128)
	if err != nil {
		return fmt.Errorf("perf reader: %w", err)
	}
	s.rd = rd
	s.closers = append(s.closers, rd)

	s.perfStop = make(chan struct{})
	s.perfPackets = make(chan ebpfSample, 1)
	go s.readEBPF()

	return nil
}

// readEBPF drains the perf ring buffer into perfPackets until the reader is
// closed or Close signals perfStop. Running the blocking read on its own
// goroutine is what makes NextPacket cancellation-aware.
func (s *Source) readEBPF() {
	defer close(s.perfPackets)

	for {
		record, err := s.rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				s.publishEBPF(ebpfSample{err: ErrClosed})
				return
			}
			// Keep reading after transient errors; the closed reader above is
			// the only condition that ends the loop.
			if !s.publishEBPF(ebpfSample{err: err}) {
				return
			}
			continue
		}

		if record.LostSamples > 0 {
			// Lost counters must not be turned into per-batch errors: a busy
			// interface would then flood both the logs and the caller.
			s.recordLostSamples(record.LostSamples)
			continue
		}

		packet, ok := s.handleEBPFSample(record.RawSample)
		if !ok {
			continue
		}
		if !s.publishEBPF(ebpfSample{packet: packet}) {
			return
		}
	}
}

func (s *Source) publishEBPF(sample ebpfSample) bool {
	select {
	case s.perfPackets <- sample:
		return true
	case <-s.perfStop:
		return false
	}
}

// handleEBPFSample decodes one perf sample and applies the malformed-sample
// counter. Samples that cannot be decoded as an Ethernet frame are dropped by
// this function; everything else (including non-TCP IP fragments) is passed on
// and handled by the stream processor.
func (s *Source) handleEBPFSample(raw []byte) (gopacket.Packet, bool) {
	packet, err := decodeEBPFSample(raw, time.Now())
	if err == nil && packet.ErrorLayer() != nil {
		err = packet.ErrorLayer().Error()
	}
	if err != nil {
		s.recordMalformedSample(len(raw), err)
		return nil, false
	}
	return packet, true
}

// decodeEBPFSample turns one XDP perf sample into a gopacket packet stamped
// with the userspace receive time (perf samples do not carry a kernel
// timestamp). The sample format is a 4-byte metadata prefix followed by the
// raw Ethernet frame, so the prefix is stripped and samples without a full
// Ethernet header are rejected. gopacket bounds IPv4/IPv6 decoding by the IP
// length fields, which also ignores the 0-7 trailing garbage bytes the kernel
// perf ring can append to a sample.
//
// It is split out from readEBPF so it can be unit tested without root, a
// kernel module or a network interface.
func decodeEBPFSample(raw []byte, ts time.Time) (gopacket.Packet, error) {
	if len(raw) < ebpfSamplePrefixLen {
		return nil, fmt.Errorf("%w: %d bytes, need at least %d for the prefix", errEBPFMalformedSample, len(raw), ebpfSamplePrefixLen)
	}

	prefix := binary.NativeEndian.Uint32(raw[:ebpfSamplePrefixLen])
	if prefix != ebpfSampleMarker && prefix != legacyEBPFSamplePrefix {
		return nil, fmt.Errorf("%w: unexpected prefix %#x", errEBPFMalformedSample, prefix)
	}

	frame := raw[ebpfSamplePrefixLen:]
	if len(frame) < minEBPFSampleLen {
		return nil, fmt.Errorf("%w: %d frame bytes, need at least %d", errEBPFMalformedSample, len(frame), minEBPFSampleLen)
	}

	packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	packet.Metadata().Timestamp = ts
	return packet, nil
}

func (s *Source) recordLostSamples(lost uint64) {
	total := s.lostSamples.Add(lost)
	if s.logAllowed(&s.lastLostLog) {
		log.Printf("ebpf: kernel dropped %d perf samples because the ring buffer was full (total %d); increase the perf buffer or reduce capture scope", lost, total)
	}
}

func (s *Source) recordMalformedSample(size int, err error) {
	total := s.malformedSamples.Add(1)
	if s.logAllowed(&s.lastMalformedLog) {
		log.Printf("ebpf: discarded malformed perf sample (%d bytes): %v (total %d)", size, err, total)
	}
}

// logAllowed returns true at most once per ebpfLogInterval using last as the
// timestamp of the previous log line.
func (s *Source) logAllowed(last *atomic.Int64) bool {
	now := time.Now().UnixNano()
	prev := last.Load()
	if prev != 0 && now-prev < int64(ebpfLogInterval) {
		return false
	}
	return last.CompareAndSwap(prev, now)
}

func (s *Source) openPCAP(cfg config.Capture) error {
	handle, err := pcap.OpenLive(cfg.Interface, 65535, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open pcap on %s: %w", cfg.Interface, err)
	}
	return s.usePCAPHandle(handle, cfg.MatchPort)
}

func (s *Source) openPCAPFile(path string, matchPort uint) error {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return fmt.Errorf("open pcap file %s: %w", path, err)
	}
	return s.usePCAPHandle(handle, matchPort)
}

func (s *Source) usePCAPHandle(handle *pcap.Handle, matchPort uint) error {
	s.closers = append(s.closers, closeFunc(func() error {
		handle.Close()
		return nil
	}))

	filter := "tcp"
	if matchPort != 0 {
		filter = fmt.Sprintf("tcp and port %d", matchPort)
	}
	if err := handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("set pcap filter %q: %w", filter, err)
	}

	s.source = gopacket.NewPacketSource(handle, handle.LinkType())
	s.source.NoCopy = true
	s.pcapHandle = handle

	return nil
}

type closeFunc func() error

func (f closeFunc) Close() error {
	return f()
}
