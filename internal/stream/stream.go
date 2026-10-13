package stream

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/sophic00/sybil/internal/fingerprint"
	"github.com/sophic00/sybil/internal/parser"
	"github.com/sophic00/sybil/internal/tlshello"
)

type Event struct {
	NetFlow          gopacket.Flow
	TransportFlow    gopacket.Flow
	Hello            *tlshello.Hello
	Fields           *parser.ClientHelloFields
	JA4              *fingerprint.JA4
	ParseError       error
	FingerprintError error
}

type Handler func(Event)

type Options struct {
	MatchPort uint
	OnEvent   Handler
	// OnExtractError, when set, is called for TLS hello extraction failures
	// (for example ErrBufferLimit) so callers can publish telemetry. The
	// stream stops processing once an extraction error occurs.
	OnExtractError func(error)
}

type Processor struct {
	matchPort uint
	assembler *tcpassembly.Assembler
}

func NewProcessor(opts Options) *Processor {
	streamFactory := &tlsStreamFactory{
		onEvent:        opts.OnEvent,
		onExtractError: opts.OnExtractError,
	}
	pool := tcpassembly.NewStreamPool(streamFactory)

	return &Processor{
		matchPort: opts.MatchPort,
		assembler: tcpassembly.NewAssembler(pool),
	}
}

func (p *Processor) ProcessPacket(packet gopacket.Packet) {
	if packet == nil {
		return
	}

	var (
		netFlow gopacket.Flow
		tcp     *layers.TCP
	)

	if ip4 := packet.Layer(layers.LayerTypeIPv4); ip4 != nil {
		netFlow = ip4.(*layers.IPv4).NetworkFlow()
	} else if ip6 := packet.Layer(layers.LayerTypeIPv6); ip6 != nil {
		netFlow = ip6.(*layers.IPv6).NetworkFlow()
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp = tcpLayer.(*layers.TCP)
	}

	if tcp != nil && p.matchPort != 0 {
		if uint(tcp.SrcPort) != p.matchPort && uint(tcp.DstPort) != p.matchPort {
			return
		}
	}

	if netFlow == (gopacket.Flow{}) || tcp == nil {
		return
	}

	timestamp := time.Time{}
	if metadata := packet.Metadata(); metadata != nil {
		timestamp = metadata.Timestamp
	}

	p.assembler.AssembleWithTimestamp(netFlow, tcp, timestamp)
}

func (p *Processor) FlushOlderThan(t time.Time) {
	p.assembler.FlushOlderThan(t)
}

// FlushAll drains and closes every tracked stream. It gives each extractor a
// final chance to emit a hello that was still buffered when capture stopped,
// so shutdown does not drop idle streams.
func (p *Processor) FlushAll() {
	if p == nil || p.assembler == nil {
		return
	}
	p.assembler.FlushAll()
}

type tlsStreamFactory struct {
	onEvent        Handler
	onExtractError func(error)
}

func (f *tlsStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	return &tlsStream{
		net:            net,
		transport:      transport,
		onEvent:        f.onEvent,
		onExtractError: f.onExtractError,
	}
}

type tlsStream struct {
	net, transport gopacket.Flow
	extractor      tlshello.Extractor
	done           bool
	onEvent        Handler
	onExtractError func(error)
}

func (s *tlsStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	if s.done {
		return
	}

	for _, reassembly := range reassemblies {
		data := reassembly.Bytes
		if len(data) == 0 {
			continue
		}

		hello, err := s.extractor.Feed(data)
		if err != nil {
			s.done = true
			if s.onExtractError != nil {
				s.onExtractError(err)
			}
			return
		}
		if hello == nil {
			continue
		}

		s.handleHello(hello)
		return
	}
}

// ReassemblyComplete is called when the assembler closes or flushes the
// stream. Let the extractor force a final scan so a complete hello blocked by
// an incomplete false-positive candidate is still reported.
func (s *tlsStream) ReassemblyComplete() {
	if s.done {
		return
	}

	if hello := s.extractor.Finish(); hello != nil {
		s.handleHello(hello)
	}
}

func (s *tlsStream) handleHello(hello *tlshello.Hello) {
	s.done = true

	event := Event{
		NetFlow:       s.net,
		TransportFlow: s.transport,
		Hello:         hello,
	}

	if hello.Type == tlshello.ClientHello {
		// Parse the defragmented handshake message rather than the first
		// TLS record: a large ClientHello can span several records.
		fields, err := parser.ParseClientHelloHandshake(hello.HandshakeBytes, hello.RecordVersion)
		if err != nil {
			event.ParseError = err
		} else {
			event.Fields = fields

			ja4, err := fingerprint.BuildJA4(fields)
			if err != nil {
				event.FingerprintError = err
			} else {
				event.JA4 = &ja4
			}
		}
	}

	if s.onEvent != nil {
		s.onEvent(event)
	}
}
