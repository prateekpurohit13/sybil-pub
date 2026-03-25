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
}

type Processor struct {
	matchPort uint
	assembler *tcpassembly.Assembler
}

func NewProcessor(opts Options) *Processor {
	streamFactory := &tlsStreamFactory{onEvent: opts.OnEvent}
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

type tlsStreamFactory struct {
	onEvent Handler
}

func (f *tlsStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	return &tlsStream{
		net:       net,
		transport: transport,
		onEvent:   f.onEvent,
	}
}

type tlsStream struct {
	net, transport gopacket.Flow
	extractor      tlshello.Extractor
	done           bool
	onEvent        Handler
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
			return
		}
		if hello == nil {
			continue
		}

		event := Event{
			NetFlow:       s.net,
			TransportFlow: s.transport,
			Hello:         hello,
		}

		if hello.Type == tlshello.ClientHello {
			fields, err := parser.ParseClientHello(hello.RecordBytes)
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
		s.done = true
		return
	}
}

func (s *tlsStream) ReassemblyComplete() {}
