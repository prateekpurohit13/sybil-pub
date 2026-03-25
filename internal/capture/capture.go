package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

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

type Source struct {
	backend string
	rd      *perf.Reader
	source  *gopacket.PacketSource
	closers []io.Closer
}

func Open(cfg config.Capture) (*Source, error) {
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

func (s *Source) NextPacket(ctx context.Context) (gopacket.Packet, error) {
	switch s.backend {
	case config.BackendEBPF:
		return s.readEBPFPacket()
	case config.BackendPCAP:
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

func (s *Source) Close() error {
	var errs []error
	for i := len(s.closers) - 1; i >= 0; i-- {
		if err := s.closers[i].Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
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

	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return fmt.Errorf("lookup interface %q: %w", cfg.Interface, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpTcpParser,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		return fmt.Errorf("attaching XDP: %w", err)
	}
	s.closers = append(s.closers, l)

	rd, err := perf.NewReader(objs.Events, osPageSize()*128)
	if err != nil {
		return fmt.Errorf("perf reader: %w", err)
	}
	s.rd = rd
	s.closers = append(s.closers, rd)

	return nil
}

func (s *Source) openPCAP(cfg config.Capture) error {
	handle, err := pcap.OpenLive(cfg.Interface, 65535, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open pcap on %s: %w", cfg.Interface, err)
	}
	s.closers = append(s.closers, closeFunc(func() error {
		handle.Close()
		return nil
	}))

	filter := "tcp"
	if cfg.MatchPort != 0 {
		filter = fmt.Sprintf("tcp and port %d", cfg.MatchPort)
	}
	if err := handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("set pcap filter %q: %w", filter, err)
	}

	s.source = gopacket.NewPacketSource(handle, handle.LinkType())
	s.source.NoCopy = true

	return nil
}

func (s *Source) readEBPFPacket() (gopacket.Packet, error) {
	for {
		record, err := s.rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return nil, ErrClosed
			}
			return nil, err
		}

		if record.LostSamples > 0 {
			return nil, fmt.Errorf("lost %d samples", record.LostSamples)
		}
		if len(record.RawSample) < 4 {
			continue
		}

		packetData := record.RawSample[4:]
		return gopacket.NewPacket(packetData, layers.LayerTypeEthernet, gopacket.Default), nil
	}
}

type closeFunc func() error

func (f closeFunc) Close() error {
	return f()
}
