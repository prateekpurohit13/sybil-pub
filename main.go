package main

import (
        "context"
        "encoding/hex"
        "errors"
        "flag"
        "fmt"
        "log"
        "net"
        "os"
        "os/signal"
        "syscall"
        "time"

        "github.com/cilium/ebpf/link"
        "github.com/cilium/ebpf/perf"
        "github.com/cilium/ebpf/rlimit"
        "github.com/google/gopacket"
        "github.com/google/gopacket/layers"
        "github.com/google/gopacket/tcpassembly"
        "github.com/sophic00/sybil/ebpf"
)

var (
        ifaceName = flag.String("iface", "lo", "Interface to attach XDP program to")
        logFile   = flag.String("log", "traffic.log", "Log file for non-TLS traffic")
)

type tlsStreamFactory struct {
        logger *log.Logger
}

func (f *tlsStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
        return &tlsStream{net: net, transport: transport, factory: f}
}

type tlsStream struct {
        net, transport gopacket.Flow
        factory        *tlsStreamFactory
        started        bool
}

func (s *tlsStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
        for _, reassembly := range reassemblies {
                data := reassembly.Bytes
                if len(data) == 0 {
                        continue
                }

                if !s.started {
                        // Find TLS Client/Server Hello in the first chunk
                        found := false
                        for i := 0; i <= len(data)-6 && i < 64; i++ {
                                if data[i] == 0x16 && data[i+1] == 0x03 {
                                        handshakeType := data[i+5]
                                        msg := ""
                                        if handshakeType == 0x01 {
                                                msg = "CLIENT HELLO"
                                        } else if handshakeType == 0x02 {
                                                msg = "SERVER HELLO"
                                        }

                                        if msg != "" {
                                                fmt.Printf("\n--- Detected TLS %s (%s:%s -> %s:%s) ---\n",
                                                        msg, s.net.Src(), s.transport.Src(), s.net.Dst(), s.transport.Dst())
                                                fmt.Println(hex.Dump(data[i:]))
                                                found = true
                                                s.started = true
                                                break
                                        }
                                }
                        }

                        if !found {
                                s.started = true
                                s.factory.logger.Printf("New Stream (No TLS header): %s:%s -> %s:%s\nData:\n%s",
                                        s.net.Src(), s.transport.Src(), s.net.Dst(), s.transport.Dst(), hex.Dump(data))
                        }
                } else {
                        s.factory.logger.Printf("Data (%s:%s -> %s:%s):\n%s",
                                s.net.Src(), s.transport.Src(), s.net.Dst(), s.transport.Dst(), hex.Dump(data))
                }
        }
}

func (s *tlsStream) ReassemblyComplete() {}

func main() {
        flag.Parse()

        // 1. Increase RLIMIT_MEMLOCK
        if err := rlimit.RemoveMemlock(); err != nil {
                log.Fatalf("failed to remove memlock: %v", err)
        }

        // 2. Load eBPF objects
        var objs ebpf.XdpTcpObjects
        if err := ebpf.LoadXdpTcpObjects(&objs, nil); err != nil {
                log.Fatalf("loading objects: %v", err)
        }
        defer objs.Close()

        // 3. Attach XDP program to the interface
        iface, err := net.InterfaceByName(*ifaceName)
        if err != nil {
                log.Fatalf("lookup interface %q: %v", *ifaceName, err)
        }

        l, err := link.AttachXDP(link.XDPOptions{
                Program:   objs.XdpTcpParser,
                Interface: iface.Index,
                Flags:     link.XDPGenericMode,
        })
        if err != nil {
                log.Fatalf("attaching XDP: %v", err)
        }
        defer l.Close()

        // 4. Setup perf reader
        rd, err := perf.NewReader(objs.Events, os.Getpagesize()*128)
        if err != nil {
                log.Fatalf("perf reader: %v", err)
        }
        defer rd.Close()

        // 5. Setup log file for non-TLS traffic
        f, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil {
                log.Fatalf("opening log file: %v", err)
        }
        defer f.Close()

        streamFactory := &tlsStreamFactory{logger: log.New(f, "", log.LstdFlags)}
        pool := tcpassembly.NewStreamPool(streamFactory)
        assembler := tcpassembly.NewAssembler(pool)

        fmt.Printf("Capturing TCP on %s... (Ctrl+C to stop)\n", *ifaceName)
        sig := make(chan os.Signal, 1)
        signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

        ticker := time.NewTicker(time.Second * 1)
        defer ticker.Stop()

        ctx, cancel := context.WithCancel(context.Background())
        defer cancel()

        go func() {
                <-sig
                cancel()
        }()

        for {
                select {
                case <-ctx.Done():
                        return
                case <-ticker.C:
                        // Periodically flush old streams to trigger reassembly
                        assembler.FlushOlderThan(time.Now().Add(-time.Second * 3))
                default:
                        record, err := rd.Read()
                        if err != nil {
                                if errors.Is(err, perf.ErrClosed) { return }
                                continue
                        }

                        if record.LostSamples > 0 {
                                log.Printf("lost %d samples", record.LostSamples)
                                continue
                        }
                        if len(record.RawSample) < 4 { continue }

                        // Skip the 4-byte dummy metadata to get the raw Ethernet frame
                        packetData := record.RawSample[4:]
                        packet := gopacket.NewPacket(packetData, layers.LayerTypeEthernet, gopacket.Default)

                        var netFlow gopacket.Flow
                        var tcp *layers.TCP

                        if ip4 := packet.Layer(layers.LayerTypeIPv4); ip4 != nil {
                                netFlow = ip4.(*layers.IPv4).NetworkFlow()
                        } else if ip6 := packet.Layer(layers.LayerTypeIPv6); ip6 != nil {
                                netFlow = ip6.(*layers.IPv6).NetworkFlow()
                        }

                        if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
                                tcp = tcpLayer.(*layers.TCP)
                        }

                        if netFlow != (gopacket.Flow{}) && tcp != nil {
                                assembler.AssembleWithTimestamp(netFlow, tcp, packet.Metadata().Timestamp)
                        }
                }
        }
}
