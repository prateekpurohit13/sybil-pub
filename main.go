package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	redis "github.com/redis/go-redis/v9"
	"github.com/sophic00/sybil/internal/capture"
	"github.com/sophic00/sybil/internal/config"
	"github.com/sophic00/sybil/internal/parser"
	"github.com/sophic00/sybil/internal/risk"
	"github.com/sophic00/sybil/internal/stream"
	"github.com/sophic00/sybil/internal/tlshello"
)

func main() {
	cfg := config.Parse()
	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	threatScorer, closeThreatScorer, err := newThreatScorer(ctx, cfg.Risk)
	if err != nil {
		log.Fatal(err)
	}
	defer closeThreatScorer()

	var helloOnce sync.Once
	onHello := func(hello *tlshello.Hello) {
		helloOnce.Do(func() {
			if cfg.Output.HelloOutPath != "" {
				if err := os.WriteFile(cfg.Output.HelloOutPath, hello.RecordBytes, 0o644); err != nil {
					log.Printf("write hello output: %v", err)
				}
			}
			if cfg.Output.ExitAfterHello {
				cancel()
			}
		})
	}

	processor := stream.NewProcessor(stream.Options{
		MatchPort: cfg.Capture.MatchPort,
		OnEvent: func(event stream.Event) {
			if event.Hello == nil {
				return
			}

			printHelloEvent(event)
			assessClientHello(ctx, threatScorer, event)
			onHello(event.Hello)
		},
	})

	source, err := capture.Open(cfg.Capture)
	if err != nil {
		log.Fatal(err)
	}
	defer source.Close()

	fmt.Printf("Capturing TCP on %s using %s backend... (Ctrl+C to stop)\n", cfg.Capture.Interface, cfg.Capture.Backend)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(time.Second * 1)
	defer ticker.Stop()

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
			processor.FlushOlderThan(time.Now().Add(-time.Second * 3))
		default:
			packet, err := source.NextPacket(ctx)
			if err != nil {
				if errors.Is(err, capture.ErrClosed) || errors.Is(err, context.Canceled) {
					return
				}
				log.Printf("capture read failed: %v", err)
				continue
			}
			processor.ProcessPacket(packet)
		}
	}
}

func newThreatScorer(ctx context.Context, cfg config.Risk) (*risk.Scorer, func(), error) {
	if cfg.RedisAddr == "" {
		return nil, func() {}, nil
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})

	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, func() {}, fmt.Errorf("redis ping failed: %w", err)
	}

	riskCfg := risk.DefaultConfig()
	riskCfg.UseHostFallback = cfg.UseHostFallback

	store := risk.NewRedisStore(rdb, cfg.KeyPrefix)
	var lookup risk.LookupClient
	if cfg.JA4LookupURL != "" {
		lookup = risk.NewHTTPLookupClient(cfg.JA4LookupURL, &http.Client{Timeout: cfg.JA4LookupTimeout})
	}

	return risk.NewScorer(store, lookup, riskCfg), func() { _ = rdb.Close() }, nil
}

func printHelloEvent(event stream.Event) {
	fmt.Printf("\n--- Detected TLS %s (%s:%s -> %s:%s) ---\n",
		event.Hello.Type, event.NetFlow.Src(), event.TransportFlow.Src(), event.NetFlow.Dst(), event.TransportFlow.Dst())
	fmt.Printf("record_bytes=%d handshake_bytes=%d stream_offset=%d\n",
		len(event.Hello.RecordBytes), len(event.Hello.HandshakeBytes), event.Hello.StreamOffset)
	fmt.Println(hex.Dump(event.Hello.RecordBytes))

	if event.Hello.Type != tlshello.ClientHello {
		return
	}

	if event.ParseError != nil {
		fmt.Printf("ClientHello parse error: %v\n", event.ParseError)
		return
	}

	fields := event.Fields
	fmt.Println("Parsed ClientHello Fields:")
	fmt.Printf("  protocol            : %s\n", fields.Protocol)
	fmt.Printf("  tls_version         : %s\n", parser.TLSVersionString(fields.TLSVersion))
	fmt.Printf("  record_version      : %s\n", parser.TLSVersionString(fields.RecordVersion))
	fmt.Printf("  hello_version       : %s\n", parser.TLSVersionString(fields.HelloVersion))
	fmt.Printf("  sni_type            : %s\n", fields.SNIType)
	fmt.Printf("  sni_hostname        : %s\n", fields.SNIHost)
	fmt.Printf("  cipher_count        : %d\n", fields.CipherCount)
	fmt.Printf("  extension_count     : %d\n", fields.ExtensionCount)
	fmt.Printf("  alpn_first          : %s\n", fields.FirstALPN)

	if event.FingerprintError != nil {
		fmt.Printf("JA4 build error: %v\n", event.FingerprintError)
		return
	}

	ja4 := event.JA4
	fmt.Printf("  ja4_a               : %s\n", ja4.A)
	fmt.Printf("  ja4_b               : %s\n", ja4.B)
	fmt.Printf("  ja4_c               : %s\n", ja4.C)
	fmt.Printf("JA4: %s\n", ja4.Fingerprint)
}

func assessClientHello(ctx context.Context, threatScorer *risk.Scorer, event stream.Event) {
	if threatScorer == nil || event.Fields == nil || event.JA4 == nil {
		return
	}

	assessment, err := threatScorer.Assess(ctx, risk.Observation{
		JA4:       event.JA4.Fingerprint,
		SourceIP:  event.NetFlow.Src().String(),
		Hostname:  event.Fields.SNIHost,
		Timestamp: time.Now(),
	})
	if err != nil {
		log.Printf("risk assessment failed for %s: %v", event.JA4.Fingerprint, err)
		return
	}

	fmt.Printf("Threat Score: %d/100 action=%s", assessment.Score, assessment.Action)
	if assessment.Delay > 0 {
		fmt.Printf(" delay=%s", assessment.Delay)
	}
	fmt.Println()
	for _, component := range assessment.Components {
		fmt.Printf("  %-20s %2d/%-2d %s\n", component.Name+":", component.Score, component.Weight, component.Detail)
	}
	if assessment.LookupError != "" {
		fmt.Printf("  lookup_error         %s\n", assessment.LookupError)
	}
}
