package tlshello

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	recordHeaderLen    = 5
	handshakeHeaderLen = 4

	// maxBufferedBytes is the hard cap on undecided stream bytes per flow.
	maxBufferedBytes = 256 << 10

	// maxHelloBytes bounds how large one extracted handshake message may be.
	// Real ClientHellos are far smaller (typically < 8 KiB); larger
	// candidates are false positives and are skipped instead of buffered.
	maxHelloBytes = 64 << 10

	// maxScanAhead bounds how many alternative candidate offsets are tried
	// when an incomplete candidate blocks scanning, keeping the scan search
	// linear in the worst case.
	maxScanAhead = 64
)

type MessageType byte

const (
	ClientHello MessageType = 0x01
	ServerHello MessageType = 0x02
)

func (m MessageType) String() string {
	switch m {
	case ClientHello:
		return "CLIENT HELLO"
	case ServerHello:
		return "SERVER HELLO"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02x)", byte(m))
	}
}

type Hello struct {
	Type           MessageType
	RecordBytes    []byte
	HandshakeBytes []byte
	StreamOffset   int
	RecordVersion  uint16
}

type Extractor struct {
	buf        []byte
	streamBase int
	scanStart  int
	done       bool
}

var (
	errNotHelloRecord = errors.New("tls record does not contain a hello handshake")
	ErrBufferLimit    = errors.New("buffered stream exceeds tls hello extractor limit")
)

func (e *Extractor) Feed(data []byte) (*Hello, error) {
	if e.done {
		return nil, nil
	}

	if len(data) > 0 {
		e.buf = append(e.buf, data...)
	}

	hello, err := e.scan()
	if hello != nil || err != nil {
		if hello != nil {
			e.done = true
		}
		return hello, err
	}

	e.trim()
	if len(e.buf) > maxBufferedBytes {
		return nil, ErrBufferLimit
	}
	return nil, nil
}

// Finish forces a final scan over everything buffered so far, skipping
// incomplete candidates. It is meant to be called when the stream is closed
// or flushed and no more data can arrive, so a complete hello that was
// blocked behind a false-positive prefix can still be recovered.
func (e *Extractor) Finish() *Hello {
	if e.done {
		return nil
	}

	for i := 0; i < maxScanAhead; i++ {
		offset, ok := findHandshakeRecord(e.buf, e.scanStart)
		if !ok {
			return nil
		}

		hello, needMore, err := parseHello(e.buf[offset:])
		if err == nil && !needMore && hello != nil {
			hello.StreamOffset = e.streamBase + offset
			e.done = true
			return hello
		}

		e.scanStart = offset + 1
	}
	return nil
}

func (e *Extractor) scan() (*Hello, error) {
	for {
		offset, ok := findHandshakeRecord(e.buf, e.scanStart)
		if !ok {
			if len(e.buf) >= recordHeaderLen-1 {
				e.scanStart = len(e.buf) - (recordHeaderLen - 1)
			}
			return nil, nil
		}

		hello, needMore, err := parseHello(e.buf[offset:])
		if needMore {
			// A candidate that cannot be completed right now must not hide
			// a complete hello further in the buffer, for example a
			// false-positive 16 03 .. header followed by the real record.
			if aheadOffset, ahead := e.scanAhead(offset + 1); ahead != nil {
				ahead.StreamOffset = e.streamBase + aheadOffset
				return ahead, nil
			}

			// Bail out of candidates that stay unconsumed past any
			// plausible hello size so stream buffers cannot grow without
			// bound on repeated false positives.
			if len(e.buf)-offset > maxHelloBytes {
				e.scanStart = offset + 1
				continue
			}
			return nil, nil
		}

		if err != nil {
			if errors.Is(err, errNotHelloRecord) {
				e.scanStart = offset + 1
				continue
			}
			return nil, err
		}

		hello.StreamOffset = e.streamBase + offset
		return hello, nil
	}
}

// scanAhead looks for a complete hello starting after from. Incomplete or
// non-hello candidates are skipped. It is bounded by maxScanAhead so the
// worst-case scan stays linear.
func (e *Extractor) scanAhead(from int) (int, *Hello) {
	offset := from
	for i := 0; i < maxScanAhead; i++ {
		next, ok := findHandshakeRecord(e.buf, offset)
		if !ok {
			return -1, nil
		}

		hello, needMore, err := parseHello(e.buf[next:])
		if err == nil && !needMore && hello != nil {
			return next, hello
		}

		offset = next + 1
	}
	return -1, nil
}

// trim drops buffered bytes that can no longer start a record header. All
// returned hello data is copied, so dropping the prefix is safe.
func (e *Extractor) trim() {
	if e.scanStart <= 0 || e.scanStart > len(e.buf) {
		return
	}

	dropped := e.scanStart
	e.buf = append(e.buf[:0], e.buf[dropped:]...)
	e.streamBase += dropped
	e.scanStart = 0
}

func findHandshakeRecord(buf []byte, start int) (int, bool) {
	for i := start; i+recordHeaderLen <= len(buf); i++ {
		if looksLikeHandshakeRecord(buf[i:]) {
			return i, true
		}
	}
	return 0, false
}

// parseHello parses one hello handshake from the beginning of stream,
// concatenating the payloads of as many consecutive handshake records as the
// handshake message needs. The handshake header itself may be split across
// records. It returns needMore=true when stream is a valid prefix of a hello
// that is not complete yet.
func parseHello(stream []byte) (*Hello, bool, error) {
	var (
		rawEnd        int
		handshake     []byte
		needPayload   = -1
		helloType     MessageType
		recordVersion uint16
	)

	firstRecord := true
	for {
		if len(stream)-rawEnd < recordHeaderLen {
			return nil, true, nil
		}

		record := stream[rawEnd:]
		if !looksLikeHandshakeRecord(record) {
			// A hello that started in an earlier record cannot continue in
			// a record that is not a handshake record.
			return nil, false, errNotHelloRecord
		}

		if firstRecord {
			recordVersion = binary.BigEndian.Uint16(record[1:3])
			firstRecord = false
		}

		recordLen := int(binary.BigEndian.Uint16(record[3:5]))
		if len(record) < recordHeaderLen+recordLen {
			// Reject records that cannot fit any plausible hello instead of
			// waiting for up to 64 KiB of attacker-chosen padding.
			if len(stream)-rawEnd > maxHelloBytes {
				return nil, false, errNotHelloRecord
			}
			return nil, true, nil
		}

		payload := record[recordHeaderLen : recordHeaderLen+recordLen]

		if needPayload == -1 {
			if len(handshake)+len(payload) < handshakeHeaderLen {
				handshake = append(handshake, payload...)
				rawEnd += recordHeaderLen + recordLen
				continue
			}

			header := make([]byte, 0, handshakeHeaderLen)
			header = append(header, handshake...)
			header = append(header, payload[:handshakeHeaderLen-len(handshake)]...)

			helloType = MessageType(header[0])
			if helloType != ClientHello && helloType != ServerHello {
				return nil, false, errNotHelloRecord
			}

			needPayload = handshakeHeaderLen +
				int(header[1])<<16 +
				int(header[2])<<8 +
				int(header[3])
			if needPayload > maxHelloBytes {
				return nil, false, errNotHelloRecord
			}
		}

		take := recordLen
		if remaining := needPayload - len(handshake); take > remaining {
			take = remaining
		}

		handshake = append(handshake, payload[:take]...)
		// Track only the bytes that actually belong to this handshake:
		// trailing bytes of the final record are left out of RecordBytes.
		rawEnd += recordHeaderLen + take

		if len(handshake) >= needPayload {
			return &Hello{
				Type:           helloType,
				RecordBytes:    append([]byte(nil), stream[:rawEnd]...),
				HandshakeBytes: append([]byte(nil), handshake[:needPayload]...),
				RecordVersion:  recordVersion,
			}, false, nil
		}
	}
}

func looksLikeHandshakeRecord(buf []byte) bool {
	if len(buf) < recordHeaderLen {
		return false
	}
	if buf[0] != 0x16 {
		return false
	}
	if buf[1] != 0x03 {
		return false
	}
	if buf[2] > 0x04 {
		return false
	}
	return binary.BigEndian.Uint16(buf[3:5]) > 0
}
