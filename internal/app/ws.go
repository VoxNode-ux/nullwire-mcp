package app

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"sync"
)

// WebSocket support is capture-only. The proxy forwards every byte untouched;
// a read-only copy of each direction is fed to a wsParser, which reassembles
// text messages for the flow record. Nothing here ever changes what is sent.

const (
	wsOpContinuation = 0x0
	wsOpText         = 0x1
	wsOpBinary       = 0x2
	wsOpClose        = 0x8
	wsOpPing         = 0x9
	wsOpPong         = 0xA

	// wsMaxMessage is how much of one message is kept; the rest of a longer
	// message is skipped, never buffered.
	wsMaxMessage = maxRespBody + scrubWindow
)

// wsMessage is one complete WebSocket message.
type wsMessage struct {
	opcode     byte
	data       []byte // text messages only
	compressed bool   // RSV1 set: unreadable without the compression state
	truncated  bool   // data was cut at wsMaxMessage
	frames     int
}

// wsParser is an incremental RFC 6455 frame reader. Feed accepts bytes in any
// chunking and must be called from a single goroutine. Bytes that do not form
// a valid frame sequence switch the parser off; forwarding is unaffected.
type wsParser struct {
	onMsg func(wsMessage)

	// maxMsg is how much of one message is kept; zero means wsMaxMessage.
	maxMsg int
	// inflate decodes permessage-deflate messages (-ws-deflate). Without it a
	// message with RSV1 set is counted as compressed and left unread.
	inflate *wsInflater

	hdr     [14]byte
	hdrHave int
	hdrNeed int

	inPayload bool
	opcode    byte
	fin       bool
	masked    bool
	maskKey   [4]byte
	remain    uint64
	pos       uint64

	msgOpcode byte
	msgPacked bool
	msgOver   bool
	msgFrames int
	msg       []byte

	broken bool
}

func newWSParser(onMsg func(wsMessage)) *wsParser { return &wsParser{onMsg: onMsg} }

// Feed parses b. It never blocks and never retains b.
func (p *wsParser) Feed(b []byte) {
	for len(b) > 0 && !p.broken {
		if !p.inPayload {
			b = p.gatherHeader(b)
			continue
		}
		take := uint64(len(b))
		if take > p.remain {
			take = p.remain
		}
		p.consume(b[:take])
		b = b[take:]
		p.remain -= take
		if p.remain == 0 {
			p.endFrame()
		}
	}
}

// Broken reports whether the stream stopped parsing as WebSocket. Read it only
// after the connection has finished.
func (p *wsParser) Broken() bool { return p.broken }

func (p *wsParser) gatherHeader(b []byte) []byte {
	for len(b) > 0 {
		p.hdr[p.hdrHave] = b[0]
		p.hdrHave++
		b = b[1:]
		if p.hdrHave == 2 {
			need := 2
			switch p.hdr[1] & 0x7f {
			case 126:
				need += 2
			case 127:
				need += 8
			}
			if p.hdr[1]&0x80 != 0 {
				need += 4
			}
			p.hdrNeed = need
		}
		if p.hdrNeed != 0 && p.hdrHave == p.hdrNeed {
			if !p.startFrame() {
				p.broken = true
			}
			return b
		}
	}
	return b
}

// startFrame decodes a complete header. It returns false when the bytes cannot
// be a valid frame sequence.
func (p *wsParser) startFrame() bool {
	b0, b1 := p.hdr[0], p.hdr[1]
	p.fin = b0&0x80 != 0
	if b0&0x30 != 0 { // RSV2 and RSV3 are never negotiated
		return false
	}
	rsv1 := b0&0x40 != 0
	p.opcode = b0 & 0x0f
	p.masked = b1&0x80 != 0
	length := uint64(b1 & 0x7f)
	off := 2
	switch length {
	case 126:
		length = uint64(binary.BigEndian.Uint16(p.hdr[2:4]))
		off = 4
	case 127:
		length = binary.BigEndian.Uint64(p.hdr[2:10])
		off = 10
	}
	if length>>63 != 0 {
		return false
	}
	if p.masked {
		copy(p.maskKey[:], p.hdr[off:off+4])
	}
	control := p.opcode&0x8 != 0
	switch {
	case p.opcode > wsOpBinary && p.opcode < wsOpClose, p.opcode > wsOpPong:
		return false // reserved opcode
	case control && (!p.fin || length > 125):
		return false // control frames are never fragmented or long
	}
	if !control {
		if p.opcode == wsOpContinuation {
			if p.msgOpcode == 0 {
				return false // a continuation with nothing to continue
			}
			p.msgFrames++
		} else {
			if p.msgOpcode != 0 {
				return false // a new message before the last one finished
			}
			p.msgOpcode = p.opcode
			p.msgPacked = rsv1
			p.msgOver = false
			p.msgFrames = 1
			p.msg = p.msg[:0]
		}
	}
	p.remain, p.pos, p.inPayload = length, 0, true
	if length == 0 {
		p.endFrame()
	}
	return true
}

func (p *wsParser) msgLimit() int {
	if p.maxMsg > 0 {
		return p.maxMsg
	}
	return wsMaxMessage
}

func (p *wsParser) consume(b []byte) {
	if p.opcode&0x8 != 0 || p.msgOpcode != wsOpText || (p.msgPacked && p.inflate == nil) || p.msgOver {
		p.pos += uint64(len(b))
		return
	}
	limit := p.msgLimit()
	for i := range b {
		c := b[i]
		if p.masked {
			c ^= p.maskKey[(p.pos+uint64(i))&3] // #nosec G115 -- i is a non-negative index into b
		}
		if len(p.msg) >= limit {
			p.msgOver = true
			break
		}
		p.msg = append(p.msg, c)
	}
	p.pos += uint64(len(b))
}

func (p *wsParser) endFrame() {
	p.inPayload = false
	p.hdrHave, p.hdrNeed = 0, 0
	if p.opcode&0x8 != 0 || !p.fin {
		return // a control frame, or the message continues
	}
	m := wsMessage{opcode: p.msgOpcode, compressed: p.msgPacked, truncated: p.msgOver, frames: p.msgFrames}
	switch {
	case p.msgPacked && p.inflate != nil && p.msgOpcode == wsOpText:
		// p.msg holds the compressed bytes of the whole message.
		if data, cut, ok := p.inflate.decode(p.msg, p.msgOver); ok {
			m.data, m.compressed, m.truncated = data, false, cut
		}
	case p.msgPacked && p.inflate != nil:
		p.inflate.skip() // a compressed message that is not decoded
	case p.msgOpcode == wsOpText && !p.msgPacked:
		m.data = append([]byte(nil), p.msg...)
	}
	if p.onMsg != nil {
		p.onMsg(m)
	}
	p.msgOpcode, p.msgPacked, p.msgOver, p.msgFrames = 0, false, false, 0
	p.msg = p.msg[:0]
}

// wsCollector gathers the text messages of one direction of one connection
// into a single bounded block of text, one message per line.
type wsCollector struct {
	mu        sync.Mutex
	buf       []byte
	max       int
	text      int
	binary    int
	packed    int
	truncated int // messages cut short, by the per-message or the total limit
	dropped   int // messages left out because the total limit was reached
	version   uint64
}

func newWSCollector(maxBytes int) *wsCollector { return &wsCollector{max: maxBytes} }

func (c *wsCollector) add(m wsMessage) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.version++
	switch {
	case m.compressed:
		c.packed++
	case m.opcode == wsOpBinary:
		c.binary++
	case m.opcode == wsOpText:
		c.text++
		line := fmt.Sprintf("[#%d] %s\n", c.text, m.data)
		room := c.max - len(c.buf)
		if room <= 0 {
			c.dropped++
			return
		}
		cut := m.truncated
		if len(line) > room {
			line = line[:room]
			cut = true
		}
		if cut {
			c.truncated++
		}
		c.buf = append(c.buf, line...)
	}
}

// Version counts the messages seen so far, so a reader can tell whether
// anything changed since it last looked.
func (c *wsCollector) Version() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.version
}

// Bytes returns the collected text, unscrubbed; capture() scrubs it.
func (c *wsCollector) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf...)
}

// Summary describes what was seen, for the flow note.
func (c *wsCollector) Summary() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := fmt.Sprintf("%d text, %d binary", c.text, c.binary)
	if c.packed > 0 {
		s += fmt.Sprintf(", %d compressed (unreadable)", c.packed)
	}
	if c.truncated > 0 {
		s += fmt.Sprintf(", %d cut short", c.truncated)
	}
	if c.dropped > 0 {
		s += fmt.Sprintf(", %d left out (capture full)", c.dropped)
	}
	return s
}

// tapRWC passes everything through and also hands each chunk it reads to
// onRead. onRead must not retain the slice and must not block.
type tapRWC struct {
	rwc    io.ReadWriteCloser
	onRead func([]byte)
}

func (t *tapRWC) Read(p []byte) (int, error) {
	n, err := t.rwc.Read(p)
	if n > 0 && t.onRead != nil {
		t.onRead(p[:n])
	}
	return n, err
}

func (t *tapRWC) Write(p []byte) (int, error) { return t.rwc.Write(p) }
func (t *tapRWC) Close() error                { return t.rwc.Close() }

func (t *tapRWC) CloseWrite() error {
	if cw, ok := t.rwc.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return t.rwc.Close()
}

// ---------------------------------------------------------------------------
// permessage-deflate (RFC 7692), used only with -ws-deflate.

const (
	// wsWindowSize is the largest back-reference window deflate can use.
	wsWindowSize = 32 * 1024
	// wsInflateBudget is the most text one direction of one connection is
	// decompressed to in total. Together with the per-message limit it bounds
	// what a compression bomb can cost.
	wsInflateBudget = 16 * 1024 * 1024
)

// wsDeflateTail is the empty block that every permessage-deflate message has
// cut off its end and that the decoder needs to see again.
var wsDeflateTail = []byte{0x00, 0x00, 0xff, 0xff}

// wsInflater decodes the compressed messages of one direction of a connection.
// It has one flate reader for the whole connection, as the extension requires
// when context takeover is on: every message may refer to the text of the
// messages before it, so the last 32 KiB of output are kept as the dictionary
// of the next message. A decoder that can no longer be trusted to be in step
// (a message was cut, was not decoded, or was bigger than the limit) switches
// itself off and the messages after that are counted as unreadable.
type wsInflater struct {
	takeover bool // false: each message is compressed on its own
	maxOut   int  // most text kept from one message
	budget   int  // text that may still be decompressed on this connection
	window   []byte
	fr       io.ReadCloser
	dead     bool
}

func newWSInflater(takeover bool, maxOut int) *wsInflater {
	return &wsInflater{takeover: takeover, maxOut: maxOut, budget: wsInflateBudget}
}

// Close releases the flate reader and the dictionary when the connection is
// over, instead of leaving them to the garbage collector. It is safe on a nil
// inflater and safe to call twice; the decoder is off afterwards.
func (z *wsInflater) Close() {
	if z == nil {
		return
	}
	if z.fr != nil {
		_ = z.fr.Close()
		z.fr = nil
	}
	z.dead, z.window = true, nil
}

// skip is called for a compressed message that is not decoded (binary). With
// context takeover the next message may depend on it, so the decoder stops.
func (z *wsInflater) skip() {
	if z.takeover {
		z.dead = true
	}
}

// decode inflates one message. cut says the compressed bytes were already cut
// short. The result is at most maxOut bytes: the reader stops there instead
// of expanding a compression bomb. truncated says the text is not complete.
func (z *wsInflater) decode(payload []byte, cut bool) (out []byte, truncated, ok bool) {
	if z.dead || z.budget <= 0 {
		z.dead = true
		return nil, false, false
	}
	src := io.MultiReader(bytes.NewReader(payload), bytes.NewReader(wsDeflateTail))
	var dict []byte
	if z.takeover {
		dict = z.window
	}
	if z.fr == nil {
		z.fr = flate.NewReaderDict(src, dict)
	} else if err := z.fr.(flate.Resetter).Reset(src, dict); err != nil {
		z.dead = true
		return nil, false, false
	}
	out, err := io.ReadAll(io.LimitReader(z.fr, int64(z.maxOut)+1))
	if len(out) > z.maxOut {
		out, truncated = out[:z.maxOut], true
	}
	z.budget -= len(out)
	clean := err == nil || err == io.ErrUnexpectedEOF // the message ends where the input does
	if !clean && len(out) == 0 {
		z.dead = true
		return nil, false, false
	}
	if z.takeover && (!clean || truncated || cut) {
		z.dead = true // the dictionary for the next message would be wrong
	}
	if z.takeover && !z.dead {
		w := append(z.window, out...)
		if len(w) > wsWindowSize {
			w = w[len(w)-wsWindowSize:]
		}
		z.window = append(make([]byte, 0, len(w)), w...)
	}
	return out, truncated || cut || !clean, true
}

// parseDeflateNegotiation reads the server's Sec-WebSocket-Extensions answer.
// found says permessage-deflate was agreed. serverFresh and clientFresh say
// that side starts every message with an empty dictionary (no context
// takeover).
func parseDeflateNegotiation(values []string) (found, serverFresh, clientFresh bool) {
	for _, v := range values {
		for _, ext := range strings.Split(v, ",") {
			parts := strings.Split(ext, ";")
			if strings.ToLower(strings.TrimSpace(parts[0])) != "permessage-deflate" {
				continue
			}
			found = true
			for _, prm := range parts[1:] {
				switch strings.ToLower(strings.TrimSpace(strings.SplitN(prm, "=", 2)[0])) {
				case "server_no_context_takeover":
					serverFresh = true
				case "client_no_context_takeover":
					clientFresh = true
				}
			}
		}
	}
	return found, serverFresh, clientFresh
}