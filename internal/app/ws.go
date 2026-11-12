package main

import (
	"encoding/binary"
	"fmt"
	"io"
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

func (p *wsParser) consume(b []byte) {
	if p.opcode&0x8 != 0 || p.msgOpcode != wsOpText || p.msgPacked || p.msgOver {
		p.pos += uint64(len(b))
		return
	}
	for i := range b {
		c := b[i]
		if p.masked {
			c ^= p.maskKey[(p.pos+uint64(i))&3]
		}
		if len(p.msg) >= wsMaxMessage {
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
	if p.onMsg != nil {
		m := wsMessage{opcode: p.msgOpcode, compressed: p.msgPacked, truncated: p.msgOver, frames: p.msgFrames}
		if p.msgOpcode == wsOpText && !p.msgPacked {
			m.data = append([]byte(nil), p.msg...)
		}
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
}

func newWSCollector(max int) *wsCollector { return &wsCollector{max: max} }

func (c *wsCollector) add(m wsMessage) {
	c.mu.Lock()
	defer c.mu.Unlock()
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
