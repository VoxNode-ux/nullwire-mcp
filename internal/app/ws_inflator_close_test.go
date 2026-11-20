package app

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestWSInflaterCloseIsSafe(t *testing.T) {
	var nilInflater *wsInflater
	nilInflater.Close() // must not panic

	z := newWSInflater(true, 1024)
	if out, _, ok := z.decode([]byte{0x4a, 0x4c, 0x4c, 0x04, 0x00}, false); !ok || string(out) != "aaa" { // "aaa", deflated
		t.Fatalf("decode before Close: got (%q, %v)", out, ok)
	}
	z.Close()
	z.Close()
	if z.fr != nil || z.window != nil {
		t.Error("Close left the reader or the dictionary behind")
	}
	if _, _, ok := z.decode([]byte{0x4a, 0x4c, 0x4c, 0x04, 0x00}, false); ok {
		t.Error("a closed inflater must not decode")
	}
}
// ---------------------------------------------------------------------------
// WebSocket parser, inflater and negotiation edge cases

func TestWSParserControlFramesAndBadHeaders(t *testing.T) {
	key := [4]byte{9, 8, 7, 6}
	// Ping, pong and close frames (masked and not) between text messages are
	// consumed without producing messages or breaking the parser.
	var stream []byte
	stream = append(stream, fxFrame(true, wsOpPing, []byte("hi"), true, key)...)
	stream = append(stream, fxFrame(true, wsOpPong, nil, false, key)...)
	stream = append(stream, fxFrame(true, wsOpText, []byte("one"), false, key)...)
	stream = append(stream, fxFrame(true, wsOpClose, []byte{0x03, 0xe8, 'b', 'y', 'e'}, true, key)...)
	stream = append(stream, fxFrame(true, wsOpText, []byte("two"), true, key)...)
	for _, chunk := range []int{len(stream), 1, 2} {
		c, p := fxParse(stream, chunk, 1<<20)
		if got := string(c.Bytes()); got != "[#1] one\n[#2] two\n" || p.Broken() {
			t.Errorf("chunk %d: text=%q broken=%v", chunk, got, p.Broken())
		}
	}

	// A frame with the top length bit set cannot be valid.
	huge := []byte{0x81, 127, 0x80, 0, 0, 0, 0, 0, 0, 0}
	if _, p := fxParse(huge, 3, 1<<20); !p.Broken() {
		t.Error("64-bit length with the top bit set must stop the parser")
	}
	// A control frame with a 16-bit length is too long to be one.
	longControl := []byte{0x89, 126, 0x00, 0x80}
	if _, p := fxParse(longControl, 1, 1<<20); !p.Broken() {
		t.Error("a long control frame must stop the parser")
	}
	for _, op := range []byte{0x3, 0x7, 0xb, 0xf} {
		if _, p := fxParse([]byte{0x80 | op, 0x00}, 1, 1<<20); !p.Broken() {
			t.Errorf("reserved opcode %#x must stop the parser", op)
		}
	}
	// Once broken, further bytes are ignored.
	c := newWSCollector(1 << 10)
	p := newWSParser(c.add)
	p.Feed([]byte{0x83, 0x00})
	p.Feed(fxFrame(true, wsOpText, []byte("late"), false, key))
	if !p.Broken() || len(c.Bytes()) != 0 {
		t.Errorf("broken parser kept reading: %q", c.Bytes())
	}
	// A parser without a callback still parses.
	q := newWSParser(nil)
	q.Feed(fxFrame(true, wsOpText, []byte("x"), false, key))
	if q.Broken() {
		t.Error("nil callback must be fine")
	}
	// A masked 64-bit-length frame.
	payload := []byte(strings.Repeat("m", 70000))
	c, p = fxParse(fxFrame(true, wsOpText, payload, true, key), 9999, 1<<20)
	if p.Broken() || len(c.Bytes()) != len("[#1] ")+70000+1 {
		t.Errorf("masked 64-bit frame: broken=%v len=%d", p.Broken(), len(c.Bytes()))
	}
}

func TestWSParserCompressedBinaryWithInflater(t *testing.T) {
	key := [4]byte{1, 1, 1, 1}
	bin := fxFrame(true, wsOpBinary, []byte{1, 2, 3}, false, key)
	bin[0] |= 0x40
	txt := deflateMessages(t, true, "after binary")[0]
	text := fxFrame(true, wsOpText, txt, false, key)
	text[0] |= 0x40

	// With context takeover a skipped compressed message desynchronises the decoder.
	c := newWSCollector(1 << 10)
	p := newWSParser(c.add)
	p.inflate = newWSInflater(true, 1<<10)
	fxFeed(p, append(append([]byte(nil), bin...), text...), 4)
	if p.inflate.dead != true || c.Summary() != "0 text, 0 binary, 2 compressed (unreadable)" {
		t.Errorf("takeover: dead=%v summary=%q", p.inflate.dead, c.Summary())
	}
	// Without context takeover the next message is still readable.
	fresh := deflateMessages(t, false, "after binary")[0]
	text = fxFrame(true, wsOpText, fresh, false, key)
	text[0] |= 0x40
	c = newWSCollector(1 << 10)
	p = newWSParser(c.add)
	p.inflate = newWSInflater(false, 1<<10)
	fxFeed(p, append(append([]byte(nil), bin...), text...), 4)
	if p.inflate.dead || string(c.Bytes()) != "[#1] after binary\n" {
		t.Errorf("no takeover: dead=%v text=%q", p.inflate.dead, c.Bytes())
	}
}

func TestWSInflaterDecodeEdges(t *testing.T) {
	// Garbage that is not deflate data switches the decoder off.
	z := newWSInflater(false, 1<<10)
	if _, _, ok := z.decode([]byte{0xff, 0xff, 0xff, 0xff, 0xff}, false); ok || !z.dead {
		t.Errorf("garbage: ok=%v dead=%v", ok, z.dead)
	}
	// A message that was already cut by the capture limit is flagged, and with
	// takeover it ends the decoder.
	msg := deflateMessages(t, true, "hello hello hello hello")[0]
	z = newWSInflater(true, 1<<10)
	if _, truncated, ok := z.decode(msg, true); !ok || !truncated || !z.dead {
		t.Errorf("cut message: ok=%v truncated=%v dead=%v", ok, truncated, z.dead)
	}
	// Without takeover the reader is reused for later messages.
	z = newWSInflater(false, 1<<10)
	for _, m := range []string{"first message here", "second message here"} {
		out, truncated, ok := z.decode(deflateMessages(t, false, m)[0], false)
		if !ok || truncated || string(out) != m {
			t.Errorf("%q: got %q ok=%v truncated=%v", m, out, ok, truncated)
		}
	}
	// With takeover the window is kept and trimmed to wsWindowSize.
	big := strings.Repeat("0123456789abcdef", 4096) // 64 KiB
	z = newWSInflater(true, 1<<20)
	if out, _, ok := z.decode(deflateMessages(t, true, big)[0], false); !ok || string(out) != big {
		t.Fatalf("big message: ok=%v len=%d", ok, len(out))
	}
	if len(z.window) != wsWindowSize {
		t.Errorf("window = %d bytes, want %d", len(z.window), wsWindowSize)
	}
	// skip only matters with takeover.
	z = newWSInflater(false, 10)
	z.skip()
	if z.dead {
		t.Error("skip must not stop a fresh-context decoder")
	}
	z = newWSInflater(true, 10)
	z.skip()
	if !z.dead {
		t.Error("skip must stop a takeover decoder")
	}
}

func TestParseDeflateNegotiationVariants(t *testing.T) {
	cases := []struct {
		in         []string
		found, sf, cf bool
	}{
		{[]string{"x-a, permessage-deflate; server_no_context_takeover"}, true, true, false},
		{[]string{" PERMESSAGE-DEFLATE ; Client_No_Context_Takeover ; server_no_context_takeover=1"}, true, true, true},
		{[]string{"permessage-deflate; server_max_window_bits=10"}, true, false, false},
		{[]string{"", ";", "permessage-deflatex"}, false, false, false},
		{[]string{"permessage-deflate", "permessage-deflate; client_no_context_takeover"}, true, false, true},
	}
	for _, c := range cases {
		found, sf, cf := parseDeflateNegotiation(c.in)
		if found != c.found || sf != c.sf || cf != c.cf {
			t.Errorf("%q: got %v %v %v, want %v %v %v", c.in, found, sf, cf, c.found, c.sf, c.cf)
		}
	}
}

type closeWriterRWC struct {
	closed, closedWrite bool
}

func (c *closeWriterRWC) Read(p []byte) (int, error)  { return copy(p, "abc"), nil }
func (c *closeWriterRWC) Write(p []byte) (int, error) { return len(p), nil }
func (c *closeWriterRWC) Close() error                { c.closed = true; return nil }
func (c *closeWriterRWC) CloseWrite() error           { c.closedWrite = true; return nil }

type plainRWC struct{ closed bool }

func (c *plainRWC) Read(p []byte) (int, error)  { return 0, io.EOF }
func (c *plainRWC) Write(p []byte) (int, error) { return len(p), nil }
func (c *plainRWC) Close() error                { c.closed = true; return nil }

func TestTapRWC(t *testing.T) {
	cw := &closeWriterRWC{}
	var seen []byte
	tap := &tapRWC{rwc: cw, onRead: func(b []byte) { seen = append(seen, b...) }}
	buf := make([]byte, 8)
	if n, _ := tap.Read(buf); n != 3 || string(seen) != "abc" {
		t.Errorf("read %d bytes, tap saw %q", n, seen)
	}
	if n, err := tap.Write([]byte("xyz")); n != 3 || err != nil {
		t.Errorf("Write = %d, %v", n, err)
	}
	_ = tap.CloseWrite()
	_ = tap.Close()
	if !cw.closedWrite || !cw.closed {
		t.Errorf("CloseWrite/Close not passed on: %+v", cw)
	}
	// Without CloseWrite support, CloseWrite closes the whole connection; a nil tap is fine.
	pr := &plainRWC{}
	tap = &tapRWC{rwc: pr}
	if n, err := tap.Read(buf); n != 0 || err != io.EOF {
		t.Errorf("Read = %d, %v", n, err)
	}
	if err := tap.CloseWrite(); !errors.Is(err, errNoHalfClose) {
		t.Errorf("CloseWrite without support = %v, want errNoHalfClose", err)
	}
	if pr.closed {
		t.Error("CloseWrite must not close the connection when half-close is unsupported")
	}
	cw2 := &closeWriterRWC{}
	tap = &tapRWC{rwc: cw2} // no onRead
	_, _ = tap.Read(buf)
}
