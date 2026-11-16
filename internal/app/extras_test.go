package app

import (
	"bytes"
	"compress/flate"
	"encoding/base32"
	"encoding/hex"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// -max-body

func TestParseMaxBody(t *testing.T) {
	ok := map[string]int{"": 0, "0": 0, "1m": 1 << 20, "1MiB": 1 << 20, "2mb": 2 << 20, "512k": 512 << 10, "64KiB": 64 << 10, "1048576": 1 << 20}
	for in, want := range ok {
		if got, err := parseMaxBody(in); err != nil || got != want {
			t.Errorf("parseMaxBody(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"3m", "-1", "abc", "16k", "1g", "2049k"} {
		if got, err := parseMaxBody(in); err == nil {
			t.Errorf("parseMaxBody(%q) = %d, want an error", in, got)
		}
	}
}

func TestLimitsOnlyRaise(t *testing.T) {
	d := limitsFor(0)
	if d.reqBody != maxReqBody || d.respBody != maxRespBody || d.reqCap != maxReqCapture || d.respCap != maxRespCapture || d.decoded != decodedLimit {
		t.Errorf("defaults changed: %+v", d)
	}
	l := limitsFor(1 << 20)
	if l.reqBody != 1<<20 || l.respBody != 1<<20 || l.reqCap < l.reqBody+scrubWindow || l.respCap < l.respBody+scrubWindow || l.decoded < l.respBody+scrubWindow {
		t.Errorf("1 MiB limits do not leave room for the scrub window: %+v", l)
	}
	if small := limitsFor(64 << 10); small.respBody != maxRespBody {
		t.Errorf("a value below a default must not lower it: %+v", small)
	}
	if (&App{}).limits() != d {
		t.Errorf("a zero App must have the defaults")
	}
}

func TestMaxBodyScrubsBeforeCutting(t *testing.T) {
	secret := "sk-" + strings.Repeat("A", 28)
	for _, maxBody := range []int{0, 1 << 20} {
		app := fxApp(t)
		app.maxBody = maxBody
		lim := app.limits()
		// The secret starts a few bytes before the stored limit, so a cut
		// before scrubbing would leave part of it in the stored text.
		body := strings.Repeat("a", lim.respBody-10) + " " + secret + strings.Repeat("b", 4096)
		e, ok := app.buildEntry(rawFlow{
			started: time.Now(), method: "GET", url: "http://h/x", status: 200,
			reqHeaders: http.Header{}, respHeaders: http.Header{}, respBody: []byte(body),
		})
		if !ok {
			t.Fatal("flow was ignored")
		}
		if strings.Contains(e.ResponseBody, "sk-AAAA") {
			t.Errorf("max-body %d: part of the secret was stored", maxBody)
		}
		if len(e.ResponseBody) > lim.respBody+len(truncMarker) {
			t.Errorf("max-body %d: stored %d bytes, limit %d", maxBody, len(e.ResponseBody), lim.respBody)
		}
		if len(e.ResponseBody) < lim.respBody-100 {
			t.Errorf("max-body %d: stored only %d bytes", maxBody, len(e.ResponseBody))
		}
	}
}

// ---------------------------------------------------------------------------
// Nested XML and CDATA

func TestScrubXMLTree(t *testing.T) {
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	pw := "hunter2hunter2"
	cases := []struct{ name, in, keep string }{
		{"nested", "<Credentials><Value>" + pw + "</Value><Type>Bearer</Type></Credentials>", "<Type>Bearer</Type>"},
		{"mixed", "<wsse:Password Type=\"x\">" + pw + "<Hint>h</Hint></wsse:Password>", ""},
		{"cdata in secret", "<Secret><![CDATA[" + pw + "]]></Secret>", ""},
		{"cdata document", "<data><![CDATA[<Password>" + pw + "</Password>]]></data>", "<data><![CDATA["},
		{"escaped", "<msg>&lt;Password&gt;" + pw + "&lt;/Password&gt;</msg>", "<msg>"},
	}
	for _, c := range cases {
		out, n := s.ScrubText(c.in)
		if n == 0 || strings.Contains(out, pw) {
			t.Errorf("%s: secret survived: %q", c.name, out)
		}
		if c.keep != "" && !strings.Contains(out, c.keep) {
			t.Errorf("%s: %q was lost: %q", c.name, c.keep, out)
		}
	}
	// Plain markup around a secret element is left exactly as it was.
	in := "<a><b>text</b><Password>" + pw + "</Password><c>more</c></a>"
	if out, _ := s.ScrubText(in); !strings.HasPrefix(out, "<a><b>text</b><Password>") || !strings.HasSuffix(out, "</Password><c>more</c></a>") {
		t.Errorf("surrounding markup changed: %q", out)
	}
	// A document that breaks off is not an error.
	if out, _ := s.ScrubText("<Credentials><Value>" + pw + "</Value><oops"); strings.Contains(out, pw) {
		t.Errorf("broken document: %q", out)
	}
}

// ---------------------------------------------------------------------------
// Hex, Base32 and Base58

func b58Encode(b []byte) string {
	n := new(big.Int).SetBytes(b)
	base, mod := big.NewInt(58), new(big.Int)
	var out []byte
	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		out = append(out, b58Alphabet[mod.Int64()])
	}
	for i := 0; i < len(b) && b[i] == 0; i++ {
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func TestScrubEncodedText(t *testing.T) {
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"password":"hunter2hunter2"}`)
	enc := map[string]string{
		"hex":    hex.EncodeToString(payload),
		"base32": base32.StdEncoding.EncodeToString(payload),
		"base58": b58Encode(payload),
	}
	for name, e := range enc {
		n := 0
		out := s.scrubEncodedText("x="+e+"&y=1", &n)
		if n != 1 || strings.Contains(out, e) || !strings.HasPrefix(out, "x=[REDACTED_") || !strings.HasSuffix(out, "&y=1") {
			t.Errorf("%s: n=%d out=%q", name, n, out)
		}
	}

	// Things that look like these encodings but hold no secret stay as they are.
	for name, in := range map[string]string{
		"hash":         strings.Repeat("ab", 32),
		"binary":       hex.EncodeToString([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}),
		"plain":        hex.EncodeToString([]byte("just some ordinary text")),
		"word":         "Internationalization",
		"base32 plain": base32.StdEncoding.EncodeToString([]byte("nothing secret in here")),
	} {
		n := 0
		if out := s.scrubEncodedText("v="+in, &n); n != 0 || out != "v="+in {
			t.Errorf("%s: changed to %q (n=%d)", name, out, n)
		}
	}

	// The same through the full pipeline.
	if out, n := s.ScrubText("data " + enc["hex"] + " end"); n == 0 || strings.Contains(out, enc["hex"]) {
		t.Errorf("full pipeline: %q", out)
	}
	if b, ok := decodeBase58Text(b58Encode(payload)); !ok || !bytes.Equal(b, payload) {
		t.Errorf("base58 round trip: %q %v", b, ok)
	}
}

// ---------------------------------------------------------------------------
// RingBuffer.Update

func TestRingUpdate(t *testing.T) {
	r := NewRingBuffer()
	id := r.Push(FlowEntry{URL: "a"})
	if !r.Update(id, func(e *FlowEntry) { e.URL = "b"; e.ID = 999 }) {
		t.Fatal("Update did not find a live entry")
	}
	if e, ok := r.GetByID(id); !ok || e.URL != "b" || e.ID != id {
		t.Errorf("after Update: %+v %v", e, ok)
	}
	for i := 0; i < ringCapacity; i++ {
		r.Push(FlowEntry{})
	}
	called := false
	if r.Update(id, func(*FlowEntry) { called = true }) || called {
		t.Error("Update must do nothing for an evicted entry")
	}
}

// ---------------------------------------------------------------------------
// Live WebSocket capture

func TestWSLiveRefresh(t *testing.T) {
	app := fxApp(t)
	up, down := newWSCollector(1<<16), newWSCollector(1<<16)
	flow := rawFlow{started: time.Now(), method: "GET", url: "http://h/ws", status: 101, reqHeaders: http.Header{}, respHeaders: http.Header{}}
	flow.note = wsLiveNote("websocket", up, down)
	id, ok := app.pushLive(flow)
	if !ok || app.ring.Len() != 1 {
		t.Fatal("the open socket must produce an entry at once")
	}
	stop, done := make(chan struct{}), make(chan struct{})
	go app.wsLiveLoop(id, flow, "websocket", up, down, stop, done)

	secret := "sk-" + strings.Repeat("A", 28)
	down.add(wsMessage{opcode: wsOpText, data: []byte("token " + secret)})
	var e FlowEntry
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if e, _ = app.ring.GetByID(id); strings.Contains(e.ResponseBody, "[REDACTED_") {
			break
		}
	}
	if strings.Contains(e.ResponseBody, secret) || !strings.Contains(e.ResponseBody, "token [REDACTED_") {
		t.Errorf("live refresh did not show the scrubbed message: %q", e.ResponseBody)
	}
	if !strings.Contains(e.Note, "still open") || !strings.Contains(e.Note, "server->client: 1 text") {
		t.Errorf("live note = %q", e.Note)
	}
	close(stop)
	<-done

	final := flow
	final.respBody = down.Bytes()
	final.note = "final"
	app.finishLive(id, final)
	if e, _ = app.ring.GetByID(id); e.Note != "final" || app.ring.Len() != 1 {
		t.Errorf("the final capture must replace the live entry: %+v (len %d)", e, app.ring.Len())
	}

	// Once the entry is evicted a refresh is a no-op, and the loop ends.
	stop2, done2 := make(chan struct{}), make(chan struct{})
	for i := 0; i < ringCapacity; i++ {
		app.ring.Push(FlowEntry{})
	}
	up.add(wsMessage{opcode: wsOpText, data: []byte("again")})
	go app.wsLiveLoop(id, flow, "websocket", up, down, stop2, done2)
	select {
	case <-done2:
	case <-time.After(5 * time.Second):
		t.Fatal("the refresher kept running after its entry was evicted")
	}
	if _, found := app.ring.GetByID(id); found {
		t.Error("an evicted entry came back")
	}
}

// ---------------------------------------------------------------------------
// permessage-deflate

// deflateMessages compresses messages with one shared compressor, as a
// connection with context takeover does, and returns each one without the
// 00 00 ff ff tail that the extension removes.
func deflateMessages(t *testing.T, takeover bool, msgs ...string) [][]byte {
	t.Helper()
	var out [][]byte
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if !takeover {
			buf.Reset()
			w.Reset(&buf)
		}
		buf.Reset()
		if _, err := w.Write([]byte(m)); err != nil {
			t.Fatal(err)
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		b := append([]byte(nil), buf.Bytes()...)
		if !bytes.HasSuffix(b, wsDeflateTail) {
			t.Fatalf("no sync tail on %q", m)
		}
		out = append(out, b[:len(b)-len(wsDeflateTail)])
	}
	return out
}

func TestWSDeflateDecode(t *testing.T) {
	key := [4]byte{5, 6, 7, 8}
	first := "the quick brown fox jumps over the lazy dog, the quick brown fox"
	second := "the quick brown fox jumps over the lazy dog again, " + first
	for _, takeover := range []bool{true, false} {
		packed := deflateMessages(t, takeover, first, second)
		var stream []byte
		for _, p := range packed {
			f := fxFrame(true, 0x1, p, true, key)
			f[0] |= 0x40 // RSV1
			stream = append(stream, f...)
		}
		c := newWSCollector(1 << 20)
		p := newWSParser(c.add)
		p.inflate = newWSInflater(takeover, 1<<20)
		fxFeed(p, stream, 3)
		want := "[#1] " + first + "\n[#2] " + second + "\n"
		if got := string(c.Bytes()); got != want || p.Broken() {
			t.Errorf("takeover=%v: text = %q, want %q", takeover, got, want)
		}
		if c.Summary() != "2 text, 0 binary" {
			t.Errorf("takeover=%v: summary %q", takeover, c.Summary())
		}
	}

	// Without an inflater a compressed message stays unreadable.
	f := fxFrame(true, 0x1, deflateMessages(t, true, first)[0], true, key)
	f[0] |= 0x40
	c := newWSCollector(1 << 20)
	fxFeed(newWSParser(c.add), f, 5)
	if c.Summary() != "0 text, 0 binary, 1 compressed (unreadable)" {
		t.Errorf("no inflater: %q", c.Summary())
	}
}

func TestWSInflateBombIsCapped(t *testing.T) {
	bomb := deflateMessages(t, false, strings.Repeat("a", 8<<20))[0]
	if len(bomb) > 64<<10 {
		t.Fatalf("test bomb is not small: %d bytes", len(bomb))
	}
	z := newWSInflater(false, 1024)
	out, truncated, ok := z.decode(bomb, false)
	if !ok || !truncated || len(out) != 1024 {
		t.Errorf("fresh messages: ok=%v truncated=%v len=%d", ok, truncated, len(out))
	}
	// With context takeover a message that was cut leaves the decoder
	// unsure of its dictionary, so it stops decoding.
	z = newWSInflater(true, 1024)
	if _, truncated, ok := z.decode(bomb, false); !ok || !truncated {
		t.Errorf("takeover: ok=%v truncated=%v", ok, truncated)
	}
	if _, _, ok := z.decode(deflateMessages(t, false, "hello hello hello")[0], false); ok {
		t.Error("a decoder that lost track must stay off")
	}
	// The total budget also stops a stream of many small bombs.
	z = newWSInflater(false, 1024)
	z.budget = 2048
	for i := 0; i < 2; i++ {
		z.decode(bomb, false)
	}
	if _, _, ok := z.decode(bomb, false); ok {
		t.Error("the decompression budget was not enforced")
	}
}

func TestParseDeflateNegotiation(t *testing.T) {
	cases := []struct {
		in                         []string
		found, serverFresh, client bool
	}{
		{nil, false, false, false},
		{[]string{"permessage-deflate"}, true, false, false},
		{[]string{"permessage-deflate; server_no_context_takeover; client_max_window_bits=15"}, true, true, false},
		{[]string{"x-other", "Permessage-Deflate; client_no_context_takeover"}, true, false, true},
		{[]string{"x-webkit-deflate-frame"}, false, false, false},
	}
	for _, c := range cases {
		found, sf, cf := parseDeflateNegotiation(c.in)
		if found != c.found || sf != c.serverFresh || cf != c.client {
			t.Errorf("%q: got %v %v %v", c.in, found, sf, cf)
		}
	}
}
