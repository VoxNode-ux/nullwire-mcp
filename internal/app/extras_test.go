package app

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"encoding/hex"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
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

// ---------------------------------------------------------------------------
// body decoding, MCP errors

func exGzip(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestDecodeBodyMaxCut(t *testing.T) {
	var zl, fl bytes.Buffer
	zw := zlib.NewWriter(&zl)
	_, _ = zw.Write([]byte("hello world"))
	_ = zw.Close()
	fw, _ := flate.NewWriter(&fl, flate.DefaultCompression)
	_, _ = fw.Write([]byte("hello world"))
	_ = fw.Close()
	gz := exGzip(t, "hello world")

	cases := []struct {
		name  string
		ce    string
		in    []byte
		limit int
		text  string
		cut   bool
		ok    bool
	}{
		{"gzip", "gzip", gz, 1 << 10, "hello world", false, true},
		{"x-gzip", "x-gzip", gz, 1 << 10, "hello world", false, true},
		{"mixed case with spaces", " GZIP ", gz, 1 << 10, "hello world", false, true},
		{"identity is ignored", "identity, gzip", gz, 1 << 10, "hello world", false, true},
		{"zlib deflate", "deflate", zl.Bytes(), 1 << 10, "hello world", false, true},
		{"raw deflate", "deflate", fl.Bytes(), 1 << 10, "hello world", false, true},
		{"cut at the limit", "gzip", gz, 5, "hello", true, true},
		{"exactly the limit counts as cut", "gzip", gz, 11, "hello world", true, true},
		{"empty gzip body", "gzip", exGzip(t, ""), 1 << 10, "", false, true},
		{"brotli is not decoded", "br", []byte("x"), 1 << 10, "", false, false},
		{"unknown encoding", "snappy", []byte("x"), 1 << 10, "", false, false},
		{"no encoding", "", []byte("x"), 1 << 10, "", false, false},
		{"not gzip", "gzip", []byte("plain text"), 1 << 10, "", false, false},
		{"gzip header and nothing else", "gzip", gz[:10], 1 << 10, "", false, false},
	}
	for _, c := range cases {
		text, cut, ok := decodeBodyMaxCut(c.ce, c.in, c.limit)
		if text != c.text || cut != c.cut || ok != c.ok {
			t.Errorf("%s: got (%q, %v, %v), want (%q, %v, %v)", c.name, text, cut, ok, c.text, c.cut, c.ok)
		}
	}

	// A stream cut short still gives what was decoded, marked as cut.
	long := exGzip(t, strings.Repeat("abcdefghij", 30000))
	text, cut, ok := decodeBodyMaxCut("gzip", long[:len(long)/2], 1<<20)
	if !ok || !cut || len(text) == 0 {
		t.Errorf("truncated stream: (%d bytes, %v, %v)", len(text), cut, ok)
	}
}

func TestDecodeBodyMaxAndHelpers(t *testing.T) {
	gz := exGzip(t, "hello world")
	if text, ok := decodeBodyMax("gzip", gz, 5); !ok || text != "hello"+truncMarker {
		t.Errorf("cut body: (%q, %v)", text, ok)
	}
	if text, ok := decodeBodyMax("gzip", gz, 100); !ok || text != "hello world" {
		t.Errorf("whole body: (%q, %v)", text, ok)
	}
	if _, ok := decodeBodyMax("br", gz, 100); ok {
		t.Error("br must not decode")
	}

	for ce, want := range map[string]bool{"gzip": true, "X-Gzip": true, " deflate ": true, "br": false, "zstd": false, "": false} {
		if got := decodableEncoding(ce); got != want {
			t.Errorf("decodableEncoding(%q) = %v, want %v", ce, got, want)
		}
	}
	for in, want := range map[string]string{"identity": "", "identity, gzip": "gzip", " gzip , br ": "gzip, br", "": "", ",,": "", "Identity": ""} {
		if got := effectiveContentEncoding(in); got != want {
			t.Errorf("effectiveContentEncoding(%q) = %q, want %q", in, got, want)
		}
	}
	h := http.Header{}
	h.Add("Content-Encoding", "identity")
	h.Add("Content-Encoding", "gzip")
	if got := joinedContentEncoding(h); got != "identity, gzip" {
		t.Errorf("joinedContentEncoding = %q", got)
	}

	if got := bodyTextMax(h, gz, 1<<10); got != "hello world" {
		t.Errorf("gzip body: %q", got)
	}
	br := http.Header{"Content-Encoding": {"br"}}
	if got := bodyTextMax(br, []byte("abc"), 1<<10); got != "[encoded body omitted: Content-Encoding br, 3 bytes captured]" {
		t.Errorf("br body: %q", got)
	}
	if got := bodyTextMax(http.Header{}, []byte("plain"), 1<<10); got != "plain" {
		t.Errorf("plain body: %q", got)
	}
	if got := bodyTextMax(h, nil, 1<<10); got != "" {
		t.Errorf("empty body: %q", got)
	}
	if got := bodyTextMax(h, gz, 5); got != "hello"+truncMarker {
		t.Errorf("body cut at the limit: %q", got)
	}
}

type exRPC struct {
	id     string
	method string
	params string
}

func (r exRPC) req() rpcRequest {
	req := rpcRequest{Method: r.method}
	if r.id != "" {
		req.ID = json.RawMessage(r.id)
	}
	if r.params != "" {
		req.Params = json.RawMessage(r.params)
	}
	return req
}

func exToolResult(t *testing.T, resp *rpcResponse) (string, bool) {
	t.Helper()
	if resp == nil || resp.Error != nil {
		t.Fatalf("expected a tool result, got %+v", resp)
	}
	res, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("result is %T", resp.Result)
	}
	return toolText(t, res)
}

func TestMCPDispatchEdges(t *testing.T) {
	app := newTestApp(t)

	// initialize echoes the client's protocol version, or falls back.
	for params, want := range map[string]string{`{"protocolVersion":"2024-11-05"}`: "2024-11-05", ``: "2025-11-25", `not json`: "2025-11-25"} {
		resp := app.dispatchTo(exRPC{"1", "initialize", params}.req())
		res, _ := resp.Result.(map[string]any)
		if resp.Error != nil || res["protocolVersion"] != want {
			t.Errorf("initialize %q: %+v", params, resp)
		}
	}

	errCases := []struct {
		name string
		r    exRPC
		code int
		msg  string
	}{
		{"empty tool name", exRPC{"1", "tools/call", `{"name":""}`}, -32602, "invalid params"},
		{"no params", exRPC{"1", "tools/call", ``}, -32602, "invalid params"},
		{"unknown tool", exRPC{"1", "tools/call", `{"name":"nope"}`}, -32602, "unknown tool"},
		{"unknown method", exRPC{"1", "nope", ``}, -32601, "method not found"},
	}
	for _, c := range errCases {
		resp := app.dispatchTo(c.r.req())
		if resp.Error == nil || resp.Error.Code != c.code || resp.Error.Message != c.msg {
			t.Errorf("%s: %+v", c.name, resp)
		}
	}

	toolCases := []struct {
		name, tool, args, want string
		isErr                  bool
	}{
		{"inspect with bad arguments", "inspect_traffic", `{"limit":"x"}`, "invalid arguments", true},
		{"inspect with null arguments", "inspect_traffic", `null`, `"flows"`, false},
		{"inspect limit below the minimum", "inspect_traffic", `{"limit":0}`, `"returned": 0`, false},
		{"inspect limit above the maximum", "inspect_traffic", `{"limit":100000}`, `"ring_capacity"`, false},
		{"har with bad arguments", "export_har", `{"limit":"x"}`, "invalid arguments", true},
		{"curl without arguments", "export_sanitized_curl", ``, "flow_id is required", true},
		{"curl with bad arguments", "export_sanitized_curl", `{"flow_id":"a"}`, "invalid arguments", true},
		{"curl with zero", "export_sanitized_curl", `{"flow_id":0}`, "must be a positive integer", true},
		{"curl with a fraction", "export_sanitized_curl", `{"flow_id":1.5}`, "must be a positive integer", true},
		{"curl with a huge id", "export_sanitized_curl", `{"flow_id":2e15}`, "must be a positive integer", true},
		{"curl for a flow that is gone", "export_sanitized_curl", `{"flow_id":99}`, "flow not in RAM ring buffer", true},
		{"clear", "clear_ram_buffer", ``, "RAM ring buffer wiped", false},
	}
	for _, c := range toolCases {
		params := `{"name":"` + c.tool + `"`
		if c.args != "" {
			params += `,"arguments":` + c.args
		}
		params += `}`
		text, isErr := exToolResult(t, app.dispatchTo(exRPC{"1", "tools/call", params}.req()))
		if !strings.Contains(text, c.want) || isErr != c.isErr {
			t.Errorf("%s: (%q, %v)", c.name, text, isErr)
		}
	}
}

func TestMCPLineAndBatchEdges(t *testing.T) {
	app := newTestApp(t)

	for name, line := range map[string]string{
		"empty line":            "   ",
		"notification":          `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		"null id notification":  `{"jsonrpc":"2.0","id":null,"method":"notifications/cancelled"}`,
		"batch of notification": `[{"jsonrpc":"2.0","method":"notifications/initialized"}]`,
	} {
		if out := rpc(t, app, line); out != "" {
			t.Errorf("%s must produce no output, got %q", name, out)
		}
	}

	m := parseFrame(t, rpc(t, app, `{"jsonrpc":"2.0","id":7}`))
	if e, _ := m["error"].(map[string]any); e == nil || e["code"] != float64(-32600) || e["message"] != "invalid request" {
		t.Errorf("missing method: %v", m)
	}
	m = parseFrame(t, rpc(t, app, `[]`))
	if e, _ := m["error"].(map[string]any); e == nil || e["code"] != float64(-32600) || e["message"] != "empty batch" {
		t.Errorf("empty batch: %v", m)
	}
	m = parseFrame(t, rpc(t, app, `[1,`))
	if e, _ := m["error"].(map[string]any); e == nil || e["code"] != float64(-32700) {
		t.Errorf("broken batch: %v", m)
	}

	out := rpc(t, app, `[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"},{"jsonrpc":"2.0","id":2},"bad"]`)
	var resps []map[string]any
	if err := json.Unmarshal([]byte(out), &resps); err != nil || len(resps) != 3 {
		t.Fatalf("batch reply: %v\n%s", err, out)
	}
	if resps[0]["id"] != float64(1) || resps[0]["result"] == nil {
		t.Errorf("ping: %v", resps[0])
	}
	if e, _ := resps[1]["error"].(map[string]any); e == nil || e["message"] != "missing method" || resps[1]["id"] != float64(2) {
		t.Errorf("missing method in a batch: %v", resps[1])
	}
	if e, _ := resps[2]["error"].(map[string]any); e == nil || e["message"] != "invalid request" || resps[2]["id"] != nil {
		t.Errorf("invalid entry in a batch: %v", resps[2])
	}
}

func TestShellQuoteAndCurlEdges(t *testing.T) {
	tag := "[REDACTED_TOKEN#abc123]"
	cases := map[string]string{
		"":                     "''",
		"plain":                "'plain'",
		"it's":                 `'it'\''s'`,
		tag:                    `"$NULLWIRE_AUTH_TOKEN"`,
		"Bearer " + tag:        `'Bearer '"$NULLWIRE_AUTH_TOKEN"`,
		"[REDACTED_COOKIE#abc123]": `"$NULLWIRE_COOKIE"`,
		"[REDACTED_IP#abc123]":     `"$NULLWIRE_IP"`,
		"[REDACTED_KEY#abc123]":    `"$NULLWIRE_PRIVATE_KEY"`,
		"[REDACTED_PAN#abc123]":    `"$NULLWIRE_CARD_NUMBER"`,
	}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %s, want %s", in, got, want)
		}
	}

	if got := buildCurl(FlowEntry{ID: 4, Method: "CONNECT"}); !strings.Contains(got, "Flow 4 was a blind CONNECT tunnel") {
		t.Errorf("CONNECT: %q", got)
	}
	e := FlowEntry{
		ID: 5, Method: "HEAD", URL: "http://x/a",
		RequestHeaders: map[string]string{"Host": "x", "Content-Length": "3", "Content-Encoding": "gzip", "X-A": tag, "Accept": "*/*"},
		RequestBody:    "[protobuf/gRPC body decoded without a schema]",
	}
	got := buildCurl(e)
	for _, want := range []string{"# Replay of flow 5", "export NULLWIRE_AUTH_TOKEN=", "curl -I 'http://x/a'", `-H 'Accept: */*'`, `-H 'X-A: '"$NULLWIRE_AUTH_TOKEN"`} {
		if !strings.Contains(got, want) {
			t.Errorf("curl is missing %q:\n%s", want, got)
		}
	}
	for _, not := range []string{"Host", "Content-Length", "Content-Encoding", "--data-raw"} {
		if strings.Contains(got, not) {
			t.Errorf("curl must not contain %q:\n%s", not, got)
		}
	}
	e = FlowEntry{ID: 6, Method: "POST", URL: "http://x/", RequestBody: "a=1" + truncMarker,
		RequestHeaders: map[string]string{"Content-Encoding": "br"}}
	if got := buildCurl(e); !strings.Contains(got, "--data-raw 'a=1'") || !strings.Contains(got, "Content-Encoding: br") {
		t.Errorf("POST curl:\n%s", got)
	}
	e.RequestBody = "[encoded body omitted: Content-Encoding br, 3 bytes captured]"
	if got := buildCurl(e); strings.Contains(got, "--data-raw") {
		t.Errorf("an omitted body must not be replayed:\n%s", got)
	}
}

func TestLoadSecretsConfigErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if c, err := loadSecretsConfig(""); err != nil || c == nil {
		t.Errorf("no path: (%v, %v)", c, err)
	}
	cases := map[string]struct{ body, want string }{
		"invalid json":      {`{`, "invalid JSON"},
		"empty pattern":     {`{"extra_regex_patterns":[{"name":"x","pattern":""}]}`, "empty pattern"},
		"bad pattern":       {`{"extra_regex_patterns":[{"name":"x","pattern":"("}]}`, "extra_regex_patterns[0]"},
		"bad vendor":        {`{"custom_vendors":[{"name":"v","pattern":"("}]}`, "custom_vendors[0]"},
	}
	for name, c := range cases {
		_, err := loadSecretsConfig(write(name+".json", c.body))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to contain %q", name, err, c.want)
		}
	}
	if _, err := loadSecretsConfig(filepath.Join(dir, "missing.json")); err == nil || !strings.Contains(err.Error(), "-secrets-config") {
		t.Errorf("missing file: %v", err)
	}
	if c, err := loadSecretsConfig(write("ok.json", `{"extra_regex_patterns":[{"name":"x","pattern":"abc[0-9]+"}]}`)); err != nil || len(c.ExtraRegexPatterns) != 1 {
		t.Errorf("valid config: (%+v, %v)", c, err)
	}
}

func TestParseTargetsAndDNSErrors(t *testing.T) {
	if def, named, err := parseTargets("http://a.example, api=http://b.example"); err != nil || def == nil || named["api"] == nil {
		t.Errorf("default and named: (%v, %v, %v)", def, named, err)
	}
	for name, spec := range map[string]string{
		"nothing":           "",
		"two defaults":      "http://a.example,http://b.example",
		"name used twice":   "api=http://a.example,API=http://b.example",
		"unusable upstream": "ftp://a.example",
	} {
		if _, _, err := parseTargets(spec); err == nil {
			t.Errorf("%s: %q must be refused", name, spec)
		}
	}
	for _, spec := range []string{"", " , ", "not-an-ip", "1.1.1.1:0", "1.1.1.1:99999", "1.1.1.1:x"} {
		if _, err := parseDNSServers(spec); err == nil {
			t.Errorf("parseDNSServers(%q) must fail", spec)
		}
	}
	if got, err := parseDNSServers("1.1.1.1, [2606:4700::1111]:5353"); err != nil || len(got) != 2 || got[0] != "1.1.1.1:53" || got[1] != "[2606:4700::1111]:5353" {
		t.Errorf("valid servers: (%v, %v)", got, err)
	}
}

// ---------------------------------------------------------------------------
// Encoded-text helpers and budgets

// lcgString returns n deterministic pseudo-random characters of alphabet.
func lcgString(n int, alphabet string, seed uint32) string {
	b := make([]byte, n)
	x := seed
	for i := range b {
		x = x*1103515245 + 12345
		b[i] = alphabet[int(x>>16)%len(alphabet)]
	}
	return string(b)
}

const (
	lcgBase64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	lcgHex    = "0123456789abcdef"
)

func TestScrubBase64WasteAndTextBudgets(t *testing.T) {
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	secret := base64.RawStdEncoding.EncodeToString([]byte(`{"password":"hunter2hunter2"}`))
	n := 0
	if out := s.scrubBase64("x "+secret+" y", &n); n != 1 || strings.Contains(out, secret) {
		t.Fatalf("a lone base64 secret must be redacted: n=%d out=%q", n, out)
	}

	// Runs that decode to binary are charged to the waste budget (4 MiB); once it
	// is used up even a real secret run is left alone.
	var b strings.Builder
	for i := 0; i < 60; i++ {
		b.WriteString(lcgString(80000, lcgBase64, uint32(i+1)))
		b.WriteByte(' ')
	}
	b.WriteString(secret)
	in := b.String()
	n = 0
	if out := s.scrubBase64(in, &n); n != 0 || out != in {
		t.Errorf("waste budget: n=%d, changed=%v", n, out != in)
	}

	// Runs that decode to harmless text are charged to the text budget (256 KiB).
	text := base64.RawStdEncoding.EncodeToString([]byte(strings.Repeat("hello world, ordinary text. ", 100)))
	b.Reset()
	for i := 0; i < 80; i++ {
		b.WriteString(text)
		b.WriteByte(' ')
	}
	b.WriteString(secret)
	in = b.String()
	n = 0
	if out := s.scrubBase64(in, &n); n != 0 || out != in {
		t.Errorf("text budget: n=%d, changed=%v", n, out != in)
	}
}

func TestScrubEncodedTextBudgets(t *testing.T) {
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	secret := hex.EncodeToString([]byte(`{"password":"hunter2hunter2"}`))
	n := 0
	if out := s.scrubEncodedText("x "+secret+" y", &n); n != 1 || strings.Contains(out, secret) {
		t.Fatalf("a lone hex secret must be redacted: n=%d out=%q", n, out)
	}

	var b strings.Builder
	for i := 0; i < 72; i++ { // binary-looking hex: 72 * 60000 > 4 MiB of waste
		b.WriteString(lcgString(60000, lcgHex, uint32(i+1)))
		b.WriteByte(' ')
	}
	b.WriteString(secret)
	in := b.String()
	n = 0
	if out := s.scrubEncodedText(in, &n); n != 0 || out != in {
		t.Errorf("waste budget: n=%d, changed=%v", n, out != in)
	}

	text := hex.EncodeToString([]byte(strings.Repeat("hello world, ordinary text. ", 100)))
	b.Reset()
	for i := 0; i < 50; i++ { // readable hex without secrets: 50 * 5600 > 256 KiB
		b.WriteString(text)
		b.WriteByte(' ')
	}
	b.WriteString(secret)
	in = b.String()
	n = 0
	if out := s.scrubEncodedText(in, &n); n != 0 || out != in {
		t.Errorf("text budget: n=%d, changed=%v", n, out != in)
	}
}

func TestEncodedTextDecoderEdges(t *testing.T) {
	printable := []byte("printable text ok")

	// Base58: an invalid byte, and leading '1' characters (0x00 bytes).
	for _, in := range []string{"abc0defghijkmnopqrstuv", "abcOdefghijkmnopqrstuv", "abcIdefghijkmnopqrstuv", "abcldefghijkmnopqrstuv"} {
		if b, ok := decodeBase58Text(in); ok || b != nil {
			t.Errorf("decodeBase58Text(%q) = %q, %v; want failure", in, b, ok)
		}
	}
	if _, ok := decodeBase58Text("11" + b58Encode(printable)); ok {
		t.Error("leading '1' characters stand for 0x00 bytes, which are not printable")
	}
	if _, ok := decodeBase58Text(b58Encode(append([]byte{0}, printable...))); ok {
		t.Error("a leading 0x00 byte is not printable")
	}
	if b, ok := decodeBase58Text(b58Encode(printable)); !ok || !bytes.Equal(b, printable) {
		t.Errorf("base58 round trip: %q %v", b, ok)
	}
	if _, ok := decodeBase58Text(""); ok {
		t.Error("empty base58 is not text")
	}

	// Base32: padded, unpadded, invalid, binary.
	b32 := base32.StdEncoding.EncodeToString(printable)
	if !strings.HasSuffix(b32, "=") {
		t.Fatalf("test input should be padded: %q", b32)
	}
	if b, ok := decodeBase32Text(b32); !ok || !bytes.Equal(b, printable) {
		t.Errorf("padded base32: %q %v", b, ok)
	}
	if b, ok := decodeBase32Text(strings.TrimRight(b32, "=")); !ok || !bytes.Equal(b, printable) {
		t.Errorf("unpadded base32: %q %v", b, ok)
	}
	if _, ok := decodeBase32Text("!!!!!!!!!!!!!!!!"); ok {
		t.Error("invalid base32 must fail")
	}
	if _, ok := decodeBase32Text(base32.StdEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})); ok {
		t.Error("binary base32 must fail")
	}

	// Hex: odd length, invalid digit, binary, too short, a DEL byte.
	for name, in := range map[string]string{
		"odd length":   "abc",
		"bad digit":    "zz" + strings.Repeat("41", 10),
		"binary":       hex.EncodeToString([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}),
		"too short":    hex.EncodeToString([]byte("short")),
		"DEL byte":     hex.EncodeToString([]byte("abcdefg\x7f")),
		"bad UTF-8":    hex.EncodeToString([]byte("abcdefg\xff")),
		"control byte": hex.EncodeToString([]byte("abcdefg\x01")),
	} {
		if _, ok := decodeHexText(in); ok {
			t.Errorf("decodeHexText(%s) should fail", name)
		}
	}
	if b, ok := decodeHexText(hex.EncodeToString([]byte("tab\tnew\nline\r ok"))); !ok || string(b) != "tab\tnew\nline\r ok" {
		t.Errorf("tabs and line breaks are printable: %q %v", b, ok)
	}

	// Base64 text: padded, URL-safe, invalid.
	if b, ok := decodeBase64Text(base64.StdEncoding.EncodeToString(printable)); !ok || !bytes.Equal(b, printable) {
		t.Errorf("padded base64: %q %v", b, ok)
	}
	if b, ok := decodeBase64Text(base64.RawURLEncoding.EncodeToString([]byte("url?safe>text~ok"))); !ok || string(b) != "url?safe>text~ok" {
		t.Errorf("url-safe base64: %q %v", b, ok)
	}
	if _, ok := decodeBase64Text("not base64 at all!!!!!!!!"); ok {
		t.Error("invalid base64 must fail")
	}
}

func TestTextShapeHelpers(t *testing.T) {
	// mostlyText: short, invalid UTF-8, too many control bytes, a few control bytes.
	if mostlyText([]byte("short")) || mostlyText([]byte("abcdefg\xff")) {
		t.Error("short or non-UTF-8 text is not mostly text")
	}
	if mostlyText(append(bytes.Repeat([]byte("a"), 70), bytes.Repeat([]byte{1}, 30)...)) {
		t.Error("30% control bytes is not text")
	}
	if !mostlyText(append(bytes.Repeat([]byte("a"), 100), 1, 1, 1, 1)) {
		t.Error("a few control bytes are tolerated")
	}
	if !mostlyText([]byte("line one\r\n\tline two\n")) {
		t.Error("tabs and line breaks are not control bytes")
	}
	// isPrintableText is stricter: no control bytes at all.
	if isPrintableText([]byte("abc")) || isPrintableText(append(bytes.Repeat([]byte("a"), 10), 1)) || isPrintableText(bytes.Repeat([]byte{0xff}, 10)) {
		t.Error("isPrintableText accepted bad input")
	}
	if !isPrintableText([]byte("plain text\n\t")) {
		t.Error("plain text must be printable")
	}

	for in, want := range map[string]bool{
		strings.Repeat("a", 23):                  false,
		strings.Repeat("a", 30):                  false, // lower case only
		strings.Repeat("A", 30):                  false, // upper case only
		strings.Repeat("1", 30):                  false, // digits only
		strings.Repeat("a", 20) + "BBBB":          true,  // lower + upper
		strings.Repeat("a", 20) + "1234":         true,  // lower + digit
		strings.Repeat("A", 20) + "1234":         true,  // upper + digit
		strings.Repeat("a", 16) + "-" + "bBcC9xyz": true,
	} {
		if got := isBase64Like(in); got != want {
			t.Errorf("isBase64Like(%q) = %v, want %v", in, got, want)
		}
	}

	for in, want := range map[string]bool{
		strings.Repeat("a", 19):                  false,
		strings.Repeat("a", 20):                  true,
		strings.Repeat("a", 10) + "-" + strings.Repeat("b", 10): false,
		"x" + strings.Repeat("9", 20) + "!":      true,
		"":                                       false,
	} {
		if got := hasEncodedRun(in); got != want {
			t.Errorf("hasEncodedRun(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestScrubJSONSecretArraysSkips(t *testing.T) {
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	in := `{"password":["","[REDACTED_TOKEN#abc]","Sup3rS3cretValue"]}`
	out := s.scrubJSONSecretArrays(in, &n)
	if n != 1 || strings.Contains(out, "Sup3rS3cretValue") || !strings.Contains(out, `"","[REDACTED_TOKEN#abc]",`) {
		t.Errorf("n=%d out=%q", n, out)
	}
	// Under a bare "key" a short or path-like value is not a secret.
	n = 0
	in = `{"key":["short","path/like/value/here","Sup3rS3cretValueZZ"]}`
	out = s.scrubJSONSecretArrays(in, &n)
	if n != 1 || !strings.Contains(out, `"short"`) || !strings.Contains(out, `"path/like/value/here"`) || strings.Contains(out, "Sup3rS3cretValueZZ") {
		t.Errorf("bare key: n=%d out=%q", n, out)
	}
}

func TestXMLOpenLocalName(t *testing.T) {
	for in, want := range map[string]string{
		`<wsse:Password Type="x">`: "Password",
		`<Password>`:               "Password",
		"<a\tb>":                   "a",
		"<a\nb>":                   "a",
		`<ns:a:b>`:                 "b",
		`Plain`:                    "Plain",
		`<>`:                       "",
	} {
		if got := xmlOpenLocalName(in); got != want {
			t.Errorf("xmlOpenLocalName(%q) = %q, want %q", in, got, want)
		}
	}
}

// scrubXMLSecrets is the regexp pass that mops up after the tree pass, so it
// is called directly here to reach its early returns.
func TestScrubXMLSecretsSkipsAndRedacts(t *testing.T) {
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string]string{
		"blank value":          "<Secret> </Secret>",
		"blank cdata":          "<Secret><![CDATA[ ]]></Secret>",
		"already redacted":     "<Secret>[REDACTED_TOKEN#aaaaaa]</Secret>",
		"placeholder":          "<Secret>${API_KEY}</Secret>",
		"template placeholder": "<Secret>{{ api_key }}</Secret>",
		"benign leaf":          "<tokenType>Bearer</tokenType>",
	} {
		n := 0
		if out := s.scrubXMLSecrets(in, &n); n != 0 || out != in {
			t.Errorf("%s: n=%d out=%q, want the input unchanged", name, n, out)
		}
	}
	for name, in := range map[string]string{
		"plain value": "<Secret>hunter2hunter2</Secret>",
		"cdata value": "<Secret><![CDATA[hunter2hunter2]]></Secret>",
		"cut value":   "<Secret>hunter2hunter2",
	} {
		n := 0
		out := s.scrubXMLSecrets(in, &n)
		if n != 1 || strings.Contains(out, "hunter2hunter2") || !strings.Contains(out, "[REDACTED_") {
			t.Errorf("%s: n=%d out=%q", name, n, out)
		}
	}
}

func TestDecodeBase58TextRejectsUnreadableOutput(t *testing.T) {
	for name, payload := range map[string][]byte{
		"invalid UTF-8":     []byte("abcdefg\xff"),
		"control byte":      []byte("abcdefg\x01h"),
		"delete byte":       []byte("abcdefg\x7fh"),
		"too short to read": []byte("abc"),
	} {
		if b, ok := decodeBase58Text(b58Encode(payload)); ok || b != nil {
			t.Errorf("%s: decodeBase58Text = %q, %v; want a failure", name, b, ok)
		}
	}
	// Leading '1' characters are 0x00 bytes, which are not printable.
	if _, ok := decodeBase58Text("111" + b58Encode([]byte("printable text ok"))); ok {
		t.Error("a zero prefix must be rejected")
	}
	if b, ok := decodeBase58Text(b58Encode([]byte("tab\there ok"))); !ok || string(b) != "tab\there ok" {
		t.Errorf("tabs and newlines are text: %q %v", b, ok)
	}
}

func TestMostlyTextBoundaries(t *testing.T) {
	ctrl := func(n int) []byte { return bytes.Repeat([]byte{1}, n) }
	for name, in := range map[string][]byte{
		"exactly 8 bytes":           []byte("abcdefgh"),
		"1 control in 21 bytes":     append(bytes.Repeat([]byte("a"), 20), ctrl(1)...),
		"tab, CR and LF are text":   []byte("a\tb\rc\nd efg"),
		"multi-byte UTF-8 is text":  []byte("héllo wörld ✓"),
	} {
		if !mostlyText(in) {
			t.Errorf("%s: want text", name)
		}
	}
	for name, in := range map[string][]byte{
		"7 bytes":                  []byte("abcdefg"),
		"empty":                    nil,
		"invalid UTF-8":            []byte("abcdefg\xc3("),
		"1 control in 20 bytes":    append(bytes.Repeat([]byte("a"), 19), ctrl(1)...),
		"mostly control":           ctrl(40),
	} {
		if mostlyText(in) {
			t.Errorf("%s: want not text", name)
		}
	}
}
