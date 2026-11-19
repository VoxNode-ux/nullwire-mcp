package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func xcovLines(out string) []string {
	out = strings.TrimSpace(out)
	if out == "" {
		return nil
	}
	return strings.Split(out, "\n")
}

// xcovCaptureStderr routes the App's stderr into a buffer via the injectable
// field. It must not swap the global os.Stderr: capture goroutines left over
// from other tests read it concurrently, which the race detector flags.
func xcovCaptureStderr(t *testing.T, app *App, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	app.barMu.Lock()
	app.stderr = &buf
	app.barMu.Unlock()
	fn()
	app.barMu.Lock()
	app.stderr = nil
	app.barMu.Unlock()
	return buf.String()
}

func xcovErrCode(t *testing.T, line string) float64 {
	t.Helper()
	var m struct {
		Error *struct {
			Code float64 `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(line), &m); err != nil || m.Error == nil {
		t.Fatalf("not an error frame: %q (%v)", line, err)
	}
	return m.Error.Code
}

// ---- MCP batch and dispatch ----

func TestXcovHandleLine(t *testing.T) {
	app := newTestApp(t)
	cases := []struct {
		name, in string
		code     float64 // 0 = expect a result, -1 = expect no output
	}{
		{"blank", "   ", -1},
		{"invalid json", "{nope", -32700},
		{"notification", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, -1},
		{"null id notification", `{"jsonrpc":"2.0","id":null,"method":"notifications/x"}`, -1},
		{"missing method", `{"jsonrpc":"2.0","id":1}`, -32600},
		{"unknown method", `{"jsonrpc":"2.0","id":2,"method":"nope"}`, -32601},
		{"call bad params", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":"x"}`, -32602},
		{"call unknown tool", `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"zzz"}}`, -32602},
		{"initialize", `{"jsonrpc":"2.0","id":5,"method":"initialize"}`, 0},
		{"discover", `{"jsonrpc":"2.0","id":6,"method":"server/discover"}`, 0},
		{"ping", `{"jsonrpc":"2.0","id":7,"method":"ping"}`, 0},
		{"tools/list", `{"jsonrpc":"2.0","id":8,"method":"tools/list"}`, 0},
		{"clear", `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"clear_ram_buffer"}}`, 0},
	}
	for _, c := range cases {
		out := captureStdout(t, func() { app.handleLine([]byte(c.in)) })
		ls := xcovLines(out)
		switch c.code {
		case -1:
			if len(ls) != 0 {
				t.Fatalf("%s: unexpected output %q", c.name, out)
			}
		case 0:
			if len(ls) != 1 || strings.Contains(ls[0], `"error"`) {
				t.Fatalf("%s: want a result, got %q", c.name, out)
			}
		default:
			if len(ls) != 1 || xcovErrCode(t, ls[0]) != c.code {
				t.Fatalf("%s: want code %v, got %q", c.name, c.code, out)
			}
		}
	}
}

func TestXcovHandleBatch(t *testing.T) {
	app := newTestApp(t)
	out := captureStdout(t, func() { app.handleLine([]byte("[]")) })
	if ls := xcovLines(out); len(ls) != 1 || xcovErrCode(t, ls[0]) != -32600 {
		t.Fatalf("empty batch: %q", out)
	}
	out = captureStdout(t, func() { app.handleLine([]byte("[1,")) })
	if ls := xcovLines(out); len(ls) != 1 || xcovErrCode(t, ls[0]) != -32700 {
		t.Fatalf("invalid batch: %q", out)
	}
	out = captureStdout(t, func() {
		app.handleLine([]byte(`[{"jsonrpc":"2.0","method":"notifications/initialized"},{"jsonrpc":"2.0","method":"notifications/x","id":null}]`))
	})
	if out != "" {
		t.Fatalf("notification-only batch wrote %q", out)
	}
	mixed := `[{"jsonrpc":"2.0","method":"notifications/initialized"},` +
		`{"jsonrpc":"2.0","id":1,"method":"ping"},5,` +
		`{"jsonrpc":"2.0","id":2},{"jsonrpc":"2.0","id":3,"method":"nope"}]`
	out = captureStdout(t, func() { app.handleLine([]byte(mixed)) })
	var resps []map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &resps); err != nil {
		t.Fatalf("batch output not an array: %q (%v)", out, err)
	}
	if len(resps) != 4 {
		t.Fatalf("want 4 responses, got %d: %q", len(resps), out)
	}
	errs, oks := 0, 0
	for _, r := range resps {
		if r["jsonrpc"] != "2.0" {
			t.Fatalf("missing jsonrpc in %v", r)
		}
		if r["error"] != nil {
			errs++
		} else {
			oks++
		}
	}
	if errs != 3 || oks != 1 {
		t.Fatalf("errs=%d oks=%d", errs, oks)
	}
}

func TestXcovWriteFallbacks(t *testing.T) {
	app := newTestApp(t)
	bad := make(chan int) // cannot be encoded as JSON
	out := captureStdout(t, func() { app.writeFrame(rpcResponse{ID: json.RawMessage("1"), Result: bad}) })
	if !strings.Contains(out, "cannot encode response") {
		t.Fatalf("writeFrame fallback: %q", out)
	}
	out = captureStdout(t, func() { app.writeBatch([]rpcResponse{{ID: json.RawMessage("1"), Result: bad}}) })
	if !strings.Contains(out, "cannot encode response") {
		t.Fatalf("writeBatch fallback: %q", out)
	}
	out = captureStdout(t, func() { app.writeError(json.RawMessage("7"), -32000, "boom") })
	if xcovErrCode(t, strings.TrimSpace(out)) != -32000 {
		t.Fatalf("writeError: %q", out)
	}
}

// ---- CONNECT, upgrades and the proxy path ----

func xcovConnectReq(hostport string) *http.Request {
	return &http.Request{Method: http.MethodConnect, Host: hostport, URL: &url.URL{Host: hostport}, Header: http.Header{}}
}

func TestXcovHandleConnectRejections(t *testing.T) {
	app := newTestApp(t)
	for _, hp := range []string{"nohostport", "host:0", "host:70000", ":80", "host:abc"} {
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, xcovConnectReq(hp))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%q: status %d", hp, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, xcovConnectReq("127.0.0.1:1")) // app.port is 1: itself
	if rec.Code != http.StatusLoopDetected {
		t.Fatalf("self dial: status %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	app.ServeHTTP(rec, xcovConnectReq("example.invalid:443")) // a recorder cannot be hijacked
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("no hijack: status %d", rec.Code)
	}
	full := newTestApp(t)
	for i := 0; i < maxTunnels; i++ {
		if !full.acquireTunnel() {
			t.Fatal("tunnel refused early")
		}
	}
	rec = httptest.NewRecorder()
	full.ServeHTTP(rec, xcovConnectReq("example.invalid:443"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("tunnel limit: status %d", rec.Code)
	}
}

func xcovClosedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func TestXcovHandleConnectUnreachable(t *testing.T) {
	app := newTestApp(t)
	proxy := httptest.NewServer(app)
	defer proxy.Close()
	target := xcovClosedAddr(t)
	conn, err := net.Dial("tcp", strings.TrimPrefix(proxy.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(conn, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d", resp.StatusCode)
	}
	waitForRing(t, app, 1)
	if e := app.ring.ListRecent(1, "", ""); len(e) != 1 || e[0].StatusCode != http.StatusBadGateway {
		t.Fatalf("entry: %+v", e)
	}
}

func TestXcovServeHTTPUpstreamErrors(t *testing.T) {
	app := newTestApp(t)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "ftp://example.test/x", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("scheme: status %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	app.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "http://"+xcovClosedAddr(t)+"/x", strings.NewReader("abc")))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("closed upstream: status %d", rec.Code)
	}
	waitForRing(t, app, 1)
	if e := app.ring.ListRecent(1, "", ""); len(e) != 1 || e[0].StatusCode != http.StatusBadGateway {
		t.Fatalf("entry: %+v", e)
	}
}

func TestXcovServeHTTPEncodingGate(t *testing.T) {
	var got int
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got++
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	defer up.Close()
	send := func(app *App) int {
		req := httptest.NewRequest(http.MethodPost, up.URL+"/x", strings.NewReader("payload"))
		req.Header.Set("Content-Encoding", "br")
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, req)
		return rec.Code
	}
	app := newTestApp(t)
	if c := send(app); c != http.StatusUnsupportedMediaType || got != 0 {
		t.Fatalf("blocked: status %d, upstream hits %d", c, got)
	}
	app.allowUninspectable = true
	if c := send(app); c != http.StatusOK || got != 1 {
		t.Fatalf("allowed: status %d, upstream hits %d", c, got)
	}
}

func TestXcovServeHTTPHopByHopAndTruncation(t *testing.T) {
	var seen http.Header
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("X-Resp-Hop", "1")
		w.Header().Set("Connection", "X-Resp-Hop")
		_, _ = w.Write([]byte("done"))
	}))
	defer up.Close()
	app := newTestApp(t)
	body := strings.Repeat("a", 100*1024) // above the 64 KiB request capture
	req := httptest.NewRequest(http.MethodPost, up.URL+"/big", strings.NewReader(body))
	req.Header.Set("Connection", "X-Hop")
	req.Header.Set("X-Hop", "secret-hop")
	req.Header.Set("Keep-Alive", "timeout=5")
	req.Header.Set("Proxy-Authorization", "Basic abc")
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "done" {
		t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
	}
	for _, h := range []string{"X-Hop", "Keep-Alive", "Proxy-Authorization"} {
		if seen.Get(h) != "" {
			t.Fatalf("hop-by-hop header %s reached upstream", h)
		}
	}
	if rec.Header().Get("X-Resp-Hop") != "" {
		t.Fatal("hop-by-hop response header reached the client")
	}
	waitForRing(t, app, 1)
	e := app.ring.ListRecent(1, "", "")[0]
	if len(e.RequestBody) >= len(body) || !strings.Contains(e.Note, "truncated") {
		t.Fatalf("body not truncated: len=%d note=%q", len(e.RequestBody), e.Note)
	}
}

func TestXcovUpgradePaths(t *testing.T) {
	// An upstream that ignores the upgrade and answers 200.
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Sec-WebSocket-Extensions") != "" {
			http.Error(w, "extensions leaked", http.StatusTeapot)
			return
		}
		_, _ = w.Write([]byte("no upgrade"))
	}))
	defer plain.Close()
	app := newTestApp(t)
	req := httptest.NewRequest(http.MethodGet, plain.URL+"/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Extensions", "permessage-deflate")
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "no upgrade" {
		t.Fatalf("non-101: status %d body %q", rec.Code, rec.Body.String())
	}
	tr1, tr2 := app.upgradeTransport(), app.upgradeTransport()
	if tr1 != tr2 || tr1.ForceAttemptHTTP2 {
		t.Fatal("upgradeTransport must be cached and HTTP/1.1 only")
	}

	// An upstream that does switch protocols; a recorder cannot be hijacked, so 502.
	sw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		c, brw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: foo\r\n\r\n")
		_ = brw.Flush()
	}))
	defer sw.Close()
	req = httptest.NewRequest(http.MethodGet, sw.URL+"/up", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "foo")
	rec = httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "upgrade is not supported") {
		t.Fatalf("101 without hijack: status %d body %q", rec.Code, rec.Body.String())
	}
}

// ---- scrubber, config and runtime edges ----

func TestXcovNewScrubberWithConfigErrors(t *testing.T) {
	if _, err := NewScrubberWithConfig(nil); err != nil {
		t.Fatalf("nil config: %v", err)
	}
	_, err := NewScrubberWithConfig(&SecretsConfig{CustomVendors: []VendorConfig{{Name: "v", Prefix: "vv_", Pattern: "("}}})
	if err == nil || !strings.Contains(err.Error(), "custom vendor") {
		t.Fatalf("bad vendor pattern: %v", err)
	}
	_, err = NewScrubberWithConfig(&SecretsConfig{ExtraRegexPatterns: []ExtraPattern{{Name: "x", Pattern: "[a-"}}})
	if err == nil || !strings.Contains(err.Error(), "extra_regex_patterns") {
		t.Fatalf("bad extra pattern: %v", err)
	}
	s, err := NewScrubberWithConfig(&SecretsConfig{
		SensitiveHeaders: []string{" X-Mine ", ""}, IgnoreHeaders: []string{"X-Skip", " "},
		CustomVendors:      []VendorConfig{{Name: "v", Prefix: "vv_"}},
		ExtraRegexPatterns: []ExtraPattern{{Name: "x", Pattern: `zz[0-9]{8}`}},
	})
	if err != nil || s == nil {
		t.Fatalf("valid config: %v", err)
	}
}

func TestXcovPathHelpers(t *testing.T) {
	plain := map[string]bool{
		"Users/Alice/Desktop/file1.txt": true,
		"Zq8Xv3LmP0aTr9Yk/abc":          false,
		"a+b/c":                         false,
		"key==/x":                       false,
	}
	for in, want := range plain {
		if got := isPlainPath(in); got != want {
			t.Fatalf("isPlainPath(%q) = %v", in, got)
		}
	}
	for _, in := range []string{"http://a.b/c", "//host/x", "/abs/Path1", "~/x/Y1", "./a/B2", "../a/B2", "com.example.app", "2024-01-02", "v1.2.3"} {
		if strictSlashDotOK(in) {
			t.Fatalf("strictSlashDotOK(%q) = true", in)
		}
	}
	if !strictSlashDotOK("aBcD3.xYz/Q9w") {
		t.Fatal("key-like value rejected")
	}
}

func TestXcovBuildEntryEdges(t *testing.T) {
	app := newTestApp(t)
	app.ignoreURLSubstrings = []string{"/health"}
	if _, ok := app.buildEntry(rawFlow{url: "http://x.test/health", started: time.Now()}); ok {
		t.Fatal("ignored URL was kept")
	}
	f := rawFlow{started: time.Now(), method: "GET", url: "http://x.test/a", status: 200,
		reqHeaders: http.Header{}, respHeaders: http.Header{"Content-Encoding": {"br"}},
		respBody: []byte("xx"), respCut: true, note: "base note"}
	e, ok := app.buildEntry(f)
	if !ok || !strings.Contains(e.Note, "base note") || !strings.Contains(e.Note, "truncated") {
		t.Fatalf("entry: ok=%v note=%q", ok, e.Note)
	}
	if !strings.Contains(e.Note, "Response body encoded") {
		t.Fatalf("encoded-body warning missing: %q", e.Note)
	}
}

func TestXcovDetached(t *testing.T) {
	app := newTestApp(t)
	d := app.scrub.detached()
	d.Tokens.Add(3)
	d.Cookies.Add(1)
	d.IPs.Add(2)
	if app.scrub.Tokens.Load() != 0 || app.scrub.Cookies.Load() != 0 || app.scrub.IPs.Load() != 0 {
		t.Fatal("detached counters leaked into the original")
	}
	if d.taint != app.scrub.taint {
		t.Fatal("detached view must share the taint ring")
	}
}

func TestXcovDrawBarAndLogf(t *testing.T) {
	app := newTestApp(t)
	app.port = 4321
	app.scrub.Tokens.Add(2)
	out := xcovCaptureStderr(t, app, func() { app.drawBar(); app.Bar(); app.Logf("hello %d", 5) })
	for _, want := range []string{"127.0.0.1:4321", "RAM Ring: 0/", "2 Tokens", "hello 5"} {
		if !strings.Contains(out, want) {
			t.Fatalf("stderr missing %q: %q", want, out)
		}
	}
}

func TestXcovNewDialer(t *testing.T) {
	d := newDialer(nil, nil)
	if d.Resolver != nil || d.Timeout != 10*time.Second {
		t.Fatalf("default dialer: %+v", d)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	ctx := context.Background()
	d = newDialer([]string{xcovClosedAddr(t), ln.Addr().String()}, nil) // first fails, second answers
	if d.Resolver == nil || !d.Resolver.PreferGo {
		t.Fatal("custom DNS dialer needs a Go resolver")
	}
	c, err := d.Resolver.Dial(ctx, "tcp", "ignored")
	if err != nil {
		t.Fatalf("fallback server not used: %v", err)
	}
	_ = c.Close()
	d = newDialer([]string{xcovClosedAddr(t)}, nil)
	if c, err := d.Resolver.Dial(ctx, "tcp", "ignored"); err == nil {
		_ = c.Close()
		t.Fatal("dead DNS server reported success")
	}
}
