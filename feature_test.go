package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Helpers are prefixed fx so they cannot collide with other test files.

var fxTagRe = regexp.MustCompile(`\[REDACTED_[A-Z]+#[0-9a-f]+\]`)

func fxApp(t *testing.T) *App {
	t.Helper()
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	return &App{ring: NewRingBuffer(), scrub: s, transport: &http.Transport{DisableCompression: true}}
}

func fxWaitRing(t *testing.T, a *App, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if a.ring.Len() >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("ring has %d entries, want %d", a.ring.Len(), n)
}

// fxStdout runs fn and returns what it wrote to os.Stdout.
func fxStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	_ = w.Close()
	os.Stdout = old
	return <-done
}

func fxFrame(fin bool, opcode byte, payload []byte, mask bool, key [4]byte) []byte {
	b0 := opcode
	if fin {
		b0 |= 0x80
	}
	b := []byte{b0}
	mbit := byte(0)
	if mask {
		mbit = 0x80
	}
	switch n := len(payload); {
	case n < 126:
		b = append(b, mbit|byte(n))
	case n < 65536:
		b = append(b, mbit|126, byte(n>>8), byte(n))
	default:
		b = append(b, mbit|127, 0, 0, 0, 0, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	if mask {
		b = append(b, key[:]...)
		for i, c := range payload {
			b = append(b, c^key[i&3])
		}
	} else {
		b = append(b, payload...)
	}
	return b
}

func fxFeed(p *wsParser, stream []byte, chunk int) {
	for i := 0; i < len(stream); i += chunk {
		end := i + chunk
		if end > len(stream) {
			end = len(stream)
		}
		p.Feed(stream[i:end])
	}
}

// fxParse parses a stream and returns what a collector with room for max bytes holds.
func fxParse(stream []byte, chunk, max int) (*wsCollector, *wsParser) {
	c := newWSCollector(max)
	p := newWSParser(c.add)
	fxFeed(p, stream, chunk)
	return c, p
}

// ---------------------------------------------------------------------------
// Scrubbing
// ---------------------------------------------------------------------------

func TestHighEntropyCatch(t *testing.T) {
	s, _ := NewScrubber()
	tokens := []string{
		"aB3xK9mP2qR7sT4w",
		"xYz9AbC8dEf7GhJ6",
		"f7G9hJ2kL5mN8pQ1rS4tU7vW",
		"0123456789abcdef",
		"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
	}
	for _, tok := range tokens {
		out, n := s.ScrubText("found " + tok + " here")
		if n == 0 || strings.Contains(out, tok) || !fxTagRe.MatchString(out) {
			t.Errorf("token %q was not redacted: %q", tok, out)
		}
	}

	nonTokens := []string{
		"get_user_by_id_from_db",
		"getUserByIdFromDb",
		"internationalization",
		"deadbeefcafebabe",
		"abcdefghijklmnop",
		"550e8400-e29b-41d4-a716-446655440000",
	}
	for _, nt := range nonTokens {
		wrap := "found " + nt + " here"
		if out, n := s.ScrubText(wrap); n != 0 || out != wrap {
			t.Errorf("false positive on %q -> %q", nt, out)
		}
	}
}

func TestIPv4StrictValidation(t *testing.T) {
	s, _ := NewScrubber()
	for _, ip := range []string{"192.168.1.1", "10.0.0.42"} {
		if out, n := s.ScrubText("peer " + ip); n != 1 || strings.Contains(out, ip) {
			t.Errorf("valid IP %q failed", ip)
		}
	}
	for _, ip := range []string{"999.999.999.999", "01.02.03.04", "256.1.1.1"} {
		in := "value " + ip
		if out, n := s.ScrubText(in); out != in || n != 0 {
			t.Errorf("invalid IPv4 %q was modified: %q", ip, out)
		}
	}
}

func TestJSONKeyField(t *testing.T) {
	s, _ := NewScrubber()
	out, n := s.ScrubText(`{"key":"supersecretvalue123"}`)
	if n == 0 || strings.Contains(out, "supersecretvalue123") || !fxTagRe.MatchString(out) {
		t.Errorf("key field not scrubbed: %q", out)
	}
}

func TestStrictFieldsOnlyForSecretKeys(t *testing.T) {
	s, _ := NewScrubber()

	benign := `{"model":"claude-opus-4-5","role":"administrator","status":"authenticated_ok","sort":"created_at_desc"}`
	if out, n := s.ScrubText(benign); n != 0 || out != benign {
		t.Errorf("ordinary fields were redacted: n=%d out=%q", n, out)
	}

	secret := map[string]string{
		`{"x-custom-auth":"plainvaluenotashape"}`: "plainvaluenotashape", // quoted key
		`{"api-key":"somethinglongenough"}`:       "somethinglongenough",
		`session=abcdefghijklmnop`:                "abcdefghijklmnop",
	}
	for in, val := range secret {
		out, n := s.ScrubText(in)
		if n == 0 || strings.Contains(out, val) {
			t.Errorf("secret field not redacted: %q -> %q", in, out)
		}
	}

	// A value that is already a tag must not be tagged again.
	tagged := `{"token":"[REDACTED_TOKEN#abc123]"}`
	if out, n := s.ScrubText(tagged); n != 0 || out != tagged {
		t.Errorf("an existing tag was redacted again: n=%d out=%q", n, out)
	}
}

func TestVendorTiers(t *testing.T) {
	s, _ := NewScrubber()
	redacted := map[string]string{
		"aws-sts":     "ASIA" + "IOSFODNN7EXAMPLE",
		"sendgrid":    "SG." + strings.Repeat("aB3", 8) + "." + strings.Repeat("cD4", 15),
		"npm":         "npm_" + strings.Repeat("aB3", 12),
		"stripe-test": "sk_test_" + strings.Repeat("aB3", 8),
		"huggingface": "hf_" + strings.Repeat("aB", 17),
		"dsn":         "postgres://app:pw@db.example.com:5432/prod",
	}
	for name, v := range redacted {
		out, n := s.ScrubText("see " + v + " now")
		if n == 0 || strings.Contains(out, v) || strings.Contains(out, v[len(v)-12:]) {
			t.Errorf("%s: not redacted: %q", name, out)
		}
	}
	if out, _ := s.ScrubText("see " + redacted["dsn"]); strings.Contains(out, "db.example.com") {
		t.Errorf("connection string host survived: %q", out)
	}

	// Prefixes inside ordinary words and identifiers must be left alone.
	plain := []string{
		"asiapacific_region_codes_list",
		"ASIAN_HOLIDAYS",
		"secret_santa_list_2",
		"hf_model_checkpoint",
		"the token expired for this user",
	}
	for _, p := range plain {
		if out, n := s.ScrubText(p); n != 0 || out != p {
			t.Errorf("false positive on %q -> %q", p, out)
		}
	}
}

// ---------------------------------------------------------------------------
// WebSocket capture
// ---------------------------------------------------------------------------

func TestWSParserMessages(t *testing.T) {
	key := [4]byte{0x11, 0x22, 0x33, 0x44}
	long := strings.Repeat("x", 300)
	var stream []byte
	stream = append(stream, fxFrame(true, 0x1, []byte("hello"), true, key)...)
	stream = append(stream, fxFrame(false, 0x1, []byte("frag-"), false, key)...)
	stream = append(stream, fxFrame(true, 0x9, []byte("ping"), false, key)...) // control frame between fragments
	stream = append(stream, fxFrame(true, 0x0, []byte("ment"), false, key)...)
	stream = append(stream, fxFrame(true, 0x2, []byte{1, 2, 3}, true, key)...)
	stream = append(stream, fxFrame(true, 0x1, []byte(long), true, key)...) // 16-bit length
	stream = append(stream, fxFrame(true, 0x1, nil, false, key)...)         // empty message
	stream = append(stream, fxFrame(true, 0x8, []byte{0x03, 0xe8}, true, key)...)

	want := "[#1] hello\n[#2] frag-ment\n[#3] " + long + "\n[#4] \n"
	for _, chunk := range []int{len(stream), 1, 3, 7} {
		c, p := fxParse(stream, chunk, 1<<20)
		if got := string(c.Bytes()); got != want {
			t.Errorf("chunk %d: text = %q, want %q", chunk, got, want)
		}
		if got := c.Summary(); got != "4 text, 1 binary" {
			t.Errorf("chunk %d: summary = %q", chunk, got)
		}
		if p.Broken() {
			t.Errorf("chunk %d: parser stopped on a valid stream", chunk)
		}
	}
}

func TestWSParserEdgeCases(t *testing.T) {
	key := [4]byte{1, 2, 3, 4}

	packed := fxFrame(true, 0x1, []byte("abc"), false, key)
	packed[0] |= 0x40 // RSV1: compressed
	c, _ := fxParse(packed, 2, 1<<20)
	if c.Summary() != "0 text, 0 binary, 1 compressed (unreadable)" || len(c.Bytes()) != 0 {
		t.Errorf("compressed frame: %q / %q", c.Summary(), c.Bytes())
	}

	// A 64-bit length frame longer than wsMaxMessage is cut, and the next message is still read.
	big := fxFrame(true, 0x1, []byte(strings.Repeat("a", wsMaxMessage+30000)), true, key)
	c, _ = fxParse(append(big, fxFrame(true, 0x1, []byte("after"), false, key)...), 4099, 1<<20)
	if c.Summary() != "2 text, 0 binary, 1 cut short" {
		t.Errorf("oversize message: summary %q", c.Summary())
	}
	if got := c.Bytes(); !strings.HasSuffix(string(got), "\n[#2] after\n") || len(got) != len("[#1] ")+wsMaxMessage+1+len("[#2] after\n") {
		t.Errorf("oversize message: kept %d bytes", len(got))
	}

	// A small total limit cuts one message and leaves out the rest.
	three := bytes.Repeat(fxFrame(true, 0x1, []byte("aaaaaaaaaa"), false, key), 3)
	c, _ = fxParse(three, 5, 30)
	if got := string(c.Bytes()); got != "[#1] aaaaaaaaaa\n[#2] aaaaaaaaa" {
		t.Errorf("limit: text = %q", got)
	}
	if c.Summary() != "3 text, 0 binary, 1 cut short, 1 left out (capture full)" {
		t.Errorf("limit: summary = %q", c.Summary())
	}

	for name, stream := range map[string][]byte{
		"reserved opcode":      {0x83, 0x00},
		"fragmented control":   fxFrame(false, 0x9, []byte("x"), false, key),
		"lone continuation":    fxFrame(true, 0x0, []byte("x"), false, key),
		"rsv2 set":             {0xa1, 0x00},
		"new message too soon": append(fxFrame(false, 0x1, []byte("a"), false, key), fxFrame(true, 0x1, []byte("b"), false, key)...),
	} {
		if _, p := fxParse(stream, 1, 1<<20); !p.Broken() {
			t.Errorf("%s: parser should have stopped", name)
		}
	}
}

func TestWebSocketCaptureEndToEnd(t *testing.T) {
	app := fxApp(t)
	srv := httptest.NewServer(app)
	t.Cleanup(srv.Close)

	secret := "sk-" + strings.Repeat("A", 28)
	key := [4]byte{9, 8, 7, 6}
	clientFrame := fxFrame(true, 0x1, []byte(`{"auth":"`+secret+`"}`), true, key)
	serverFrame := fxFrame(true, 0x1, []byte("server saw "+secret), false, key)

	gotFrame := make(chan []byte, 1)
	gotExt := make(chan string, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotExt <- r.Header.Get("Sec-WebSocket-Extensions")
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		c, brw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: x\r\n\r\n")
		_ = brw.Flush()
		buf := make([]byte, len(clientFrame))
		if _, err := io.ReadFull(brw, buf); err != nil {
			return
		}
		gotFrame <- buf
		_, _ = c.Write(serverFrame)
		_, _ = io.Copy(io.Discard, c) // wait for the client to hang up
	}))
	t.Cleanup(up.Close)

	c, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)

	upHost := strings.TrimPrefix(up.URL, "http://")
	fmt.Fprintf(c, "GET %s/ws HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n", up.URL, upHost)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("handshake: %v / %v", err, resp)
	}
	if _, err := c.Write(clientFrame); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	back := make([]byte, len(serverFrame))
	if _, err := io.ReadFull(br, back); err != nil || !bytes.Equal(back, serverFrame) {
		t.Fatalf("the server frame did not arrive byte for byte: %v", err)
	}
	select {
	case b := <-gotFrame:
		if !bytes.Equal(b, clientFrame) {
			t.Errorf("the upstream received modified frame bytes")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the upstream never received the client frame")
	}
	if ext := <-gotExt; ext != "" {
		t.Errorf("Sec-WebSocket-Extensions must be dropped so frames stay readable, upstream saw %q", ext)
	}
	_ = c.Close()

	fxWaitRing(t, app, 1)
	if app.ring.Len() != 1 {
		t.Errorf("a WebSocket connection must produce one flow, got %d", app.ring.Len())
	}
	e := app.ring.ListRecent(1, "GET", "/ws")[0]
	if strings.Contains(e.RequestBody, secret) || !strings.Contains(e.RequestBody, "[REDACTED_TOKEN#") {
		t.Errorf("client->server text not captured and scrubbed: %q", e.RequestBody)
	}
	if strings.Contains(e.ResponseBody, secret) || !strings.Contains(e.ResponseBody, "server saw [REDACTED_TOKEN#") {
		t.Errorf("server->client text not captured and scrubbed: %q", e.ResponseBody)
	}
	if !strings.Contains(e.Note, "client->server: 1 text, 0 binary") || !strings.Contains(e.Note, "forwarded unmodified") {
		t.Errorf("note = %q", e.Note)
	}
}

func FuzzWSParserChunking(f *testing.F) {
	key := [4]byte{1, 2, 3, 4}
	f.Add(fxFrame(true, 0x1, []byte("hello"), true, key))
	f.Add(append(fxFrame(false, 0x1, []byte("a"), false, key), fxFrame(true, 0x0, []byte("b"), false, key)...))
	f.Add([]byte{0x81, 0x7e, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'})
	f.Add([]byte{0x83, 0x00, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		wc, wp := fxParse(data, len(data)+1, 4096)
		bc, bp := fxParse(data, 1, 4096)
		if !bytes.Equal(wc.Bytes(), bc.Bytes()) || wc.Summary() != bc.Summary() || wp.Broken() != bp.Broken() {
			t.Fatalf("the result depends on read sizes\nwhole:    %q / %s\nbytewise: %q / %s", wc.Bytes(), wc.Summary(), bc.Bytes(), bc.Summary())
		}
		if len(wc.Bytes()) > 4096 {
			t.Fatalf("collected %d bytes, the limit is 4096", len(wc.Bytes()))
		}
	})
}

// ---------------------------------------------------------------------------
// JSON-RPC batches
// ---------------------------------------------------------------------------

func TestJSONRPCBatch(t *testing.T) {
	app := fxApp(t)
	run := func(line string) string {
		return fxStdout(t, func() { app.handleLine([]byte(line)) })
	}

	out := run(`[{"jsonrpc":"2.0","id":1,"method":"ping"},` +
		`{"jsonrpc":"2.0","method":"notifications/initialized"},` +
		`{"jsonrpc":"2.0","id":2,"method":"no/such"},42]`)
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
		t.Fatalf("a batch answer must be exactly one line, got %q", out)
	}
	var arr []map[string]any
	if err := json.Unmarshal([]byte(out), &arr); err != nil {
		t.Fatalf("the batch answer is not a JSON array: %v (%q)", err, out)
	}
	if len(arr) != 3 {
		t.Fatalf("want 3 responses (the notification is silent), got %d: %v", len(arr), arr)
	}
	if arr[0]["id"] != float64(1) || arr[0]["result"] == nil {
		t.Errorf("first response = %v", arr[0])
	}
	if e, _ := arr[1]["error"].(map[string]any); arr[1]["id"] != float64(2) || e["code"] != float64(-32601) {
		t.Errorf("second response = %v", arr[1])
	}
	if e, _ := arr[2]["error"].(map[string]any); arr[2]["id"] != nil || e["code"] != float64(-32600) {
		t.Errorf("a non-object item must give -32600 with a null id, got %v", arr[2])
	}

	if got := run(`[{"jsonrpc":"2.0","method":"notifications/initialized"}]`); got != "" {
		t.Errorf("a batch of only notifications must produce no output, got %q", got)
	}

	for _, c := range []struct {
		name, line string
		code       float64
	}{
		{"empty batch", `[]`, -32600},
		{"broken batch", `[{"jsonrpc":`, -32700},
	} {
		var m map[string]any
		if err := json.Unmarshal([]byte(run(c.line)), &m); err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if e, _ := m["error"].(map[string]any); e["code"] != c.code || m["id"] != nil {
			t.Errorf("%s: got %v, want code %v and a null id", c.name, m, c.code)
		}
	}

	var single map[string]any
	if err := json.Unmarshal([]byte(run(`{"jsonrpc":"2.0","id":7,"method":"ping"}`)), &single); err != nil || single["id"] != float64(7) {
		t.Errorf("a single request broke: %v %v", single, err)
	}
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

func TestScanFindsSecrets(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, ".mcp.json")
	body := `{"mcpServers":{"github":{"env":{"TOKEN":"ghp_` + strings.Repeat("a1", 20) + `"}}}}`
	if err := os.WriteFile(cfg, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	s, _ := NewScrubber()
	var report strings.Builder
	ok, hits, tokens, _ := scanFile(s, cfg, &report)
	if !ok || hits == 0 || tokens == 0 || strings.Contains(report.String(), strings.Repeat("a1", 20)) {
		t.Fatalf("scan missed or leaked a secret:\n%s", report.String())
	}
}

func TestScanRoutesFileTypes(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(".env", "API_TOKEN=abcdefgh\nPORT=8080\nAUTHOR=jane\n")
	write("config.toml", "[server]\napi_key = \"short\"\nname = \"x\"\n")
	write(".mcp.json", `{"mcpServers":{"a":{"env":{"GITHUB_TOKEN":"ghp_`+strings.Repeat("a1", 20)+`"}}}}`)

	var out, errw bytes.Buffer
	code := runScanTo(&out, &errw, []string{dir})
	report := out.String()
	if code != 0 {
		t.Fatalf("exit code %d\n%s%s", code, report, errw.String())
	}
	for _, want := range []string{"API_TOKEN", "server.api_key", hiddenValue, "GITHUB_TOKEN"} {
		if !strings.Contains(report, want) {
			t.Errorf("report is missing %q:\n%s", want, report)
		}
	}
	for _, bad := range []string{"invalid JSON", "AUTHOR", "abcdefgh", strings.Repeat("a1", 20)} {
		if strings.Contains(report, bad) {
			t.Errorf("report must not contain %q:\n%s", bad, report)
		}
	}
}

func TestScanDeepSkipsOnlyByDirectoryName(t *testing.T) {
	root := t.TempDir()
	cfg := `{"mcpServers":{"a":{"env":{"TOKEN":"ghp_` + strings.Repeat("a1", 20) + `"}}}}`
	for _, rel := range []string{
		filepath.Join("rebuild-tools", ".github", "mcp.json"), // names merely contain "build" and ".git"
		filepath.Join("node_modules", "pkg", "mcp.json"),      // really skipped
	} {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(cfg), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var out, errw bytes.Buffer
	runScanTo(&out, &errw, []string{"--deep", root})
	report := out.String()
	if !strings.Contains(report, filepath.Join("rebuild-tools", ".github", "mcp.json")) {
		t.Errorf("the config under .github was not scanned:\n%s", report)
	}
	if strings.Contains(report, "node_modules") {
		t.Errorf("node_modules must be skipped:\n%s", report)
	}
}

func TestHistoryScanNeverPrintsText(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".bash_history")
	secret := "ghp_" + strings.Repeat("a1", 20)
	if err := os.WriteFile(path, []byte("ls -la\nexport GITHUB_TOKEN="+secret+"\ngit status\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s, _ := NewScrubber()
	var report strings.Builder
	ok, hits, tokens := scanHistoryFile(s, path, &report)
	if !ok || hits != 1 || tokens == 0 {
		t.Fatalf("ok=%v hits=%d tokens=%d\n%s", ok, hits, tokens, report.String())
	}
	if strings.Contains(report.String(), "ghp_") || strings.Contains(report.String(), "export") || !strings.Contains(report.String(), "text not shown") {
		t.Errorf("history text must never be shown:\n%s", report.String())
	}
}

// ---------------------------------------------------------------------------
// More redaction layers
// ---------------------------------------------------------------------------

func TestPEMPrivateKeys(t *testing.T) {
	s, _ := NewScrubber()
	cases := map[string]string{
		"rsa":      "key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234\nabcdefgh\n-----END RSA PRIVATE KEY-----\nrest ok",
		"plain":    "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\n-----END PRIVATE KEY-----",
		"json":     `{"k":"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\n-----END PRIVATE KEY-----\n"}`,
		"pgp":      "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQdGBF\n-----END PGP PRIVATE KEY BLOCK-----",
		"cut off":  "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA",
	}
	for name, in := range cases {
		out, n := s.ScrubText(in)
		for _, body := range []string{"MIIEow", "MIIEvQ", "lQdGBF", "b3BlbnNzaC1r", "abcdefgh"} {
			if strings.Contains(out, body) {
				t.Errorf("%s: key material %q survived: %q", name, body, out)
			}
		}
		if n == 0 || !fxTagRe.MatchString(out) {
			t.Errorf("%s: not redacted: n=%d out=%q", name, n, out)
		}
	}
	if out, _ := s.ScrubText(cases["rsa"]); !strings.Contains(out, "rest ok") {
		t.Errorf("text after the key block must survive: %q", out)
	}
	cert := "-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIE\n-----END CERTIFICATE-----"
	if out, n := s.ScrubText(cert); n != 0 || out != cert {
		t.Errorf("a public certificate must not be redacted: n=%d out=%q", n, out)
	}
}

func TestXMLSecrets(t *testing.T) {
	s, _ := NewScrubber()
	in := `<user><password>hunter2hunter2</password><name>bob</name></user>`
	out, n := s.ScrubText(in)
	if n == 0 || strings.Contains(out, "hunter2hunter2") || !strings.Contains(out, "<name>bob</name>") {
		t.Errorf("password element: n=%d out=%q", n, out)
	}
	for _, in := range []string{
		`<wsse:Password Type="x">topsecretvalue</wsse:Password>`,
		`<apiKey><![CDATA[abc123def456ghi]]></apiKey>`,
	} {
		if out, n := s.ScrubText(in); n == 0 || strings.Contains(out, "topsecretvalue") || strings.Contains(out, "abc123def456ghi") {
			t.Errorf("not redacted: %q -> %q", in, out)
		}
	}
	tagged := `<token>[REDACTED_TOKEN#abc123]</token>`
	if out, n := s.ScrubText(tagged); n != 0 || out != tagged {
		t.Errorf("an existing tag was redacted again: n=%d out=%q", n, out)
	}
}

// The XML must stay well formed for whoever reads it: only the text inside the
// element is replaced, and the closing tag keeps its name.
func TestXMLSecretsKeepClosingTags(t *testing.T) {
	s, _ := NewScrubber()
	keep := regexp.MustCompile(`^<user><password>\[REDACTED_TOKEN#[0-9a-f]+\]</password><name>bob</name></user>$`)
	if out, _ := s.ScrubText(`<user><password>hunter2hunter2</password><name>bob</name></user>`); !keep.MatchString(out) {
		t.Errorf("closing tags were damaged: %q", out)
	}
	cdata := regexp.MustCompile(`^<apiKey>\[REDACTED_TOKEN#[0-9a-f]+\]</apiKey>$`)
	if out, _ := s.ScrubText(`<apiKey><![CDATA[abc123def456ghi]]></apiKey>`); !cdata.MatchString(out) {
		t.Errorf("CDATA element: %q", out)
	}

	// A body cut off by the capture limit must still not leak the value.
	for _, in := range []string{`<password>hunter2hunter2</passw`, `<password>hunter2hunter2</`, `<password>hunter2hunter2`} {
		out, n := s.ScrubText(in)
		if n == 0 || strings.Contains(out, "hunter2hunter2") {
			t.Errorf("truncated body leaked: %q -> %q", in, out)
		}
	}
	if out, _ := s.ScrubText(`<password>hunter2hunter2</passw`); !strings.HasSuffix(out, "</passw") {
		t.Errorf("the cut-off tail must be left as it was: %q", out)
	}
}

func TestJSONSecretArrays(t *testing.T) {
	s, _ := NewScrubber()
	in := `{"Password": ["value1234abcd", "second5678efgh"], "user": ["bob"]}`
	out, n := s.ScrubText(in)
	if n != 2 || strings.Contains(out, "value1234abcd") || strings.Contains(out, "second5678efgh") || !strings.Contains(out, `"user": ["bob"]`) {
		t.Errorf("array secrets: n=%d out=%q", n, out)
	}
}

func TestSecretsInsideBase64(t *testing.T) {
	s, _ := NewScrubber()
	secret := "sk-" + strings.Repeat("A", 28)
	blob := base64.StdEncoding.EncodeToString([]byte(`{"api_key":"` + secret + `","user":"bob"}`))
	out, n := s.ScrubText("payload: " + blob + " end")
	if n == 0 || strings.Contains(out, blob) || !fxTagRe.MatchString(out) || !strings.Contains(out, " end") {
		t.Errorf("padded standard base64: n=%d out=%q", n, out)
	}

	blob2 := base64.RawURLEncoding.EncodeToString([]byte("password=hunter2hunter2&user=bob&padding=xxxx"))
	if out, n := s.ScrubText(blob2); n == 0 || strings.Contains(out, blob2) {
		t.Errorf("unpadded URL-safe base64: n=%d out=%q", n, out)
	}

	// Binary data such as an image decodes to nothing readable and is left alone.
	img := "data:image/jpeg;base64," + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xff, 0xd8, 0xff, 0xe0}, 12))
	if out, n := s.ScrubText(img); n != 0 || out != img {
		t.Errorf("binary base64 was modified: n=%d out=%q", n, out)
	}
}

func TestRestrictAcceptEncoding(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"gzip, br, zstd;q=0.9", "gzip"},
		{"br", "identity"},
		{"gzip;q=0, deflate", "deflate"},
		{"*", "gzip, deflate"},
		{"gzip, deflate, br", "gzip, deflate"},
		{"identity", "identity"},
	} {
		src := http.Header{}
		src.Set("Accept-Encoding", c.in)
		dst := http.Header{}
		restrictAcceptEncoding(dst, src)
		if got := dst.Get("Accept-Encoding"); got != c.want {
			t.Errorf("%q -> %q, want %q", c.in, got, c.want)
		}
	}
	dst := http.Header{}
	restrictAcceptEncoding(dst, http.Header{})
	if _, present := dst["Accept-Encoding"]; present {
		t.Errorf("no client header must mean no upstream header, got %v", dst)
	}
}

func TestUpstreamNeverSeesBrotli(t *testing.T) {
	app := fxApp(t)
	got := make(chan string, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get("Accept-Encoding")
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(up.Close)
	req := httptest.NewRequest("GET", up.URL+"/x", nil)
	req.Header.Set("Accept-Encoding", "br, gzip")
	app.ServeHTTP(httptest.NewRecorder(), req)
	if g := <-got; g != "gzip" {
		t.Errorf("upstream saw Accept-Encoding %q, want gzip", g)
	}
}

func TestProtobufBodiesAreNotCaptured(t *testing.T) {
	app := fxApp(t)
	app.capture(rawFlow{
		started: time.Now(), method: "POST", url: "http://127.0.0.1:9/svc.Chat/Send",
		reqHeaders: http.Header{"Content-Type": {"application/grpc"}}, reqBody: []byte{0, 0, 0, 0, 5, 1, 2, 3, 4, 5},
		status: 200, respHeaders: http.Header{"Content-Type": {"application/x-protobuf"}}, respBody: []byte("secret-looking-bytes"),
	})
	e := app.ring.ListRecent(1, "POST", "/svc.Chat")[0]
	if e.RequestBody != "[protobuf/gRPC body not captured: 10 bytes]" || e.ResponseBody != "[protobuf/gRPC body not captured: 20 bytes]" {
		t.Errorf("bodies = %q / %q", e.RequestBody, e.ResponseBody)
	}
	if !strings.Contains(e.Note, "Protobuf/gRPC") {
		t.Errorf("note = %q", e.Note)
	}
}

// ---------------------------------------------------------------------------
// Request shield and multipart
// ---------------------------------------------------------------------------

func TestFailClosedRequestShield(t *testing.T) {
	app := fxApp(t)
	post := func(enc string) int {
		req := httptest.NewRequest("POST", "/v1/chat", strings.NewReader("payload-bytes"))
		req.Header.Set("Content-Encoding", enc)
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, req)
		return rec.Code
	}
	for _, enc := range []string{"br", "zstd", "gzip, br"} {
		if code := post(enc); code != http.StatusUnsupportedMediaType {
			t.Errorf("Content-Encoding %q: status %d, want 415", enc, code)
		}
	}
	// Encodings NullWire can read pass the shield (and then fail later for lack of an upstream).
	for _, enc := range []string{"gzip", "deflate", "identity"} {
		if code := post(enc); code == http.StatusUnsupportedMediaType {
			t.Errorf("Content-Encoding %q must not be blocked", enc)
		}
	}
	app.allowUninspectable = true
	if code := post("br"); code == http.StatusUnsupportedMediaType {
		t.Errorf("-allow-uninspectable must let the request through")
	}
}

func TestMultipartScrubbing(t *testing.T) {
	app := &App{scrub: func() *Scrubber { s, _ := NewScrubber(); return s }()}
	body := "--boundary\r\n" +
		"Content-Disposition: form-data; name=\"username\"\r\n\r\nadmin\r\n" +
		"--boundary\r\n" +
		"Content-Disposition: form-data; name=\"token\"\r\n\r\nsk_live_1234567890abcdef\r\n" +
		"--boundary\r\n" +
		"Content-Disposition: form-data; name=\"upload\"; filename=\"notes.txt\"\r\nContent-Type: text/plain\r\n\r\nfile contents here\r\n" +
		"--boundary--\r\n"
	out := app.scrubMultipart("multipart/form-data; boundary=boundary", []byte(body))
	if !strings.Contains(out, "username=admin") {
		t.Errorf("ordinary field missing: %q", out)
	}
	if strings.Contains(out, "sk_live_1234567890abcdef") || !fxTagRe.MatchString(out) {
		t.Errorf("secret field not redacted: %q", out)
	}
	if strings.Contains(out, "file contents here") || !strings.Contains(out, `upload=[file "notes.txt"`) {
		t.Errorf("file content must not be stored: %q", out)
	}

	// A body that cannot be parsed is still scrubbed, never passed through.
	broken := app.scrubMultipart("multipart/form-data; boundary=zzz", []byte("password=hunter2hunter2"))
	if strings.Contains(broken, "hunter2hunter2") {
		t.Errorf("unparseable multipart leaked: %q", broken)
	}
}

// ---------------------------------------------------------------------------
// YAML and ZIP scanning
// ---------------------------------------------------------------------------

func TestYAMLScan(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.yaml")
	body := "# settings\ndatabase:\n  username: admin\n  password: \"supersecretvalue123\"\n  port: 5432\n" +
		"api_key: sk_live_1234567890abcdefghijklmnop\nlist:\n  - token: abcdefghijklmnop12345\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	s, _ := NewScrubber()
	var report strings.Builder
	ok, hits, tokens := scanYAMLFile(s, path, &report)
	if !ok || hits != 3 || tokens < 3 {
		t.Fatalf("ok=%v hits=%d tokens=%d\n%s", ok, hits, tokens, report.String())
	}
	for _, leak := range []string{"supersecretvalue123", "sk_live_1234567890abcdefghijklmnop", "abcdefghijklmnop12345"} {
		if strings.Contains(report.String(), leak) {
			t.Errorf("report leaked %q:\n%s", leak, report.String())
		}
	}
}

func TestScanYAMLNeedsFlag(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.yaml"), []byte("password: supersecretvalue123\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errw bytes.Buffer
	runScanTo(&out, &errw, []string{dir})
	if strings.Contains(out.String(), "app.yaml") {
		t.Errorf("YAML must not be scanned without --yaml:\n%s", out.String())
	}
	out.Reset()
	runScanTo(&out, &errw, []string{"--yaml", dir})
	if !strings.Contains(out.String(), "app.yaml") || !strings.Contains(out.String(), "password") || strings.Contains(out.String(), "supersecretvalue123") {
		t.Errorf("--yaml report wrong:\n%s", out.String())
	}
}

func TestZipBombShield(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.zip")
	secret := "ghp_" + strings.Repeat("a1", 20)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("bomb.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write(bytes.Repeat([]byte("A"), 3<<20)) // compresses to a few KB, expands to 3 MiB
	w, err = zw.Create("config.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("export GITHUB_TOKEN=" + secret + "\n"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}

	s, _ := NewScrubber()
	var report strings.Builder
	ok, hits, tokens := scanZipFile(s, path, &report)
	if !ok || hits != 1 || tokens == 0 {
		t.Fatalf("ok=%v hits=%d tokens=%d\n%s", ok, hits, tokens, report.String())
	}
	r := report.String()
	if !strings.Contains(r, "Zip Bomb Shield") || !strings.Contains(r, `"config.txt"`) || strings.Contains(r, secret) {
		t.Errorf("report wrong:\n%s", r)
	}
}

func TestCurlExportCoversEveryTagKind(t *testing.T) {
	e := FlowEntry{
		ID: 3, Method: "POST", URL: "https://api.example.com/v1",
		RequestHeaders: map[string]string{"Content-Type": "application/json"},
		RequestBody:    `{"key":"[REDACTED_KEY#abc123]","t":"[REDACTED_TOKEN#def456]","ip":"[REDACTED_IP#012345]"}`,
	}
	out := buildCurl(e)
	for _, want := range []string{"NULLWIRE_PRIVATE_KEY", "NULLWIRE_AUTH_TOKEN", "NULLWIRE_IP"} {
		if !strings.Contains(out, want) {
			t.Errorf("curl export is missing %s:\n%s", want, out)
		}
	}
}
