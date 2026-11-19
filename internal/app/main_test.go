package app

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	tokenTagRe  = regexp.MustCompile(`\[REDACTED_TOKEN#[0-9a-f]{6}\]`)
	cookieTagRe = regexp.MustCompile(`^\[REDACTED_COOKIE#[0-9a-f]{6}\]$`)
	ipTagRe     = regexp.MustCompile(`\[REDACTED_IP#[0-9a-f]{6}\]`)
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newTestApp(t *testing.T) *App {
	t.Helper()
	s := mustScrubber()
	app := &App{
		ring:      NewRingBuffer(),
		scrub:     s,
		port:      1,
		transport: &http.Transport{Proxy: nil, DisableCompression: true},
	}
	t.Cleanup(app.transport.CloseIdleConnections)
	return app
}

func waitForRing(t *testing.T, app *App, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for app.ring.Len() < n {
		if time.Now().After(deadline) {
			t.Fatalf("ring buffer never reached %d entries (has %d)", n, app.ring.Len())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// captureStdout runs fn while os.Stdout is redirected, returning what was written.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	func() {
		defer func() { os.Stdout = orig }()
		fn()
	}()
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

func rpc(t *testing.T, app *App, line string) string {
	t.Helper()
	return captureStdout(t, func() { app.handleLine([]byte(line)) })
}

func parseFrame(t *testing.T, out string) map[string]any {
	t.Helper()
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("frame must end with newline, got %q", out)
	}
	if strings.Count(out, "\n") != 1 {
		t.Fatalf("frame must be exactly one line, got %q", out)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("frame is not valid JSON: %v (%q)", err, out)
	}
	if m["jsonrpc"] != "2.0" {
		t.Fatalf("jsonrpc field = %v, want 2.0", m["jsonrpc"])
	}
	return m
}

func resultOf(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	res, ok := m["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result object in %v", m)
	}
	return res
}

// toolText extracts content[0].text and isError from a tool result map.
func toolText(t *testing.T, res map[string]any) (string, bool) {
	t.Helper()
	content, ok := res["content"].([]any)
	if !ok || len(content) != 1 {
		t.Fatalf("bad content in %v", res)
	}
	first, ok := content[0].(map[string]any)
	if !ok || first["type"] != "text" {
		t.Fatalf("bad content item in %v", res)
	}
	text, _ := first["text"].(string)
	isErr, _ := res["isError"].(bool)
	if res["resultType"] != "complete" {
		t.Fatalf("resultType = %v, want complete", res["resultType"])
	}
	return text, isErr
}

// ---------------------------------------------------------------------------
// Scrubber
// ---------------------------------------------------------------------------

func TestScrubberCorrelationTags(t *testing.T) {
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	secretA := "sk-" + strings.Repeat("A", 28)
	secretB := "sk-" + strings.Repeat("B", 28)

	out1, n1 := s.ScrubText("first request used " + secretA)
	out2, n2 := s.ScrubText("second request used " + secretA + " again")
	outB, _ := s.ScrubText("third request used " + secretB)

	if n1 != 1 || n2 != 1 {
		t.Fatalf("redaction counts = %d, %d; want 1, 1", n1, n2)
	}
	tag1, tag2, tagB := tokenTagRe.FindString(out1), tokenTagRe.FindString(out2), tokenTagRe.FindString(outB)
	if tag1 == "" || tag2 == "" || tagB == "" {
		t.Fatalf("missing tags: %q %q %q", out1, out2, outB)
	}
	if tag1 != tag2 {
		t.Errorf("equal secrets must share a tag: %s vs %s", tag1, tag2)
	}
	if tag1 == tagB {
		t.Errorf("different secrets must not share a tag: %s", tag1)
	}
	for _, out := range []string{out1, out2, outB} {
		if strings.Contains(out, secretA) || strings.Contains(out, secretB) {
			t.Errorf("secret leaked: %q", out)
		}
	}

	// A second scrubber has a different nonce, so the same secret hashes differently.
	s2 := mustScrubber()
	other, _ := s2.ScrubText(secretA)
	if tokenTagRe.FindString(other) == tag1 {
		t.Errorf("tags must be salted per process, but two scrubbers agreed on %s", tag1)
	}
}

func TestScrubberIPsAndLoopback(t *testing.T) {
	s := mustScrubber()
	in := "peer 192.168.10.20 local 127.0.0.1 any 0.0.0.0 peer2 192.168.10.20"
	out, n := s.ScrubText(in)

	if strings.Contains(out, "192.168.10.20") {
		t.Errorf("IP leaked: %q", out)
	}
	if !strings.Contains(out, "127.0.0.1") || !strings.Contains(out, "0.0.0.0") {
		t.Errorf("127.0.0.1 and 0.0.0.0 must be preserved: %q", out)
	}
	tags := ipTagRe.FindAllString(out, -1)
	if len(tags) != 2 || tags[0] != tags[1] {
		t.Errorf("want two identical IP tags, got %v", tags)
	}
	if n != 2 || s.IPs.Load() != 2 {
		t.Errorf("count = %d, IPs counter = %d; want 2, 2", n, s.IPs.Load())
	}
}

func TestScrubberSecretShapes(t *testing.T) {
	s := mustScrubber()
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	cases := map[string][]string{
		"jwt":      {"token value " + jwt, jwt},
		"json":     {`{"password":"correct-horse-battery","session_id":"abc123def456"}`, "correct-horse-battery"},
		"query":    {"https://api.test/x?api_key=supersecret99&ok=1", "supersecret99"},
		"bearer":   {"Authorization: Bearer abcdefghijklmnop", "abcdefghijklmnop"},
		"github":   {"ghp_" + strings.Repeat("a1", 20), "ghp_" + strings.Repeat("a1", 20)},
		"userinfo": {"http://admin:hunter2pass@db.internal/path", "hunter2pass"},
	}
	for name, c := range cases {
		out, n := s.ScrubText(c[0])
		if n == 0 {
			t.Errorf("%s: nothing was redacted in %q", name, c[0])
		}
		if strings.Contains(out, c[1]) {
			t.Errorf("%s: secret leaked: %q", name, out)
		}
	}
	if s.Tokens.Load() == 0 {
		t.Errorf("Tokens counter never moved")
	}
}

func TestScrubHeaders(t *testing.T) {
	s := mustScrubber()
	h := http.Header{
		"Authorization": {"Bearer abcdefghijklmnop"},
		"Cookie":        {"sid=abc; theme=dark"},
		"X-Api-Key":     {"k-12345"},
		"Accept":        {"application/json"},
	}
	out, n := s.ScrubHeaders(h)
	if !strings.HasPrefix(out["Authorization"], "Bearer [REDACTED_TOKEN#") {
		t.Errorf("Authorization = %q", out["Authorization"])
	}
	if !cookieTagRe.MatchString(out["Cookie"]) {
		t.Errorf("Cookie = %q", out["Cookie"])
	}
	if !tokenTagRe.MatchString(out["X-Api-Key"]) {
		t.Errorf("X-Api-Key = %q", out["X-Api-Key"])
	}
	if out["Accept"] != "application/json" {
		t.Errorf("Accept changed: %q", out["Accept"])
	}
	if n != 3 || s.Cookies.Load() != 1 {
		t.Errorf("count = %d, Cookies = %d; want 3, 1", n, s.Cookies.Load())
	}
}

// ---------------------------------------------------------------------------
// RingBuffer
// ---------------------------------------------------------------------------

func TestRingBufferWrapAndClear(t *testing.T) {
	r := NewRingBuffer()
	for i := 1; i <= 60; i++ {
		r.Push(FlowEntry{Method: "GET", URL: fmt.Sprintf("/item/%d", i)})
	}
	if r.Len() != ringCapacity {
		t.Fatalf("Len = %d, want %d", r.Len(), ringCapacity)
	}
	all := r.ListRecent(100, "", "")
	if len(all) != ringCapacity {
		t.Fatalf("ListRecent returned %d entries, want %d", len(all), ringCapacity)
	}
	if all[0].ID != 60 || all[len(all)-1].ID != 11 {
		t.Errorf("newest/oldest IDs = %d/%d, want 60/11", all[0].ID, all[len(all)-1].ID)
	}
	if _, ok := r.GetByID(10); ok {
		t.Errorf("flow 10 should have been evicted")
	}
	if e, ok := r.GetByID(11); !ok || e.URL != "/item/11" {
		t.Errorf("flow 11 should still exist, got %+v ok=%v", e, ok)
	}

	r.Push(FlowEntry{Method: "POST", URL: "/Special/Path"})
	if got := r.ListRecent(10, "post", "special"); len(got) != 1 || got[0].ID != 61 {
		t.Errorf("filtered list = %+v", got)
	}
	if got := r.ListRecent(3, "", ""); len(got) != 3 || got[0].ID != 61 || got[2].ID != 59 {
		t.Errorf("limit 3 list = %+v", got)
	}

	r.Clear()
	if r.Len() != 0 || len(r.ListRecent(10, "", "")) != 0 {
		t.Errorf("ring not empty after Clear")
	}
	if _, ok := r.GetByID(61); ok {
		t.Errorf("cleared flow still retrievable")
	}
	r.Push(FlowEntry{Method: "GET", URL: "/after"})
	if got := r.ListRecent(1, "", ""); len(got) != 1 || got[0].ID != 62 {
		t.Errorf("ID after Clear = %+v, want 62 (monotonic)", got)
	}
}

// ---------------------------------------------------------------------------
// End-to-end proxy
// ---------------------------------------------------------------------------

type upstreamSeen struct {
	mu             sync.Mutex
	acceptEncoding string
	targetHeader   string
	authorization  string
	contentType    string
	host           string
	path           string
	body           string
}

func newUpstream(t *testing.T, seen *upstreamSeen) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen.mu.Lock()
		seen.acceptEncoding = r.Header.Get("Accept-Encoding")
		seen.targetHeader = r.Header.Get("X-Target-URL")
		seen.authorization = r.Header.Get("Authorization")
		seen.contentType = r.Header.Get("Content-Type")
		seen.host = r.Host
		seen.path = r.URL.RequestURI()
		seen.body = string(b)
		seen.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Set-Cookie", "session=zzzTOPSECRETzzz; Path=/")
		_, _ = io.WriteString(w, `{"access_token":"tok_supersecretvalue_12345","user":"bob"}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestReverseGatewayCaptureAndCurlExport(t *testing.T) {
	app := newTestApp(t)
	seen := &upstreamSeen{}
	up := newUpstream(t, seen)

	req := httptest.NewRequest("POST", "/v1/login?api_key=abcd1234secret", strings.NewReader(`{"password":"hunter2hunter2"}`))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("X-Target-URL", up.URL)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Authorization", "Bearer abcdefghijklmnop12345")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	app.ServeHTTP(rec, req)

	// The local client must get the original, un-scrubbed response.
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "tok_supersecretvalue_12345") {
		t.Errorf("client did not receive the original body: %q", rec.Body.String())
	}

	// Upstream must see an un-scrubbed request, without X-Target-URL. Accept-Encoding
	// is cut down to what NullWire can decode, so a gzip offer passes through.
	seen.mu.Lock()
	if seen.acceptEncoding != "gzip" {
		t.Errorf("upstream Accept-Encoding = %q, want gzip", seen.acceptEncoding)
	}
	if seen.targetHeader != "" {
		t.Errorf("X-Target-URL reached upstream: %q", seen.targetHeader)
	}
	if seen.authorization != "Bearer abcdefghijklmnop12345" {
		t.Errorf("upstream Authorization = %q", seen.authorization)
	}
	if seen.host != strings.TrimPrefix(up.URL, "http://") {
		t.Errorf("upstream Host = %q, want %q", seen.host, strings.TrimPrefix(up.URL, "http://"))
	}
	if seen.path != "/v1/login?api_key=abcd1234secret" {
		t.Errorf("upstream path = %q", seen.path)
	}
	if seen.body != `{"password":"hunter2hunter2"}` {
		t.Errorf("upstream body = %q", seen.body)
	}
	seen.mu.Unlock()

	// The ring buffer holds only scrubbed data.
	waitForRing(t, app, 1)
	flows := app.ring.ListRecent(1, "", "")
	if len(flows) != 1 {
		t.Fatalf("ring has %d flows", len(flows))
	}
	e := flows[0]
	if e.Method != "POST" || e.StatusCode != 200 || e.ID != 1 {
		t.Errorf("unexpected entry header: %+v", e)
	}
	if strings.Contains(e.ResponseBody, "tok_supersecretvalue_12345") || !strings.Contains(e.ResponseBody, "[REDACTED_TOKEN#") {
		t.Errorf("response body not scrubbed: %q", e.ResponseBody)
	}
	if !strings.Contains(e.ResponseBody, `"user":"bob"`) {
		t.Errorf("non-secret data was damaged: %q", e.ResponseBody)
	}
	if strings.Contains(e.RequestBody, "hunter2hunter2") || !strings.Contains(e.RequestBody, "[REDACTED_TOKEN#") {
		t.Errorf("request body not scrubbed: %q", e.RequestBody)
	}
	if strings.Contains(e.URL, "abcd1234secret") || !strings.Contains(e.URL, "api_key=[REDACTED_TOKEN#") {
		t.Errorf("URL not scrubbed: %q", e.URL)
	}
	if !strings.HasPrefix(e.RequestHeaders["Authorization"], "Bearer [REDACTED_TOKEN#") {
		t.Errorf("Authorization header not scrubbed: %q", e.RequestHeaders["Authorization"])
	}
	if !strings.HasPrefix(e.ResponseHeaders["Set-Cookie"], "[REDACTED_COOKIE#") {
		t.Errorf("Set-Cookie not scrubbed: %q", e.ResponseHeaders["Set-Cookie"])
	}
	if e.RedactionCount < 5 {
		t.Errorf("RedactionCount = %d, want at least 5", e.RedactionCount)
	}

	// export_sanitized_curl
	res := app.toolExportCurl(json.RawMessage(fmt.Sprintf(`{"flow_id":%d}`, e.ID)))
	cmd, isErr := toolText(t, res)
	if isErr {
		t.Fatalf("export failed: %s", cmd)
	}
	for _, secret := range []string{"hunter2hunter2", "abcd1234secret", "abcdefghijklmnop12345", "zzzTOPSECRETzzz"} {
		if strings.Contains(cmd, secret) {
			t.Errorf("curl output leaked %q:\n%s", secret, cmd)
		}
	}
	for _, want := range []string{
		"curl -X 'POST' 'http://127.0.0.1:",
		`api_key='"$NULLWIRE_AUTH_TOKEN"`,
		`-H 'Authorization: Bearer '"$NULLWIRE_AUTH_TOKEN"`,
		"-H 'Content-Type: application/json'",
		"--data-raw",
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("curl output missing %q:\n%s", want, cmd)
		}
	}
	if strings.Contains(cmd, "Accept-Encoding") || strings.Contains(cmd, "Content-Length") {
		t.Errorf("curl output contains headers it should skip:\n%s", cmd)
	}
	var commandLines []string
	for _, line := range strings.Split(cmd, "\n") {
		if !strings.HasPrefix(line, "#") {
			commandLines = append(commandLines, line)
		}
	}
	command := strings.Join(commandLines, "\n")
	if strings.Contains(command, "[REDACTED_") {
		t.Errorf("an unresolved redaction tag remains in the command:\n%s", command)
	}
	if strings.Count(command, "'")%2 != 0 || strings.Count(command, `"`)%2 != 0 {
		t.Errorf("unbalanced quotes in command:\n%s", command)
	}

	// Unknown flow IDs are reported as tool errors, not crashes.
	msg, isErr := toolText(t, app.toolExportCurl(json.RawMessage(`{"flow_id":999}`)))
	if !isErr || !strings.Contains(msg, "not in RAM ring buffer") {
		t.Errorf("missing flow: isErr=%v msg=%q", isErr, msg)
	}
}

func TestReverseGatewayRejectsForeignHost(t *testing.T) {
	app := newTestApp(t)
	req := httptest.NewRequest("GET", "/v1/users", nil)
	req.Host = "evil.example.com"
	req.Header.Set("X-Target-URL", "http://127.0.0.1:9")
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if app.ring.Len() != 0 {
		t.Errorf("rejected request must not be captured")
	}
}

func TestReverseGatewayWithoutTarget(t *testing.T) {
	app := newTestApp(t)
	req := httptest.NewRequest("GET", "/v1/users", nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestForwardProxyMode(t *testing.T) {
	app := newTestApp(t)
	seen := &upstreamSeen{}
	up := newUpstream(t, seen)

	req := httptest.NewRequest("GET", up.URL+"/headers?x=1", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"user":"bob"`) {
		t.Fatalf("forward mode response: %d %q", rec.Code, rec.Body.String())
	}
	seen.mu.Lock()
	if seen.acceptEncoding != "gzip" {
		t.Errorf("upstream Accept-Encoding = %q, want gzip", seen.acceptEncoding)
	}
	if seen.path != "/headers?x=1" {
		t.Errorf("upstream path = %q", seen.path)
	}
	seen.mu.Unlock()

	waitForRing(t, app, 1)
	e := app.ring.ListRecent(1, "GET", "/headers")[0]
	if !strings.Contains(e.URL, "/headers?x=1") {
		t.Errorf("URL = %q", e.URL)
	}
}

// ---------------------------------------------------------------------------
// MCP JSON-RPC
// ---------------------------------------------------------------------------

func TestMCPServerDiscover(t *testing.T) {
	app := newTestApp(t)
	m := parseFrame(t, rpc(t, app, `{"jsonrpc":"2.0","id":1,"method":"server/discover"}`))
	if m["id"] != float64(1) {
		t.Errorf("id = %v", m["id"])
	}
	res := resultOf(t, m)
	if res["resultType"] != "complete" {
		t.Errorf("resultType = %v", res["resultType"])
	}
	versions, _ := res["protocolVersions"].([]any)
	if len(versions) != 3 || versions[0] != "2026-07-28" || versions[1] != "2025-11-25" || versions[2] != "2024-11-05" {
		t.Errorf("protocolVersions = %v", versions)
	}
	if _, ok := res["capabilities"].(map[string]any)["tools"]; !ok {
		t.Errorf("capabilities = %v", res["capabilities"])
	}
	if info := res["serverInfo"].(map[string]any); info["name"] != "nullwire-mcp" || info["version"] != "1.2.0" {
		t.Errorf("serverInfo = %v", info)
	}
}

func TestMCPInitializeAndPing(t *testing.T) {
	app := newTestApp(t)

	res := resultOf(t, parseFrame(t, rpc(t, app,
		`{"jsonrpc":"2.0","id":"abc","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}`)))
	if res["protocolVersion"] != "2024-11-05" {
		t.Errorf("protocolVersion echo = %v", res["protocolVersion"])
	}
	if info := res["serverInfo"].(map[string]any); info["name"] != "nullwire-mcp" {
		t.Errorf("serverInfo = %v", info)
	}

	m := parseFrame(t, rpc(t, app, `{"jsonrpc":"2.0","id":2,"method":"initialize"}`))
	if resultOf(t, m)["protocolVersion"] != "2025-11-25" {
		t.Errorf("default protocolVersion = %v", resultOf(t, m)["protocolVersion"])
	}

	m = parseFrame(t, rpc(t, app, `{"jsonrpc":"2.0","id":3,"method":"ping"}`))
	if resultOf(t, m)["resultType"] != "complete" {
		t.Errorf("ping result = %v", m["result"])
	}
}

func TestMCPNotificationsEmitNothing(t *testing.T) {
	app := newTestApp(t)
	lines := []string{
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`,
		`{"jsonrpc":"2.0","id":null,"method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","method":"ping"}`,
	}
	for _, l := range lines {
		if out := rpc(t, app, l); out != "" {
			t.Errorf("notification %s wrote %q to stdout", l, out)
		}
	}
}

func TestMCPToolsList(t *testing.T) {
	app := newTestApp(t)
	res := resultOf(t, parseFrame(t, rpc(t, app, `{"jsonrpc":"2.0","id":4,"method":"tools/list"}`)))
	if res["resultType"] != "complete" || res["ttlMs"] != float64(300000) || res["cacheScope"] != "global" {
		t.Errorf("list metadata = %v", res)
	}
	tools, _ := res["tools"].([]any)
	if len(tools) != 5 {
		t.Fatalf("got %d tools, want 5", len(tools))
	}
	names := map[string]map[string]any{}
	for _, raw := range tools {
		tool := raw.(map[string]any)
		names[tool["name"].(string)] = tool
		schema, ok := tool["inputSchema"].(map[string]any)
		if !ok || schema["type"] != "object" {
			t.Errorf("tool %v has bad inputSchema", tool["name"])
		}
	}
	for _, n := range []string{"inspect_traffic", "export_har", "export_sanitized_curl", "clear_ram_buffer", "export_attestation"} {
		if names[n] == nil {
			t.Errorf("tool %s missing", n)
		}
	}
	req, _ := names["export_sanitized_curl"]["inputSchema"].(map[string]any)["required"].([]any)
	if len(req) != 1 || req[0] != "flow_id" {
		t.Errorf("export_sanitized_curl required = %v", req)
	}
}

func TestMCPToolsCall(t *testing.T) {
	app := newTestApp(t)
	app.ring.Push(FlowEntry{Method: "GET", URL: "http://api.test/a", StatusCode: 200})
	app.ring.Push(FlowEntry{Method: "POST", URL: "http://api.test/b", StatusCode: 201})

	// inspect_traffic with filters
	m := parseFrame(t, rpc(t, app,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"inspect_traffic","arguments":{"limit":5,"method":"post"}}}`))
	text, isErr := toolText(t, resultOf(t, m))
	if isErr {
		t.Fatalf("inspect_traffic failed: %s", text)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		t.Fatalf("inspect_traffic text is not JSON: %v", err)
	}
	flows, _ := payload["flows"].([]any)
	if len(flows) != 1 || payload["returned"] != float64(1) || payload["ring_size"] != float64(2) {
		t.Errorf("payload = %v", payload)
	}

	// inspect_traffic without arguments
	m = parseFrame(t, rpc(t, app, `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"inspect_traffic"}}`))
	text, _ = toolText(t, resultOf(t, m))
	_ = json.Unmarshal([]byte(text), &payload)
	if flows, _ := payload["flows"].([]any); len(flows) != 2 {
		t.Errorf("default inspect returned %d flows, want 2", len(flows))
	}

	// export_sanitized_curl
	m = parseFrame(t, rpc(t, app,
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"export_sanitized_curl","arguments":{"flow_id":1}}}`))
	text, isErr = toolText(t, resultOf(t, m))
	if isErr || !strings.Contains(text, "curl -X 'GET' 'http://api.test/a'") {
		t.Errorf("export result: isErr=%v text=%q", isErr, text)
	}

	// export with missing argument is a tool-level error
	m = parseFrame(t, rpc(t, app,
		`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"export_sanitized_curl","arguments":{}}}`))
	if _, isErr = toolText(t, resultOf(t, m)); !isErr {
		t.Errorf("missing flow_id should set isError")
	}

	// clear_ram_buffer
	app.scrub.Tokens.Add(5)
	m = parseFrame(t, rpc(t, app, `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"clear_ram_buffer","arguments":{}}}`))
	if _, isErr = toolText(t, resultOf(t, m)); isErr {
		t.Errorf("clear_ram_buffer reported an error")
	}
	if app.ring.Len() != 0 || app.scrub.Tokens.Load() != 0 {
		t.Errorf("ring len = %d, Tokens = %d; want both 0", app.ring.Len(), app.scrub.Tokens.Load())
	}
}

func TestMCPErrors(t *testing.T) {
	app := newTestApp(t)
	cases := []struct {
		name string
		line string
		code float64
		id   any
	}{
		{"unknown tool", `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"nope"}}`, -32602, float64(10)},
		{"bad params", `{"jsonrpc":"2.0","id":11,"method":"tools/call","params":"x"}`, -32602, float64(11)},
		{"unknown method", `{"jsonrpc":"2.0","id":12,"method":"resources/list"}`, -32601, float64(12)},
		{"parse error", `{not json`, -32700, nil},
	}
	for _, c := range cases {
		m := parseFrame(t, rpc(t, app, c.line))
		errObj, ok := m["error"].(map[string]any)
		if !ok {
			t.Errorf("%s: no error object in %v", c.name, m)
			continue
		}
		if errObj["code"] != c.code {
			t.Errorf("%s: code = %v, want %v", c.name, errObj["code"], c.code)
		}
		if m["id"] != c.id {
			t.Errorf("%s: id = %v, want %v", c.name, m["id"], c.id)
		}
	}
}

// ---------------------------------------------------------------------------
// CONNECT tunnels, protocol upgrades, DNS, body decoding
// ---------------------------------------------------------------------------

func rawProxyConn(t *testing.T, srv *httptest.Server) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	return c, bufio.NewReader(c)
}

func startEchoTCP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestConnectBlindTunnel(t *testing.T) {
	app := newTestApp(t)
	srv := httptest.NewServer(app)
	t.Cleanup(srv.Close)
	echo := startEchoTCP(t)

	c, br := rawProxyConn(t, srv)
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic dXNlcjpwYXNzd29yZA==\r\n\r\n", echo, echo)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("write through tunnel: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo through tunnel = %q, %v", buf, err)
	}
	_ = c.Close()

	waitForRing(t, app, 1)
	e := app.ring.ListRecent(1, "CONNECT", "")[0]
	if e.URL != echo || e.StatusCode != 200 {
		t.Errorf("flow = %q / %d, want %q / 200", e.URL, e.StatusCode, echo)
	}
	if !strings.Contains(e.Note, "blind CONNECT tunnel") || !strings.Contains(e.Note, "4 B client->upstream") {
		t.Errorf("note = %q", e.Note)
	}
	if got := e.RequestHeaders["Proxy-Authorization"]; strings.Contains(got, "dXNlcjpwYXNzd29yZA") {
		t.Errorf("Proxy-Authorization leaked into the ring: %q", got)
	}
	if e.RequestBody != "" || e.ResponseBody != "" {
		t.Errorf("tunnel payload must never be stored")
	}
	text := buildCurl(e)
	if !strings.Contains(text, "blind CONNECT tunnel") || strings.Contains(text, "curl ") {
		t.Errorf("CONNECT flows must not produce a curl command, got %q", text)
	}
}

func TestConnectUnreachableTarget(t *testing.T) {
	app := newTestApp(t)
	srv := httptest.NewServer(app)
	t.Cleanup(srv.Close)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	_ = ln.Close() // nothing listens here any more

	c, br := rawProxyConn(t, srv)
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", dead, dead)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
	waitForRing(t, app, 1)
}

func TestConnectGuards(t *testing.T) {
	app := newTestApp(t)

	req := httptest.NewRequest("CONNECT", "127.0.0.1:1", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != http.StatusLoopDetected {
		t.Errorf("self CONNECT status = %d, want 508", rec.Code)
	}

	req = httptest.NewRequest("CONNECT", "nohostport", nil)
	rec = httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("CONNECT without port status = %d, want 400", rec.Code)
	}

	req = httptest.NewRequest("CONNECT", "example.com:99999", nil)
	rec = httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("CONNECT with bad port status = %d, want 400", rec.Code)
	}
}

func TestUpgradePassThrough(t *testing.T) {
	app := newTestApp(t)
	srv := httptest.NewServer(app)
	t.Cleanup(srv.Close)

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
		_ = brw.Flush()
		buf := make([]byte, 5)
		if _, err := io.ReadFull(brw, buf); err != nil {
			return
		}
		_, _ = c.Write(bytes.ToUpper(buf))
	}))
	t.Cleanup(up.Close)

	c, br := rawProxyConn(t, srv)
	upHost := strings.TrimPrefix(up.URL, "http://")
	fmt.Fprintf(c, "GET %s/ws HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n", up.URL, upHost)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read handshake: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("handshake status = %d, want 101", resp.StatusCode)
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "echo") {
		t.Errorf("Upgrade header lost: %v", resp.Header)
	}
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatalf("write after upgrade: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "HELLO" {
		t.Fatalf("upgraded echo = %q, %v", buf, err)
	}
	_ = c.Close()

	waitForRing(t, app, 1)
	e := app.ring.ListRecent(1, "GET", "/ws")[0]
	if e.StatusCode != http.StatusSwitchingProtocols || !strings.Contains(e.Note, "upgraded connection") {
		t.Errorf("flow = %d / %q", e.StatusCode, e.Note)
	}
}

func TestSpliceIdleTimeout(t *testing.T) {
	a, b := net.Pipe()
	c, d := net.Pipe()
	done := make(chan struct{})
	go func() {
		splice(b, c, 80*time.Millisecond, nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("idle tunnel was never closed")
	}
	_ = a.Close()
	_ = d.Close()
}

func TestParseDNSServers(t *testing.T) {
	got, err := parseDNSServers("1.1.1.1, [2606:4700:4700::1111]:5353,9.9.9.9:53")
	if err != nil {
		t.Fatalf("parseDNSServers: %v", err)
	}
	want := []string{"1.1.1.1:53", "[2606:4700:4700::1111]:5353", "9.9.9.9:53"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %v, want %v", got, want)
	}
	for _, bad := range []string{"", "dns.example", "1.1.1.1:0", "1.1.1.1:abc"} {
		if _, err := parseDNSServers(bad); err == nil {
			t.Errorf("parseDNSServers(%q) should fail", bad)
		}
	}
}

func TestGzipBodiesAreDecodedAndScrubbed(t *testing.T) {
	var zb bytes.Buffer
	zw := gzip.NewWriter(&zb)
	_, _ = zw.Write([]byte(`{"ok":true,"password":"hunter2hunter2"}`))
	_ = zw.Close()

	h := http.Header{"Content-Encoding": []string{"gzip"}}
	text := bodyText(h, zb.Bytes())
	if !strings.Contains(text, `"ok":true`) {
		t.Fatalf("gzip body not decoded: %q", text)
	}
	if got := bodyText(http.Header{"Content-Encoding": []string{"br"}}, []byte("xx")); !strings.HasPrefix(got, "[encoded body omitted") {
		t.Errorf("unsupported encoding should stay a placeholder, got %q", got)
	}

	app := newTestApp(t)
	out, _ := app.scrub.ScrubText(text)
	if strings.Contains(out, "hunter2hunter2") {
		t.Errorf("decoded secret was not scrubbed: %q", out)
	}

	e := FlowEntry{ID: 1, Method: "POST", URL: "http://x/y",
		RequestHeaders: map[string]string{"Content-Encoding": "gzip", "Content-Type": "application/json"},
		RequestBody:    out}
	if cmd := buildCurl(e); strings.Contains(strings.ToLower(cmd), "content-encoding") {
		t.Errorf("replay must drop Content-Encoding for a decoded body:\n%s", cmd)
	}
}

// ---------------------------------------------------------------------------
// coverage: upstream and proxy routing
// ---------------------------------------------------------------------------

// covReq builds a relative-URL request with a Host and header pairs.
func covReq(method, target, host string, hdr ...string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.Host = host
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	return r
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

func TestCovResolveUpstreamXTargetURLRejections(t *testing.T) {
	app := newTestApp(t) // port 1, so http://127.0.0.1:1 is the proxy itself
	cases := []struct {
		name, target string
		status       int
		msg          string
	}{
		{"bad scheme", "ftp://example.com/x", http.StatusBadRequest, "http(s)"},
		{"no scheme", "example.com/x", http.StatusBadRequest, "http(s)"},
		{"no host", "http:///x", http.StatusBadRequest, "http(s)"},
		{"malformed", "http://[::1", http.StatusBadRequest, "invalid target URL"},
		{"self loop ip", "http://127.0.0.1:1/v1", http.StatusLoopDetected, "proxy itself"},
		{"self loop localhost", "http://localhost:1", http.StatusLoopDetected, "proxy itself"},
		{"self loop ipv6", "http://[::1]:1/", http.StatusLoopDetected, "proxy itself"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := covReq("GET", "/v1/x", "127.0.0.1:8080", "X-Target-URL", tc.target)
			u, reverse, status, err := app.resolveUpstream(r)
			if err == nil || u != nil {
				t.Fatalf("want an error and no URL, got %v / %v", u, err)
			}
			if status != tc.status || !reverse {
				t.Errorf("status = %d reverse = %v, want %d true", status, reverse, tc.status)
			}
			if !strings.Contains(err.Error(), tc.msg) {
				t.Errorf("error = %q, want it to contain %q", err, tc.msg)
			}

			rec := httptest.NewRecorder()
			app.ServeHTTP(rec, covReq("GET", "/v1/x", "127.0.0.1:8080", "X-Target-URL", tc.target))
			if rec.Code != tc.status || !strings.HasPrefix(rec.Body.String(), "nullwire-mcp: ") {
				t.Errorf("ServeHTTP = %d %q, want %d with a nullwire-mcp message", rec.Code, rec.Body.String(), tc.status)
			}
		})
	}

	// A blank header is the same as no header: nothing to route to.
	_, _, status, err := app.resolveUpstream(covReq("GET", "/x", "127.0.0.1:8080", "X-Target-URL", "   "))
	if err == nil || status != http.StatusBadRequest || !strings.Contains(err.Error(), "no upstream") {
		t.Errorf("blank X-Target-URL: %d %v", status, err)
	}
	// Only loopback Host headers are answered in reverse mode.
	_, reverse, status, err := app.resolveUpstream(covReq("GET", "/x", "evil.example.com"))
	if err == nil || status != http.StatusForbidden || !reverse {
		t.Errorf("foreign Host: %d %v reverse=%v", status, err, reverse)
	}
}

func TestCovResolveUpstreamForwardModeRejections(t *testing.T) {
	app := newTestApp(t)
	for _, c := range []struct {
		raw    string
		status int
	}{
		{"ftp://example.com/x", http.StatusBadRequest},
		{"http://127.0.0.1:1/x", http.StatusLoopDetected},
		{"https://localhost:1/x", http.StatusLoopDetected},
	} {
		u := mustParseURL(t, c.raw)
		r := &http.Request{Method: "GET", URL: u, Host: u.Host, Header: http.Header{}}
		got, reverse, status, err := app.resolveUpstream(r)
		if err == nil || got != nil || status != c.status || reverse {
			t.Errorf("%s: got %v reverse=%v status=%d err=%v, want status %d", c.raw, got, reverse, status, err, c.status)
		}
	}
	u := mustParseURL(t, "http://example.com:8080/a?b=1")
	got, reverse, status, err := app.resolveUpstream(&http.Request{Method: "GET", URL: u, Host: u.Host, Header: http.Header{}})
	if err != nil || status != 0 || reverse || got == nil || got.String() != "http://example.com:8080/a?b=1" {
		t.Errorf("plain forward request: %v reverse=%v status=%d err=%v", got, reverse, status, err)
	}
}

func TestCovResolveUpstreamTargetMapErrors(t *testing.T) {
	app := newTestApp(t)
	app.gwMap = map[string]*url.URL{
		"alpha": mustParseURL(t, "http://gw.example.com/base"),
		"me":    mustParseURL(t, "http://127.0.0.1:1"),
	}
	app.upstreams = map[string]*url.URL{"named": mustParseURL(t, "http://named.example.com")}

	// An unknown gateway name is a 404 that lists the names that exist,
	// including the ones given to -target.
	_, _, status, err := app.resolveUpstream(covReq("GET", "/_gw/nope/x", "127.0.0.1:8080"))
	if err == nil || status != http.StatusNotFound || !strings.Contains(err.Error(), `unknown gateway name "nope"`) ||
		!strings.Contains(err.Error(), "alpha") || !strings.Contains(err.Error(), "named") {
		t.Errorf("unknown gateway name: %d %v", status, err)
	}
	// The bare prefix has no name at all.
	if _, _, status, err = app.resolveUpstream(covReq("GET", "/_gw", "127.0.0.1:8080")); err == nil || status != http.StatusNotFound {
		t.Errorf("bare /_gw: %d %v", status, err)
	}
	// The prefix must not be percent-encoded.
	if _, _, status, err = app.resolveUpstream(covReq("GET", "/%5Fgw/alpha/x", "127.0.0.1:8080")); err == nil ||
		status != http.StatusBadRequest || !strings.Contains(err.Error(), "percent-encoded") {
		t.Errorf("encoded prefix: %d %v", status, err)
	}
	// A route that points back at the proxy is refused.
	if _, _, status, err = app.resolveUpstream(covReq("GET", "/_gw/me/x", "127.0.0.1:8080")); err == nil || status != http.StatusLoopDetected {
		t.Errorf("self-pointing gateway: %d %v", status, err)
	}
	// A known name keeps the base path and the query; the match ignores case.
	u, reverse, status, err := app.resolveUpstream(covReq("GET", "/_gw/ALPHA/v1/chat?x=1", "127.0.0.1:8080"))
	if err != nil || status != 0 || !reverse || u == nil || u.String() != "http://gw.example.com/base/v1/chat?x=1" {
		t.Errorf("alpha: %v reverse=%v status=%d err=%v", u, reverse, status, err)
	}
	// Names from -target also work under /_gw/.
	if u, _, _, err = app.resolveUpstream(covReq("GET", "/_gw/named/ping", "127.0.0.1:8080")); err != nil || u == nil || u.Host != "named.example.com" || u.Path != "/ping" {
		t.Errorf("-target name under /_gw/: %v %v", u, err)
	}

	// With only -target-map set, a path outside /_gw/ has no route.
	only := newTestApp(t)
	only.gwMap = map[string]*url.URL{"alpha": mustParseURL(t, "http://gw.example.com")}
	_, _, status, err = only.resolveUpstream(covReq("GET", "/v1/chat", "127.0.0.1:8080"))
	if err == nil || status != http.StatusNotFound || !strings.Contains(err.Error(), "unknown route") || !strings.Contains(err.Error(), "/_gw/<name>/") {
		t.Errorf("unknown route: %d %v", status, err)
	}
}

func TestCovMatchUpstreamAndUpstreamNames(t *testing.T) {
	app := newTestApp(t)
	if got := app.upstreamNames(); len(got) != 0 {
		t.Errorf("no upstreams: names = %v", got)
	}
	if _, _, _, found, err := app.matchUpstream("/alpha/x", ""); found || err != nil {
		t.Errorf("no upstreams must never match: found=%v err=%v", found, err)
	}

	app.upstreams = map[string]*url.URL{
		"zeta":  mustParseURL(t, "http://z.example.com"),
		"alpha": mustParseURL(t, "http://a.example.com"),
		"mid":   mustParseURL(t, "http://b.example.com/base"),
	}
	if got := strings.Join(app.upstreamNames(), ","); got != "alpha,mid,zeta" {
		t.Errorf("upstreamNames = %q, want sorted alpha,mid,zeta", got)
	}

	cases := []struct {
		path, raw   string
		found       bool
		host, rest  string
		wantRawRest string
	}{
		{"/alpha/v1/x", "", true, "a.example.com", "/v1/x", ""},
		{"/ALPHA/v1", "", true, "a.example.com", "/v1", ""},
		{"/mid", "", true, "b.example.com", "/", ""},
		{"/zeta/", "", true, "z.example.com", "/", ""},
		{"/alpha/v1/x", "/alpha/v1/x", true, "a.example.com", "/v1/x", "/v1/x"},
		{"/gamma/x", "", false, "", "", ""},
		{"alpha/x", "", false, "", "", ""},
		{"/", "", false, "", "", ""},
	}
	for _, c := range cases {
		base, rest, rawRest, found, err := app.matchUpstream(c.path, c.raw)
		if err != nil || found != c.found {
			t.Errorf("matchUpstream(%q, %q): found=%v err=%v, want found=%v", c.path, c.raw, found, err, c.found)
			continue
		}
		if !found {
			continue
		}
		if base.Host != c.host || rest != c.rest || rawRest != c.wantRawRest {
			t.Errorf("matchUpstream(%q, %q) = %s %q %q, want %s %q %q", c.path, c.raw, base.Host, rest, rawRest, c.host, c.rest, c.wantRawRest)
		}
	}
	if _, _, _, found, err := app.matchUpstream("/alpha/v1", "/%61lpha/v1"); found || err == nil || !strings.Contains(err.Error(), "percent-encoded") {
		t.Errorf("encoded prefix: found=%v err=%v", found, err)
	}

	// Through resolveUpstream: no -target and an unknown first segment.
	_, _, status, err := app.resolveUpstream(covReq("GET", "/gamma/x", "127.0.0.1:8080"))
	if err == nil || status != http.StatusNotFound || !strings.Contains(err.Error(), "unknown upstream") ||
		!strings.Contains(err.Error(), "/alpha/, /mid/, /zeta/") {
		t.Errorf("unknown upstream: %d %v", status, err)
	}
	// The default -target takes a path that names no upstream.
	app.target = mustParseURL(t, "http://default.example.com/root")
	u, _, status, err := app.resolveUpstream(covReq("GET", "/gamma/x", "127.0.0.1:8080"))
	if err != nil || status != 0 || u.Host != "default.example.com" || u.Path != "/root/gamma/x" {
		t.Errorf("default target: %v %d %v", u, status, err)
	}
	// An upstream prefix wins over the default and is stripped.
	u, _, _, err = app.resolveUpstream(covReq("GET", "/mid/v1?q=1", "127.0.0.1:8080"))
	if err != nil || u.Host != "b.example.com" || u.Path != "/base/v1" || u.RawQuery != "q=1" {
		t.Errorf("mid upstream: %v %v", u, err)
	}
	if _, _, status, err = app.resolveUpstream(covReq("GET", "/%61lpha/v1", "127.0.0.1:8080")); err == nil || status != http.StatusBadRequest {
		t.Errorf("percent-encoded upstream prefix: %d %v", status, err)
	}
}

func TestCovIgnoredURLSubstringsAreNotCaptured(t *testing.T) {
	app := newTestApp(t)
	app.ignoreURLSubstrings = []string{"", "/healthz"} // an empty entry must ignore nothing
	flow := func(u string) rawFlow {
		return rawFlow{method: "GET", url: u, reqHeaders: http.Header{}, respHeaders: http.Header{}, status: 200}
	}
	if _, ok := app.buildEntry(flow("http://svc.test/healthz?probe=1")); ok {
		t.Errorf("a URL with an ignored substring must not be stored")
	}
	if e, ok := app.buildEntry(flow("http://svc.test/api")); !ok || !strings.Contains(e.URL, "svc.test/api") {
		t.Errorf("an ordinary URL must be stored: %v %q", ok, e.URL)
	}

	// End to end: the client still gets its answer, but only /api is recorded.
	up := newUpstream(t, &upstreamSeen{})
	app.target = mustParseURL(t, up.URL)
	for _, p := range []string{"/healthz", "/api"} {
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, covReq("GET", p, "127.0.0.1:8080"))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", p, rec.Code)
		}
	}
	waitForRing(t, app, 1)
	if n := app.ring.Len(); n != 1 {
		t.Errorf("ring has %d entries, want only the /api flow", n)
	}
	if e := app.ring.ListRecent(1, "", "")[0]; !strings.HasSuffix(e.URL, "/api") {
		t.Errorf("stored flow = %q", e.URL)
	}
}

func TestCovCopyHeadersDropsHopByHop(t *testing.T) {
	src := http.Header{"Connection": {"close, x-a"}, "X-A": {"1"}, "Te": {"trailers"}, "Trailer": {"X-T"}, "Upgrade": {"websocket"}, "Transfer-Encoding": {"chunked"}, "Keep-Alive": {"timeout=5"}, "Content-Type": {"text/plain"}, "X-Drop": {"1"}, "x-lower": {"v"}}
	dst := copyHeaders(src, "x-drop")
	if len(dst) != 2 || dst.Get("Content-Type") != "text/plain" || dst.Get("X-Lower") != "v" {
		t.Errorf("copyHeaders = %v, want only Content-Type and X-Lower", dst)
	}
	dst["Content-Type"][0] = "changed"
	if src.Get("Content-Type") != "text/plain" {
		t.Errorf("copyHeaders must copy the value slices")
	}
}

func TestCovServeHTTPStripsHopByHopHeaders(t *testing.T) {
	app := newTestApp(t)
	got := make(chan http.Header, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(up.Close)
	app.target = mustParseURL(t, up.URL)

	req := covReq("GET", "/x", "127.0.0.1:8080",
		"Connection", "keep-alive, X-Hop-Custom",
		"X-Hop-Custom", "drop-me",
		"Keep-Alive", "timeout=5",
		"Proxy-Connection", "keep-alive",
		"Proxy-Authorization", "Basic dXNlcjpwYXNz",
		"X-Target-URL", up.URL,
		"X-Keep", "stay")
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	var h http.Header
	select {
	case h = <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream never saw the request")
	}
	for _, name := range []string{"X-Hop-Custom", "Keep-Alive", "Proxy-Connection", "Proxy-Authorization", "X-Target-URL"} {
		if v := h.Get(name); v != "" {
			t.Errorf("upstream received %s: %q", name, v)
		}
	}
	if h.Get("X-Keep") != "stay" {
		t.Errorf("an ordinary header was lost: %v", h)
	}
}

func TestCovServeHTTPTruncatesStoredBodiesButForwardsAll(t *testing.T) {
	app := newTestApp(t)
	respBig := strings.Repeat("lorem ipsum dolor ", 17000) // 306000 bytes, over maxRespBody
	reqBig := strings.Repeat("hello world ", 4000)         // 48000 bytes, over maxReqBody
	var mu sync.Mutex
	gotLen := -1
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotLen = len(b)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, respBig)
	}))
	t.Cleanup(up.Close)
	app.target = mustParseURL(t, up.URL)

	req := httptest.NewRequest("POST", "/big", strings.NewReader(reqBig))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.Len() != len(respBig) {
		t.Fatalf("client got %d with %d bytes, want 200 with %d", rec.Code, rec.Body.Len(), len(respBig))
	}
	mu.Lock()
	if gotLen != len(reqBig) {
		t.Errorf("upstream received %d bytes, want the full %d", gotLen, len(reqBig))
	}
	mu.Unlock()

	waitForRing(t, app, 1)
	e := app.ring.ListRecent(1, "POST", "/big")[0]
	if !strings.HasSuffix(e.ResponseBody, truncMarker) || len(e.ResponseBody) > maxRespBody+len(truncMarker) {
		t.Errorf("stored response: %d bytes, marker=%v", len(e.ResponseBody), strings.HasSuffix(e.ResponseBody, truncMarker))
	}
	if !strings.HasSuffix(e.RequestBody, truncMarker) || len(e.RequestBody) > maxReqBody+len(truncMarker) {
		t.Errorf("stored request: %d bytes, marker=%v", len(e.RequestBody), strings.HasSuffix(e.RequestBody, truncMarker))
	}
}

func TestCovServeHTTPUnreachableUpstreamReturns502(t *testing.T) {
	app := newTestApp(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	_ = ln.Close() // nothing listens here any more
	app.target = mustParseURL(t, "http://"+dead)

	req := httptest.NewRequest("POST", "/v1/chat", strings.NewReader("ping body"))
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "upstream error") {
		t.Fatalf("got %d %q, want 502 with an upstream error", rec.Code, rec.Body.String())
	}
	waitForRing(t, app, 1)
	e := app.ring.ListRecent(1, "POST", "/v1/chat")[0]
	if e.StatusCode != http.StatusBadGateway || !strings.Contains(e.ResponseBody, "upstream error") {
		t.Errorf("flow = %d %q", e.StatusCode, e.ResponseBody)
	}
}

// ---------------------------------------------------------------------------
// coverage: tunnels and upgrades
// ---------------------------------------------------------------------------

// covNoHijack is a recorder that claims to be hijackable but always refuses.
type covNoHijack struct{ *httptest.ResponseRecorder }

func (covNoHijack) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, fmt.Errorf("hijack refused")
}

func covConnect(authority string) *http.Request {
	return &http.Request{Method: http.MethodConnect, Host: authority, URL: &url.URL{Host: authority}, Header: http.Header{}}
}

func TestCovConnectRejectsMalformedAuthority(t *testing.T) {
	app := newTestApp(t)
	for _, authority := range []string{"", "example.com", "example.com:abc", ":80", "example.com:0", "example.com:-1", "example.com:65536"} {
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, covConnect(authority))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "host:port") {
			t.Errorf("CONNECT %q = %d %q, want 400 about host:port", authority, rec.Code, rec.Body.String())
		}
	}
	if n := app.tunnels.Load(); n != 0 {
		t.Errorf("rejected CONNECTs left %d tunnels counted", n)
	}
}

func TestCovConnectRefusesSelfDial(t *testing.T) {
	app := newTestApp(t) // port 1
	for _, authority := range []string{"127.0.0.1:1", "localhost:1", "[::1]:1", "0.0.0.0:1", "127.0.0.2:1"} {
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, covConnect(authority))
		if rec.Code != http.StatusLoopDetected || !strings.Contains(rec.Body.String(), "proxy itself") {
			t.Errorf("CONNECT %s = %d %q, want 508", authority, rec.Code, rec.Body.String())
		}
	}
	if n := app.tunnels.Load(); n != 0 {
		t.Errorf("refused CONNECTs left %d tunnels counted", n)
	}
}

func TestCovTunnelCapacity(t *testing.T) {
	app := newTestApp(t)
	for i := 0; i < maxTunnels; i++ {
		if !app.acquireTunnel() {
			t.Fatalf("acquire %d of %d failed", i+1, maxTunnels)
		}
	}
	if app.acquireTunnel() {
		t.Fatalf("acquire beyond maxTunnels must fail")
	}
	if n := app.tunnels.Load(); n != maxTunnels {
		t.Errorf("a refused acquire must not change the count: %d", n)
	}

	// At capacity both entry points answer 503 before touching the network.
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, covConnect("example.com:443"))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "too many concurrent tunnels") {
		t.Errorf("CONNECT at capacity = %d %q", rec.Code, rec.Body.String())
	}
	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })
	resp := &http.Response{StatusCode: http.StatusSwitchingProtocols, Header: http.Header{}, Body: c1}
	rec = httptest.NewRecorder()
	app.handleUpgrade(covNoHijack{rec}, resp, rawFlow{started: time.Now(), method: "GET", url: "http://x.test/ws", reqHeaders: http.Header{}}, true)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "too many concurrent tunnels") {
		t.Errorf("upgrade at capacity = %d %q", rec.Code, rec.Body.String())
	}
	if n := app.tunnels.Load(); n != maxTunnels {
		t.Errorf("count after refusals = %d, want %d", n, maxTunnels)
	}

	app.releaseTunnel()
	if !app.acquireTunnel() {
		t.Errorf("a released slot must be usable again")
	}
	for i := 0; i < maxTunnels; i++ {
		app.releaseTunnel()
	}
	if n := app.tunnels.Load(); n != 0 {
		t.Errorf("count after releasing everything = %d", n)
	}
}

func TestCovConnectWithoutHijackerReleasesTunnel(t *testing.T) {
	app := newTestApp(t)
	rec := httptest.NewRecorder() // not an http.Hijacker
	app.ServeHTTP(rec, covConnect("example.com:443"))
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "hijacked") {
		t.Errorf("CONNECT without hijack = %d %q", rec.Code, rec.Body.String())
	}
	if n := app.tunnels.Load(); n != 0 {
		t.Errorf("tunnel slot leaked: %d", n)
	}
}

func TestCovHandleUpgradeFailureBranches(t *testing.T) {
	flow := func() rawFlow {
		return rawFlow{started: time.Now(), method: "GET", url: "http://x.test/ws", reqHeaders: http.Header{}}
	}

	// A body that cannot be written to, and a writer that cannot be hijacked.
	app := newTestApp(t)
	resp := &http.Response{StatusCode: http.StatusSwitchingProtocols, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}
	rec := httptest.NewRecorder()
	app.handleUpgrade(rec, resp, flow(), true)
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "not supported") {
		t.Errorf("unsupported upgrade = %d %q", rec.Code, rec.Body.String())
	}
	waitForRing(t, app, 1)
	if e := app.ring.ListRecent(1, "GET", "/ws")[0]; e.StatusCode != http.StatusBadGateway {
		t.Errorf("recorded status = %d, want 502", e.StatusCode)
	}

	// Hijack itself fails: nothing is written and the slot is given back.
	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })
	resp = &http.Response{StatusCode: http.StatusSwitchingProtocols, Header: http.Header{}, Body: c1}
	app.handleUpgrade(covNoHijack{httptest.NewRecorder()}, resp, flow(), false)
	if n := app.tunnels.Load(); n != 0 {
		t.Errorf("tunnel slot leaked after a failed hijack: %d", n)
	}
}

func TestCovServeHTTPUpgradeRefusedByUpstream(t *testing.T) {
	app := newTestApp(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ok" {
			_, _ = io.WriteString(w, "plain ok")
			return
		}
		http.Error(w, "upgrade refused", http.StatusUpgradeRequired)
	}))
	t.Cleanup(up.Close)
	app.target = mustParseURL(t, up.URL)

	hdr := []string{"Connection", "Upgrade", "Upgrade", "websocket", "Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Version", "13"}
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, covReq("GET", "/ws", "127.0.0.1:8080", hdr...))
	if rec.Code != http.StatusUpgradeRequired || !strings.Contains(rec.Body.String(), "upgrade refused") {
		t.Errorf("refused upgrade = %d %q, want the upstream's 426 passed on", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	app.ServeHTTP(rec, covReq("GET", "/ok", "127.0.0.1:8080", hdr...))
	if rec.Code != http.StatusOK || rec.Body.String() != "plain ok" {
		t.Errorf("upstream ignoring the upgrade = %d %q", rec.Code, rec.Body.String())
	}

	waitForRing(t, app, 2)
	refused := app.ring.ListRecent(1, "GET", "/ws")[0]
	if refused.StatusCode != http.StatusUpgradeRequired || strings.Contains(refused.Note, "upgraded connection") {
		t.Errorf("refused flow = %d %q", refused.StatusCode, refused.Note)
	}
	if ok := app.ring.ListRecent(1, "GET", "/ok")[0]; ok.StatusCode != http.StatusOK {
		t.Errorf("ok flow status = %d", ok.StatusCode)
	}
	if n := app.tunnels.Load(); n != 0 {
		t.Errorf("no tunnel should be open: %d", n)
	}
}

// ---------------------------------------------------------------------------
// coverage: MCP batch, safeDispatch and tools
// ---------------------------------------------------------------------------

func covBatchFrames(t *testing.T, out string) []map[string]any {
	t.Helper()
	if !strings.HasSuffix(out, "\n") || strings.Count(out, "\n") != 1 {
		t.Fatalf("a batch reply must be exactly one line, got %q", out)
	}
	var frames []map[string]any
	if err := json.Unmarshal([]byte(out), &frames); err != nil {
		t.Fatalf("batch reply is not a JSON array: %v (%q)", err, out)
	}
	for i, f := range frames {
		if f["jsonrpc"] != "2.0" {
			t.Errorf("frame %d: jsonrpc = %v", i, f["jsonrpc"])
		}
	}
	return frames
}

func covErrCode(t *testing.T, m map[string]any) int {
	t.Helper()
	e, ok := m["error"].(map[string]any)
	if !ok {
		t.Fatalf("no error object in %v", m)
	}
	code, _ := e["code"].(float64)
	return int(code)
}

func TestCovBatchEmptyAndMalformed(t *testing.T) {
	app := newTestApp(t)
	for _, line := range []string{`[]`, `[ ]`, "  []  "} {
		m := parseFrame(t, rpc(t, app, line))
		if covErrCode(t, m) != -32600 || m["id"] != nil {
			t.Errorf("%q = %v, want -32600 with a null id", line, m)
		}
		if msg := m["error"].(map[string]any)["message"]; msg != "empty batch" {
			t.Errorf("%q message = %v", line, msg)
		}
	}
	for _, line := range []string{`[{"jsonrpc":"2.0","id":1,"method":"ping"}`, `[1,`, `[{`} {
		m := parseFrame(t, rpc(t, app, line))
		if covErrCode(t, m) != -32700 || m["id"] != nil {
			t.Errorf("%q = %v, want -32700 with a null id", line, m)
		}
	}
}

func TestCovBatchNonObjectEntries(t *testing.T) {
	app := newTestApp(t)
	// 1 and "x" are not requests; null is read as an empty notification and skipped.
	frames := covBatchFrames(t, rpc(t, app, `[1,"x",null]`))
	if len(frames) != 2 {
		t.Fatalf("got %d frames, want 2: %v", len(frames), frames)
	}
	for _, f := range frames {
		if covErrCode(t, f) != -32600 || f["id"] != nil {
			t.Errorf("frame = %v, want -32600 with a null id", f)
		}
	}
}

func TestCovBatchMixedNotificationCallAndErrors(t *testing.T) {
	app := newTestApp(t)
	line := `[` +
		`{"jsonrpc":"2.0","method":"notifications/initialized"},` +
		`{"jsonrpc":"2.0","id":1,"method":"ping"},` +
		`{"jsonrpc":"2.0","id":2},` +
		`{"jsonrpc":"2.0","id":3,"method":"nope"},` +
		`{"jsonrpc":"2.0","id":null,"method":"notifications/cancelled"}` +
		`]`
	frames := covBatchFrames(t, rpc(t, app, line))
	if len(frames) != 3 {
		t.Fatalf("got %d frames, want 3 (the two notifications get no reply): %v", len(frames), frames)
	}
	if frames[0]["id"] != float64(1) || frames[0]["error"] != nil || resultOf(t, frames[0])["resultType"] != "complete" {
		t.Errorf("ping frame = %v", frames[0])
	}
	if frames[1]["id"] != float64(2) || covErrCode(t, frames[1]) != -32600 ||
		frames[1]["error"].(map[string]any)["message"] != "missing method" {
		t.Errorf("missing-method frame = %v", frames[1])
	}
	if frames[2]["id"] != float64(3) || covErrCode(t, frames[2]) != -32601 {
		t.Errorf("unknown-method frame = %v", frames[2])
	}
}

func TestCovBatchOnlyNotificationsIsSilent(t *testing.T) {
	app := newTestApp(t)
	line := `[{"jsonrpc":"2.0","method":"notifications/initialized"},{"jsonrpc":"2.0","id":null,"method":"notifications/cancelled"}]`
	if out := rpc(t, app, line); out != "" {
		t.Errorf("a batch of notifications must produce no output, got %q", out)
	}
}

func TestCovBatchToolCalls(t *testing.T) {
	app := newTestApp(t)
	line := `[` +
		`{"jsonrpc":"2.0","id":"a","method":"tools/call","params":{"name":"clear_ram_buffer"}},` +
		`{"jsonrpc":"2.0","id":"b","method":"tools/call","params":{"name":"nope"}},` +
		`{"jsonrpc":"2.0","id":"c","method":"tools/call","params":{}}` +
		`]`
	frames := covBatchFrames(t, rpc(t, app, line))
	if len(frames) != 3 {
		t.Fatalf("got %d frames: %v", len(frames), frames)
	}
	if frames[0]["id"] != "a" || resultOf(t, frames[0])["isError"] != false {
		t.Errorf("clear frame = %v", frames[0])
	}
	if frames[1]["id"] != "b" || covErrCode(t, frames[1]) != -32602 || frames[1]["error"].(map[string]any)["message"] != "unknown tool" {
		t.Errorf("unknown tool frame = %v", frames[1])
	}
	if frames[2]["id"] != "c" || covErrCode(t, frames[2]) != -32602 || frames[2]["error"].(map[string]any)["message"] != "invalid params" {
		t.Errorf("empty params frame = %v", frames[2])
	}
}

func TestCovSafeDispatch(t *testing.T) {
	app := newTestApp(t)
	resp := app.safeDispatch(rpcRequest{ID: json.RawMessage(`7`), Method: "ping"})
	if resp == nil || resp.Error != nil || string(resp.ID) != "7" {
		t.Errorf("ping = %+v", resp)
	}
	resp = app.safeDispatch(rpcRequest{ID: json.RawMessage(`"x"`), Method: "no/such"})
	if resp == nil || resp.Error == nil || resp.Error.Code != -32601 || string(resp.ID) != `"x"` {
		t.Errorf("unknown method = %+v", resp)
	}
}

type covInspectPayload struct {
	RingSize       int               `json:"ring_size"`
	RingCapacity   int               `json:"ring_capacity"`
	Returned       int               `json:"returned"`
	ScrubbedTotals map[string]uint64 `json:"scrubbed_totals"`
	Flows          []FlowEntry       `json:"flows"`
}

func covSeedRing(app *App) {
	app.ring.Push(FlowEntry{Method: "GET", URL: "https://a.test/one"})
	app.ring.Push(FlowEntry{Method: "POST", URL: "https://a.test/Two", RedactionCount: 2})
	app.ring.Push(FlowEntry{Method: "GET", URL: "https://b.test/three"})
	app.ring.Push(FlowEntry{Method: "get", URL: "https://a.test/four"})
}

func covInspect(t *testing.T, app *App, args string) (covInspectPayload, string) {
	t.Helper()
	text, isErr := toolText(t, app.toolInspect(json.RawMessage(args)))
	if isErr {
		t.Fatalf("toolInspect(%s) failed: %s", args, text)
	}
	var p covInspectPayload
	if err := json.Unmarshal([]byte(text), &p); err != nil {
		t.Fatalf("toolInspect(%s) is not JSON: %v", args, err)
	}
	return p, text
}

func covURLs(flows []FlowEntry) string {
	var parts []string
	for _, f := range flows {
		parts = append(parts, strings.TrimPrefix(f.URL, "https://"))
	}
	return strings.Join(parts, " ")
}

func TestCovToolInspectEmptyRing(t *testing.T) {
	app := newTestApp(t)
	p, text := covInspect(t, app, "")
	if p.Returned != 0 || p.RingSize != 0 || p.RingCapacity != ringCapacity || len(p.Flows) != 0 {
		t.Errorf("empty ring payload = %+v", p)
	}
	if !strings.Contains(text, `"flows": []`) {
		t.Errorf("an empty ring must encode flows as [], got %s", text)
	}
	if p, _ = covInspect(t, app, `{"method":"GET","url_filter":"x","limit":3}`); p.Returned != 0 {
		t.Errorf("filters on an empty ring returned %d", p.Returned)
	}
}

func TestCovToolInspectFilters(t *testing.T) {
	app := newTestApp(t)
	covSeedRing(app)
	app.scrub.Tokens.Store(3)

	cases := []struct {
		args string
		want string // URLs, newest first
	}{
		{``, "a.test/four b.test/three a.test/Two a.test/one"},
		{`null`, "a.test/four b.test/three a.test/Two a.test/one"},
		{`{}`, "a.test/four b.test/three a.test/Two a.test/one"},
		{`{"limit":2}`, "a.test/four b.test/three"},
		{`{"limit":2.9}`, "a.test/four b.test/three"},
		{`{"limit":0}`, "a.test/four"},
		{`{"limit":-5}`, "a.test/four"},
		{`{"limit":9999}`, "a.test/four b.test/three a.test/Two a.test/one"},
		{`{"method":"GET"}`, "a.test/four b.test/three a.test/one"},
		{`{"method":"post"}`, "a.test/Two"},
		{`{"method":"DELETE"}`, ""},
		{`{"url_filter":"A.TEST"}`, "a.test/four a.test/Two a.test/one"},
		{`{"url_filter":"two"}`, "a.test/Two"},
		{`{"url_filter":"a.test","method":"GET"}`, "a.test/four a.test/one"},
		{`{"url_filter":"a.test","method":"GET","limit":1}`, "a.test/four"},
		{`{"url_filter":"nowhere"}`, ""},
		// Arguments the tool does not define are ignored, not honoured.
		{`{"last":1,"offset":1,"redacted_only":true,"path":"/one"}`, "a.test/four b.test/three a.test/Two a.test/one"},
	}
	for _, c := range cases {
		p, _ := covInspect(t, app, c.args)
		if got := covURLs(p.Flows); got != c.want || p.Returned != len(p.Flows) {
			t.Errorf("args %q: flows = %q (returned %d), want %q", c.args, got, p.Returned, c.want)
		}
		if p.RingSize != 4 || p.RingCapacity != ringCapacity {
			t.Errorf("args %q: ring size/capacity = %d/%d", c.args, p.RingSize, p.RingCapacity)
		}
	}
	if p, _ := covInspect(t, app, ""); p.ScrubbedTotals["tokens"] != 3 {
		t.Errorf("scrubbed_totals = %v, want tokens 3", p.ScrubbedTotals)
	}
}

func TestCovToolInspectInvalidArguments(t *testing.T) {
	app := newTestApp(t)
	for _, args := range []string{`{"limit":"ten"}`, `{not json`, `[1]`, `{"method":5}`} {
		text, isErr := toolText(t, app.toolInspect(json.RawMessage(args)))
		if !isErr || !strings.Contains(text, "invalid arguments") {
			t.Errorf("args %s = %q (isError %v), want an invalid-arguments error", args, text, isErr)
		}
	}
	// And through the protocol, an explicit null arguments value is fine.
	m := parseFrame(t, rpc(t, app, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"inspect_traffic","arguments":null}}`))
	if text, isErr := toolText(t, resultOf(t, m)); isErr || !strings.Contains(text, `"returned": 0`) {
		t.Errorf("null arguments = %q (isError %v)", text, isErr)
	}
}

func TestCovShellQuote(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", `''`},
		{"abc", `'abc'`},
		{"it's", `'it'\''s'`},
		{"''", `''\'''\'''`},
		{"a\nb", "'a\nb'"},
		{"[REDACTED_TOKEN#abc123]", `"$NULLWIRE_AUTH_TOKEN"`},
		{"Bearer [REDACTED_TOKEN#abc123]", `'Bearer '"$NULLWIRE_AUTH_TOKEN"`},
		{"a[REDACTED_COOKIE#abcdef]b'c", `'a'"$NULLWIRE_COOKIE"'b'\''c'`},
		{"[REDACTED_IP#aaaaaa]:[REDACTED_KEY#bbbbbb]", `"$NULLWIRE_IP"':'"$NULLWIRE_PRIVATE_KEY"`},
		{"[REDACTED_PAN#012345]", `"$NULLWIRE_CARD_NUMBER"`},
		// Not a tag the exporter wrote: upper-case hex and an unknown kind stay literal.
		{"[REDACTED_TOKEN#ABCDEF]", `'[REDACTED_TOKEN#ABCDEF]'`},
		{"[REDACTED_FOO#abcdef]", `'[REDACTED_FOO#abcdef]'`},
	}
	for _, c := range cases {
		if got := shellQuote(c.in); got != c.want {
			t.Errorf("shellQuote(%q) = %s, want %s", c.in, got, c.want)
		}
	}
	for kind, want := range map[string]string{"TOKEN": "NULLWIRE_AUTH_TOKEN", "COOKIE": "NULLWIRE_COOKIE", "IP": "NULLWIRE_IP", "KEY": "NULLWIRE_PRIVATE_KEY", "PAN": "NULLWIRE_CARD_NUMBER", "other": "NULLWIRE_AUTH_TOKEN"} {
		if got := envFor(kind); got != want {
			t.Errorf("envFor(%q) = %q, want %q", kind, got, want)
		}
	}
}

func TestCovToolExportCurlErrors(t *testing.T) {
	app := newTestApp(t)
	app.ring.Push(FlowEntry{Method: "GET", URL: "https://a.test/"})
	cases := []struct{ args, want string }{
		{``, "flow_id is required"},
		{`null`, "flow_id is required"},
		{`{}`, "flow_id is required"},
		{`{"flow_id":0}`, "positive integer"},
		{`{"flow_id":-3}`, "positive integer"},
		{`{"flow_id":1.5}`, "positive integer"},
		{`{"flow_id":1e16}`, "positive integer"},
		{`{"flow_id":999}`, "not in RAM ring buffer"},
		{`{"flow_id":"1"}`, "invalid arguments"},
		{`{oops`, "invalid arguments"},
	}
	for _, c := range cases {
		text, isErr := toolText(t, app.toolExportCurl(json.RawMessage(c.args)))
		if !isErr || !strings.Contains(text, c.want) {
			t.Errorf("args %q = %q (isError %v), want an error containing %q", c.args, text, isErr, c.want)
		}
	}
}

func TestCovToolExportCurlQuotingAndRedaction(t *testing.T) {
	app := newTestApp(t)
	entry := FlowEntry{Method: "POST", URL: "https://api.test/v1?q=it's"}
	entry.RequestHeaders = map[string]string{"Authorization": "Bearer [REDACTED_TOKEN#abc123]", "Cookie": "[REDACTED_COOKIE#def456]", "Content-Type": "application/json", "Content-Encoding": "gzip", "Host": "api.test", "Content-Length": "40", "Accept-Encoding": "gzip"}
	entry.RequestBody = "line1\nit's [REDACTED_TOKEN#abc123]" + truncMarker
	app.ring.Push(entry)
	text, isErr := toolText(t, app.toolExportCurl(json.RawMessage(`{"flow_id":1}`)))
	if isErr {
		t.Fatalf("export failed: %s", text)
	}
	if !strings.HasPrefix(text, "# Replay of flow 1\n# Set environment variables first:\n") {
		t.Errorf("unexpected header:\n%s", text)
	}
	for _, legend := range []string{
		"# export NULLWIRE_AUTH_TOKEN=...   # was [REDACTED_TOKEN#abc123]",
		"# export NULLWIRE_COOKIE=...   # was [REDACTED_COOKIE#def456]",
	} {
		if !strings.Contains(text, legend) {
			t.Errorf("missing legend line %q in:\n%s", legend, text)
		}
	}
	if n := strings.Count(text, "# export NULLWIRE_AUTH_TOKEN="); n != 1 {
		t.Errorf("a tag used twice must be listed once, got %d", n)
	}
	i := strings.Index(text, "curl -X")
	if i < 0 {
		t.Fatalf("no curl command in:\n%s", text)
	}
	cmd := text[i:]
	for _, want := range []string{
		`curl -X 'POST' 'https://api.test/v1?q=it'\''s'`,
		`-H 'Authorization: Bearer '"$NULLWIRE_AUTH_TOKEN"`,
		`-H 'Content-Type: application/json'`,
		`-H 'Cookie: '"$NULLWIRE_COOKIE"`,
		"--data-raw 'line1\n" + `it'\''s '"$NULLWIRE_AUTH_TOKEN"`,
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("curl command lacks %s:\n%s", want, cmd)
		}
	}
	for _, bad := range []string{"Host:", "Content-Length", "Accept-Encoding", "Content-Encoding", "[REDACTED_", "truncated"} {
		if strings.Contains(cmd, bad) {
			t.Errorf("curl command must not contain %q:\n%s", bad, cmd)
		}
	}
}

func TestCovToolExportCurlSpecialFlows(t *testing.T) {
	app := newTestApp(t)
	app.ring.Push(FlowEntry{Method: "HEAD", URL: "https://x.test/"})
	app.ring.Push(FlowEntry{Method: "CONNECT", URL: "x.test:443"})
	app.ring.Push(FlowEntry{Method: "POST", URL: "https://x.test/up", RequestBody: "[encoded body omitted: gzip]"})

	text, _ := toolText(t, app.toolExportCurl(json.RawMessage(`{"flow_id":1}`)))
	if !strings.Contains(text, "curl -I 'https://x.test/'") {
		t.Errorf("HEAD flow = %q", text)
	}
	text, _ = toolText(t, app.toolExportCurl(json.RawMessage(`{"flow_id":2}`)))
	if !strings.Contains(text, "Flow 2 was a blind CONNECT tunnel") || strings.Contains(text, "curl ") {
		t.Errorf("CONNECT flow = %q", text)
	}
	text, _ = toolText(t, app.toolExportCurl(json.RawMessage(`{"flow_id":3}`)))
	if strings.Contains(text, "--data-raw") {
		t.Errorf("a placeholder body must not be replayed: %q", text)
	}
}

func TestCovToolClearWipesRingAndCounters(t *testing.T) {
	app := newTestApp(t)
	covSeedRing(app)
	app.scrub.Tokens.Store(4)
	app.scrub.Cookies.Store(2)
	app.scrub.IPs.Store(1)

	text, isErr := toolText(t, app.toolClear())
	if isErr || !strings.Contains(text, "wiped") {
		t.Errorf("toolClear = %q (isError %v)", text, isErr)
	}
	if app.ring.Len() != 0 {
		t.Errorf("ring still has %d entries", app.ring.Len())
	}
	if _, ok := app.ring.GetByID(1); ok {
		t.Errorf("a cleared flow must not be found by ID")
	}
	if app.scrub.Tokens.Load() != 0 || app.scrub.Cookies.Load() != 0 || app.scrub.IPs.Load() != 0 {
		t.Errorf("counters not reset: %d/%d/%d", app.scrub.Tokens.Load(), app.scrub.Cookies.Load(), app.scrub.IPs.Load())
	}
	if _, isErr = toolText(t, app.toolClear()); isErr {
		t.Errorf("clearing an empty ring must succeed")
	}

	// The same through the protocol.
	covSeedRing(app)
	m := parseFrame(t, rpc(t, app, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"clear_ram_buffer"}}`))
	if _, isErr = toolText(t, resultOf(t, m)); isErr || app.ring.Len() != 0 {
		t.Errorf("clear over RPC: isError=%v ring=%d", isErr, app.ring.Len())
	}
}

func TestSplicePreWriteFailureClosesBoth(t *testing.T) {
	c1, c2 := net.Pipe()
	u1, u2 := net.Pipe()
	_ = u2.Close() // the upstream is already gone, so writing the buffered bytes fails
	toUp, toClient := splice(c1, u1, 0, []byte("hello"))
	if toUp != 0 || toClient != 0 {
		t.Errorf("counts = %d, %d; want 0, 0", toUp, toClient)
	}
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c2.Read(make([]byte, 1)); err == nil {
		t.Error("the client side must be closed after a failed pre-write")
	}
	_ = c2.Close()
}

// net.Pipe ends have no CloseWrite, so end-of-input must close the destination.
func TestSpliceClosesDestinationWithoutCloseWrite(t *testing.T) {
	c1, c2 := net.Pipe()
	u1, u2 := net.Pipe()
	done := make(chan int64, 1)
	go func() {
		sent, _ := splice(c1, u1, 0, nil)
		done <- sent
	}()
	got := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(u2)
		got <- b
	}()
	if _, err := c2.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = c2.Close()
	select {
	case b := <-got:
		if string(b) != "hello" {
			t.Errorf("upstream received %q", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the destination was never closed at end of input")
	}
	select {
	case sent := <-done:
		if sent != 5 {
			t.Errorf("client->upstream bytes = %d, want 5", sent)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("splice did not return")
	}
	_ = u2.Close()
}

func TestServeHTTPChunkedStreamKeepsTrailersAndSendsNoUserAgent(t *testing.T) {
	var mu sync.Mutex
	var hadUA bool
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		_, hadUA = r.Header["User-Agent"]
		mu.Unlock()
		w.Header().Set("Trailer", "X-Sum")
		_, _ = w.Write([]byte("part1"))
		w.(http.Flusher).Flush() // no Content-Length: the response is chunked
		_, _ = w.Write([]byte("part2"))
		w.Header().Set("X-Sum", "abc")
	}))
	defer up.Close()

	app := newTestApp(t)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, up.URL+"/stream", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "part1part2" {
		t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
	}
	if !rec.Flushed {
		t.Error("an unknown-length response must be flushed to the client")
	}
	if got := rec.Header()[http.TrailerPrefix+"X-Sum"]; len(got) != 1 || got[0] != "abc" {
		t.Errorf("trailer = %q, want [abc]", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if hadUA {
		t.Error("a client that sent no User-Agent must not get a default one added")
	}
}

func TestBuildEntryWarnsOnEncodedBodies(t *testing.T) {
	app := newTestApp(t)
	app.capture(rawFlow{
		started: time.Now(), method: "POST", url: "http://x.test/enc", status: 200,
		reqHeaders:  http.Header{"Content-Encoding": {"br"}},
		reqBody:     []byte("xx"),
		respHeaders: http.Header{"Content-Encoding": {"br"}},
		respBody:    []byte("yy"),
	})
	es := app.ring.ListRecent(1, "POST", "/enc")
	if len(es) != 1 {
		t.Fatalf("captured %d flows", len(es))
	}
	for _, want := range []string{"Request body encoded", "Response body encoded"} {
		if !strings.Contains(es[0].Note, want) {
			t.Errorf("note %q lacks %q", es[0].Note, want)
		}
	}
}
