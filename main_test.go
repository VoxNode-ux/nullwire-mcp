package main

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
	s, err := NewScrubber()
	if err != nil {
		t.Fatalf("NewScrubber: %v", err)
	}
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
	s2, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	other, _ := s2.ScrubText(secretA)
	if tokenTagRe.FindString(other) == tag1 {
		t.Errorf("tags must be salted per process, but two scrubbers agreed on %s", tag1)
	}
}

func TestScrubberIPsAndLoopback(t *testing.T) {
	s, _ := NewScrubber()
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
	s, _ := NewScrubber()
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
	s, _ := NewScrubber()
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

	// Upstream must see an un-scrubbed request, minus Accept-Encoding and X-Target-URL.
	seen.mu.Lock()
	if seen.acceptEncoding != "" {
		t.Errorf("Accept-Encoding reached upstream: %q", seen.acceptEncoding)
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
	if !isErr || !strings.Contains(msg, "not in the RAM ring buffer") {
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
	if seen.acceptEncoding != "" {
		t.Errorf("Accept-Encoding reached upstream: %q", seen.acceptEncoding)
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
	if len(tools) != 3 {
		t.Fatalf("got %d tools, want 3", len(tools))
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
	for _, n := range []string{"inspect_traffic", "export_sanitized_curl", "clear_ram_buffer"} {
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
