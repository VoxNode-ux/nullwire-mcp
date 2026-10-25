// nullwire-mcp: a zero-dependency, RAM-only DLP diagnostic HTTP proxy and
// Model Context Protocol (MCP) server over stdio.
//
// stdout is reserved exclusively for single-line JSON-RPC 2.0 frames.
// Everything meant for humans goes to stderr. Nothing is ever written to disk.
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ringCapacity  = 50
	maxReqBody    = 8 * 1024
	maxRespBody   = 16 * 1024
	captureLimit  = 64 * 1024
	truncMarker   = "…[truncated]"
	serverName    = "nullwire-mcp"
	serverVersion = "1.0.0"
)

// ---------------------------------------------------------------------------
// MODULE 1: RAM ring buffer
// ---------------------------------------------------------------------------

// FlowEntry is one scrubbed HTTP exchange. Every string is already scrubbed.
type FlowEntry struct {
	ID              uint64            `json:"id"`
	Timestamp       string            `json:"timestamp"`
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	RequestHeaders  map[string]string `json:"request_headers"`
	RequestBody     string            `json:"request_body"`
	StatusCode      int               `json:"status_code"`
	ResponseHeaders map[string]string `json:"response_headers"`
	ResponseBody    string            `json:"response_body"`
	LatencyMs       int64             `json:"latency_ms"`
	RedactionCount  int               `json:"redaction_count"`
}

// RingBuffer is a fixed-size, thread-safe circular store of FlowEntry values.
type RingBuffer struct {
	mu     sync.RWMutex
	slots  [ringCapacity]FlowEntry
	next   int
	size   int
	nextID uint64
}

// NewRingBuffer returns an empty ring whose first flow ID will be 1.
func NewRingBuffer() *RingBuffer {
	return &RingBuffer{nextID: 1}
}

// Push stores entry, assigning it the next monotonic ID and overwriting the
// oldest slot once the ring is full.
func (r *RingBuffer) Push(entry FlowEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry.ID = r.nextID
	r.nextID++
	r.slots[r.next] = entry
	r.next = (r.next + 1) % ringCapacity
	if r.size < ringCapacity {
		r.size++
	}
}

// Len returns the number of occupied slots.
func (r *RingBuffer) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.size
}

// ListRecent returns up to limit entries, newest first. methodFilter matches
// the HTTP method case-insensitively; urlSubstring matches case-insensitively.
func (r *RingBuffer) ListRecent(limit int, methodFilter string, urlSubstring string) []FlowEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if limit <= 0 {
		limit = 10
	}
	if limit > ringCapacity {
		limit = ringCapacity
	}
	needle := strings.ToLower(urlSubstring)
	out := make([]FlowEntry, 0, limit)
	for i := 0; i < r.size && len(out) < limit; i++ {
		idx := (r.next - 1 - i + 2*ringCapacity) % ringCapacity
		e := r.slots[idx]
		if methodFilter != "" && !strings.EqualFold(e.Method, methodFilter) {
			continue
		}
		if needle != "" && !strings.Contains(strings.ToLower(e.URL), needle) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// GetByID returns the flow with the given ID if it is still in the ring.
func (r *RingBuffer) GetByID(id uint64) (FlowEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for i := 0; i < r.size; i++ {
		idx := (r.next - 1 - i + 2*ringCapacity) % ringCapacity
		if r.slots[idx].ID == id {
			return r.slots[idx], true
		}
	}
	return FlowEntry{}, false
}

// Clear zeroes every slot and empties the ring. The ID counter keeps rising so
// an old flow ID can never silently refer to a new flow.
func (r *RingBuffer) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.slots {
		r.slots[i] = FlowEntry{}
	}
	r.next = 0
	r.size = 0
}

// ---------------------------------------------------------------------------
// MODULE 2: deterministic correlation DLP scrubber
// ---------------------------------------------------------------------------

// Scrubber replaces secrets with [REDACTED_KIND#hash] tags. The hash is a
// 6-hex-char SHA-256 prefix salted with a per-process random nonce, so equal
// secrets correlate within one run but cannot be compared across runs.
type Scrubber struct {
	nonce []byte

	reBearer          *regexp.Regexp
	reSensitiveHeader *regexp.Regexp
	reJWT             *regexp.Regexp
	reAPIKey          *regexp.Regexp
	reJSONSecret      *regexp.Regexp
	reQuerySecret     *regexp.Regexp
	reUserInfo        *regexp.Regexp
	reIPv4            *regexp.Regexp

	Tokens  atomic.Uint64
	Cookies atomic.Uint64
	IPs     atomic.Uint64
}

// NewScrubber compiles all patterns and draws the per-process nonce from RAM.
func NewScrubber() (*Scrubber, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return &Scrubber{
		nonce:             nonce,
		reBearer:          regexp.MustCompile(`(?i)(Bearer|Basic|Token)\s+([A-Za-z0-9._~+/=-]{8,})`),
		reSensitiveHeader: regexp.MustCompile(`(?i)^(authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token|proxy-authorization)$`),
		reJWT:             regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
		reAPIKey:          regexp.MustCompile(`(?i)\b(sk-[a-zA-Z0-9_-]{20,}|ghp_[a-zA-Z0-9]{30,}|github_pat_[a-zA-Z0-9_]{30,}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[0-9a-zA-Z-]+|AKIA[0-9A-Z]{16})\b`),
		reJSONSecret:      regexp.MustCompile(`(?i)("(?:access_token|refresh_token|id_token|api_key|apikey|secret|client_secret|password|passwd|session_id|auth_token)"\s*:\s*")((?:[^"\\]|\\.)+)(")`),
		reQuerySecret:     regexp.MustCompile(`(?i)((?:^|[?&])(?:api_key|apikey|token|access_token|refresh_token|id_token|secret|client_secret|password|passwd|key)=)([^&\s#]+)`),
		reUserInfo:        regexp.MustCompile(`(://[^/\s:@]+:)([^@/\s]+)(@)`),
		reIPv4:            regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
	}, nil
}

// tag builds a correlation tag such as [REDACTED_TOKEN#a1b2c3].
func (s *Scrubber) tag(kind, raw string) string {
	h := sha256.New()
	h.Write(s.nonce)
	h.Write([]byte(raw))
	sum := hex.EncodeToString(h.Sum(nil))
	return "[REDACTED_" + kind + "#" + sum[:6] + "]"
}

// ResetCounters zeroes the scrub totals.
func (s *Scrubber) ResetCounters() {
	s.Tokens.Store(0)
	s.Cookies.Store(0)
	s.IPs.Store(0)
}

// ScrubText redacts every known secret shape in in and reports how many
// redactions were made.
func (s *Scrubber) ScrubText(in string) (string, int) {
	if in == "" {
		return in, 0
	}
	count := 0

	out := s.reJSONSecret.ReplaceAllStringFunc(in, func(m string) string {
		g := s.reJSONSecret.FindStringSubmatch(m)
		if g == nil {
			return m
		}
		count++
		s.Tokens.Add(1)
		return g[1] + s.tag("TOKEN", g[2]) + g[3]
	})

	out = s.reQuerySecret.ReplaceAllStringFunc(out, func(m string) string {
		g := s.reQuerySecret.FindStringSubmatch(m)
		if g == nil {
			return m
		}
		count++
		s.Tokens.Add(1)
		return g[1] + s.tag("TOKEN", g[2])
	})

	out = s.reUserInfo.ReplaceAllStringFunc(out, func(m string) string {
		g := s.reUserInfo.FindStringSubmatch(m)
		if g == nil {
			return m
		}
		count++
		s.Tokens.Add(1)
		return g[1] + s.tag("TOKEN", g[2]) + g[3]
	})

	out = s.reBearer.ReplaceAllStringFunc(out, func(m string) string {
		g := s.reBearer.FindStringSubmatch(m)
		if g == nil {
			return m
		}
		count++
		s.Tokens.Add(1)
		return g[1] + " " + s.tag("TOKEN", g[2])
	})

	out = s.reJWT.ReplaceAllStringFunc(out, func(m string) string {
		count++
		s.Tokens.Add(1)
		return s.tag("TOKEN", m)
	})

	out = s.reAPIKey.ReplaceAllStringFunc(out, func(m string) string {
		count++
		s.Tokens.Add(1)
		return s.tag("TOKEN", m)
	})

	out = s.reIPv4.ReplaceAllStringFunc(out, func(m string) string {
		if m == "127.0.0.1" || m == "0.0.0.0" {
			return m
		}
		count++
		s.IPs.Add(1)
		return s.tag("IP", m)
	})

	return out, count
}

// ScrubHeaders returns a flat, scrubbed copy of h and the redaction count.
func (s *Scrubber) ScrubHeaders(h http.Header) (map[string]string, int) {
	out := make(map[string]string, len(h))
	count := 0
	for name, vals := range h {
		joined := strings.Join(vals, ", ")
		lname := strings.ToLower(name)
		if s.reSensitiveHeader.MatchString(name) {
			switch {
			case lname == "cookie" || lname == "set-cookie":
				out[name] = s.tag("COOKIE", joined)
				s.Cookies.Add(1)
				count++
			case (lname == "authorization" || lname == "proxy-authorization") && s.reBearer.MatchString(joined):
				v, n := s.ScrubText(joined)
				out[name] = v
				count += n
			default:
				out[name] = s.tag("TOKEN", joined)
				s.Tokens.Add(1)
				count++
			}
			continue
		}
		v, n := s.ScrubText(joined)
		out[name] = v
		count += n
	}
	return out, count
}

// ---------------------------------------------------------------------------
// Shared app state, MODULE 3: stderr telemetry bar
// ---------------------------------------------------------------------------

// App ties together the ring, the scrubber, the proxy and the MCP server.
type App struct {
	ring      *RingBuffer
	scrub     *Scrubber
	port      int
	target    *url.URL
	transport *http.Transport

	barMu    sync.Mutex
	stdoutMu sync.Mutex
}

// drawBar writes the inline status bar. Caller must hold barMu.
func (a *App) drawBar() {
	fmt.Fprintf(os.Stderr,
		"\r\033[K⚡ [NullWire-MCP] Proxy 127.0.0.1:%d | RAM Ring: %d/%d | Scrubbed: %d Tokens, %d Cookies, %d IPs | Disk: 0B",
		a.port, a.ring.Len(), ringCapacity,
		a.scrub.Tokens.Load(), a.scrub.Cookies.Load(), a.scrub.IPs.Load())
}

// Bar redraws the telemetry bar on stderr.
func (a *App) Bar() {
	a.barMu.Lock()
	defer a.barMu.Unlock()
	a.drawBar()
}

// Logf prints a human message on stderr above the telemetry bar.
func (a *App) Logf(format string, args ...any) {
	a.barMu.Lock()
	defer a.barMu.Unlock()
	fmt.Fprintf(os.Stderr, "\r\033[K"+format+"\n", args...)
	a.drawBar()
}

// ---------------------------------------------------------------------------
// MODULE 4: loopback HTTP diagnostic proxy
// ---------------------------------------------------------------------------

// capBuffer keeps at most max bytes of whatever is written to it.
type capBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (c *capBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if room := c.max - len(c.buf); room > 0 {
		if len(p) > room {
			c.buf = append(c.buf, p[:room]...)
		} else {
			c.buf = append(c.buf, p...)
		}
	}
	return len(p), nil
}

func (c *capBuffer) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf...)
}

// flushWriter flushes after every write so streaming responses stay live.
type flushWriter struct {
	w http.ResponseWriter
}

func (f *flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if fl, ok := f.w.(http.Flusher); ok {
		fl.Flush()
	}
	return n, err
}

var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// copyHeaders clones src without hop-by-hop headers and without extraDrop.
func copyHeaders(src http.Header, extraDrop ...string) http.Header {
	drop := make(map[string]bool, len(hopByHop)+len(extraDrop))
	for _, h := range hopByHop {
		drop[h] = true
	}
	for _, v := range src.Values("Connection") {
		for _, f := range strings.Split(v, ",") {
			if f = strings.TrimSpace(f); f != "" {
				drop[http.CanonicalHeaderKey(f)] = true
			}
		}
	}
	for _, e := range extraDrop {
		drop[http.CanonicalHeaderKey(e)] = true
	}
	dst := make(http.Header, len(src))
	for k, vs := range src {
		ck := http.CanonicalHeaderKey(k)
		if drop[ck] {
			continue
		}
		dst[ck] = append([]string(nil), vs...)
	}
	return dst
}

func parseTarget(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %v", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("target URL must look like http(s)://host[:port][/base]")
	}
	return u, nil
}

func isLoopbackHost(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

func (a *App) isSelf(hostport string) bool {
	h := strings.ToLower(hostport)
	return h == fmt.Sprintf("127.0.0.1:%d", a.port) ||
		h == fmt.Sprintf("localhost:%d", a.port) ||
		h == fmt.Sprintf("[::1]:%d", a.port)
}

// resolveUpstream decides between forward-proxy and reverse-gateway mode and
// returns the full upstream URL. On failure it returns an HTTP status.
func (a *App) resolveUpstream(r *http.Request) (*url.URL, bool, int, error) {
	if r.URL.IsAbs() && r.URL.Host != "" {
		if r.URL.Scheme != "http" && r.URL.Scheme != "https" {
			return nil, false, http.StatusBadRequest, fmt.Errorf("unsupported scheme %q", r.URL.Scheme)
		}
		if a.isSelf(r.URL.Host) {
			return nil, false, http.StatusLoopDetected, fmt.Errorf("refusing to proxy a request back to the proxy itself")
		}
		u := *r.URL
		return &u, false, 0, nil
	}

	// Reverse gateway: only answer loopback Host headers (DNS-rebinding guard).
	if !isLoopbackHost(r.Host) {
		return nil, true, http.StatusForbidden, fmt.Errorf("reverse gateway only answers loopback Host headers")
	}
	base := a.target
	if raw := strings.TrimSpace(r.Header.Get("X-Target-URL")); raw != "" {
		parsed, err := parseTarget(raw)
		if err != nil {
			return nil, true, http.StatusBadRequest, err
		}
		base = parsed
	}
	if base == nil {
		return nil, true, http.StatusBadRequest,
			fmt.Errorf("no upstream: send an absolute URL (forward mode), an X-Target-URL header, or start with -target")
	}
	if a.isSelf(base.Host) {
		return nil, true, http.StatusLoopDetected, fmt.Errorf("refusing to proxy a request back to the proxy itself")
	}
	u := *base
	u.Path = strings.TrimRight(base.Path, "/") + r.URL.Path
	u.RawPath = ""
	if r.URL.RawPath != "" {
		u.RawPath = strings.TrimRight(base.EscapedPath(), "/") + r.URL.RawPath
	}
	if r.URL.RawQuery != "" {
		u.RawQuery = r.URL.RawQuery
	}
	u.Fragment = ""
	return &u, true, 0, nil
}

// rawFlow is an un-scrubbed copy of an exchange, handed to capture().
type rawFlow struct {
	started     time.Time
	method      string
	url         string
	reqHeaders  http.Header
	reqBody     []byte
	status      int
	respHeaders http.Header
	respBody    []byte
	latencyMs   int64
}

// ServeHTTP implements both forward-proxy and reverse-gateway modes. The
// client always receives the original, un-scrubbed traffic.
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	if r.Method == http.MethodConnect {
		http.Error(w, "nullwire-mcp: CONNECT/HTTPS tunnelling is not supported; use a plain http:// URL or the reverse gateway with -target / X-Target-URL", http.StatusNotImplemented)
		return
	}

	outURL, reverse, status, err := a.resolveUpstream(r)
	if err != nil {
		http.Error(w, "nullwire-mcp: "+err.Error(), status)
		return
	}

	reqCap := &capBuffer{max: captureLimit}
	var outBody io.Reader = http.NoBody
	hasBody := r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0
	if hasBody {
		outBody = io.TeeReader(r.Body, reqCap)
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), outBody)
	if err != nil {
		http.Error(w, "nullwire-mcp: cannot build upstream request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if hasBody {
		outReq.ContentLength = r.ContentLength
	} else {
		outReq.ContentLength = 0
	}
	if reverse {
		outReq.Header = copyHeaders(r.Header, "X-Target-URL", "Accept-Encoding")
	} else {
		outReq.Header = copyHeaders(r.Header, "Accept-Encoding")
	}
	if _, ok := outReq.Header["User-Agent"]; !ok {
		outReq.Header["User-Agent"] = []string{""}
	}

	flow := rawFlow{
		started:    start,
		method:     r.Method,
		url:        outURL.String(),
		reqHeaders: r.Header.Clone(),
	}

	outReq.Host = outURL.Host
	resp, err := a.transport.RoundTrip(outReq)
	if err != nil {
		msg := "nullwire-mcp: upstream error: " + err.Error()
		http.Error(w, msg, http.StatusBadGateway)
		flow.reqBody = reqCap.Bytes()
		flow.status = http.StatusBadGateway
		flow.respHeaders = http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}}
		flow.respBody = []byte(msg)
		flow.latencyMs = time.Since(start).Milliseconds()
		go a.capture(flow)
		return
	}
	defer resp.Body.Close()

	respCap := &capBuffer{max: captureLimit}
	dst := w.Header()
	for k, vs := range copyHeaders(resp.Header) {
		dst[k] = vs
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(&flushWriter{w: w}, io.TeeReader(resp.Body, respCap))

	flow.reqBody = reqCap.Bytes()
	flow.status = resp.StatusCode
	flow.respHeaders = resp.Header.Clone()
	flow.respBody = respCap.Bytes()
	flow.latencyMs = time.Since(start).Milliseconds()
	go a.capture(flow)
}

func bodyText(h http.Header, b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if ce := strings.TrimSpace(h.Get("Content-Encoding")); ce != "" && !strings.EqualFold(ce, "identity") {
		return fmt.Sprintf("[encoded body omitted: Content-Encoding %s, %d bytes captured]", ce, len(b))
	}
	return string(b)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + truncMarker
}

// capture scrubs a copy of the flow and pushes it into the ring. Scrubbing
// always happens before truncation so a secret is never cut in half and kept.
func (a *App) capture(f rawFlow) {
	defer func() { _ = recover() }()

	total := 0
	u, n := a.scrub.ScrubText(f.url)
	total += n
	rh, n := a.scrub.ScrubHeaders(f.reqHeaders)
	total += n
	rb, n := a.scrub.ScrubText(bodyText(f.reqHeaders, f.reqBody))
	total += n
	ph, n := a.scrub.ScrubHeaders(f.respHeaders)
	total += n
	pb, n := a.scrub.ScrubText(bodyText(f.respHeaders, f.respBody))
	total += n

	a.ring.Push(FlowEntry{
		Timestamp:       f.started.UTC().Format(time.RFC3339),
		Method:          f.method,
		URL:             u,
		RequestHeaders:  rh,
		RequestBody:     truncate(rb, maxReqBody),
		StatusCode:      f.status,
		ResponseHeaders: ph,
		ResponseBody:    truncate(pb, maxRespBody),
		LatencyMs:       f.latencyMs,
		RedactionCount:  total,
	})
	a.Bar()
}

// ---------------------------------------------------------------------------
// MODULE 5: JSON-RPC 2.0 MCP server over stdio
// ---------------------------------------------------------------------------

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// writeFrame writes exactly one compact JSON line to stdout.
func (a *App) writeFrame(resp rpcResponse) {
	resp.JSONRPC = "2.0"
	b, err := json.Marshal(resp)
	if err != nil {
		b = []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"internal error: cannot encode response"}}`)
	}
	b = append(b, '\n')
	a.stdoutMu.Lock()
	defer a.stdoutMu.Unlock()
	_, _ = os.Stdout.Write(b)
}

func (a *App) writeError(id json.RawMessage, code int, msg string) {
	a.writeFrame(rpcResponse{ID: id, Error: &rpcError{Code: code, Message: msg}})
}

func toolResult(text string, isErr bool) map[string]any {
	return map[string]any{
		"resultType": "complete",
		"content":    []any{map[string]any{"type": "text", "text": text}},
		"isError":    isErr,
	}
}

func isEmptyArgs(raw json.RawMessage) bool {
	t := strings.TrimSpace(string(raw))
	return t == "" || t == "null"
}

func toolDefinitions() []any {
	return []any{
		map[string]any{
			"name":        "inspect_traffic",
			"description": "Returns recent scrubbed HTTP flows captured by the nullwire-mcp proxy from its in-RAM ring buffer, newest first. Secrets appear as [REDACTED_KIND#hash] tags; equal hashes mean the same secret value.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"limit": map[string]any{
						"type":        "integer",
						"description": "Maximum number of flows to return (1-50).",
						"default":     10,
						"minimum":     1,
						"maximum":     ringCapacity,
					},
					"method": map[string]any{
						"type":        "string",
						"description": "Only return flows with this HTTP method (case-insensitive), e.g. GET.",
					},
					"url_filter": map[string]any{
						"type":        "string",
						"description": "Only return flows whose scrubbed URL contains this substring (case-insensitive).",
					},
				},
				"additionalProperties": false,
			},
		},
		map[string]any{
			"name":        "export_sanitized_curl",
			"description": "Rebuilds a ready-to-run curl command for a captured flow. Redacted secrets are replaced by environment variable placeholders: $NULLWIRE_AUTH_TOKEN, $NULLWIRE_COOKIE (and $NULLWIRE_IP for redacted addresses).",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"flow_id": map[string]any{
						"type":        "integer",
						"description": "The id of a flow returned by inspect_traffic.",
						"minimum":     1,
					},
				},
				"required":             []any{"flow_id"},
				"additionalProperties": false,
			},
		},
		map[string]any{
			"name":        "clear_ram_buffer",
			"description": "Wipes all 50 slots of the RAM ring buffer and resets the scrub counters.",
			"inputSchema": map[string]any{
				"type":                 "object",
				"properties":           map[string]any{},
				"additionalProperties": false,
			},
		},
	}
}

func (a *App) toolInspect(args json.RawMessage) map[string]any {
	var in struct {
		Limit     *float64 `json:"limit"`
		Method    string   `json:"method"`
		URLFilter string   `json:"url_filter"`
	}
	if !isEmptyArgs(args) {
		if err := json.Unmarshal(args, &in); err != nil {
			return toolResult("invalid arguments: "+err.Error(), true)
		}
	}
	limit := 10
	if in.Limit != nil {
		switch {
		case *in.Limit < 1:
			limit = 1
		case *in.Limit > ringCapacity:
			limit = ringCapacity
		default:
			limit = int(*in.Limit)
		}
	}
	flows := a.ring.ListRecent(limit, in.Method, in.URLFilter)
	payload := map[string]any{
		"ring_size":     a.ring.Len(),
		"ring_capacity": ringCapacity,
		"returned":      len(flows),
		"scrubbed_totals": map[string]uint64{
			"tokens":  a.scrub.Tokens.Load(),
			"cookies": a.scrub.Cookies.Load(),
			"ips":     a.scrub.IPs.Load(),
		},
		"flows": flows,
	}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return toolResult("failed to encode flows: "+err.Error(), true)
	}
	return toolResult(string(b), false)
}

var reTag = regexp.MustCompile(`\[REDACTED_(TOKEN|COOKIE|IP)#[0-9a-f]{6}\]`)

func envFor(kind string) string {
	switch kind {
	case "COOKIE":
		return "NULLWIRE_COOKIE"
	case "IP":
		return "NULLWIRE_IP"
	default:
		return "NULLWIRE_AUTH_TOKEN"
	}
}

// shellQuote single-quotes s for a POSIX shell and splices redaction tags in
// as double-quoted environment variable references.
func shellQuote(s string) string {
	var b strings.Builder
	emit := func(lit string) {
		if lit == "" {
			return
		}
		b.WriteString("'" + strings.ReplaceAll(lit, "'", `'\''`) + "'")
	}
	last := 0
	for _, m := range reTag.FindAllStringSubmatchIndex(s, -1) {
		emit(s[last:m[0]])
		b.WriteString(`"$` + envFor(s[m[2]:m[3]]) + `"`)
		last = m[1]
	}
	emit(s[last:])
	if b.Len() == 0 {
		return "''"
	}
	return b.String()
}

func sortStrings(a []string) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j-1] > a[j]; j-- {
			a[j-1], a[j] = a[j], a[j-1]
		}
	}
}

var curlSkipHeaders = map[string]bool{
	"host": true, "content-length": true, "connection": true, "proxy-connection": true,
	"proxy-authorization": true, "accept-encoding": true, "keep-alive": true,
	"transfer-encoding": true, "te": true, "trailer": true, "upgrade": true,
}

func buildCurl(e FlowEntry) string {
	names := make([]string, 0, len(e.RequestHeaders))
	for k := range e.RequestHeaders {
		if !curlSkipHeaders[strings.ToLower(k)] {
			names = append(names, k)
		}
	}
	sortStrings(names)

	body := e.RequestBody
	var warnings []string
	if strings.HasSuffix(body, truncMarker) {
		body = strings.TrimSuffix(body, truncMarker)
		warnings = append(warnings, "# WARNING: the request body was truncated in the RAM buffer; this replay is incomplete.")
	}
	if strings.HasPrefix(body, "[encoded body omitted") {
		warnings = append(warnings, "# WARNING: the request body was encoded and is not available; no body is sent.")
		body = ""
	}

	// Collect the redaction tags this command depends on.
	source := e.URL + "\n" + body
	for _, k := range names {
		source += "\n" + e.RequestHeaders[k]
	}
	seen := map[string]bool{}
	var legend []string
	for _, m := range reTag.FindAllStringSubmatch(source, -1) {
		if seen[m[0]] {
			continue
		}
		seen[m[0]] = true
		legend = append(legend, fmt.Sprintf("# export %s=...   # was %s", envFor(m[1]), m[0]))
	}

	var b strings.Builder
	b.WriteString("# Replay of flow " + fmt.Sprint(e.ID) + " (" + e.Timestamp + ")\n")
	for _, w := range warnings {
		b.WriteString(w + "\n")
	}
	if len(legend) > 0 {
		b.WriteString("# Set these environment variables first (distinct tags share one placeholder):\n")
		for _, l := range legend {
			b.WriteString(l + "\n")
		}
	}
	if strings.EqualFold(e.Method, "HEAD") {
		b.WriteString("curl -I")
	} else {
		b.WriteString("curl -X " + shellQuote(e.Method))
	}
	b.WriteString(" " + shellQuote(e.URL))
	for _, k := range names {
		b.WriteString(" \\\n  -H " + shellQuote(k+": "+e.RequestHeaders[k]))
	}
	if body != "" {
		b.WriteString(" \\\n  --data-raw " + shellQuote(body))
	}
	b.WriteString("\n")
	return b.String()
}

func (a *App) toolExportCurl(args json.RawMessage) map[string]any {
	var in struct {
		FlowID *float64 `json:"flow_id"`
	}
	if !isEmptyArgs(args) {
		if err := json.Unmarshal(args, &in); err != nil {
			return toolResult("invalid arguments: "+err.Error(), true)
		}
	}
	if in.FlowID == nil {
		return toolResult("flow_id is required", true)
	}
	if *in.FlowID < 1 || *in.FlowID > 1e15 || *in.FlowID != float64(uint64(*in.FlowID)) {
		return toolResult("flow_id must be a positive integer", true)
	}
	id := uint64(*in.FlowID)
	entry, ok := a.ring.GetByID(id)
	if !ok {
		return toolResult(fmt.Sprintf("flow %d is not in the RAM ring buffer (it may have been overwritten or cleared)", id), true)
	}
	return toolResult(buildCurl(entry), false)
}

func (a *App) toolClear() map[string]any {
	a.ring.Clear()
	a.scrub.ResetCounters()
	a.Bar()
	return toolResult(fmt.Sprintf("RAM ring buffer wiped: all %d slots zeroed, scrub counters reset.", ringCapacity), false)
}

// dispatch handles one request that expects a response.
func (a *App) dispatch(req rpcRequest) {
	id := req.ID
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		version := p.ProtocolVersion
		if version == "" {
			version = "2025-11-25"
		}
		a.writeFrame(rpcResponse{ID: id, Result: map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": serverName, "version": serverVersion},
		}})

	case "server/discover":
		a.writeFrame(rpcResponse{ID: id, Result: map[string]any{
			"resultType":       "complete",
			"protocolVersions": []any{"2026-07-28", "2025-11-25", "2024-11-05"},
			"capabilities":     map[string]any{"tools": map[string]any{}},
			"serverInfo":       map[string]any{"name": serverName, "version": serverVersion},
		}})

	case "ping":
		a.writeFrame(rpcResponse{ID: id, Result: map[string]any{"resultType": "complete"}})

	case "tools/list":
		a.writeFrame(rpcResponse{ID: id, Result: map[string]any{
			"resultType": "complete",
			"ttlMs":      300000,
			"cacheScope": "global",
			"tools":      toolDefinitions(),
		}})

	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
			a.writeError(id, -32602, "invalid params: expected {\"name\": string, \"arguments\": object}")
			return
		}
		var result map[string]any
		switch p.Name {
		case "inspect_traffic":
			result = a.toolInspect(p.Arguments)
		case "export_sanitized_curl":
			result = a.toolExportCurl(p.Arguments)
		case "clear_ram_buffer":
			result = a.toolClear()
		default:
			a.writeError(id, -32602, "unknown tool: "+p.Name)
			return
		}
		a.writeFrame(rpcResponse{ID: id, Result: result})

	default:
		a.writeError(id, -32601, "method not found: "+req.Method)
	}
}

// handleLine parses one stdin line and answers it, honouring the rule that
// notifications never produce output.
func (a *App) handleLine(line []byte) {
	var req rpcRequest
	if err := json.Unmarshal(line, &req); err != nil {
		a.writeError(nil, -32700, "parse error")
		return
	}
	if len(req.ID) == 0 {
		return // no id: a notification, never answer
	}
	if string(req.ID) == "null" && strings.HasPrefix(req.Method, "notifications/") {
		return
	}
	if req.Method == "" {
		a.writeError(req.ID, -32600, "invalid request: missing method")
		return
	}
	defer func() {
		if rec := recover(); rec != nil {
			a.Logf("internal error handling %q: %v", req.Method, rec)
			a.writeError(req.ID, -32603, "internal error")
		}
	}()
	a.dispatch(req)
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "\r\033[K"+format+"\n", args...)
	os.Exit(1)
}

func main() {
	port := flag.Int("port", 8080, "TCP port for the diagnostic proxy (always bound to 127.0.0.1)")
	target := flag.String("target", "", "default upstream base URL for reverse gateway mode, e.g. https://api.example.com")
	flag.Parse()

	if *port < 0 || *port > 65535 {
		fatalf("nullwire-mcp: -port must be between 0 and 65535")
	}

	scrub, err := NewScrubber()
	if err != nil {
		fatalf("nullwire-mcp: cannot read random bytes for the hash salt: %v", err)
	}

	app := &App{
		ring:  NewRingBuffer(),
		scrub: scrub,
		transport: &http.Transport{
			Proxy:                 nil,
			DisableCompression:    true,
			MaxIdleConns:          32,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 120 * time.Second,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		},
	}
	if *target != "" {
		u, err := parseTarget(*target)
		if err != nil {
			fatalf("nullwire-mcp: -target: %v", err)
		}
		app.target = u
	}

	// Strict loopback bind: the host is hard-coded and re-verified.
	ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		fatalf("nullwire-mcp: cannot listen on 127.0.0.1:%d: %v", *port, err)
	}
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok || !tcpAddr.IP.IsLoopback() {
		ln.Close()
		fatalf("nullwire-mcp: refusing to run on a non-loopback address")
	}
	app.port = tcpAddr.Port

	srv := &http.Server{
		Handler:           app,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			app.Logf("proxy server stopped: %v", err)
		}
	}()

	app.Bar()
	app.Logf("MCP stdio server ready (2026-07-28, 2025-11-25, 2024-11-05); proxy listening on 127.0.0.1:%d", app.port)

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		app.handleLine([]byte(line))
	}
	if err := scanner.Err(); err != nil {
		app.Logf("stdin error: %v", err)
	}

	app.Logf("stdin closed; wiping RAM ring buffer and shutting down")
	app.ring.Clear()
	_ = srv.Close()
}
