// nullwire-mcp: a zero-dependency, RAM-only DLP diagnostic HTTP proxy and
// Model Context Protocol (MCP) server over stdio.
//
// stdout is reserved exclusively for single-line JSON-RPC 2.0 frames.
// Everything meant for humans goes to stderr. Nothing is ever written to disk.
package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	ringCapacity  = 50
	maxReqBody    = 8 * 1024
	maxRespBody   = 16 * 1024
	captureLimit  = 64 * 1024
	truncMarker   = "…[truncated]"
	serverName    = "nullwire-mcp"
	serverVersion = "1.2.0"

	// maxTunnels caps concurrent CONNECT tunnels and upgraded (WebSocket)
	// connections so a runaway client cannot exhaust file descriptors.
	maxTunnels = 256
	// tunnelIdle closes a tunnel after this long with no bytes in either
	// direction.
	tunnelIdle = 10 * time.Minute
	// decodedLimit bounds how much a gzip/deflate body may inflate while it is
	// decoded for capture (decompression-bomb guard).
	decodedLimit = 256 * 1024
)

// defaultAndroidDNS is used only on Termux/Android, where a static Go binary
// has no resolver configuration. Override with -dns, disable with -dns system.
var defaultAndroidDNS = []string{"1.1.1.1:53", "9.9.9.9:53"}

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
	Note            string            `json:"note,omitempty"`
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
	reVendorKey       *regexp.Regexp
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
		// Vendor key shapes: Stripe, OpenAI project, Google OAuth, GitLab,
		// Hugging Face, npm and SendGrid. Case-sensitive on purpose: the
		// prefixes are exact, and a case-insensitive match would flag words.
		reVendorKey: regexp.MustCompile(`\b(?:(?:sk|rk)_live_[A-Za-z0-9]{16,}` +
			`|sk-proj-[A-Za-z0-9_-]{20,}` +
			`|ya29\.[A-Za-z0-9_-]{20,}` +
			`|glpat-[A-Za-z0-9_-]{20,}(?:\.[A-Za-z0-9_-]+)*` +
			`|hf_[A-Za-z0-9]{30,}` +
			`|npm_[A-Za-z0-9]{30,}` +
			`|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})`),
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

	out = s.reVendorKey.ReplaceAllStringFunc(out, func(m string) string {
		count++
		s.Tokens.Add(1)
		return s.tag("TOKEN", m)
	})

	out = s.reAPIKey.ReplaceAllStringFunc(out, func(m string) string {
		count++
		s.Tokens.Add(1)
		return s.tag("TOKEN", m)
	})

	// IPv6 first, so an IPv4-mapped address (::ffff:192.0.2.1) is redacted as
	// one unit instead of being split by the IPv4 rule.
	var n6 int
	out, n6 = s.scrubIPv6(out)
	count += n6

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

// ---------------------------------------------------------------------------
// IPv6 redaction
//
// A single regex cannot do this safely: RE2 has no lookaround, and anything
// loose enough to catch "fe80::1" also catches "std::vector", MAC addresses
// and clock times. So the scanner finds runs of address characters and lets
// net/netip decide whether a run really is an IPv6 address.
// ---------------------------------------------------------------------------

func isV6Byte(c byte) bool {
	return c == ':' || c == '.' ||
		(c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isWordByte(c byte) bool {
	return c == '_' ||
		(c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// ipv6Redactable reports whether a parsed address should be redacted. The
// loopback and unspecified addresses stay visible, like 127.0.0.1 and
// 0.0.0.0 do. An address with no decimal digit and fewer than three groups
// ("a::b", "dead::beef", "::face") is left alone: it is indistinguishable
// from C++ and Rust namespaces and costs far more in false positives than
// the near-zero chance that it is a real address.
func ipv6Redactable(a netip.Addr) bool {
	if !a.Is6() {
		return false
	}
	if a.Is4In6() {
		v4 := a.Unmap()
		if v4 == netip.AddrFrom4([4]byte{127, 0, 0, 1}) || v4 == netip.AddrFrom4([4]byte{}) {
			return false
		}
	}
	if a == netip.IPv6Loopback() || a == netip.IPv6Unspecified() {
		return false
	}
	text := a.String()
	if strings.ContainsAny(text, "0123456789") {
		return true
	}
	groups := 0
	for _, g := range strings.Split(text, ":") {
		if g != "" {
			groups++
		}
	}
	return groups >= 3
}

// matchIPv6 examines the run in[i:j] (all address characters) and returns the
// canonical address plus the byte range to replace.
func matchIPv6(in string, i, j, floor int) (addr netip.Addr, start, end int, ok bool) {
	if strings.Count(in[i:j], ":") < 2 {
		return netip.Addr{}, 0, 0, false
	}
	// A letter g-z or an underscore touching the run means it is part of a
	// longer identifier ("std::vector" starts mid-word), not an address.
	// Bytes before floor were already consumed by a previous match (a zone
	// like "%0" can end in a word byte), so they do not count as a prefix.
	if i > 0 && i-1 >= floor && isWordByte(in[i-1]) {
		return netip.Addr{}, 0, 0, false
	}
	start = i
	for start < j && in[start] == '.' {
		start++
	}
	end = j
	for end > start {
		cand := in[start:end]
		if a, err := netip.ParseAddr(cand); err == nil && a.Is6() {
			if !ipv6Redactable(a) {
				return netip.Addr{}, 0, 0, false
			}
			// A word character right after an untrimmed run ("dead::beefx")
			// means the run is part of something longer.
			if end == j && j < len(in) && isWordByte(in[j]) {
				return netip.Addr{}, 0, 0, false
			}
			// Swallow a zone ("fe80::1%eth0") so the interface name goes too.
			if end == j && j < len(in) && in[j] == '%' {
				k := j + 1
				for k < len(in) && isWordByte(in[k]) {
					k++
				}
				if k > j+1 {
					end = k
				}
			}
			return a, start, end, true
		}
		// Trailing sentence punctuation: "seen at fe80::1." or "fe80::1:".
		if last := in[end-1]; last == '.' || last == ':' {
			end--
			continue
		}
		break
	}
	return netip.Addr{}, 0, 0, false
}

// scrubIPv6 replaces every IPv6 address in in with an [REDACTED_IP#...] tag.
// Different spellings of one address share a tag (the hash uses the
// canonical form), so correlation still works.
func (s *Scrubber) scrubIPv6(in string) (string, int) {
	if strings.Count(in, ":") < 2 {
		return in, 0
	}
	var b strings.Builder
	count, last := 0, 0
	for i := 0; i < len(in); {
		if !isV6Byte(in[i]) {
			i++
			continue
		}
		j := i
		for j < len(in) && isV6Byte(in[j]) {
			j++
		}
		if addr, start, end, ok := matchIPv6(in, i, j, last); ok {
			b.WriteString(in[last:start])
			b.WriteString(s.tag("IP", addr.String()))
			s.IPs.Add(1)
			count++
			last = end
			if end > j {
				j = end
			}
		}
		i = j
	}
	if count == 0 {
		return in, 0
	}
	b.WriteString(in[last:])
	return b.String(), count
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
	target    *url.URL            // default upstream, may be nil
	upstreams map[string]*url.URL // named upstreams, keyed by lower-case path prefix
	transport *http.Transport

	tunnels    atomic.Int64  // live CONNECT / upgraded connections
	tunnelIdle time.Duration // 0 means the tunnelIdle constant

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

// reUpstreamName is what a named upstream may be called: it becomes the first
// path segment, so it must be plain and URL-safe.
var reUpstreamName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)

// parseTargets parses the -target flag. Entries are comma separated. An entry
// is either a bare URL (the default upstream, at most one) or name=URL (a
// named upstream, selected by the first path segment). A single bare URL is
// the original, still supported form.
func parseTargets(spec string) (def *url.URL, named map[string]*url.URL, err error) {
	named = map[string]*url.URL{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, raw := "", part
		if i := strings.Index(part, "="); i > 0 && reUpstreamName.MatchString(part[:i]) {
			name, raw = strings.ToLower(part[:i]), part[i+1:]
		}
		label := name
		if label == "" {
			label = "default"
		}
		u, perr := parseTarget(raw)
		if perr != nil {
			return nil, nil, fmt.Errorf("upstream %q: %v", label, perr)
		}
		if name == "" {
			if def != nil {
				return nil, nil, fmt.Errorf("more than one default upstream; name them like openai=https://api.openai.com")
			}
			def = u
			continue
		}
		if _, dup := named[name]; dup {
			return nil, nil, fmt.Errorf("upstream name %q is used twice", name)
		}
		named[name] = u
	}
	if def == nil && len(named) == 0 {
		return nil, nil, fmt.Errorf("no upstream given")
	}
	return def, named, nil
}

// upstreamNames returns the named-upstream prefixes, sorted.
func (a *App) upstreamNames() []string {
	names := make([]string, 0, len(a.upstreams))
	for n := range a.upstreams {
		names = append(names, n)
	}
	sortStrings(names)
	return names
}

// matchUpstream selects a named upstream by the first path segment and returns
// the path with that segment removed. found is false when no name matches (the
// caller then falls back to the default upstream). The prefix must appear
// literally: a percent-encoded prefix is rejected rather than guessed at.
func (a *App) matchUpstream(p, rawPath string) (base *url.URL, rest, rawRest string, found bool, err error) {
	if len(a.upstreams) == 0 || !strings.HasPrefix(p, "/") {
		return nil, "", "", false, nil
	}
	seg, tail := p[1:], ""
	if i := strings.IndexByte(seg, '/'); i >= 0 {
		seg, tail = seg[:i], seg[i:]
	}
	b, ok := a.upstreams[strings.ToLower(seg)]
	if !ok {
		return nil, "", "", false, nil
	}
	if rawPath != "" {
		pre := "/" + seg
		if len(rawPath) < len(pre) || !strings.EqualFold(rawPath[:len(pre)], pre) ||
			(len(rawPath) > len(pre) && rawPath[len(pre)] != '/') {
			return nil, "", "", false, fmt.Errorf("the upstream prefix %q must not be percent-encoded", seg)
		}
		rawRest = rawPath[len(pre):]
	}
	if tail == "" {
		tail = "/"
	}
	return b, tail, rawRest, true, nil
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
	rest, restRaw := r.URL.Path, r.URL.RawPath
	if raw := strings.TrimSpace(r.Header.Get("X-Target-URL")); raw != "" {
		parsed, err := parseTarget(raw)
		if err != nil {
			return nil, true, http.StatusBadRequest, err
		}
		base = parsed
	} else {
		nb, nrest, nraw, found, err := a.matchUpstream(r.URL.Path, r.URL.RawPath)
		if err != nil {
			return nil, true, http.StatusBadRequest, err
		}
		if found {
			base, rest, restRaw = nb, nrest, nraw
		}
	}
	if base == nil {
		if names := a.upstreamNames(); len(names) > 0 {
			return nil, true, http.StatusNotFound,
				fmt.Errorf("unknown upstream: start the path with one of /%s/", strings.Join(names, "/, /"))
		}
		return nil, true, http.StatusBadRequest,
			fmt.Errorf("no upstream: send an absolute URL (forward mode), an X-Target-URL header, or start with -target")
	}
	if a.isSelf(base.Host) {
		return nil, true, http.StatusLoopDetected, fmt.Errorf("refusing to proxy a request back to the proxy itself")
	}
	u := *base
	u.Path = strings.TrimRight(base.Path, "/") + rest
	u.RawPath = ""
	if restRaw != "" {
		u.RawPath = strings.TrimRight(base.EscapedPath(), "/") + restRaw
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
	note        string
}

// ServeHTTP implements both forward-proxy and reverse-gateway modes. The
// client always receives the original, un-scrubbed traffic.
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	if r.Method == http.MethodConnect {
		a.handleConnect(w, r, start)
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
	upgrade := isUpgradeRequest(r.Header)
	if upgrade {
		// Upgrade and Connection are hop-by-hop and were stripped above;
		// re-add exactly what the handshake needs (e.g. WebSocket).
		outReq.Header.Set("Connection", "Upgrade")
		outReq.Header.Set("Upgrade", r.Header.Get("Upgrade"))
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

	if upgrade && resp.StatusCode == http.StatusSwitchingProtocols {
		flow.reqBody = reqCap.Bytes()
		a.handleUpgrade(w, resp, flow)
		return
	}

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

// ---------------------------------------------------------------------------
// CONNECT tunnels and protocol upgrades (WebSocket)
// ---------------------------------------------------------------------------

type closeWriter interface{ CloseWrite() error }

func (a *App) idle() time.Duration {
	if a.tunnelIdle > 0 {
		return a.tunnelIdle
	}
	return tunnelIdle
}

func (a *App) acquireTunnel() bool {
	if a.tunnels.Add(1) > maxTunnels {
		a.tunnels.Add(-1)
		return false
	}
	return true
}

func (a *App) releaseTunnel() { a.tunnels.Add(-1) }

// dial opens an upstream TCP connection with the same dialer (and therefore
// the same DNS settings) the HTTP transport uses.
func (a *App) dial(ctx context.Context, addr string) (net.Conn, error) {
	if a.transport != nil && a.transport.DialContext != nil {
		return a.transport.DialContext(ctx, "tcp", addr)
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	return d.DialContext(ctx, "tcp", addr)
}

// isUpgradeRequest reports a "Connection: Upgrade" + "Upgrade: x" handshake.
func isUpgradeRequest(h http.Header) bool {
	if h.Get("Upgrade") == "" {
		return false
	}
	for _, v := range h.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
				return true
			}
		}
	}
	return false
}

// splice copies bytes both ways until either side ends or the tunnel has been
// idle for idle. pre is data already read from the client that must reach the
// upstream first. It never inspects or stores payload bytes.
func splice(client, upstream io.ReadWriteCloser, idle time.Duration, pre []byte) (toUpstream, toClient int64) {
	var sent, recv, last atomic.Int64
	last.Store(time.Now().UnixNano())
	closeBoth := func() {
		_ = client.Close()
		_ = upstream.Close()
	}
	if len(pre) > 0 {
		n, err := upstream.Write(pre)
		sent.Add(int64(n))
		if err != nil {
			closeBoth()
			return sent.Load(), 0
		}
	}

	var wg sync.WaitGroup
	pump := func(dst, src io.ReadWriteCloser, ctr *atomic.Int64) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				last.Store(time.Now().UnixNano())
				w, werr := dst.Write(buf[:n])
				ctr.Add(int64(w))
				if werr != nil {
					closeBoth()
					return
				}
			}
			if err != nil {
				if err == io.EOF {
					if cw, ok := dst.(closeWriter); ok {
						_ = cw.CloseWrite() // half-close: let the other direction drain
					} else {
						_ = dst.Close()
					}
				} else {
					closeBoth()
				}
				return
			}
		}
	}

	stop := make(chan struct{})
	if idle > 0 {
		go func() {
			iv := idle / 4
			if iv < 5*time.Millisecond {
				iv = 5 * time.Millisecond
			}
			t := time.NewTicker(iv)
			defer t.Stop()
			for {
				select {
				case <-stop:
					return
				case <-t.C:
					if time.Since(time.Unix(0, last.Load())) > idle {
						closeBoth()
						return
					}
				}
			}
		}()
	}

	wg.Add(2)
	go pump(upstream, client, &sent)
	go pump(client, upstream, &recv)
	wg.Wait()
	close(stop)
	closeBoth()
	return sent.Load(), recv.Load()
}

// handleConnect answers HTTP CONNECT with a blind TCP tunnel. There is no TLS
// interception: no root CA, no key material, nothing to trust. Only metadata
// (target, byte counts, timing) is recorded; the payload is never read into
// the ring.
func (a *App) handleConnect(w http.ResponseWriter, r *http.Request, start time.Time) {
	authority := r.Host
	if authority == "" {
		authority = r.URL.Host
	}
	host, portStr, err := net.SplitHostPort(authority)
	port, perr := strconv.Atoi(portStr)
	if err != nil || host == "" || perr != nil || port < 1 || port > 65535 {
		http.Error(w, "nullwire-mcp: CONNECT target must look like host:port", http.StatusBadRequest)
		return
	}
	target := net.JoinHostPort(host, portStr)
	if a.isSelf(target) {
		http.Error(w, "nullwire-mcp: refusing to tunnel back to the proxy itself", http.StatusLoopDetected)
		return
	}
	if !a.acquireTunnel() {
		http.Error(w, "nullwire-mcp: too many concurrent tunnels", http.StatusServiceUnavailable)
		return
	}
	defer a.releaseTunnel()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "nullwire-mcp: connection cannot be hijacked for CONNECT", http.StatusInternalServerError)
		return
	}

	flow := rawFlow{
		started:     start,
		method:      http.MethodConnect,
		url:         target,
		reqHeaders:  r.Header.Clone(),
		respHeaders: http.Header{},
	}

	up, err := a.dial(r.Context(), target)
	if err != nil {
		msg := "nullwire-mcp: cannot reach " + target + ": " + err.Error()
		http.Error(w, msg, http.StatusBadGateway)
		flow.status = http.StatusBadGateway
		flow.note = msg
		flow.latencyMs = time.Since(start).Milliseconds()
		go a.capture(flow)
		return
	}

	client, brw, err := hj.Hijack()
	if err != nil {
		_ = up.Close()
		return
	}
	_ = client.SetDeadline(time.Time{})
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = client.Close()
		_ = up.Close()
		return
	}
	var pre []byte
	if n := brw.Reader.Buffered(); n > 0 {
		if b, _ := brw.Reader.Peek(n); len(b) > 0 {
			pre = append([]byte(nil), b...)
		}
	}

	sent, recv := splice(client, up, a.idle(), pre)

	flow.status = http.StatusOK
	flow.latencyMs = time.Since(start).Milliseconds()
	flow.note = fmt.Sprintf("blind CONNECT tunnel: %d B client->upstream, %d B upstream->client; payload not inspected or stored", sent, recv)
	go a.capture(flow)
}

// handleUpgrade completes a 101 Switching Protocols handshake (WebSocket and
// friends) and then splices the raw connection. Only the handshake is recorded.
func (a *App) handleUpgrade(w http.ResponseWriter, resp *http.Response, flow rawFlow) {
	rwc, ok := resp.Body.(io.ReadWriteCloser)
	hj, hok := w.(http.Hijacker)
	if !ok || !hok {
		msg := "nullwire-mcp: protocol upgrade is not supported on this connection"
		http.Error(w, msg, http.StatusBadGateway)
		flow.status = http.StatusBadGateway
		flow.respHeaders = http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}}
		flow.respBody = []byte(msg)
		flow.latencyMs = time.Since(flow.started).Milliseconds()
		go a.capture(flow)
		return
	}
	if !a.acquireTunnel() {
		http.Error(w, "nullwire-mcp: too many concurrent tunnels", http.StatusServiceUnavailable)
		return
	}
	defer a.releaseTunnel()

	client, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})

	var head strings.Builder
	head.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	_ = resp.Header.Write(&head)
	head.WriteString("\r\n")
	if _, err := client.Write([]byte(head.String())); err != nil {
		_ = client.Close()
		return
	}
	var pre []byte
	if n := brw.Reader.Buffered(); n > 0 {
		if b, _ := brw.Reader.Peek(n); len(b) > 0 {
			pre = append([]byte(nil), b...)
		}
	}

	sent, recv := splice(client, rwc, a.idle(), pre)

	flow.status = http.StatusSwitchingProtocols
	flow.respHeaders = resp.Header.Clone()
	flow.latencyMs = time.Since(flow.started).Milliseconds()
	flow.note = fmt.Sprintf("upgraded connection (%s): %d B client->upstream, %d B upstream->client; frames not inspected or stored",
		resp.Header.Get("Upgrade"), sent, recv)
	go a.capture(flow)
}

// ---------------------------------------------------------------------------
// DNS selection
// ---------------------------------------------------------------------------

// parseDNSServers turns "1.1.1.1, [2606:4700:4700::1111]:53" into dialable
// host:port strings. Only IP literals are accepted (a hostname would need DNS
// to resolve DNS).
func parseDNSServers(spec string) ([]string, error) {
	var out []string
	for _, raw := range strings.Split(spec, ",") {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		host, port := s, "53"
		if h, p, err := net.SplitHostPort(s); err == nil {
			host, port = h, p
		} else {
			host = strings.Trim(s, "[]")
		}
		if net.ParseIP(host) == nil {
			return nil, fmt.Errorf("-dns: %q is not an IP address (example: 1.1.1.1 or 9.9.9.9:53)", s)
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("-dns: bad port in %q", s)
		}
		out = append(out, net.JoinHostPort(host, port))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("-dns: no servers given")
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// TLS trust roots
//
// A static Go binary on Termux/Android finds no CA bundle: Go only looks in
// /etc/ssl and friends, and Termux keeps its bundle under $PREFIX. Without one
// every HTTPS upstream fails with "x509: certificate signed by unknown
// authority" (plain-HTTP forward mode keeps working, which makes it confusing).
// ---------------------------------------------------------------------------

// termuxCAPaths lists where a Termux/Android device keeps trusted roots, best
// first. Entries may be PEM bundle files or directories of PEM files.
func termuxCAPaths() []string {
	var out []string
	if p := os.Getenv("PREFIX"); p != "" {
		out = append(out, p+"/etc/tls/cert.pem", p+"/etc/ssl/certs/ca-certificates.crt")
	}
	return append(out,
		"/data/data/com.termux/files/usr/etc/tls/cert.pem",
		"/system/etc/security/cacerts", // Android system store (directory)
	)
}

// addPEMPath adds every certificate in the file, or in every file of the
// directory, at path to pool. It reports whether at least one PEM block was
// accepted. A missing path is not an error here; the caller decides.
func addPEMPath(pool *x509.CertPool, path string) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	if !fi.IsDir() {
		pem, err := os.ReadFile(path)
		if err != nil {
			return false, err
		}
		return pool.AppendCertsFromPEM(pem), nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return false, err
	}
	got := false
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		pem, err := os.ReadFile(path + "/" + e.Name())
		if err != nil {
			continue
		}
		if pool.AppendCertsFromPEM(pem) {
			got = true
		}
	}
	return got, nil
}

// buildRootCAs returns the pool to verify upstream servers with, and a short
// description of where it came from.
//
//   - cacert != "": the system pool plus that file or directory. A bad path is
//     an error, because the user asked for it explicitly.
//   - Termux/Android with no SSL_CERT_FILE / SSL_CERT_DIR: the system pool plus
//     the first bundle found in termuxCAPaths.
//   - Anything else: (nil, "", nil), which keeps Go's default behaviour.
//
// Certificate verification is never switched off.
func buildRootCAs(cacert string, termux bool) (*x509.CertPool, string, error) {
	explicit := cacert != ""
	if !explicit && (!termux || os.Getenv("SSL_CERT_FILE") != "" || os.Getenv("SSL_CERT_DIR") != "") {
		return nil, "", nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if explicit {
		ok, err := addPEMPath(pool, cacert)
		if err != nil {
			return nil, "", fmt.Errorf("-cacert %s: %v", cacert, err)
		}
		if !ok {
			return nil, "", fmt.Errorf("-cacert %s: no PEM certificates found", cacert)
		}
		return pool, cacert, nil
	}
	for _, p := range termuxCAPaths() {
		if ok, _ := addPEMPath(pool, p); ok {
			return pool, p, nil
		}
	}
	return pool, "", nil
}

// onTermux detects Termux/Android from the environment (no file access).
func onTermux() bool {
	return os.Getenv("TERMUX_VERSION") != "" || strings.Contains(os.Getenv("PREFIX"), "com.termux")
}

// newDialer returns the upstream dialer. With servers set, name lookups use
// the pure-Go resolver pointed at those servers instead of the system config.
func newDialer(servers []string) *net.Dialer {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	if len(servers) > 0 {
		d.Resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				nd := net.Dialer{Timeout: 5 * time.Second}
				var last error
				for _, s := range servers {
					c, err := nd.DialContext(ctx, network, s)
					if err == nil {
						return c, nil
					}
					last = err
				}
				return nil, last
			},
		}
	}
	return d
}

// decodableEncoding reports whether ce is a Content-Encoding NullWire can
// decode with the standard library alone (gzip and deflate; not br or zstd).
func decodableEncoding(ce string) bool {
	switch strings.ToLower(strings.TrimSpace(ce)) {
	case "gzip", "x-gzip", "deflate":
		return true
	}
	return false
}

// decodeBody inflates a gzip/deflate body with a hard output limit. The input
// may itself be truncated (capture is capped), so a partial result is fine.
func decodeBody(ce string, b []byte) (string, bool) {
	var rd io.Reader
	switch strings.ToLower(strings.TrimSpace(ce)) {
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return "", false
		}
		rd = zr
	case "deflate":
		if zr, err := zlib.NewReader(bytes.NewReader(b)); err == nil {
			rd = zr
		} else {
			rd = flate.NewReader(bytes.NewReader(b)) // raw deflate, sent by some servers
		}
	default:
		return "", false
	}
	out, err := io.ReadAll(io.LimitReader(rd, decodedLimit))
	if len(out) == 0 && err != nil {
		return "", false
	}
	text := string(out)
	if err != nil || len(out) >= decodedLimit {
		text += truncMarker
	}
	return text, true
}

func bodyText(h http.Header, b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if ce := strings.TrimSpace(h.Get("Content-Encoding")); ce != "" && !strings.EqualFold(ce, "identity") {
		if text, ok := decodeBody(ce, b); ok {
			return text
		}
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
		Note:            f.note,
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

// marshalJSON encodes v without HTML escaping (so <, > and & stay readable and
// cost fewer tokens). With indent=false the output is a single compact line.
func marshalJSON(v any, indent bool) (string, error) {
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	enc.SetEscapeHTML(false)
	if indent {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(sb.String(), "\n"), nil
}

// writeFrame writes exactly one compact JSON line to stdout.
func (a *App) writeFrame(resp rpcResponse) {
	resp.JSONRPC = "2.0"
	line, err := marshalJSON(resp, false)
	if err != nil {
		line = `{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"internal error: cannot encode response"}}`
	}
	b := []byte(line + "\n")
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
	text, err := marshalJSON(payload, true)
	if err != nil {
		return toolResult("failed to encode flows: "+err.Error(), true)
	}
	return toolResult(text, false)
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
	if strings.EqualFold(e.Method, http.MethodConnect) {
		return fmt.Sprintf("# Flow %d (%s) was a blind CONNECT tunnel to %s.\n"+
			"# The HTTP inside it was never visible to NullWire, so there is nothing to replay.\n"+
			"# To capture HTTPS requests in full, use the reverse gateway: -target https://HOST or an X-Target-URL header.\n",
			e.ID, e.Timestamp, e.URL)
	}
	names := make([]string, 0, len(e.RequestHeaders))
	for k := range e.RequestHeaders {
		lk := strings.ToLower(k)
		if curlSkipHeaders[lk] {
			continue
		}
		// Bodies are stored decoded, so a replay must not claim they are still encoded.
		if lk == "content-encoding" && decodableEncoding(e.RequestHeaders[k]) {
			continue
		}
		names = append(names, k)
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
	target := flag.String("target", "", "upstream base URL(s) for reverse gateway mode: https://api.example.com, or named: openai=https://api.openai.com,anthropic=https://api.anthropic.com (selected by the first path segment); a bare URL in the list is the default")
	cacert := flag.String("cacert", "", "extra CA certificates (PEM file or directory) to trust for HTTPS upstreams; on Termux/Android a bundle is found automatically")
	dnsSpec := flag.String("dns", "auto", "upstream DNS: auto (Termux/Android uses 1.1.1.1 and 9.9.9.9), system, or a comma list of IPs like 1.1.1.1,9.9.9.9:53")
	flag.Parse()

	if *port < 0 || *port > 65535 {
		fatalf("nullwire-mcp: -port must be between 0 and 65535")
	}

	scrub, err := NewScrubber()
	if err != nil {
		fatalf("nullwire-mcp: cannot read random bytes for the hash salt: %v", err)
	}

	var dnsServers []string
	dnsNotice := ""
	switch spec := strings.ToLower(strings.TrimSpace(*dnsSpec)); spec {
	case "system":
	case "", "auto":
		if onTermux() {
			dnsServers = defaultAndroidDNS
			dnsNotice = "Termux/Android detected: upstream DNS queries go to 1.1.1.1 / 9.9.9.9 because static binaries have no system resolver. Use -dns to choose your own, or -dns system to disable."
		}
	default:
		dnsServers, err = parseDNSServers(*dnsSpec)
		if err != nil {
			fatalf("nullwire-mcp: %v", err)
		}
	}
	dialer := newDialer(dnsServers)

	rootCAs, caSource, err := buildRootCAs(*cacert, onTermux())
	if err != nil {
		fatalf("nullwire-mcp: %v", err)
	}
	var tlsCfg *tls.Config
	if rootCAs != nil {
		tlsCfg = &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}
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
			DialContext:           dialer.DialContext,
			TLSClientConfig:       tlsCfg,
		},
	}
	if *target != "" {
		def, named, err := parseTargets(*target)
		if err != nil {
			fatalf("nullwire-mcp: -target: %v", err)
		}
		app.target = def
		app.upstreams = named
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

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigs
		app.Logf("signal received; wiping RAM ring buffer and shutting down")
		app.ring.Clear()
		_ = srv.Close()
		os.Exit(0)
	}()

	app.Bar()
	if dnsNotice != "" {
		app.Logf("%s", dnsNotice)
	}
	switch {
	case caSource != "":
		app.Logf("TLS roots: system store plus %s", caSource)
	case onTermux() && rootCAs != nil:
		app.Logf("warning: no CA bundle found, so HTTPS upstreams will fail with \"certificate signed by unknown authority\". Run: pkg install ca-certificates   (or pass -cacert /path/to/cert.pem)")
	}
	if names := app.upstreamNames(); len(names) > 0 {
		app.Logf("named upstreams: /%s/", strings.Join(names, "/, /"))
	}
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
 