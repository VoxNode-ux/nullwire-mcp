// nullwire-mcp: a zero-dependency, RAM-only DLP diagnostic HTTP proxy and
// Model Context Protocol (MCP) server over stdio.
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
	"math"
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
	maxReqBody    = 32 * 1024
	maxRespBody   = 256 * 1024
	maxReqCapture = 64 * 1024
	maxRespCapture = 512 * 1024
	scrubWindow   = 8 * 1024

	truncMarker   = "…[truncated]"
	serverName    = "nullwire-mcp"
	serverVersion = "1.2.0"
	maxTunnels    = 256
	tunnelIdle    = 10 * time.Minute
	decodedLimit  = 1024 * 1024

	entropyMinLen         = 16
	entropyMaxLen         = 128
	entropyHexMin         = 3.0
	entropyLongMin        = 3.3
	entropyShortMin       = 3.6
	entropyMaxVowel       = 0.25
	hasTokenSignalAutoLen = 24
)

var defaultAndroidDNS = []string{"1.1.1.1:53", "9.9.9.9:53"}

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

type RingBuffer struct {
	mu     sync.RWMutex
	slots  [ringCapacity]FlowEntry
	next   int
	size   int
	nextID uint64
}

func NewRingBuffer() *RingBuffer { return &RingBuffer{nextID: 1} }

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

func (r *RingBuffer) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.size
}

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

func (r *RingBuffer) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.slots {
		r.slots[i] = FlowEntry{}
	}
	r.next = 0
	r.size = 0
}

type VendorConfig struct {
	Name    string `json:"name"`
	Prefix  string `json:"prefix"`
	Pattern string `json:"pattern,omitempty"`
}

type SecretsConfig struct {
	SensitiveHeaders    []string       `json:"sensitive_headers"`
	IgnoreURLSubstrings []string       `json:"ignore_url_substrings"`
	IgnoreHeaders       []string       `json:"ignore_headers"`
	CustomVendors       []VendorConfig `json:"custom_vendors"`
	ExtraRegexPatterns  []ExtraPattern `json:"extra_regex_patterns"`
}

type ExtraPattern struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
}

func loadSecretsConfig(path string) (*SecretsConfig, error) {
	if path == "" {
		return &SecretsConfig{}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("-secrets-config %s: %v", path, err)
	}
	var c SecretsConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("-secrets-config %s: invalid JSON: %v", path, err)
	}
	for i, p := range c.ExtraRegexPatterns {
		if p.Pattern == "" {
			return nil, fmt.Errorf("-secrets-config %s: extra_regex_patterns[%d] has empty pattern", path, i)
		}
		if _, err := regexp.Compile(p.Pattern); err != nil {
			return nil, fmt.Errorf("-secrets-config %s: extra_regex_patterns[%d] (%q): %v", path, i, p.Name, err)
		}
	}
	for i, v := range c.CustomVendors {
		if v.Pattern != "" {
			if _, err := regexp.Compile(v.Pattern); err != nil {
				return nil, fmt.Errorf("-secrets-config %s: custom_vendors[%d] (%q): %v", path, i, v.Name, err)
			}
		}
	}
	return &c, nil
}

type Scrubber struct {
	nonce          []byte
	extraSensitive map[string]bool
	ignoreHeaders  map[string]bool
	extraPatterns  []*regexp.Regexp
	vendorGate     []string     // lower-cased prefixes for the cheap pre-check
	vendorRules    []vendorRule // strong, weak, DSN and custom prefix rules

	reBearer          *regexp.Regexp
	reSensitiveHeader *regexp.Regexp
	reJWT             *regexp.Regexp
	reAPIKey          *regexp.Regexp
	reJSONSecret      *regexp.Regexp
	reQuerySecret     *regexp.Regexp
	reUserInfo        *regexp.Regexp
	reIPv4            *regexp.Regexp
	rePEM             *regexp.Regexp
	reXML             *regexp.Regexp
	reJSONSecretArr   *regexp.Regexp

	Tokens  atomic.Uint64
	Cookies atomic.Uint64
	IPs     atomic.Uint64
}

func NewScrubber() (*Scrubber, error) { return NewScrubberWithConfig(&SecretsConfig{}) }

func NewScrubberWithConfig(cfg *SecretsConfig) (*Scrubber, error) {
	if cfg == nil {
		cfg = &SecretsConfig{}
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	extra := make(map[string]bool, len(cfg.SensitiveHeaders))
	for _, h := range cfg.SensitiveHeaders {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			extra[h] = true
		}
	}
	ignore := make(map[string]bool, len(cfg.IgnoreHeaders))
	for _, h := range cfg.IgnoreHeaders {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			ignore[h] = true
		}
	}

	customPrefixes := make([]string, 0, len(cfg.CustomVendors))
	extras := make([]*regexp.Regexp, 0, len(cfg.ExtraRegexPatterns)+len(cfg.CustomVendors))

	for _, cv := range cfg.CustomVendors {
		if cv.Prefix != "" {
			customPrefixes = append(customPrefixes, cv.Prefix)
		}
		if cv.Pattern != "" {
			re, err := regexp.Compile(cv.Pattern)
			if err != nil {
				return nil, fmt.Errorf("custom vendor %q pattern error: %v", cv.Name, err)
			}
			extras = append(extras, re)
		}
	}

	for _, p := range cfg.ExtraRegexPatterns {
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return nil, fmt.Errorf("extra_regex_patterns[%q]: %v", p.Name, err)
		}
		extras = append(extras, re)
	}

	var rules []vendorRule
	var gate []string
	seenGate := map[string]bool{}
	for _, spec := range []struct {
		prefixes []string
		class    string
		min      int
		weak     bool
	}{
		{DefaultVendorPrefixes, vendorTokenClass, 16, false},
		{DefaultWeakVendorPrefixes, vendorTokenClass, 20, true},
		{DefaultDSNPrefixes, vendorDSNClass, 8, false},
		{customPrefixes, vendorTokenClass, 8, false},
	} {
		if r, ok := buildVendorRule(spec.prefixes, spec.class, spec.min, spec.weak); ok {
			rules = append(rules, r)
		}
		for _, p := range spec.prefixes {
			if lp := strings.ToLower(p); !seenGate[lp] {
				seenGate[lp] = true
				gate = append(gate, lp)
			}
		}
	}

	return &Scrubber{
		nonce:          nonce,
		extraSensitive: extra,
		ignoreHeaders:  ignore,
		extraPatterns:  extras,
		vendorGate:     gate,
		vendorRules:    rules,
		reBearer:       regexp.MustCompile(`(?i)(Bearer|Basic|Token)\s+([A-Za-z0-9._~+/=-]{8,})`),
		reSensitiveHeader: regexp.MustCompile(`(?i)^(authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token|proxy-authorization)$`),
		reJWT:             regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
		reAPIKey:          regexp.MustCompile(`(?i)\b(sk-[a-zA-Z0-9_-]{20,}|ghp_[a-zA-Z0-9]{30,}|github_pat_[a-zA-Z0-9_]{30,}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[0-9a-zA-Z-]+|AKIA[0-9A-Z]{16})\b`),
		reJSONSecret:      regexp.MustCompile(`(?i)("(?:access_token|refresh_token|id_token|api_key|apikey|secret|client_secret|password|passwd|session_id|auth_token|key)"\s*:\s*")((?:[^"\\]|\\.)+)(")`),
		reQuerySecret:     regexp.MustCompile(`(?i)((?:^|[?&])(?:api_key|apikey|token|access_token|refresh_token|id_token|secret|client_secret|password|passwd|key)=)([^&\s#]+)`),
		reUserInfo:        regexp.MustCompile(`(://[^/\s:@]+:)([^@/\s]+)(@)`),
		reIPv4:            regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
		// A private key block, from BEGIN to END; a block cut off by the capture limit is redacted to the end of the text.
		rePEM: regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----(?:.*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|.*)`),
		// The text of an XML element whose name suggests a secret. Only the opening "</" is part of the match, so the rest of the closing tag is
		// left in place; a body cut off before the closing tag is redacted to the end of the text. RE2 has no backreferences, so the closing
		// tag name is not compared with the opening one.
		reXML: regexp.MustCompile(`(?is)(<(?:[A-Za-z0-9_.-]+:)?[A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|apikey|api_key|api-key|authorization|credential|privatekey|private_key|accesskey|access_key|sessionid|session_id)[A-Za-z0-9_.-]*(?:\s[^<>]*)?>)(<!\[CDATA\[.*?\]\]>|[^<]+)(</|\z)`),
		// "password": ["a", "b"]
		reJSONSecretArr: regexp.MustCompile(`(?i)("(?:access_token|refresh_token|id_token|api_key|apikey|secret|client_secret|password|passwd|session_id|auth_token|key)"\s*:\s*\[)((?:\s*"(?:[^"\\]|\\.)*"\s*,?)+)(\s*\])`),
	}, nil
}

func (s *Scrubber) tag(kind, raw string) string {
	h := sha256.New()
	h.Write(s.nonce)
	h.Write([]byte(raw))
	return "[REDACTED_" + kind + "#" + hex.EncodeToString(h.Sum(nil))[:6] + "]"
}

func (s *Scrubber) ResetCounters() {
	s.Tokens.Store(0)
	s.Cookies.Store(0)
	s.IPs.Store(0)
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// Character classes for what may follow a vendor prefix. Tokens use a narrow
// class so the match stops at quotes, spaces, commas and brackets; connection
// strings may also contain URL punctuation.
const (
	vendorTokenClass = `[A-Za-z0-9._~+/=-]`
	vendorDSNClass   = `[A-Za-z0-9._~:/?#\[\]@!$&*+=%-]`
)

// vendorRule redacts "<prefix><at least min class characters>". A weak rule
// only redacts when the part after the prefix also looks like a key.
type vendorRule struct {
	re       *regexp.Regexp
	prefixes []string
	weak     bool
}

func buildVendorRule(prefixes []string, class string, min int, weak bool) (vendorRule, bool) {
	if len(prefixes) == 0 {
		return vendorRule{}, false
	}
	var b strings.Builder
	b.WriteString(`\b(?:`)
	for i, p := range prefixes {
		if i > 0 {
			b.WriteString(`|`)
		}
		b.WriteString(regexp.QuoteMeta(p))
	}
	b.WriteString(`)`)
	b.WriteString(class)
	b.WriteString(fmt.Sprintf("{%d,}", min))
	return vendorRule{re: regexp.MustCompile(b.String()), prefixes: prefixes, weak: weak}, true
}

// weakVendorMatchOK checks the text after the matched prefix.
func weakVendorMatchOK(m string, prefixes []string) bool {
	best := 0
	for _, p := range prefixes {
		if len(p) > best && strings.HasPrefix(m, p) {
			best = len(p)
		}
	}
	return hasTokenSignal(m[best:])
}

// ScrubText redacts everything NullWire recognises in in and returns the
// result with the number of redactions.
func (s *Scrubber) ScrubText(in string) (string, int) { return s.scrubLayers(in, true) }

// scrubLayers runs every rule. Base64 decoding is switched off for text that
// was itself decoded from base64, so it never nests.
func (s *Scrubber) scrubLayers(in string, allowB64 bool) (string, int) {
	if in == "" {
		return in, 0
	}
	lower := strings.ToLower(in)

	preJWT := strings.Contains(in, "eyJ")
	preVendor := containsAny(lower, s.vendorGate)
	preAPIKey := containsAny(lower, []string{"sk-", "ghp_", "github_pat_", "aiza", "xox", "akia"})
	preUserInfo := strings.Contains(in, "://") && strings.Contains(in, "@")
	preBearer := containsAny(lower, []string{"bearer", "basic", "token"})
	preSecretKey := containsAny(lower, []string{"token", "secret", "password", "passwd", "session_id", "api_key", "apikey", "key=", `"key"`})

	count := 0
	out := in

	if strings.Contains(in, "-----BEGIN") {
		out = s.rePEM.ReplaceAllStringFunc(out, func(m string) string {
			count++
			s.Tokens.Add(1)
			return s.tag("KEY", m)
		})
	}

	if preSecretKey {
		out = s.reJSONSecret.ReplaceAllStringFunc(out, func(m string) string {
			g := s.reJSONSecret.FindStringSubmatch(m)
			if g == nil {
				return m
			}
			count++
			s.Tokens.Add(1)
			return g[1] + s.tag("TOKEN", g[2]) + g[3]
		})
		out = s.scrubJSONSecretArrays(out, &count)
		out = s.reQuerySecret.ReplaceAllStringFunc(out, func(m string) string {
			g := s.reQuerySecret.FindStringSubmatch(m)
			if g == nil {
				return m
			}
			count++
			s.Tokens.Add(1)
			return g[1] + s.tag("TOKEN", g[2])
		})
	}
	if strings.Contains(in, "</") && containsAny(lower, xmlSecretHints) {
		out = s.scrubXMLSecrets(out, &count)
	}
	if preUserInfo {
		out = s.reUserInfo.ReplaceAllStringFunc(out, func(m string) string {
			g := s.reUserInfo.FindStringSubmatch(m)
			if g == nil {
				return m
			}
			count++
			s.Tokens.Add(1)
			return g[1] + s.tag("TOKEN", g[2]) + g[3]
		})
	}
	if preBearer {
		out = s.reBearer.ReplaceAllStringFunc(out, func(m string) string {
			g := s.reBearer.FindStringSubmatch(m)
			if g == nil {
				return m
			}
			count++
			s.Tokens.Add(1)
			return g[1] + " " + s.tag("TOKEN", g[2])
		})
	}
	if preJWT {
		out = s.reJWT.ReplaceAllStringFunc(out, func(m string) string {
			count++
			s.Tokens.Add(1)
			return s.tag("TOKEN", m)
		})
	}
	if preVendor {
		for _, vr := range s.vendorRules {
			out = vr.re.ReplaceAllStringFunc(out, func(m string) string {
				if vr.weak && !weakVendorMatchOK(m, vr.prefixes) {
					return m
				}
				count++
				s.Tokens.Add(1)
				return s.tag("TOKEN", m)
			})
		}
	}
	if preAPIKey {
		out = s.reAPIKey.ReplaceAllStringFunc(out, func(m string) string {
			count++
			s.Tokens.Add(1)
			return s.tag("TOKEN", m)
		})
	}

	var nStrict int
	out, nStrict = s.scrubStrictFields(out)
	count += nStrict

	for _, re := range s.extraPatterns {
		out = re.ReplaceAllStringFunc(out, func(m string) string {
			count++
			s.Tokens.Add(1)
			return s.tag("TOKEN", m)
		})
	}

	var n6 int
	out, n6 = s.scrubIPv6(out)
	count += n6

	out = s.reIPv4.ReplaceAllStringFunc(out, func(m string) string {
		addr, err := netip.ParseAddr(m)
		if err != nil || !addr.Is4() {
			return m
		}
		canon := addr.String()
		if canon == "127.0.0.1" || canon == "0.0.0.0" {
			return m
		}
		count++
		s.IPs.Add(1)
		return s.tag("IP", canon)
	})

	if allowB64 {
		out = s.scrubBase64(out, &count)
	}

	var nEntropy int
	out, nEntropy = s.scrubHighEntropy(out)
	count += nEntropy
	return out, count
}

// strictKeyHints are fragments of field names that usually hold secrets.
var strictKeyHints = []string{"token", "secret", "passw", "pwd", "auth", "credential", "session", "signature", "apikey", "api_key", "api-key", "private", "cookie", "bearer"}

func isKeyByte(c byte) bool {
	return c == '_' || c == '-' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// keyBefore returns the field name that ends just before in[i] (a ':' or '='),
// skipping quotes and spaces: `"api_key": ` gives api_key.
func keyBefore(in string, i int) string {
	j := i
	for j > 0 && (in[j-1] == ' ' || in[j-1] == '"' || in[j-1] == '\'') {
		j--
	}
	k := j
	for k > 0 && isKeyByte(in[k-1]) {
		k--
	}
	return in[k:j]
}

func secretishKey(key string) bool {
	k := strings.ToLower(key)
	if k == "" {
		return false
	}
	if strings.HasSuffix(k, "key") || k == "sig" || strings.HasSuffix(k, "_sig") || strings.HasSuffix(k, "-sig") {
		return true
	}
	for _, h := range strictKeyHints {
		if strings.Contains(k, h) {
			return true
		}
	}
	return false
}

// scrubStrictFields redacts the value of a secret-looking field (token, key,
// auth, session, ...) even when the value matches no known key shape. It only
// fires for 12-256 character values without spaces, slashes, dots or colons
// (so URLs, paths and timestamps are left alone), and never for a field whose
// name gives no hint: ordinary values like "model":"claude-opus-4-5" survive.
func (s *Scrubber) scrubStrictFields(in string) (string, int) {
	if len(in) < 12 {
		return in, 0
	}
	var b strings.Builder
	count, last := 0, 0
	for i := 0; i < len(in); i++ {
		if in[i] != ':' && in[i] != '=' {
			continue
		}
		start := i + 1
		for start < len(in) && (in[start] == ' ' || in[start] == '"' || in[start] == '\'') {
			start++
		}
		end := start
		for end < len(in) && in[end] != ' ' && in[end] != '"' && in[end] != '\'' && in[end] != ',' && in[end] != '\n' && in[end] != '}' && in[end] != '&' {
			end++
		}
		if end-start < 12 || end-start > 256 {
			continue
		}
		if !secretishKey(keyBefore(in, i)) {
			continue
		}
		val := in[start:end]
		if strings.HasPrefix(val, "[REDACTED_") || strings.ContainsAny(val, "/.\\:") {
			continue
		}
		b.WriteString(in[last:start])
		b.WriteString(s.tag("TOKEN", val))
		s.Tokens.Add(1)
		last = end
		count++
		i = end - 1
	}
	if count == 0 {
		return in, 0
	}
	b.WriteString(in[last:])
	return b.String(), count
}

func isEntropyCandidate(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-'
}

func isHexLike(s string) bool {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

func hasTokenSignal(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') {
			return true
		}
	}
	return len(s) >= hasTokenSignalAutoLen
}

func vowelRatio(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	v := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case 'a', 'e', 'i', 'o', 'u', 'A', 'E', 'I', 'O', 'U', 'y', 'Y':
			v++
		}
	}
	return float64(v) / float64(len(s))
}

func shannonEntropyBits(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func looksLikeToken(s string) bool {
	n := len(s)
	if n < entropyMinLen || n > entropyMaxLen {
		return false
	}

	if n == 36 && s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-' {
		return false
	}

	h := shannonEntropyBits(s)
	if isHexLike(s) {
		return h >= entropyHexMin
	}
	if !hasTokenSignal(s) {
		return false
	}
	if vowelRatio(s) > entropyMaxVowel {
		return false
	}
	if n >= 32 {
		return h >= entropyLongMin
	}
	return h >= entropyShortMin
}

func (s *Scrubber) scrubHighEntropy(in string) (string, int) {
	if len(in) < entropyMinLen {
		return in, 0
	}
	var b strings.Builder
	count, last := 0, 0
	for i := 0; i < len(in); {
		if !isEntropyCandidate(in[i]) {
			i++
			continue
		}
		j := i
		for j < len(in) && isEntropyCandidate(in[j]) {
			j++
		}
		cand := in[i:j]

		if !strings.Contains(cand, "REDACTED_") && looksLikeToken(cand) {
			b.WriteString(in[last:i])
			b.WriteString(s.tag("TOKEN", cand))
			s.Tokens.Add(1)
			count++
			last = j
		}
		i = j
	}
	if count == 0 {
		return in, 0
	}
	b.WriteString(in[last:])
	return b.String(), count
}

func isV6Byte(c byte) bool {
	return c == ':' || c == '.' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isWordByte(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

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

func matchIPv6(in string, i, j, floor int) (addr netip.Addr, start, end int, ok bool) {
	if strings.Count(in[i:j], ":") < 2 {
		return netip.Addr{}, 0, 0, false
	}
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
			if end == j && j < len(in) && isWordByte(in[j]) {
				return netip.Addr{}, 0, 0, false
			}
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
		if last := in[end-1]; last == '.' || last == ':' {
			end--
			continue
		}
		break
	}
	return netip.Addr{}, 0, 0, false
}

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

func (s *Scrubber) ScrubHeaders(h http.Header) (map[string]string, int) {
	out := make(map[string]string, len(h))
	count := 0
	for name, vals := range h {
		joined := strings.Join(vals, ", ")
		lname := strings.ToLower(name)
		if s.ignoreHeaders[lname] {
			out[name] = joined
			continue
		}
		if s.reSensitiveHeader.MatchString(name) || s.extraSensitive[lname] {
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

type App struct {
	ring                *RingBuffer
	scrub               *Scrubber
	port                int
	target              *url.URL
	upstreams           map[string]*url.URL
	transport           *http.Transport
	ignoreURLSubstrings []string
	tunnels             atomic.Int64
	tunnelIdle          time.Duration
	allowUninspectable  bool // forward request bodies whose Content-Encoding cannot be decoded
	barMu               sync.Mutex
	stdoutMu            sync.Mutex
}

func (a *App) drawBar() {
	fmt.Fprintf(os.Stderr, "\r\033[K⚡ [NullWire-MCP] Proxy 127.0.0.1:%d | RAM Ring: %d/%d | Scrubbed: %d Tokens, %d Cookies, %d IPs | Disk: 0B",
		a.port, a.ring.Len(), ringCapacity, a.scrub.Tokens.Load(), a.scrub.Cookies.Load(), a.scrub.IPs.Load())
}
func (a *App) Bar() { a.barMu.Lock(); defer a.barMu.Unlock(); a.drawBar() }
func (a *App) Logf(format string, args ...any) { a.barMu.Lock(); defer a.barMu.Unlock(); fmt.Fprintf(os.Stderr, "\r\033[K"+format+"\n", args...); a.drawBar() }

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
func (c *capBuffer) Bytes() []byte { c.mu.Lock(); defer c.mu.Unlock(); return append([]byte(nil), c.buf...) }

type flushWriter struct{ w http.ResponseWriter }

func (f *flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if fl, ok := f.w.(http.Flusher); ok {
		fl.Flush()
	}
	return n, err
}

var hopByHop = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

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
	return h == fmt.Sprintf("127.0.0.1:%d", a.port) || h == fmt.Sprintf("localhost:%d", a.port) || h == fmt.Sprintf("[::1]:%d", a.port)
}

var reUpstreamName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)

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
				return nil, nil, fmt.Errorf("more than one default upstream")
			}
			def = u
			continue
		}
		if _, dup := named[name]; dup {
			return nil, nil, fmt.Errorf("upstream name %q used twice", name)
		}
		named[name] = u
	}
	if def == nil && len(named) == 0 {
		return nil, nil, fmt.Errorf("no upstream given")
	}
	return def, named, nil
}

func (a *App) upstreamNames() []string {
	names := make([]string, 0, len(a.upstreams))
	for n := range a.upstreams {
		names = append(names, n)
	}
	sortStrings(names)
	return names
}

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
		if len(rawPath) < len(pre) || !strings.EqualFold(rawPath[:len(pre)], pre) || (len(rawPath) > len(pre) && rawPath[len(pre)] != '/') {
			return nil, "", "", false, fmt.Errorf("the upstream prefix %q must not be percent-encoded", seg)
		}
		rawRest = rawPath[len(pre):]
	}
	if tail == "" {
		tail = "/"
	}
	return b, tail, rawRest, true, nil
}

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
			return nil, true, http.StatusNotFound, fmt.Errorf("unknown upstream: start the path with one of /%s/", strings.Join(names, "/, /"))
		}
		return nil, true, http.StatusBadRequest, fmt.Errorf("no upstream: send an absolute URL (forward mode), an X-Target-URL header, or start with -target")
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

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if r.Method == http.MethodConnect {
		a.handleConnect(w, r, start)
		return
	}
	if !a.allowUninspectable && r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0 {
		if enc, blocked := uninspectableRequestEncoding(r.Header); blocked {
			// Fail closed: a body that cannot be read cannot be scrubbed, so it
			// is not forwarded unless the user chose -allow-uninspectable.
			a.Logf("blocked a %s request with Content-Encoding %s (cannot be inspected)", r.Method, enc)
			http.Error(w, "nullwire-mcp: refusing to forward a request body with Content-Encoding "+enc+
				" because it cannot be inspected; send it uncompressed or as gzip, or start nullwire-mcp with -allow-uninspectable",
				http.StatusUnsupportedMediaType)
			return
		}
	}
	outURL, reverse, status, err := a.resolveUpstream(r)
	if err != nil {
		http.Error(w, "nullwire-mcp: "+err.Error(), status)
		return
	}
	reqCap := &capBuffer{max: maxReqCapture}
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
	// Response shield: never ask the server for an encoding NullWire cannot read.
	restrictAcceptEncoding(outReq.Header, r.Header)
	upgrade := isUpgradeRequest(r.Header)
	if upgrade {
		outReq.Header.Set("Connection", "Upgrade")
		outReq.Header.Set("Upgrade", r.Header.Get("Upgrade"))
		if strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
			// Extensions such as permessage-deflate compress the frames, which
			// would make them unreadable. Dropping the offer is always legal:
			// the server then simply sends uncompressed frames.
			outReq.Header.Del("Sec-WebSocket-Extensions")
		}
	}
	if _, ok := outReq.Header["User-Agent"]; !ok {
		outReq.Header["User-Agent"] = []string{""}
	}
	flow := rawFlow{started: start, method: r.Method, url: outURL.String(), reqHeaders: r.Header.Clone()}
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
		isWS := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
		flow.reqBody = reqCap.Bytes()
		a.handleUpgrade(w, resp, flow, isWS)
		return
	}
	respCap := &capBuffer{max: maxRespCapture}
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
func (a *App) dial(ctx context.Context, addr string) (net.Conn, error) {
	if a.transport != nil && a.transport.DialContext != nil {
		return a.transport.DialContext(ctx, "tcp", addr)
	}
	return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", addr)
}

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

func splice(client, upstream io.ReadWriteCloser, idle time.Duration, pre []byte) (toUpstream, toClient int64) {
	var sent, recv, last atomic.Int64
	last.Store(time.Now().UnixNano())
	closeBoth := func() { _ = client.Close(); _ = upstream.Close() }
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
						_ = cw.CloseWrite()
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
	flow := rawFlow{started: start, method: http.MethodConnect, url: target, reqHeaders: r.Header.Clone(), respHeaders: http.Header{}}
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

func (a *App) handleUpgrade(w http.ResponseWriter, resp *http.Response, flow rawFlow, isWS bool) {
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
	for k, vs := range resp.Header {
		switch strings.ToLower(k) {
		case "content-length", "transfer-encoding", "trailer":
			continue
		}
		for _, v := range vs {
			head.WriteString(k)
			head.WriteString(": ")
			head.WriteString(v)
			head.WriteString("\r\n")
		}
	}
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

	var clientRWC io.ReadWriteCloser = client
	var upstreamRWC io.ReadWriteCloser = rwc
	var wsUp, wsDown *wsCollector
	if isWS {
		// Read-only taps: every byte is forwarded untouched and a copy is
		// parsed for capture. client->server frames are what the client sends.
		wsUp = newWSCollector(maxReqBody + scrubWindow)
		wsDown = newWSCollector(maxRespBody + scrubWindow)
		upParser := newWSParser(wsUp.add)
		downParser := newWSParser(wsDown.add)
		clientRWC = &tapRWC{rwc: client, onRead: upParser.Feed}
		upstreamRWC = &tapRWC{rwc: rwc, onRead: downParser.Feed}
		if len(pre) > 0 {
			upParser.Feed(pre)
		}
	}

	sent, recv := splice(clientRWC, upstreamRWC, a.idle(), pre)

	flow.status = http.StatusSwitchingProtocols
	flow.respHeaders = resp.Header.Clone()
	flow.latencyMs = time.Since(flow.started).Milliseconds()
	note := fmt.Sprintf("upgraded connection (%s): %d B client->upstream, %d B upstream->client", resp.Header.Get("Upgrade"), sent, recv)
	if isWS {
		flow.reqBody = wsUp.Bytes()
		flow.respBody = wsDown.Bytes()
		note += fmt.Sprintf("; WebSocket text messages are captured and scrubbed when the connection closes (client->server: %s; server->client: %s); live frames are forwarded unmodified", wsUp.Summary(), wsDown.Summary())
	} else {
		note += "; frames not inspected or stored"
	}
	flow.note = note
	go a.capture(flow)
}

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
			return nil, fmt.Errorf("-dns: %q is not an IP address", s)
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

func termuxCAPaths() []string {
	var out []string
	if p := os.Getenv("PREFIX"); p != "" {
		out = append(out, p+"/etc/tls/cert.pem", p+"/etc/ssl/certs/ca-certificates.crt")
	}
	return append(out, "/data/data/com.termux/files/usr/etc/tls/cert.pem", "/system/etc/security/cacerts")
}

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

func onTermux() bool {
	return os.Getenv("TERMUX_VERSION") != "" || strings.Contains(os.Getenv("PREFIX"), "com.termux")
}

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

func decodableEncoding(ce string) bool {
	switch strings.ToLower(strings.TrimSpace(ce)) {
	case "gzip", "x-gzip", "deflate":
		return true
	}
	return false
}

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
			rd = flate.NewReader(bytes.NewReader(b))
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

func (a *App) capture(f rawFlow) {
	defer func() { _ = recover() }()
	for _, sub := range a.ignoreURLSubstrings {
		if sub != "" && strings.Contains(f.url, sub) {
			return
		}
	}

	total := 0
	note := f.note

	u, n := a.scrub.ScrubText(f.url)
	total += n
	rh, n := a.scrub.ScrubHeaders(f.reqHeaders)
	total += n

	rawReqBody := bodyText(f.reqHeaders, f.reqBody)
	if ct := f.reqHeaders.Get("Content-Type"); strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "multipart/") &&
		!strings.HasPrefix(rawReqBody, "[encoded body omitted") {
		rawReqBody = a.scrubMultipart(ct, []byte(rawReqBody))
	}
	rawRespBody := bodyText(f.respHeaders, f.respBody)
	// Protobuf and gRPC bodies are binary: storing their bytes helps nobody and
	// cannot be scrubbed, so only their size is recorded.
	if len(f.reqBody) > 0 && isProtobufContentType(f.reqHeaders.Get("Content-Type")) {
		rawReqBody = fmt.Sprintf("[protobuf/gRPC body not captured: %d bytes]", len(f.reqBody))
		note += " Protobuf/gRPC request body not captured (binary)."
	}
	if len(f.respBody) > 0 && isProtobufContentType(f.respHeaders.Get("Content-Type")) {
		rawRespBody = fmt.Sprintf("[protobuf/gRPC body not captured: %d bytes]", len(f.respBody))
		note += " Protobuf/gRPC response body not captured (binary)."
	}

	if strings.HasPrefix(rawReqBody, "[encoded body omitted") {
		note += " ⚠️ WARNING: Request body encoded (Brotli/Zstd), not inspected."
	}
	if strings.HasPrefix(rawRespBody, "[encoded body omitted") {
		note += " ⚠️ WARNING: Response body encoded (Brotli/Zstd), not inspected."
	}

	if len(f.reqBody) >= maxReqCapture || len(f.respBody) >= maxRespCapture {
		note += " ⚠️ WARNING: Payload exceeded memory limits; truncated before full inspection."
	}

	rawReqBody = truncate(rawReqBody, maxReqBody+scrubWindow)
	rawRespBody = truncate(rawRespBody, maxRespBody+scrubWindow)

	rb, n := a.scrub.ScrubText(rawReqBody)
	total += n
	ph, n := a.scrub.ScrubHeaders(f.respHeaders)
	total += n
	pb, n := a.scrub.ScrubText(rawRespBody)
	total += n

	a.ring.Push(FlowEntry{
		Timestamp: f.started.UTC().Format(time.RFC3339), Method: f.method, URL: u,
		RequestHeaders: rh, RequestBody: truncate(rb, maxReqBody),
		StatusCode: f.status, ResponseHeaders: ph, ResponseBody: truncate(pb, maxRespBody),
		LatencyMs: f.latencyMs, RedactionCount: total, Note: strings.TrimSpace(note),
	})
	a.Bar()
}

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

func (a *App) writeFrame(resp rpcResponse) {
	resp.JSONRPC = "2.0"
	line, err := marshalJSON(resp, false)
	if err != nil {
		line = `{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"internal error: cannot encode response"}}`
	}
	a.stdoutMu.Lock()
	defer a.stdoutMu.Unlock()
	_, _ = os.Stdout.Write([]byte(line + "\n"))
}

func (a *App) writeBatch(resps []rpcResponse) {
	for i := range resps {
		resps[i].JSONRPC = "2.0"
	}
	line, err := marshalJSON(resps, false)
	if err != nil {
		line = `{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"internal error: cannot encode response"}}`
	}
	a.stdoutMu.Lock()
	defer a.stdoutMu.Unlock()
	_, _ = os.Stdout.Write([]byte(line + "\n"))
}

func (a *App) writeError(id json.RawMessage, code int, msg string) {
	a.writeFrame(rpcResponse{ID: id, Error: &rpcError{Code: code, Message: msg}})
}

func toolResult(text string, isErr bool) map[string]any {
	return map[string]any{"resultType": "complete", "content": []any{map[string]any{"type": "text", "text": text}}, "isError": isErr}
}

func isEmptyArgs(raw json.RawMessage) bool {
	t := strings.TrimSpace(string(raw))
	return t == "" || t == "null"
}

func toolDefinitions() []any {
	return []any{
		map[string]any{
			"name": "inspect_traffic", "description": "Returns recent scrubbed HTTP/WS flows.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"limit":      map[string]any{"type": "integer", "default": 10, "minimum": 1, "maximum": ringCapacity},
					"method":     map[string]any{"type": "string"},
					"url_filter": map[string]any{"type": "string"},
				},
				"additionalProperties": false,
			},
		},
		map[string]any{
			"name": "export_sanitized_curl", "description": "Rebuilds a curl command with env placeholders.",
			"inputSchema": map[string]any{
				"type": "object", "properties": map[string]any{"flow_id": map[string]any{"type": "integer", "minimum": 1}},
				"required": []any{"flow_id"}, "additionalProperties": false,
			},
		},
		map[string]any{
			"name": "clear_ram_buffer", "description": "Wipes all 50 slots and resets counters.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false},
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
		"ring_size": a.ring.Len(), "ring_capacity": ringCapacity, "returned": len(flows),
		"scrubbed_totals": map[string]uint64{"tokens": a.scrub.Tokens.Load(), "cookies": a.scrub.Cookies.Load(), "ips": a.scrub.IPs.Load()},
		"flows":           flows,
	}
	text, err := marshalJSON(payload, true)
	if err != nil {
		return toolResult("failed to encode flows: "+err.Error(), true)
	}
	return toolResult(text, false)
}

var reTag = regexp.MustCompile(`\[REDACTED_(TOKEN|COOKIE|IP|KEY)#[0-9a-f]{6}\]`)

func envFor(kind string) string {
	switch kind {
	case "COOKIE":
		return "NULLWIRE_COOKIE"
	case "IP":
		return "NULLWIRE_IP"
	case "KEY":
		return "NULLWIRE_PRIVATE_KEY"
	default:
		return "NULLWIRE_AUTH_TOKEN"
	}
}

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

var curlSkipHeaders = map[string]bool{"host": true, "content-length": true, "connection": true, "proxy-connection": true, "proxy-authorization": true, "accept-encoding": true, "keep-alive": true, "transfer-encoding": true, "te": true, "trailer": true, "upgrade": true}

func buildCurl(e FlowEntry) string {
	if strings.EqualFold(e.Method, http.MethodConnect) {
		return fmt.Sprintf("# Flow %d was a blind CONNECT tunnel.\n", e.ID)
	}
	names := make([]string, 0, len(e.RequestHeaders))
	for k := range e.RequestHeaders {
		lk := strings.ToLower(k)
		if curlSkipHeaders[lk] {
			continue
		}
		if lk == "content-encoding" && decodableEncoding(e.RequestHeaders[k]) {
			continue
		}
		names = append(names, k)
	}
	sortStrings(names)
	body := e.RequestBody
	if strings.HasSuffix(body, truncMarker) {
		body = strings.TrimSuffix(body, truncMarker)
	}
	if strings.HasPrefix(body, "[encoded body omitted") {
		body = ""
	}
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
	b.WriteString("# Replay of flow " + fmt.Sprint(e.ID) + "\n")
	if len(legend) > 0 {
		b.WriteString("# Set environment variables first:\n")
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
	entry, ok := a.ring.GetByID(uint64(*in.FlowID))
	if !ok {
		return toolResult("flow not in RAM ring buffer", true)
	}
	return toolResult(buildCurl(entry), false)
}

func (a *App) toolClear() map[string]any {
	a.ring.Clear()
	a.scrub.ResetCounters()
	a.Bar()
	return toolResult("RAM ring buffer wiped and scrub counters reset.", false)
}

func (a *App) dispatchTo(req rpcRequest) *rpcResponse {
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
		return &rpcResponse{ID: id, Result: map[string]any{"protocolVersion": version, "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": serverName, "version": serverVersion}}}
	case "server/discover":
		return &rpcResponse{ID: id, Result: map[string]any{"resultType": "complete", "protocolVersions": []any{"2026-07-28", "2025-11-25", "2024-11-05"}, "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": serverName, "version": serverVersion}}}
	case "ping":
		return &rpcResponse{ID: id, Result: map[string]any{"resultType": "complete"}}
	case "tools/list":
		return &rpcResponse{ID: id, Result: map[string]any{"resultType": "complete", "ttlMs": 300000, "cacheScope": "global", "tools": toolDefinitions()}}
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
			return &rpcResponse{ID: id, Error: &rpcError{Code: -32602, Message: "invalid params"}}
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
			return &rpcResponse{ID: id, Error: &rpcError{Code: -32602, Message: "unknown tool"}}
		}
		return &rpcResponse{ID: id, Result: result}
	default:
		return &rpcResponse{ID: id, Error: &rpcError{Code: -32601, Message: "method not found"}}
	}
}

func (a *App) safeDispatch(req rpcRequest) (resp *rpcResponse) {
	defer func() {
		if rec := recover(); rec != nil {
			a.Logf("panic: %v", rec)
			resp = &rpcResponse{ID: req.ID, Error: &rpcError{Code: -32603, Message: "internal error"}}
		}
	}()
	return a.dispatchTo(req)
}

func (a *App) handleLine(line []byte) {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 {
		return
	}
	if trimmed[0] == '[' {
		a.handleBatch(trimmed)
		return
	}
	var req rpcRequest
	if err := json.Unmarshal(trimmed, &req); err != nil {
		a.writeError(nil, -32700, "parse error")
		return
	}
	if len(req.ID) == 0 {
		return
	}
	if string(req.ID) == "null" && strings.HasPrefix(req.Method, "notifications/") {
		return
	}
	if req.Method == "" {
		a.writeError(req.ID, -32600, "invalid request")
		return
	}
	if resp := a.safeDispatch(req); resp != nil {
		a.writeFrame(*resp)
	}
}

func (a *App) handleBatch(line []byte) {
	var rawReqs []json.RawMessage
	if err := json.Unmarshal(line, &rawReqs); err != nil {
		a.writeError(nil, -32700, "parse error")
		return
	}
	if len(rawReqs) == 0 {
		a.writeError(nil, -32600, "empty batch")
		return
	}

	responses := make([]rpcResponse, 0, len(rawReqs))
	for _, raw := range rawReqs {
		var req rpcRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			responses = append(responses, rpcResponse{
				ID:    nil,
				Error: &rpcError{Code: -32600, Message: "invalid request"},
			})
			continue
		}
		if len(req.ID) == 0 || (string(req.ID) == "null" && strings.HasPrefix(req.Method, "notifications/")) {
			continue
		}
		if req.Method == "" {
			responses = append(responses, rpcResponse{ID: req.ID, Error: &rpcError{Code: -32600, Message: "missing method"}})
			continue
		}
		if resp := a.safeDispatch(req); resp != nil {
			responses = append(responses, *resp)
		}
	}
	if len(responses) == 0 {
		return
	}
	a.writeBatch(responses)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "\r\033[K"+format+"\n", args...)
	os.Exit(1)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "scan" {
		os.Exit(runScan(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "protect" {
		os.Exit(runProtect(os.Args[2:]))
	}

	port := flag.Int("port", 8080, "TCP port for the diagnostic proxy (always bound to 127.0.0.1)")
	target := flag.String("target", "", "upstream base URL(s)")
	cacert := flag.String("cacert", "", "extra CA certificates")
	dnsSpec := flag.String("dns", "auto", "upstream DNS")
	secretsConfig := flag.String("secrets-config", "", "path to -secrets-config JSON")
	scrubHeaders := flag.String("scrub-headers", "", "extra sensitive headers")
	allowUninspectable := flag.Bool("allow-uninspectable", false, "forward request bodies whose Content-Encoding (br, zstd, ...) cannot be inspected; by default they are refused with 415")
	flag.Parse()

	if *port < 0 || *port > 65535 {
		fatalf("nullwire-mcp: -port must be between 0 and 65535")
	}
	cfg, err := loadSecretsConfig(*secretsConfig)
	if err != nil {
		fatalf("nullwire-mcp: %v", err)
	}
	for _, h := range strings.Split(*scrubHeaders, ",") {
		if h = strings.TrimSpace(h); h != "" {
			cfg.SensitiveHeaders = append(cfg.SensitiveHeaders, h)
		}
	}
	scrub, err := NewScrubberWithConfig(cfg)
	if err != nil {
		fatalf("nullwire-mcp: %v", err)
	}

	var dnsServers []string
	var dnsNotice string
	switch spec := strings.ToLower(strings.TrimSpace(*dnsSpec)); spec {
	case "system":
	case "", "auto":
		if onTermux() {
			dnsServers = defaultAndroidDNS
			dnsNotice = "Termux/Android detected: using 1.1.1.1/9.9.9.9"
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
		ring: NewRingBuffer(), scrub: scrub, ignoreURLSubstrings: cfg.IgnoreURLSubstrings, allowUninspectable: *allowUninspectable,
		transport: &http.Transport{Proxy: nil, DisableCompression: true, MaxIdleConns: 32, IdleConnTimeout: 60 * time.Second, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 120 * time.Second, DialContext: dialer.DialContext, TLSClientConfig: tlsCfg},
	}
	if *target != "" {
		def, named, err := parseTargets(*target)
		if err != nil {
			fatalf("nullwire-mcp: -target: %v", err)
		}
		app.target = def
		app.upstreams = named
	}

	ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		fatalf("nullwire-mcp: cannot listen: %v", err)
	}
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok || !tcpAddr.IP.IsLoopback() {
		ln.Close()
		fatalf("nullwire-mcp: refusing to run on non-loopback")
	}
	app.port = tcpAddr.Port

	srv := &http.Server{Handler: app, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			app.Logf("proxy server stopped: %v", err)
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigs
		app.Logf("signal received; wiping RAM")
		app.ring.Clear()
		_ = srv.Close()
		os.Exit(0)
	}()

	app.Bar()
	if dnsNotice != "" {
		app.Logf("%s", dnsNotice)
	}
	if caSource != "" {
		app.Logf("TLS roots: %s", caSource)
	}
	app.Logf("MCP stdio server ready; proxy listening on 127.0.0.1:%d", app.port)

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
	app.Logf("stdin closed; wiping RAM")
	app.ring.Clear()
	_ = srv.Close()
}