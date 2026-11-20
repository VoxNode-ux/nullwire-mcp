// nullwire-mcp: a zero-dependency, RAM-only DLP diagnostic HTTP proxy and
// Model Context Protocol (MCP) server over stdio.
package app

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
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
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/VoxNode-ux/nullwire-mcp/internal/cliio"
	"github.com/VoxNode-ux/nullwire-mcp/internal/install"
	"github.com/VoxNode-ux/nullwire-mcp/internal/protect"
	"github.com/VoxNode-ux/nullwire-mcp/internal/scan"
	"github.com/VoxNode-ux/nullwire-mcp/internal/vendors"
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

	// Header and query values are single short values, so the randomness
	// check looks at much longer runs there than in free-text bodies.
	entropyMaxLenWide    = 2048
	entropyHexWebhookMin = 2.0
	strictFieldMax       = 256
	strictFieldMaxWide   = 2048
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

// Push stores entry and returns the ID it was given.
func (r *RingBuffer) Push(entry FlowEntry) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry.ID = r.nextID
	r.nextID++
	r.slots[r.next] = entry
	r.next = (r.next + 1) % ringCapacity
	if r.size < ringCapacity {
		r.size++
	}
	return entry.ID
}

// Update changes the entry with the given ID in place and reports whether it
// was found. It does nothing, and returns false, when the entry has already
// been pushed out of the buffer (or the buffer was cleared).
func (r *RingBuffer) Update(id uint64, fn func(*FlowEntry)) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := 0; i < r.size; i++ {
		idx := (r.next - 1 - i + 2*ringCapacity) % ringCapacity
		if r.slots[idx].ID == id {
			fn(&r.slots[idx])
			r.slots[idx].ID = id // fn cannot move an entry to another ID
			return true
		}
	}
	return false
}

func (r *RingBuffer) Len() int {
	if r == nil {
		return 0
	}
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
	clear(r.slots[:])
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
	IgnoreFields        []string       `json:"ignore_fields"`   // body fields whose value is left as it is
	IgnorePatterns      []string       `json:"ignore_patterns"` // body text matching one of these is left alone
	CustomVendors       []VendorConfig `json:"custom_vendors"`
	ExtraRegexPatterns  []ExtraPattern `json:"extra_regex_patterns"`

	// Host egress controls: exact hosts, *.domain wildcards, IPs and CIDRs.
	// blocked always beats allowed; a non-empty allowed list denies the rest.
	AllowedUpstreamHosts []string `json:"allowed_upstream_hosts"`
	BlockedUpstreamHosts []string `json:"blocked_upstream_hosts"`

	// Built-in upstream address blocks. Cloud metadata (169.254.0.0/16,
	// fd00:ec2::254) is blocked unless allow_metadata_upstream is true; CGNAT
	// (100.64.0.0/10) and IPv6 link-local (fe80::/10) are blocked only when
	// asked for, so Tailscale and local networks work by default.
	AllowMetadataUpstream  bool `json:"allow_metadata_upstream"`
	BlockCGNATUpstream     bool `json:"block_cgnat_upstream"`
	BlockLinkLocalUpstream bool `json:"block_link_local_upstream"`

	// Presets switches on compliance redaction: pci-dss, hipaa, gdpr or all.
	Presets []string `json:"presets"`
}

type ExtraPattern struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
}

func loadSecretsConfig(path string) (*SecretsConfig, error) {
	if path == "" {
		return &SecretsConfig{}, nil
	}
	raw, err := cliio.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("-secrets-config %s: %v", path, err)
	}
	return parseSecretsConfig(path, raw)
}

// parseSecretsConfig validates the bytes of a -secrets-config file. A signed
// policy pack is verified on these same bytes before they get here.
func parseSecretsConfig(path string, raw []byte) (*SecretsConfig, error) {
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
	if _, err := newAllowlist(c.IgnoreFields, c.IgnorePatterns); err != nil {
		return nil, fmt.Errorf("-secrets-config %s: %v", path, err)
	}
	for i, v := range c.CustomVendors {
		if v.Pattern != "" {
			if _, err := regexp.Compile(v.Pattern); err != nil {
				return nil, fmt.Errorf("-secrets-config %s: custom_vendors[%d] (%q): %v", path, i, v.Name, err)
			}
		}
	}
	if _, err := newEgressPolicy(c.AllowedUpstreamHosts, c.BlockedUpstreamHosts); err != nil {
		return nil, fmt.Errorf("-secrets-config %s: %v", path, err)
	}
	if _, err := normalizePresets(c.Presets); err != nil {
		return nil, fmt.Errorf("-secrets-config %s: presets: %v", path, err)
	}
	return &c, nil
}

type Scrubber struct {
	nonce          []byte
	taint          *taintRing // keyed hashes of secrets redacted earlier in this run
	extraSensitive map[string]bool
	ignoreHeaders  map[string]bool
	extraPatterns  []*regexp.Regexp
	vendorGate     *lazyVendorGate // Aho-Corasick pre-check over every prefix (run on lower-cased text); built on first use
	vendorRules    []vendorRule // strong, weak, DSN and custom prefix rules
	allow          *allowlist   // body exemptions from the user's config; nil when none are set
	presets        presetSet    // -preset: pci-dss, hipaa, gdpr (all off by default)

	reBearer          *lazyRegexp
	reSensitiveHeader *lazyRegexp
	reJWT             *lazyRegexp
	reAPIKey          *lazyRegexp
	reJSONSecret      *lazyRegexp
	reQuerySecret     *lazyRegexp
	reUserInfo        *lazyRegexp
	reIPv4            *lazyRegexp
	rePEM             *lazyRegexp
	reXML             *lazyRegexp
	reJSONSecretArr   *lazyRegexp

	// Counters are pointers so detached() can give a live refresh its own set.
	Tokens  *atomic.Uint64
	Cookies *atomic.Uint64
	IPs     *atomic.Uint64
}

// detached returns a view of s that shares every rule and the taint ring but
// counts into counters of its own. Live SSE/WebSocket refreshes rebuild the
// same entry every ~500 ms; they use a detached view so the global totals are
// raised once, by the final capture, and not on every refresh.
func (s *Scrubber) detached() *Scrubber {
	c := *s
	c.Tokens, c.Cookies, c.IPs = new(atomic.Uint64), new(atomic.Uint64), new(atomic.Uint64)
	return &c
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
	for _, h := range cloudSensitiveHeaders {
		extra[h] = true
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
		{vendors.DefaultVendorPrefixes, vendorTokenClass, 16, false},
		{vendors.DefaultDollarVendorPrefixes, vendorDollarTokenClass, 16, false},
		{vendors.DefaultWeakVendorPrefixes, vendorTokenClass, 20, true},
		{vendors.DefaultDSNPrefixes, vendorDSNClass, 8, false},
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

	allow, err := newAllowlist(cfg.IgnoreFields, cfg.IgnorePatterns)
	if err != nil {
		return nil, fmt.Errorf("secrets config: %v", err)
	}

	pnames, err := normalizePresets(cfg.Presets)
	if err != nil {
		return nil, fmt.Errorf("secrets config: presets: %v", err)
	}

	return &Scrubber{
		Tokens:         new(atomic.Uint64),
		Cookies:        new(atomic.Uint64),
		IPs:            new(atomic.Uint64),
		nonce:          nonce,
		taint:          newTaintRing(nonce),
		allow:          allow,
		presets:        newPresetSet(pnames),
		extraSensitive: extra,
		ignoreHeaders:  ignore,
		extraPatterns:  extras,
		vendorGate:     lazyVendors(gate),
		vendorRules:    rules,
		// The DLP regular expressions are shared and compiled on first use (see
		// lazyinit.go), so building a Scrubber compiles none of them.
		reBearer:          reBearerShared,
		reSensitiveHeader: reSensitiveHeaderShared,
		reJWT:             reJWTShared,
		reAPIKey:          reAPIKeyShared,
		reJSONSecret:      reJSONSecretShared,
		reQuerySecret:     reQuerySecretShared,
		reUserInfo:        reUserInfoShared,
		reIPv4:            reIPv4Shared,
		rePEM:             rePEMShared,
		reXML:             reXMLShared,
		reJSONSecretArr:   reJSONSecretArrShared,
	}, nil
}

// tag returns a short label for a redacted value. It is a keyed hash (HMAC-SHA256 with a random per-run key), cut to six hex characters,
// so the same value gets the same label within one run and the label cannot be used to guess the value. It is never stored.
func (s *Scrubber) tag(kind, raw string) string {
	if s.taint != nil && (kind == "TOKEN" || kind == "KEY") {
		s.taint.add(raw)
	}
	h := hmac.New(sha256.New, s.nonce)
	h.Write([]byte(raw))
	return "[REDACTED_" + kind + "#" + hex.EncodeToString(h.Sum(nil))[:6] + "]"
}

func (s *Scrubber) ResetCounters() {
	s.Tokens.Store(0)
	s.Cookies.Store(0)
	s.IPs.Store(0)
	s.taint.clear()
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
	// Like vendorTokenClass, plus "$" for tokens such as access_token$production$<id>$<hex>.
	vendorDollarTokenClass = `[A-Za-z0-9._~+/=$-]`
	vendorDSNClass   = `[A-Za-z0-9._~:/?#\[\]@!$&*+=%-]`
)

// vendorRule redacts "<prefix><at least min class characters>". A weak rule
// only redacts when the part after the prefix also looks like a key.
type vendorRule struct {
	re       *lazyRegexp
	prefixes []string
	weak     bool
}

func buildVendorRule(prefixes []string, class string, minLen int, weak bool) (vendorRule, bool) {
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
	fmt.Fprintf(&b, "{%d,}", minLen)
	return vendorRule{re: lazyRe(b.String()), prefixes: prefixes, weak: weak}, true
}

// weakVendorMatchOK checks the text after the matched prefix.
func weakVendorMatchOK(m string, prefixes []string) bool {
	if validatedSecret(m) { // a format validator affirms it: promote, never demote
		return true
	}
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
func (s *Scrubber) ScrubText(in string) (string, int) { return s.ScrubTextIn(in, ContextBody) }

// ScrubTextIn is ScrubText for text whose origin is known. Header and query
// contexts apply stricter rules than ContextBody (see ScrubContext).
func (s *Scrubber) ScrubTextIn(in string, ctx ScrubContext) (string, int) {
	o := scrubOpts{allowB64: true, ctx: ctx}
	if s.allow != nil && ctx == ContextBody {
		return s.scrubWithAllowlist(in, o)
	}
	return s.scrubLayersOpts(in, o)
}

// scrubLayers runs every rule. Base64 decoding is switched off for text that
// was itself decoded from base64, so it never nests.
func (s *Scrubber) scrubLayers(in string, allowB64 bool) (string, int) {
	return s.scrubLayersOpts(in, scrubOpts{allowB64: allowB64})
}

func (s *Scrubber) scrubLayersOpts(in string, o scrubOpts) (string, int) {
	if in == "" {
		return in, 0
	}
	// Stage 1: secrets hidden by URL-encoding or escaped quotes are replaced
	// first, on the original text; it allocates only when such escapes exist.
	count := 0
	{
		var n int
		in, n = s.scrubUnwrapped(in, o.ctx)
		count += n
	}
	// Stage 2: the deterministic rules (keys, secret fields, credentials, vendor
	// formats, your own patterns, IP addresses and base64).
	// One zero-allocation pass answers every pre-check below.
	gm := scrubGate.Match(in)

	preJWT := gm&gateJWT != 0 && strings.Contains(in, "eyJ")
	preVendor := s.vendorGate.Match(in)
	preAPIKey := gm&gateAPIKey != 0
	preUserInfo := strings.Contains(in, "://") && strings.Contains(in, "@")
	preBearer := gm&gateBearer != 0
	preSecretKey := gm&gateSecretKey != 0

	out := in

	if strings.Contains(in, "-----BEGIN") {
		out = s.rePEM.ReplaceAllStringFunc(out, func(m string) string {
			count++
			s.Tokens.Add(1)
			return s.tag("KEY", m)
		})
	}

	// Structural pass: on a complete JSON document, a string under a
	// secret-looking key is redacted by the key that owns it. Anything that is
	// not a whole JSON document is left to the rules below.
	out = s.scrubJSONTree(out, &count)

	if preSecretKey {
		// gateSecretKey is coarse; secretKeyGate says which of the three regexps
		// below can match at all (see gatemask.go).
		sk := secretKeyGate.Match(in)
		if sk&jsonKeyBit != 0 {
			out = s.scrubJSONSecretFields(out, &count)
			out = s.scrubJSONSecretArrays(out, &count)
		}
		if sk&queryKeyBit != 0 {
			out = s.scrubQuerySecrets(out, &count)
		}
	}
	if gm&gateXML != 0 && (strings.Contains(in, "<") || strings.Contains(in, "&lt;")) {
		// Tree pass first: it handles CDATA, nesting, benign leaves and entity-escaped markup.
		// The regexp then only mops up what the tree could not follow (e.g. malformed documents).
		out = s.scrubXMLTree(out, &count)
		out = s.scrubXMLSecrets(out, &count)
	}
	if preUserInfo {
		out = s.reUserInfo.ReplaceAllStringFunc(out, func(m string) string {
			g := s.reUserInfo.FindStringSubmatch(m)
			if g == nil {
				return m
			}
			if strings.HasPrefix(g[2], "[REDACTED_") || isAllowMarkOnly(g[2]) || isPlaceholderValue(g[2]) {
				return m
			}
			// A DSN whose password is only template words or <angle brackets>
			// is documentation, not a credential. A password with an
			// explicit secret prefix is never treated that way.
			if !hasStructuredPrefix(g[2]) && dsnPasswordIsPlaceholder("x"+m+"h") {
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
			if g == nil || proseAfterScheme(g[1], g[2], o.ctx) {
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
				// A match that already holds a redaction (a DSN whose password reUserInfo
				// tagged) was handled by an earlier rule; redacting it again would
				// overwrite that tag and count it twice.
				if strings.Contains(m, "[REDACTED_") {
					// Already counted by reUserInfo: collapse the whole DSN (host and
					// path included) into one tag without counting it again.
					if strings.Contains(m, "://") {
						return s.tag("TOKEN", m)
					}
					return m
				}
				if vr.weak && !weakVendorMatchOK(m, vr.prefixes) {
					return m
				}
				// A DSN whose password is only template words is documentation.
				if strings.Contains(m, "://") && dsnMatchIsTemplate(m) {
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

	var nCloud int
	out, nCloud = s.scrubCloudSecrets(out, gm)
	count += nCloud

	var nStrict int
	out, nStrict = s.scrubStrictFieldsMax(out, o.strictMax())
	count += nStrict

	for _, re := range s.extraPatterns {
		out = re.ReplaceAllStringFunc(out, func(m string) string {
			count++
			s.Tokens.Add(1)
			return s.tag("TOKEN", m)
		})
	}

	var nTail int
	out, nTail = s.scrubTail(out, o.skipIP)
	count += nTail

	if s.presets.enabled() {
		var nPreset int
		out, nPreset = s.scrubPresets(out)
		count += nPreset
	}

	if o.allowB64 && hasBase64Run(out) {
		out = s.scrubBase64(out, &count)
	}
	if o.allowB64 && hasEncodedRun(out) {
		out = s.scrubEncodedText(out, &count)
	}

	// Stage 3: identity matching against earlier redactions, then the
	// randomness heuristics, which are guesses and so run last. Both are skipped
	// for exempt headers and allowlisted fields.
	if !o.skipEntropy {
		var nTaint int
		out, nTaint = s.scrubTainted(out)
		count += nTaint
		if o.ctx == ContextHeader || o.ctx == ContextQuery {
			var nHex int
			out, nHex = s.scrubHexSecrets(out)
			count += nHex
		}
		var nEntropy int
		out, nEntropy = s.scrubHighEntropyMax(out, o.entropyMax())
		count += nEntropy
	}
	return out, count
}

// scrubTail runs the last three rules of scrubLayersOpts: IPv6, IPv4 and
// payment-card numbers. Each sits behind a gate that is a necessary condition
// for the rule to match, so skipping it loses nothing. The gates read the text
// as it stands when its rule runs, and use the SIMD-backed strings.Count and
// strings.IndexByte where they can. TestScrubTailMatchesUngated holds this to
// the ungated rules.
func (s *Scrubber) scrubTail(out string, skipIP bool) (string, int) {
	count := 0
	if !skipIP && strings.Count(out, ":") >= 2 {
		var n6 int
		out, n6 = s.scrubIPv6(out)
		count += n6
	}
	if !skipIP && strings.IndexByte(out, '.') >= 0 && maybeIPv4(out) {
		out = replaceIPv4(s, out, &count)
	}
	if hasPANChain(out) {
		var nPAN int
		out, nPAN = s.scrubPANs(out)
		count += nPAN
	}
	return out, count
}

// scrubJSONSecretFields redacts the value of every "password": "..." style
// field. Split out of scrubLayersOpts so the regexp can sit behind its own gate.
func (s *Scrubber) scrubJSONSecretFields(out string, count *int) string {
	return s.reJSONSecret.ReplaceAllStringFunc(out, func(m string) string {
		g := s.reJSONSecret.FindStringSubmatch(m)
		if g == nil {
			return m
		}
		// Stage 1 may already have replaced this value with its own tag. Leave
		// that tag exactly as it is: tagging a tag corrupts it.
		if strings.HasPrefix(g[2], "[REDACTED_") || isAllowMarkOnly(g[2]) || isPlaceholderValue(g[2]) || benignBareKey(g[1], g[2]) {
			return m
		}
		*count++
		s.Tokens.Add(1)
		return g[1] + s.tag("TOKEN", g[2]) + g[3]
	})
}

// scrubQuerySecrets redacts the value of every ?token=... / &api_key=... style
// parameter.
func (s *Scrubber) scrubQuerySecrets(out string, count *int) string {
	return s.reQuerySecret.ReplaceAllStringFunc(out, func(m string) string {
		g := s.reQuerySecret.FindStringSubmatch(m)
		if g == nil {
			return m
		}
		if strings.HasPrefix(g[2], "[REDACTED_") || isAllowMarkOnly(g[2]) || isPlaceholderValue(g[2]) || benignBareKey(g[1], g[2]) {
			return m
		}
		*count++
		s.Tokens.Add(1)
		return g[1] + s.tag("TOKEN", g[2])
	})
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
	for j > 0 && (in[j-1] == ' ' || in[j-1] == '"' || in[j-1] == '\'' || in[j-1] == '\\') {
		j--
	}
	k := j
	for k > 0 && isKeyByte(in[k-1]) {
		k--
	}
	return in[k:j]
}

// nonSecretFields lists common API/DB/metadata field names that end in "key" or
// contain hints like "secret"/"token"/"api" without holding actual secrets.
// Adapted from Gitleaks' generic-api-key allowlist (MIT License, Zachary Rice).
var nonSecretFields = map[string]bool{
	"public_key": true, "public-key": true, "publickey": true,
	"primary_key": true, "primary-key": true, "primarykey": true,
	"foreign_key": true, "foreign-key": true, "foreignkey": true,
	"partition_key": true, "partition-key": true, "partitionkey": true,
	"sort_key": true, "sort-key": true, "sortkey": true,
	"schema_key": true, "schema-key": true,
	"bucket_key": true, "bucket-key": true,
	"idempotency_key": true, "idempotency-key": true, "idempotencykey": true,
	"cache_key": true, "cache-key": true, "cachekey": true,
	"key_id": true, "key-id": true, "keyid": true,
	"key_name": true, "key-name": true, "keyname": true,
	"key_alias": true, "key-alias": true,
	"key_type": true, "key-type": true,
	"key_size": true, "key-size": true,
	"key_length": true, "key-length": true,
	"secret_name": true, "secret-name": true,
	"secret_size": true, "secret-size": true,
	"secret_length": true, "secret-length": true,
	"api_id": true, "api-id": true,
	"api_name": true, "api-name": true,
	"api_version": true, "api-version": true,
	"api_endpoint": true, "api-endpoint": true,
	"api_url": true, "api-url": true,
	"token_endpoint": true, "token-endpoint": true,
	"token_url": true, "token-url": true,
	"token_uri": true, "token-uri": true,
	"credentials_id": true, "credentials-id": true,
	"credentials_url": true, "credentials-url": true,
	"credentials_endpoint": true, "credentials-endpoint": true,
	"withcredentials": true, "author": true,
	"monkey": true, "donkey": true, "turkey": true,
	"translation_key": true, "translation-key": true, "translationkey": true,
	"i18n_key": true, "i18n-key": true, "i18nkey": true,
	"react_key": true, "react-key": true, "reactkey": true,
	"token_type": true, "token-type": true, "tokentype": true,
	"token_scope": true, "token-scope": true, "tokenscope": true,
	"session_state": true, "session-state": true, "sessionstate": true,
	"signature_algorithm": true, "signature-algorithm": true, "signaturealgorithm": true,
	"password_policy": true, "password-policy": true, "passwordpolicy": true,
	"auth_method": true, "auth-method": true, "authmethod": true,
	"authorizer": true,
	"routing_key": true, "routing-key": true, "routingkey": true,
	"object_key": true, "object-key": true, "objectkey": true,
	"s3_key": true, "s3-key": true, "s3key": true,
	"shard_key": true, "shard-key": true, "shardkey": true,
	"project_key": true, "project-key": true, "projectkey": true,
	// Pagination cursors: opaque, but they page through results, not log in.
	"next_page_token": true, "next-page-token": true, "nextpagetoken": true,
	"page_token": true, "page-token": true, "pagetoken": true,
	"next_token": true, "next-token": true, "nexttoken": true,
	"continuation_token": true, "continuation-token": true, "continuationtoken": true,
	"pagination_token": true, "pagination-token": true, "paginationtoken": true,
}

func secretishKey(key string) bool {
	k := strings.ToLower(key)
	if k == "" || nonSecretFields[k] {
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

// isPlaceholderValue skips template expressions (${VAR}, ${{ secrets.X }},
// {{var}}, %VAR%) and repeated dummy masks ("******", "xxxxxx") so CI YAML,
// templates, and masked error messages remain debuggable.
// Adapted from Gitleaks' global allowlist (MIT License, Zachary Rice).
func isPlaceholderValue(s string) bool {
	t := strings.TrimSpace(s)
	if len(t) == 0 {
		return false
	}
	switch strings.ToLower(t) {
	case "true", "false", "null", "none", "undefined", "changeme", "changeit":
		return true
	}
	if (strings.HasPrefix(t, "${") && strings.HasSuffix(t, "}")) ||
		(strings.HasPrefix(t, "{{") && strings.HasSuffix(t, "}}")) ||
		(len(t) > 2 && t[0] == '%' && t[len(t)-1] == '%' && !strings.ContainsAny(t[1:len(t)-1], " \t%")) {
		return true
	}
	first := t[0]
	if first == '*' || first == 'x' || first == 'X' || first == '.' || first == '-' {
		for i := 1; i < len(t); i++ {
			if t[i] != first {
				return false
			}
		}
		return true
	}
	return false
}

// scrubStrictFields redacts the value of a secret-looking field (token, key,
// auth, session, ...) even when the value matches no known key shape. It only
// fires for 12-256 character values without spaces, slashes, dots or colons
// (so URLs, paths and timestamps are left alone), and never for a field whose
// name gives no hint: ordinary values like "model":"claude-opus-4-5" survive.

// scrubStrictFieldsMax is scrubStrictFields with a limit on the value length:
// 256 for bodies, 2048 for header and query contexts.

func (s *Scrubber) scrubStrictFieldsMax(in string, maxVal int) (string, int) {
	ranges := strictFieldRanges(in, maxVal)
	if len(ranges) == 0 {
		return in, 0
	}
	var b strings.Builder
	last := 0
	for _, r := range ranges {
		b.WriteString(in[last:r[0]])
		b.WriteString(s.tag("TOKEN", in[r[0]:r[1]]))
		s.Tokens.Add(1)
		last = r[1]
	}
	b.WriteString(in[last:])
	return b.String(), len(ranges)
}

// strictValueStop reports whether c ends an unquoted field value.
func strictValueStop(c byte) bool {
	switch c {
	case ' ', '"', '\'', ',', '\n', '\r', '\t', '}', ']', ')', '&', ';':
		return true
	}
	return false
}

// strictFieldRanges finds the [start, end) ranges of the values that
// scrubStrictFieldsMax redacts.
func strictFieldRanges(in string, maxVal int) [][2]int {
	if len(in) < 12 {
		return nil
	}
	var out [][2]int
	for i := 0; i < len(in); i++ {
		if in[i] != ':' && in[i] != '=' {
			continue
		}
		start := i + 1
		for start < len(in) {
			if c := in[start]; c == ' ' || c == '"' || c == '\'' {
				start++
			} else if c == '\\' && start+1 < len(in) && in[start+1] == '"' {
				start += 2 // escaped quote, as in {\"custom_key\":\"...\"}
			} else {
				break
			}
		}
		end := start
		for end < len(in) && !strictValueStop(in[end]) && (in[end] != '\\' || end+1 >= len(in) || in[end+1] != '"') {
			end++
		}
		if start < len(in) && ((in[start] == '%' && isPlaceholderValue(in[start:end])) || strings.HasPrefix(in[start:], "${") || strings.HasPrefix(in[start:], "{{")) {
			continue // template: the end scan would stop at its brace
		}
		if end-start < 12 || end-start > maxVal {
			continue
		}
		kb := keyBefore(in, i)
		if !secretishKey(kb) {
			continue
		}
		val := in[start:end]
		if strings.HasPrefix(val, "[REDACTED_") || hasAllowMark(val) || isPlaceholderValue(val) || strings.ContainsAny(val, "\\:") {
			continue
		}
		if strings.ContainsAny(val, "/.") && !strictSlashDotOK(val) && (!isSignatureKey(kb) || !signatureValueOK(val)) {
			continue
		}
		if !hasStructuredPrefix(val) && stage3Placeholder(val) {
			continue // YOUR_API_KEY_HERE style template, no explicit prefix
		}
		out = append(out, [2]int{start, end})
		i = end - 1
	}
	return out
}

var (
	reStrictDate    = lazyRe(`^\d{4}-\d{2}-\d{2}(?:[Tt][0-9:.+Zz-]*)?$`)
	reStrictVersion = lazyRe(`^[vV]?\d+(?:\.\d+)+(?:[-+][A-Za-z0-9.-]+)?$`)
	reStrictPath    = lazyRe(`^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+/?$`)
)

// isSignatureKey reports whether k names a signature field: sig, signature, x-amz-signature.
func isSignatureKey(k string) bool {
	k = strings.ToLower(k)
	return k == "sig" || k == "signature" || strings.HasSuffix(k, "_sig") || strings.HasSuffix(k, "-sig") ||
		strings.HasSuffix(k, "_signature") || strings.HasSuffix(k, "-signature")
}

// signatureValueOK reports whether v looks like a percent-encoded or base64 signature,
// as in an Azure SAS URL (?sv=...&sig=Ab%2Fc...%3D), whatever the mix of letters:
// only URL-safe and base64 characters, and either a %XX escape or a base64 "/", "+" or "=".
func signatureValueOK(v string) bool {
	if len(v) < 12 || strings.Contains(v, "://") || strings.HasPrefix(v, "/") {
		return false
	}
	special := false
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		case c == '%':
			if i+2 >= len(v) || !isHexByte(v[i+1]) || !isHexByte(v[i+2]) {
				return false
			}
			special = true
		case c == '/' || c == '+' || c == '=':
			special = true
		default:
			return false
		}
	}
	return special
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// isPlainPath reports whether v is a slash-separated path such as
// "Users/Alice/Desktop/file1.txt" or "Config/Prod2/App.json". Base64 keys with
// "+" or "=" never match reStrictPath; a base64 key whose only symbol is "/"
// does, so with upper case present every segment must also be word-like: at
// most one capital, and only as the first letter. Random base64 pieces such as
// "Zq8Xv3LmP0aTr9Yk" have several and stay candidates for redaction.
func isPlainPath(v string) bool {
	if strings.ContainsAny(v, "+=") || !reStrictPath.MatchString(v) {
		return false
	}
	for _, seg := range strings.Split(v, "/") {
		for i := 1; i < len(seg); i++ {
			if seg[i] >= 'A' && seg[i] <= 'Z' {
				return false
			}
		}
	}
	return true
}

// strictSlashDotOK reports whether a value that holds "/" or "." may still be
// a secret. Base64 signing and encryption keys use both characters; URLs,
// paths, ISO dates, versions and plain dotted names do not count.
func strictSlashDotOK(v string) bool {
	if strings.Contains(v, "://") || strings.HasPrefix(v, "//") || strings.HasPrefix(v, "/") || strings.HasPrefix(v, "~/") || strings.HasPrefix(v, "./") || strings.HasPrefix(v, "../") {
		return false
	}
	if reStrictDate.MatchString(v) || reStrictVersion.MatchString(v) || isPlainPath(v) {
		return false
	}
	var lower, upper, digit bool
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9':
			digit = true
		}
	}
	// A key mixes cases or letters and digits; "com.example.app" does not.
	return (lower && (upper || digit)) || (upper && digit)
}

func isEntropyCandidate(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-'
}

// isHexLike reports whether s is hex digits with at least one letter a-f. A
// run of only decimal digits is a number (timestamp, id), not a hex secret.
func isHexLike(s string) bool {
	hasLetter := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
		case (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'):
			hasLetter = true
		default:
			return false
		}
	}
	return hasLetter
}

// isAllDigits reports whether s is non-empty and holds only 0-9.
func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
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

// isHexUUID reports whether s is a canonical 8-4-4-4-12 UUID made only of hex digits.
func isHexUUID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// looksLikeTokenMax is looksLikeToken with a limit on the run length.
func looksLikeTokenMax(s string, maxLen int) bool {
	n := len(s)
	if n < entropyMinLen || n > maxLen {
		return false
	}

	// A validator that affirms the format promotes the candidate past every
	// penalty below. A heuristic-only candidate (no explicit prefix) made of
	// template words is a placeholder. A candidate WITH an explicit prefix is
	// never dropped by this test.
	if validatedSecret(s) {
		return true
	}
	if !hasStructuredPrefix(s) && stage3Placeholder(s) {
		return false
	}

	if isHexUUID(s) {
		return false
	}

	if benignResourceID(s) {
		return false
	}

	// A run of only decimal digits is a number (nanosecond timestamp, order or
	// account id). Digits alone score as random under the log-odds model, so
	// without this a 19-digit timestamp sits right at the threshold.
	if isAllDigits(s) {
		return false
	}
	if isHexLike(s) {
		return shannonEntropyBits(s) >= entropyHexMin
	}
	// Cheap rejections first: a lower-case run with no digit or capital (and
	// shorter than hasTokenSignalAutoLen) is prose or a path, and is dropped
	// here before any floating-point math. The entropy is only computed for
	// the branches that read it.
	if !hasTokenSignal(s) {
		return false
	}
	if useLogOdds {
		return tokenLogOdds(s) > 0
	}
	if vowelRatio(s) > entropyMaxVowel {
		return false
	}
	h := shannonEntropyBits(s)
	if n >= 32 {
		return h >= entropyLongMin
	}
	return h >= entropyShortMin
}

func (s *Scrubber) scrubHighEntropyMax(in string, maxLen int) (string, int) {
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

		// A hex value under sha=, digest=, commit= ... is an identifier, not a secret.
		if isHexLike(cand) && hexValueKeyIsIdentifier(in, i) {
			i = j
			continue
		}
		if !strings.Contains(cand, "REDACTED_") && looksLikeTokenMax(cand, maxLen) {
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

// identifierHexKeys name fields whose hex value is an identifier (a commit, a
// digest, a checksum), not a secret.
var identifierHexKeys = map[string]bool{
	"sha": true, "sha1": true, "sha256": true, "sha512": true, "md5": true,
	"digest": true, "commit": true, "commit_id": true, "commit_sha": true,
	"revision": true, "rev": true, "checksum": true, "etag": true,
	"hash": true, "tree": true, "parent": true, "git_sha": true, "image_id": true,
	"trace_id": true, "traceid": true, "request_id": true, "requestid": true,
	"correlation_id": true, "correlationid": true, "span_id": true, "spanid": true, "parent_id": true,
}

// hexValueKeyIsIdentifier reports whether the entropy candidate that starts at
// in[i] is the value of an identifier field such as sha=, digest: or "commit":.
func hexValueKeyIsIdentifier(in string, i int) bool {
	j := i
	for j > 0 && (in[j-1] == ' ' || in[j-1] == '"' || in[j-1] == '\'' || in[j-1] == '\\') {
		j--
	}
	if j == 0 || (in[j-1] != ':' && in[j-1] != '=') {
		return false
	}
	key := strings.ReplaceAll(strings.ToLower(keyBefore(in, j-1)), "-", "_")
	if key == "" || strings.Contains(key, "secret") || strings.Contains(key, "pass") || strings.Contains(key, "token") {
		return false
	}
	if identifierHexKeys[key] {
		return true
	}
	for _, suf := range []string{"_sha", "_sha1", "_sha256", "_digest", "_checksum", "_commit", "_hash", "_trace_id", "_request_id", "_correlation_id", "_span_id", "_parent_id"} {
		if strings.HasSuffix(key, suf) {
			return true
		}
	}
	return false
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
				v, n := s.scrubHeaderValue(lname, joined)
				out[name] = v
				count += n
			default:
				// Custom Authorization schemes ("ApiKey secret"): keep the scheme, tag only the credential,
				// so the taint ring stores the bare secret and not "scheme secret".
				if lname == "authorization" || lname == "proxy-authorization" {
					if i := strings.IndexByte(joined, ' '); i > 0 && strings.TrimSpace(joined[i+1:]) != "" {
						out[name] = joined[:i+1] + s.tag("TOKEN", strings.TrimSpace(joined[i+1:]))
						s.Tokens.Add(1)
						count++
						continue
					}
				}
				out[name] = s.tag("TOKEN", joined)
				s.Tokens.Add(1)
				count++
			}
			continue
		}
		v, n := s.scrubHeaderValue(lname, joined)
		out[name] = v
		count += n
	}
	return out, count
}

type App struct {
	ring                *RingBuffer
	scrub               *Scrubber
	egress              *egressPolicy   // -secrets-config allowed/blocked_upstream_hosts; nil means no policy
	disabledTools       map[string]bool // -disable-tools
	port                int
	target              *url.URL
	upstreams           map[string]*url.URL
	gwMap               map[string]*url.URL // -target-map: reached as /_gw/<name>/
	transport           *http.Transport
	h2cOnce             sync.Once
	h2c                 *http.Transport
	h1Once              sync.Once
	h1                  *http.Transport
	ignoreURLSubstrings []string
	finishing           sync.WaitGroup // background finishLive calls; tests wait on it
	tunnels             atomic.Int64
	tunnelIdle          time.Duration
	allowUninspectable  bool // forward request bodies whose Content-Encoding cannot be decoded
	maxBody             int  // -max-body: stored body size in bytes; 0 means the defaults
	wsDeflate           bool // -ws-deflate: keep permessage-deflate and decode it for capture
	listener            string // "" for the TCP loopback listener, "unix" for -listen
	sockPath            string // the -listen socket path, for the status bar
	tokenOn             bool   // -proxy-token: every request must carry the token
	tokenSum            [sha256.Size]byte
	att                 attestInfo // facts export_attestation reports
	barMu               sync.Mutex
	capQ                atomic.Pointer[capturePool] // nil until startCapture; see captureworker.go
	captureDropped      atomic.Int64                // flows wiped unrecorded because the capture queue was full
	barDirty            atomic.Bool                 // a redraw is wanted; the ticker draws it
	barTick             atomic.Bool                 // the ticker is running, so markBar only sets barDirty
	barStop             chan struct{}
	barWG               sync.WaitGroup
	barStopOnce         sync.Once
	stdoutMu            sync.Mutex
	stdout, stderr      io.Writer // nil means os.Stdout / os.Stderr (run() injects its own)
}

func (a *App) outW() io.Writer {
	if a.stdout != nil {
		return a.stdout
	}
	return os.Stdout
}

func (a *App) errW() io.Writer {
	if a.stderr != nil {
		return a.stderr
	}
	return os.Stderr
}

func (a *App) drawBar() {
	where := fmt.Sprintf("127.0.0.1:%d", a.port)
	if a.listener == "unix" {
		where = "unix socket"
	}
	fmt.Fprintf(a.errW(), "\r\033[K⚡ [NullWire-MCP] Proxy %s | RAM Ring: %d/%d | Scrubbed: %d Tokens, %d Cookies, %d IPs | Disk: 0B",
		where, a.ring.Len(), ringCapacity, a.scrub.Tokens.Load(), a.scrub.Cookies.Load(), a.scrub.IPs.Load())
}
func (a *App) Bar() { a.barMu.Lock(); defer a.barMu.Unlock(); a.drawBar() }
func (a *App) Logf(format string, args ...any) { a.barMu.Lock(); defer a.barMu.Unlock(); fmt.Fprintf(a.errW(), "\r\033[K"+format+"\n", args...); a.drawBar() }

type capBuffer struct {
	mu   sync.Mutex
	buf  []byte
	max  int
	done bool // release was called: later writes are dropped
	solo bool // only one goroutine ever touches it, so the mutex is skipped

	// full is set, under the lock, once buf holds max bytes. From then on Write
	// answers with one atomic load: no lock, no copy, no allocation, however
	// much more of the body goes by. truncated is set once a byte has actually
	// been dropped because of the cap.
	full      atomic.Bool
	truncated atomic.Bool
}

// capBufPool recycles the backing arrays of capBuffer. Every array in it is
// all zero: release clears what was written (the only part ever written)
// before the array goes back, so one request's bytes are never visible to the
// next.
var capBufPool = sync.Pool{New: func() any { b := make([]byte, 0, 8<<10); return &b }}

// capBufPoolMax is the largest array kept for reuse; bigger ones are zeroed
// and left to the garbage collector so one huge body does not pin memory.
const capBufPoolMax = 1 << 20

// newCapBuffer makes a capture buffer that several goroutines may touch (the
// request body is read by the transport's own goroutine). No array is taken
// from the pool until the first byte is written, so a request without a body
// costs nothing.
func newCapBuffer(limit int) *capBuffer { return &capBuffer{max: limit} }

// newSoloCapBuffer is newCapBuffer for a buffer used by one goroutine only.
func newSoloCapBuffer(limit int) *capBuffer { return &capBuffer{max: limit, solo: true} }

func (c *capBuffer) lock() {
	if !c.solo {
		c.mu.Lock()
	}
}

func (c *capBuffer) unlock() {
	if !c.solo {
		c.mu.Unlock()
	}
}

// release zeroes the bytes that were written and returns the array to the
// pool. Only buf[:len(buf)] was ever written, so clearing that is the same as
// clearing the whole array, without touching the unused tail. Bytes() hands
// out a copy, so flows already built are not affected. Safe to call twice and
// on a capBuffer that never held a byte.
func (c *capBuffer) release() {
	if c == nil { // a request without a body never made one
		return
	}
	c.lock()
	defer c.unlock()
	if c.done {
		return
	}
	c.done = true
	buf := c.buf
	c.buf = nil
	if cap(buf) == 0 {
		return
	}
	clear(buf)
	runtime.KeepAlive(buf)
	if cap(buf) <= capBufPoolMax {
		buf = buf[:0]
		capBufPool.Put(&buf)
	}
}

// Truncated reports that more bytes were written than the buffer holds, so the
// capture is a prefix of the body.
func (c *capBuffer) Truncated() bool { return c != nil && c.truncated.Load() }

func (c *capBuffer) Write(p []byte) (int, error) {
	// Capture limit already reached: swallow the rest of the body untouched.
	if c.full.Load() {
		if len(p) > 0 {
			c.truncated.Store(true)
		}
		return len(p), nil
	}
	c.lock()
	defer c.unlock()
	if c.done {
		return len(p), nil
	}
	room := c.max - len(c.buf)
	if room <= 0 {
		c.full.Store(true)
		if len(p) > 0 {
			c.truncated.Store(true)
		}
		return len(p), nil
	}
	q := p
	if len(q) > room {
		q = q[:room]
		c.truncated.Store(true)
	}
	if len(q) == 0 {
		return len(p), nil
	}
	if c.buf == nil {
		bp := capBufPool.Get().(*[]byte)
		c.buf = (*bp)[:0]
	}
	if need := len(c.buf) + len(q); need > cap(c.buf) {
		// Grow by hand so the array being left behind can be zeroed; append
		// would drop it with the captured bytes still in it.
		newCap := 2 * cap(c.buf)
		if newCap < need {
			newCap = need
		}
		nb := make([]byte, len(c.buf), newCap)
		copy(nb, c.buf)
		clear(c.buf)
		runtime.KeepAlive(c.buf)
		c.buf = nb
	}
	c.buf = append(c.buf, q...)
	if len(c.buf) >= c.max {
		c.full.Store(true)
	}
	return len(p), nil
}

func (c *capBuffer) Bytes() []byte {
	if c == nil {
		return nil
	}
	c.lock()
	defer c.unlock()
	return append([]byte(nil), c.buf...)
}

// copyBufSize is the size of the pooled buffer that copies a response body.
const copyBufSize = 32 << 10

var copyBufPool = sync.Pool{New: func() any { b := make([]byte, copyBufSize); return &b }}

// copyBuffered copies src to w with a pooled buffer, teeing every byte into
// capture first (as io.TeeReader did). It flushes after each write only when
// fl is non-nil (a stream of unknown length); a body of known length passes
// nil and is never flushed. Only the part of the buffer that was actually
// filled is zeroed before it goes back to the pool, so the pooled buffers hold
// no response bytes.
func copyBuffered(w io.Writer, src io.Reader, capture io.Writer, fl http.Flusher) {
	bp := copyBufPool.Get().(*[]byte)
	buf := *bp
	used := 0
	for {
		n, err := src.Read(buf)
		if n > used {
			used = n
		}
		if n > 0 {
			_, _ = capture.Write(buf[:n])
			if _, werr := w.Write(buf[:n]); werr != nil {
				break
			}
			if fl != nil {
				fl.Flush()
			}
		}
		if err != nil {
			break
		}
	}
	clear(buf[:used])
	runtime.KeepAlive(buf)
	copyBufPool.Put(bp)
}

var hopByHop = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

// hopByHopSet is hopByHop as a read-only set, built once. Every key in it is
// already in canonical form.
var hopByHopSet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(hopByHop))
	for _, h := range hopByHop {
		m[http.CanonicalHeaderKey(h)] = struct{}{}
	}
	return m
}()

// connectionNamed returns the header names that src's own Connection header
// lists (they are hop-by-hop for this message). Most messages list none, so
// nothing is allocated for them and the result is nil, which reads as empty.
func connectionNamed(src http.Header) map[string]struct{} {
	var named map[string]struct{}
	for _, v := range src.Values("Connection") {
		for _, f := range strings.Split(v, ",") {
			if f = strings.TrimSpace(f); f != "" {
				if named == nil {
					named = make(map[string]struct{}, 2)
				}
				named[http.CanonicalHeaderKey(f)] = struct{}{}
			}
		}
	}
	return named
}

// copyHeadersInto adds the end-to-end headers of src to dst without building
// an intermediate map: the response path used to copy src into a new
// http.Header and then copy that again into the ResponseWriter's.
// The value slices are shared with src (capped, so an append to one cannot
// write into src); neither side changes them in place.
func copyHeadersInto(dst, src http.Header) {
	named := connectionNamed(src)
	for k, vs := range src {
		ck := http.CanonicalHeaderKey(k)
		if _, drop := hopByHopSet[ck]; drop {
			continue
		}
		if _, drop := named[ck]; drop {
			continue
		}
		dst[ck] = vs[:len(vs):len(vs)]
	}
}

// Headers the request path drops whatever else it forwards.
var (
	dropForward        = []string{"Accept-Encoding"}
	dropForwardReverse = []string{"X-Target-URL", "Accept-Encoding"}
)

// headersForwardable reports whether copyHeaders(h, drop...) would return h
// unchanged: every key is already canonical, none is hop-by-hop (which also
// rules out a Connection header, and so any names it lists) and none is in
// drop. It allocates nothing. When it is true the request can be forwarded with
// h itself, and the map is copied only if something has to change it later.
func headersForwardable(h http.Header, drop []string) bool {
	for k := range h {
		ck := http.CanonicalHeaderKey(k)
		if ck != k {
			return false
		}
		if _, hop := hopByHopSet[ck]; hop {
			return false
		}
		for _, e := range drop {
			if strings.EqualFold(ck, e) {
				return false
			}
		}
	}
	return true
}

func copyHeaders(src http.Header, extraDrop ...string) http.Header {
	named := connectionNamed(src)
	// One backing array holds every kept value slice, instead of one small
	// allocation per header. The three-index slices stop a later append to one
	// header from running into its neighbour.
	total := 0
	for _, vs := range src {
		total += len(vs)
	}
	backing := make([]string, 0, total)
	dst := make(http.Header, len(src))
	for k, vs := range src {
		ck := http.CanonicalHeaderKey(k)
		if _, drop := hopByHopSet[ck]; drop {
			continue
		}
		if _, drop := named[ck]; drop {
			continue
		}
		skip := false
		for _, e := range extraDrop {
			// Canonical names differ only in letter case, so EqualFold is the
			// same test as comparing with CanonicalHeaderKey(e).
			if strings.EqualFold(ck, e) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		start := len(backing)
		backing = append(backing, vs...)
		dst[ck] = backing[start:len(backing):len(backing)]
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
	hp := strings.ToLower(strings.TrimSpace(hostport))
	host, port, err := net.SplitHostPort(hp)
	if err != nil {
		// No explicit port (http://localhost): the default HTTP port, 80.
		host, port = strings.Trim(hp, "[]"), "80"
	}
	if port != strconv.Itoa(a.port) {
		return false
	}
	if host == "localhost" {
		return true
	}
	// Any loopback address (127.0.0.0/8, ::1) and the unspecified addresses
	// (0.0.0.0, ::) reach this proxy when it listens on loopback.
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

var reUpstreamName = lazyRe(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)

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

// resolveUpstream picks the destination and then applies the egress policy to
// its host, so every route (forward proxy, X-Target-URL, -target, -target-map)
// is checked in one place.
func (a *App) resolveUpstream(r *http.Request) (*url.URL, bool, int, error) {
	u, reverse, status, err := a.resolveUpstreamRaw(r)
	if err != nil {
		return u, reverse, status, err
	}
	if perr := a.egress.checkHost(u.Hostname()); perr != nil {
		return nil, reverse, http.StatusForbidden, perr
	}
	return u, reverse, 0, nil
}

func (a *App) resolveUpstreamRaw(r *http.Request) (*url.URL, bool, int, error) {
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
	} else if len(a.gwMap) > 0 && hasGatewayPrefix(r.URL.Path) {
		nb, nrest, nraw, status, err := a.matchGateway(r.URL.Path, r.URL.RawPath)
		if err != nil {
			return nil, true, status, err
		}
		base, rest, restRaw = nb, nrest, nraw
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
		if len(a.upstreams) == 0 && len(a.gwMap) > 0 {
			return nil, true, http.StatusNotFound, fmt.Errorf("unknown route: start the path with %s/<name>/ with one of: %s", gwBase, strings.Join(a.gatewayNames(), ", "))
		}
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
	respCut     bool // the body was cut by a collector smaller than respCap (SSE)
	latencyMs   int64
	note        string

	respTrailers http.Header // read after the body; gRPC puts its status here

	// hdrBorrowed means reqHeaders and respHeaders are the live maps of the
	// request and response, not copies. capture() clones them on its worker.
	hdrBorrowed bool
}

// upgradeTransport returns a transport that never negotiates HTTP/2. An
// upgrade (WebSocket or any other) exists only in HTTP/1.1, and an
// HTTP/2-capable HTTPS server would otherwise answer the TLS handshake with h2.
func (a *App) upgradeTransport() *http.Transport {
	a.h1Once.Do(func() {
		t := a.transport.Clone()
		t.ForceAttemptHTTP2 = false
		// A non-nil, empty map is the documented way to switch HTTP/2 off. The
		// copied TLS settings may already offer "h2" (the main transport added it).
		t.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		if t.TLSClientConfig != nil {
			t.TLSClientConfig.NextProtos = nil
		}
		a.h1 = t
	})
	return a.h1
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if !a.authorize(w, r) {
		return
	}
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
	// Body must be a ReadCloser; http.NoBody has to stay as it is, because the
	// transport recognises it to send a request with no body at all.
	var outBody io.ReadCloser = http.NoBody
	hasBody := r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0
	// No body, no capture buffer: reqCap stays nil, and its methods accept that.
	var reqCap *capBuffer
	contentLen := int64(0)
	if hasBody {
		reqCap = newCapBuffer(a.limits().reqCap)
		defer reqCap.release()
		outBody = io.NopCloser(io.TeeReader(r.Body, reqCap))
		contentLen = r.ContentLength
	}
	// The URL was already parsed (and checked) by resolveUpstream, so the
	// request is built directly: no NewRequest parse of an empty URL and no
	// header map that the code below would only replace. The copy keeps the
	// request's URL its own. Header is set just below; Host is set before the
	// round trip.
	outURLCopy := *outURL
	outReq := (&http.Request{
		Method:        r.Method,
		URL:           &outURLCopy,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          outBody,
		ContentLength: contentLen,
	}).WithContext(r.Context())
	drop := dropForward
	if reverse {
		drop = dropForwardReverse
	}
	// Fast path: a request with no hop-by-hop header (and nothing else to drop)
	// is forwarded with its own header map, which the transport only reads, so
	// no new map is built. own() makes a private copy at the first change.
	hdrShared := headersForwardable(r.Header, drop)
	if hdrShared {
		outReq.Header = r.Header
	} else {
		outReq.Header = copyHeaders(r.Header, drop...)
	}
	own := func() {
		if hdrShared {
			outReq.Header = r.Header.Clone()
			hdrShared = false
		}
	}
	// gRPC servers look for "TE: trailers", so this one hop-by-hop value travels on.
	if acceptsTrailers(r.Header) {
		own()
		outReq.Header.Set("Te", "trailers")
	}
	// Response shield: never ask the server for an encoding NullWire cannot read.
	restrictAcceptEncoding(outReq.Header, r.Header)
	upgrade := isUpgradeRequest(r.Header)
	if upgrade {
		own()
		outReq.Header.Set("Connection", "Upgrade")
		outReq.Header.Set("Upgrade", r.Header.Get("Upgrade"))
		if strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
			// Extensions such as permessage-deflate compress the frames, which
			// would make them unreadable. Dropping the offer is always legal:
			// the server then simply sends uncompressed frames. With
			// -ws-deflate the offer is kept and the frames are decoded instead.
			if !a.wsDeflate {
				outReq.Header.Del("Sec-WebSocket-Extensions")
			}
		}
	}
	if _, ok := outReq.Header["User-Agent"]; !ok {
		own()
		outReq.Header["User-Agent"] = []string{""}
	}
	// The flow borrows the request's headers: nothing in ServeHTTP changes
	// r.Header from here on, and capture() takes its own copy on a worker, off
	// the forwarding path (hdrBorrowed).
	flow := rawFlow{started: start, method: r.Method, url: outURL.String(), reqHeaders: r.Header, hdrBorrowed: true}
	outReq.Host = outURL.Host
	rt := a.roundTripperFor(r, outURL)
	if upgrade {
		// Go keeps WebSocket on HTTP/1.1 by itself, but not other upgrade tokens,
		// so every upgrade goes over a transport that cannot choose HTTP/2.
		rt = a.upgradeTransport()
	}
	resp, err := rt.RoundTrip(outReq)
	if err != nil {
		msg := "nullwire-mcp: upstream error: " + err.Error()
		code := http.StatusBadGateway
		if errors.Is(err, errEgressDenied) {
			code = http.StatusForbidden // the resolved address is blocked (DNS rebinding guard)
		}
		http.Error(w, msg, code)
		flow.reqBody = reqCap.Bytes()
		flow.status = code
		flow.respHeaders = http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}}
		flow.respBody = []byte(msg)
		flow.latencyMs = time.Since(start).Milliseconds()
		a.dispatchCapture(flow)
		return
	}
	defer resp.Body.Close()
	if upgrade && resp.StatusCode == http.StatusSwitchingProtocols {
		isWS := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
		flow.reqBody = reqCap.Bytes()
		a.handleUpgrade(w, resp, flow, isWS)
		return
	}
	if isEventStream(resp.Header) {
		a.streamSSE(w, r, resp, flow, reqCap, start)
		return
	}
	respCap := newSoloCapBuffer(a.limits().respCap)
	defer respCap.release()
	copyHeadersInto(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	// Streaming (unknown length, or trailers to come) flushes as data arrives;
	// a body of known length is copied straight through without flushes.
	var fl http.Flusher
	if resp.ContentLength < 0 || len(resp.Trailer) > 0 {
		// The client sees the headers now, not together with the first chunk.
		fl, _ = w.(http.Flusher)
		if fl != nil && resp.ContentLength < 0 {
			fl.Flush()
		}
	}
	copyBuffered(w, resp.Body, respCap, fl)
	// Trailers are only known once the body has been read.
	for k, vs := range resp.Trailer {
		if len(vs) > 0 { // a declared trailer the server never sent has no value
			w.Header()[http.TrailerPrefix+k] = append([]string(nil), vs...)
		}
	}
	flow.reqBody = reqCap.Bytes()
	flow.status = resp.StatusCode
	flow.respHeaders = resp.Header // borrowed, like reqHeaders; capture() copies it
	flow.respTrailers = resp.Trailer.Clone() // trailers may still be filled in by the transport until the body ends, so copy now
	flow.respBody = respCap.Bytes()
	flow.latencyMs = time.Since(start).Milliseconds()
	a.dispatchCapture(flow)
}

// wipe zeroes the captured body copies once they are scrubbed and stored.
func (f *rawFlow) wipe() {
	clear(f.reqBody)
	clear(f.respBody)
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

// halfCloseDrain is how long the other direction may keep draining after one
// side half-closed or stopped being writable, so a peer's final frame (for
// WebSocket, the Close frame) still reaches its destination. It is a variable
// so tests can shorten it.
var halfCloseDrain = 5 * time.Second

func splice(client, upstream io.ReadWriteCloser, idle time.Duration, pre []byte) (toUpstream, toClient int64) {
	var sent, recv, last atomic.Int64
	last.Store(time.Now().UnixNano())
	closeBoth := func() { _ = client.Close(); _ = upstream.Close() }
	var drainOnce sync.Once
	var drainTimer *time.Timer
	var drainMu sync.Mutex
	// armDrain lets the reverse direction finish, but never for longer than
	// halfCloseDrain, so a silent half-close cannot hang the tunnel.
	armDrain := func() {
		drainOnce.Do(func() {
			drainMu.Lock()
			drainTimer = time.AfterFunc(halfCloseDrain, closeBoth)
			drainMu.Unlock()
		})
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
					// dst is gone (e.g. EPIPE after a protocol-error close):
					// stop this direction but let the reverse one deliver
					// whatever the peer already sent, such as a Close frame.
					armDrain()
					return
				}
			}
			if err != nil {
				if err == io.EOF {
					cw, ok := dst.(closeWriter)
					if !ok || cw.CloseWrite() != nil {
						// No real half-close: keep dst open so the reverse
						// direction can drain, bounded by the drain timer.
						armDrain()
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
	drainMu.Lock()
	if drainTimer != nil {
		drainTimer.Stop()
	}
	drainMu.Unlock()
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
	if perr := a.egress.checkHost(host); perr != nil {
		msg := "nullwire-mcp: " + perr.Error()
		http.Error(w, msg, http.StatusForbidden)
		a.dispatchCapture(rawFlow{started: start, method: http.MethodConnect, url: target, reqHeaders: r.Header.Clone(), respHeaders: http.Header{}, status: http.StatusForbidden, note: msg, latencyMs: time.Since(start).Milliseconds()})
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
		code := http.StatusBadGateway
		if errors.Is(err, errEgressDenied) {
			code = http.StatusForbidden // the resolved address is blocked (DNS rebinding guard)
		}
		http.Error(w, msg, code)
		flow.status = code
		flow.note = msg
		flow.latencyMs = time.Since(start).Milliseconds()
		a.dispatchCapture(flow)
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
		if b, _ := brw.Peek(n); len(b) > 0 {
			pre = append([]byte(nil), b...)
		}
	}
	sent, recv := splice(client, up, a.idle(), pre)
	flow.status = http.StatusOK
	flow.latencyMs = time.Since(start).Milliseconds()
	flow.note = fmt.Sprintf("blind CONNECT tunnel: %d B client->upstream, %d B upstream->client; payload not inspected or stored", sent, recv)
	a.dispatchCapture(flow)
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
		a.dispatchCapture(flow)
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
		if b, _ := brw.Peek(n); len(b) > 0 {
			pre = append([]byte(nil), b...)
		}
	}

	var clientRWC io.ReadWriteCloser = client
	var upstreamRWC = rwc
	var wsUp, wsDown *wsCollector
	var wsUpInfl, wsDownInfl *wsInflater
	liveID := uint64(0)
	var liveStop chan struct{}
	var liveDone chan struct{}
	flow.status = http.StatusSwitchingProtocols
	flow.respHeaders = resp.Header.Clone()
	if isWS {
		// Read-only taps: every byte is forwarded untouched and a copy is
		// parsed for capture. client->server frames are what the client sends.
		lim := a.limits()
		wsUp = newWSCollector(lim.reqBody + scrubWindow)
		wsDown = newWSCollector(lim.respBody + scrubWindow)
		upParser := newWSParser(wsUp.add)
		downParser := newWSParser(wsDown.add)
		upParser.maxMsg = lim.respBody + scrubWindow
		downParser.maxMsg = lim.respBody + scrubWindow
		if a.wsDeflate {
			if found, serverFresh, clientFresh := parseDeflateNegotiation(resp.Header.Values("Sec-WebSocket-Extensions")); found {
				wsUpInfl = newWSInflater(!clientFresh, lim.respBody+scrubWindow)
				wsDownInfl = newWSInflater(!serverFresh, lim.respBody+scrubWindow)
				upParser.inflate, downParser.inflate = wsUpInfl, wsDownInfl
			}
		}
		clientRWC = &tapRWC{rwc: client, onRead: upParser.Feed}
		upstreamRWC = &tapRWC{rwc: rwc, onRead: downParser.Feed}
		if len(pre) > 0 {
			upParser.Feed(pre)
		}
		// The flow is visible as soon as the socket opens and is refreshed
		// while it stays open; the final capture replaces it on close.
		open := flow
		open.latencyMs = 0
		open.note = wsLiveNote(resp.Header.Get("Upgrade"), wsUp, wsDown)
		if id, ok := a.pushLive(open); ok {
			liveID = id
			liveStop, liveDone = make(chan struct{}), make(chan struct{})
			go a.wsLiveLoop(liveID, open, resp.Header.Get("Upgrade"), wsUp, wsDown, liveStop, liveDone)
		}
	}

	sent, recv := splice(clientRWC, upstreamRWC, a.idle(), pre)
	// The connection is over: release the flate readers now, not at the next GC.
	wsUpInfl.Close()
	wsDownInfl.Close()

	if liveStop != nil {
		// Wait for the refresher to stop, so a late refresh cannot overwrite
		// the final capture.
		close(liveStop)
		<-liveDone
	}
	flow.latencyMs = time.Since(flow.started).Milliseconds()
	note := fmt.Sprintf("upgraded connection (%s): %d B client->upstream, %d B upstream->client", resp.Header.Get("Upgrade"), sent, recv)
	if wsUp != nil && wsDown != nil {
		flow.reqBody = wsUp.Bytes()
		flow.respBody = wsDown.Bytes()
		note += fmt.Sprintf("; WebSocket text messages are captured and scrubbed (refreshed live while open, final on close) (client->server: %s; server->client: %s); live frames are forwarded unmodified", wsUp.Summary(), wsDown.Summary())
	} else {
		note += "; frames not inspected or stored"
	}
	flow.note = note
	a.goFinishLive(liveID, flow)
}

func parseDNSServers(spec string) ([]string, error) {
	var out []string
	for _, raw := range strings.Split(spec, ",") {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		host, port := strings.Trim(s, "[]"), "53"
		if h, p, err := net.SplitHostPort(s); err == nil {
			host, port = h, p
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
		pem, err := cliio.ReadFile(path)
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
		pem, err := cliio.ReadFile(path + "/" + e.Name())
		if err != nil {
			continue
		}
		if pool.AppendCertsFromPEM(pem) {
			got = true
		}
	}
	return got, nil
}

// buildClientCert loads the upstream mTLS client certificate. Both files or
// neither must be given; with neither it returns (nil, nil).
func buildClientCert(certFile, keyFile string) (*tls.Certificate, error) {
	if certFile == "" && keyFile == "" {
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, errors.New("-client-cert and -client-key must be given together")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("client certificate: %w", err)
	}
	return &cert, nil
}

// buildTLSConfig returns the upstream TLS settings, or nil when neither extra
// roots nor a client certificate is set.
func buildTLSConfig(rootCAs *x509.CertPool, cert *tls.Certificate) *tls.Config {
	if rootCAs == nil && cert == nil {
		return nil
	}
	cfg := &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return cfg
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

// newDialer builds a dialer that enforces only the user's egress CIDR rules.
func newDialer(servers []string, egress *egressPolicy) *net.Dialer {
	return newDialerBlocks(servers, egress, nil)
}

// newDialerBlocks is newDialer plus the built-in upstream blocks (cloud
// metadata by default; CGNAT and IPv6 link-local on request). With blocks nil
// it behaves exactly like newDialer.
func newDialerBlocks(servers []string, egress *egressPolicy, blocks *upstreamBlocks) *net.Dialer {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	switch {
	case blocks != nil:
		// Runs on the resolved address of every connection attempt, so a name
		// that resolves or rebinds into a blocked range is refused.
		d.Control = upstreamControl(egress, *blocks)
	case egress.needsDialControl():
		d.Control = egress.control
	}
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

// decodeBodyMax decodes a gzip or deflate body, expanding it to at most limit
// bytes of text (the guard against compression bombs). When the text was cut
// there, truncMarker is appended to it.
func decodeBodyMax(ce string, b []byte, limit int) (string, bool) {
	text, cut, ok := decodeBodyMaxCut(ce, b, limit)
	if ok && cut {
		text += truncMarker
	}
	return text, ok
}

// decodeBodyMaxCut is decodeBodyMax for callers that need the bytes
// themselves: it returns the text without a marker and reports the cut
// separately, so a body that really ends in the marker text is not mistaken
// for a cut one.
func decodeBodyMaxCut(ce string, b []byte, limit int) (text string, cut, ok bool) {
	var rd io.ReadCloser
	switch strings.ToLower(effectiveContentEncoding(ce)) {
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return "", false, false
		}
		rd = zr
	case "deflate":
		if zr, err := zlib.NewReader(bytes.NewReader(b)); err == nil {
			rd = zr
		} else {
			rd = flate.NewReader(bytes.NewReader(b))
		}
	default:
		return "", false, false
	}
	defer rd.Close()
	out, err := io.ReadAll(io.LimitReader(rd, int64(limit)))
	defer clear(out) // string(out) below is a copy
	if len(out) == 0 && err != nil {
		return "", false, false
	}
	return string(out), err != nil || len(out) >= limit, true
}

func bodyText(h http.Header, b []byte) string { return bodyTextMax(h, b, decodedLimit) }

// joinedContentEncoding returns every Content-Encoding header line joined with ", ",
// so a stacked "Content-Encoding: identity" + "Content-Encoding: gzip" is seen whole.
func joinedContentEncoding(h http.Header) string {
	return strings.Join(h.Values("Content-Encoding"), ", ")
}

// effectiveContentEncoding drops "identity" entries and blanks from a Content-Encoding
// value: "identity, gzip" becomes "gzip", and "identity" becomes "".
func effectiveContentEncoding(ce string) string {
	var keep []string
	for _, p := range strings.Split(ce, ",") {
		if p = strings.TrimSpace(p); p != "" && !strings.EqualFold(p, "identity") {
			keep = append(keep, p)
		}
	}
	return strings.Join(keep, ", ")
}

func bodyTextMax(h http.Header, b []byte, decoded int) string {
	if len(b) == 0 {
		return ""
	}
	if ce := effectiveContentEncoding(joinedContentEncoding(h)); ce != "" {
		if text, ok := decodeBodyMax(ce, b, decoded); ok {
			return text
		}
		return fmt.Sprintf("[encoded body omitted: Content-Encoding %s, %d bytes captured]", ce, len(b))
	}
	return string(b)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen < 0 {
		maxLen = 0
	}
	cut := maxLen
	// Never split a multi-byte rune: s[cut] must start one.
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	// Never leave half a redaction tag: when the cut falls inside "[REDACTED_...]",
	// step back to its opening bracket.
	lo := cut - truncTagLookback
	if lo < 0 {
		lo = 0
	}
	if i := strings.LastIndex(s[lo:cut], "[REDACTED_"); i >= 0 && !strings.Contains(s[lo+i:cut], "]") {
		cut = lo + i
	} else {
		// ...or inside the opening "[REDACTED_" itself.
		const open = "[REDACTED_"
		for k := len(open) - 1; k >= 1; k-- {
			if strings.HasSuffix(s[:cut], open[:k]) {
				cut -= k
				break
			}
		}
	}
	return s[:cut] + truncMarker
}

// truncTagLookback is how far back truncate looks for an unfinished redaction tag
// ("[REDACTED_TOKEN#ab12cd]" is 24 bytes; the margin covers longer kinds).
const truncTagLookback = 40

func (a *App) capture(f rawFlow) {
	defer func() { _ = recover() }()
	defer f.wipe()
	if f.hdrBorrowed {
		f.reqHeaders = f.reqHeaders.Clone()
		f.respHeaders = f.respHeaders.Clone()
		f.hdrBorrowed = false
	}
	if e, ok := a.buildEntry(f); ok {
		a.ring.Push(e)
		a.markBar()
	}
}

// buildEntry scrubs a flow and returns the entry to store. ok is false for a
// flow that is ignored (-secrets-config ignore_url_substrings).
func (a *App) buildEntry(f rawFlow) (FlowEntry, bool) { return a.buildEntryWith(a.scrub, f) }

// buildEntryWith is buildEntry using sc, whose counters receive the redaction counts.
func (a *App) buildEntryWith(sc *Scrubber, f rawFlow) (FlowEntry, bool) {
	for _, sub := range a.ignoreURLSubstrings {
		if sub != "" && strings.Contains(f.url, sub) {
			return FlowEntry{}, false
		}
	}
	lim := a.limits()

	total := 0
	note := f.note

	u, n := sc.ScrubURL(f.url)
	total += n
	rh, n := sc.ScrubHeaders(f.reqHeaders)
	total += n

	rawReqBody := bodyTextMax(f.reqHeaders, f.reqBody, lim.decoded)
	gqlSrc := "" // the "operations" field of a GraphQL multipart upload
	if ct := f.reqHeaders.Get("Content-Type"); strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "multipart/") &&
		!strings.HasPrefix(rawReqBody, "[encoded body omitted") {
		gqlSrc = gqlMultipartBody(ct, rawReqBody)
		var mn int
		rawReqBody, mn = a.scrubMultipartWith(sc, ct, []byte(rawReqBody), int64(lim.reqBody+scrubWindow))
		total += mn
	}
	rawRespBody := bodyTextMax(f.respHeaders, f.respBody, lim.decoded)
	// Protobuf and gRPC bodies are binary. They are read without a schema into
	// text, which is scrubbed like any other body; the raw bytes are never
	// stored. A body that is not readable protobuf records only its size.
	if len(f.reqBody) > 0 && isProtobufContentType(f.reqHeaders.Get("Content-Type")) {
		if text, ok := decodeProtoBody(f.reqHeaders, f.reqBody, lim.decoded); ok {
			rawReqBody = text
			note += " Protobuf/gRPC request body decoded without a schema (values scrubbed; field-name rules cannot apply)."
		} else {
			rawReqBody = fmt.Sprintf("[protobuf/gRPC body not captured: %d bytes]", len(f.reqBody))
			note += " Protobuf/gRPC request body not captured (binary)."
		}
	}
	if len(f.respBody) > 0 && isProtobufContentType(f.respHeaders.Get("Content-Type")) {
		if text, ok := decodeProtoBody(f.respHeaders, f.respBody, lim.decoded); ok {
			rawRespBody = text
			note += " Protobuf/gRPC response body decoded without a schema (values scrubbed; field-name rules cannot apply)."
		} else {
			rawRespBody = fmt.Sprintf("[protobuf/gRPC body not captured: %d bytes]", len(f.respBody))
			note += " Protobuf/gRPC response body not captured (binary)."
		}
	}

	// MessagePack and CBOR are binary too. They are shown as JSON, which the
	// JSON rules then scrub; binaryBodyText leaves every other body alone.
	if text, bn, ok := binaryBodyText(f.reqHeaders, rawReqBody, lim.decoded); ok {
		rawReqBody = text
		note += bn
	}
	if text, bn, ok := binaryBodyText(f.respHeaders, rawRespBody, lim.decoded); ok {
		rawRespBody = text
		note += bn
	}

	// GraphQL: say which operation the request was. The note holds only a name
	// that is a plain identifier and passes the scrubber.
	gqlBody := rawReqBody
	if gqlSrc != "" {
		gqlBody = gqlSrc
	}
	if gn, cnt := a.graphqlNoteWith(sc, f.method, f.url, f.reqHeaders.Get("Content-Type"), gqlBody); gn != "" {
		note += gn
		total += cnt
		// Say that the call failed even on a 200: only the count, never the text.
		if ne, more := gqlResponseErrors(rawRespBody); ne > 0 {
			plus := ""
			if more {
				plus = "+"
			}
			note += fmt.Sprintf(" GraphQL errors: %d%s.", ne, plus)
		}
	}

	if st, msg := grpcStatus(f); st != "" {
		note += " gRPC status " + st
		if msg != "" {
			scrubbed, cnt := sc.ScrubTextIn(msg, ContextHeader)
			total += cnt
			note += ": " + truncate(scrubbed, 200)
		}
		note += "."
	}

	if strings.HasPrefix(rawReqBody, "[encoded body omitted") {
		note += " ⚠️ WARNING: Request body encoded (Brotli/Zstd), not inspected."
	}
	if strings.HasPrefix(rawRespBody, "[encoded body omitted") {
		note += " ⚠️ WARNING: Response body encoded (Brotli/Zstd), not inspected."
	}

	if len(f.reqBody) >= lim.reqCap || len(f.respBody) >= lim.respCap || f.respCut {
		note += " ⚠️ WARNING: Payload exceeded memory limits; truncated before full inspection."
	}

	// Scrub first, cut second: the extra scrubWindow lets a secret that
	// straddles the stored limit be seen whole before the text is cut.
	rawReqBody = truncate(rawReqBody, lim.reqBody+scrubWindow)
	rawRespBody = truncate(rawRespBody, lim.respBody+scrubWindow)

	rb, n := sc.ScrubText(rawReqBody)
	total += n
	ph, n := sc.ScrubHeaders(f.respHeaders)
	total += n
	pb, n := sc.ScrubText(rawRespBody)
	total += n

	return FlowEntry{
		Timestamp: f.started.UTC().Format(time.RFC3339), Method: f.method, URL: u,
		RequestHeaders: rh, RequestBody: truncate(rb, lim.reqBody),
		StatusCode: f.status, ResponseHeaders: ph, ResponseBody: truncate(pb, lim.respBody),
		LatencyMs: f.latencyMs, RedactionCount: total, Note: strings.TrimSpace(note),
	}, true
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
	_, _ = a.outW().Write([]byte(line + "\n"))
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
	_, _ = a.outW().Write([]byte(line + "\n"))
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
			"name": "export_har", "description": "Returns recent scrubbed flows as a HAR 1.2 document, built in memory (nothing is written to disk). Bodies are left out unless include_bodies is true. The reply is capped at 1 MiB.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"limit":          map[string]any{"type": "integer", "default": 10, "minimum": 1, "maximum": ringCapacity},
					"method":         map[string]any{"type": "string"},
					"url_contains":   map[string]any{"type": "string"},
					"include_bodies": map[string]any{"type": "boolean", "default": false},
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
		map[string]any{
			"name": "export_attestation", "description": "Returns a signed local attestation (ECDSA P-256): counts, policy SHA-256, active presets and a control summary. It holds no URLs, bodies or redaction tags.",
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

var reTag = lazyRe(`\[REDACTED_(TOKEN|COOKIE|IP|KEY|PAN)#[0-9a-f]{6}\]`)

func envFor(kind string) string {
	switch kind {
	case "COOKIE":
		return "NULLWIRE_COOKIE"
	case "IP":
		return "NULLWIRE_IP"
	case "KEY":
		return "NULLWIRE_PRIVATE_KEY"
	case "PAN":
		return "NULLWIRE_CARD_NUMBER"
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
	body = strings.TrimSuffix(body, truncMarker)
	if strings.HasPrefix(body, "[encoded body omitted") || strings.HasPrefix(body, "[protobuf/gRPC body") {
		body = "" // a placeholder or a decoded protobuf is not a body that can be replayed
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
		if !isEmptyArgs(req.Params) {
			if err := json.Unmarshal(req.Params, &p); err != nil {
				return &rpcResponse{ID: id, Error: &rpcError{Code: -32602, Message: "invalid params"}}
			}
		}
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
		return &rpcResponse{ID: id, Result: map[string]any{"resultType": "complete", "ttlMs": 300000, "cacheScope": "global", "tools": a.toolDefs()}}
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
			return &rpcResponse{ID: id, Error: &rpcError{Code: -32602, Message: "invalid params"}}
		}
		if a.disabledTools[p.Name] {
			return &rpcResponse{ID: id, Error: &rpcError{Code: -32602, Message: "tool disabled: " + p.Name}}
		}
		var result map[string]any
		switch p.Name {
		case "inspect_traffic":
			result = a.toolInspect(p.Arguments)
		case "export_har":
			result = a.toolExportHAR(p.Arguments)
		case "export_sanitized_curl":
			result = a.toolExportCurl(p.Arguments)
		case "clear_ram_buffer":
			result = a.toolClear()
		case "export_attestation":
			result = a.toolAttestation()
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

// Main runs the nullwire-mcp command line and returns when it is done.
func Main() {
	if len(os.Args) > 1 && os.Args[1] == "scan" {
		os.Exit(scan.Run(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "protect" {
		os.Exit(protect.Run(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "install" {
		os.Exit(install.Run(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "policy" {
		os.Exit(RunPolicy(os.Args[2:], os.Stdout, os.Stderr))
	}

	err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	switch {
	case err == nil:
	case errors.Is(err, flag.ErrHelp):
	case errors.As(err, new(flagParseError)):
		os.Exit(2) // the flag set already printed the message
	default:
		fmt.Fprintf(os.Stderr, "\r\033[K%v\n", err)
		os.Exit(1)
	}
}

// proxyMemoryLimit is the soft heap target of the proxy (see run).
const proxyMemoryLimit = 48 << 20

// flagParseError marks a command-line parse failure (already reported by the flag set).
type flagParseError struct{ error }

func (e flagParseError) Unwrap() error { return e.error }

// run is the proxy + MCP stdio server behind Main. It returns when stdin
// reaches EOF (nil) or when startup validation fails (a non-nil error).
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	// A soft heap target keeps resident memory low under large-body floods
	// (the capture buffers stop at their cap, see capBuffer). It is a GC
	// target, not a hard cap, and an explicit GOMEMLIMIT from the operator
	// wins. The previous value comes back when run returns, so a test that
	// calls run does not leave the limit set for the rest of the process.
	if os.Getenv("GOMEMLIMIT") == "" {
		defer debug.SetMemoryLimit(debug.SetMemoryLimit(proxyMemoryLimit))
	}
	fs := flag.NewFlagSet("nullwire-mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	port := fs.Int("port", 8080, "TCP port for the diagnostic proxy (always bound to 127.0.0.1)")
	target := fs.String("target", "", "upstream base URL(s)")
	targetMap := fs.String("target-map", "", "fixed routes name=URL,... reached as /_gw/<name>/ (an explicit allowlist, for clients that cannot send X-Target-URL)")
	cacert := fs.String("cacert", "", "extra CA certificates")
	dnsSpec := fs.String("dns", "auto", "upstream DNS")
	secretsConfig := fs.String("secrets-config", "", "path to -secrets-config JSON")
	clientCert := fs.String("client-cert", "", "PEM client certificate presented to upstream servers (mTLS); needs -client-key")
	clientKey := fs.String("client-key", "", "PEM private key for -client-cert")
	scrubHeaders := fs.String("scrub-headers", "", "extra sensitive headers")
	disableTools := fs.String("disable-tools", "", "comma-separated MCP tools to turn off, e.g. export_sanitized_curl,export_har (they are hidden from tools/list and refused by tools/call)")
	presetSpec := fs.String("preset", "", "comma-separated compliance redaction presets: pci-dss, hipaa, gdpr, all (off by default)")
	allowUninspectable := fs.Bool("allow-uninspectable", false, "forward request bodies whose Content-Encoding (br, zstd, ...) cannot be inspected; by default they are refused with 415")
	maxBodySpec := fs.String("max-body", "", "stored body size per request/response, e.g. 1m (default 32 KiB request / 256 KiB response; at most 2m). Secrets are scrubbed before the cut")
	wsDeflate := fs.Bool("ws-deflate", false, "keep WebSocket permessage-deflate and decode it for capture (default: drop the offer so frames stay readable)")
	policyPubkey := fs.String("policy-pubkey", "", "enterprise mode: ECDSA P-256 public key (PEM file, hex file or hex text) that must verify <secrets-config>.sig; also refuses -allow-uninspectable")
	attestOut := fs.String("attest-out", "", "write the signed attestation report to this file when the server exits")
	attestKey := fs.String("attest-key", "", "PEM ECDSA P-256 key that signs attestation reports (default: a fresh key per run)")
	proxyToken := fs.String("proxy-token", "", "require this token on every proxy request (Proxy-Authorization password, or "+tokenHeader+"); \"auto\" makes one and prints it; also read from "+tokenEnv)
	listen := fs.String("listen", "", "opt-in: listen on a unix socket instead of TCP, as unix:///absolute/path.sock (mode 0600; Linux and macOS)")
	if err := fs.Parse(args); err != nil {
		return flagParseError{err}
	}

	if *port < 0 || *port > 65535 {
		return errors.New("nullwire-mcp: -port must be between 0 and 65535")
	}
	maxBody, err := parseMaxBody(*maxBodySpec)
	if err != nil {
		return fmt.Errorf("nullwire-mcp: %v", err)
	}
	if err := policyLockError(*policyPubkey != "", *allowUninspectable); err != nil {
		return fmt.Errorf("nullwire-mcp: %v", err)
	}
	cfg, polSHA, polSigned, err := loadPolicy(*secretsConfig, *policyPubkey)
	if err != nil {
		return fmt.Errorf("nullwire-mcp: %v", err)
	}
	for _, h := range strings.Split(*scrubHeaders, ",") {
		if h = strings.TrimSpace(h); h != "" {
			cfg.SensitiveHeaders = append(cfg.SensitiveHeaders, h)
		}
	}
	cfg.Presets = append(cfg.Presets, splitPresetFlag(*presetSpec)...)
	activePresets, err := normalizePresets(cfg.Presets)
	if err != nil {
		return fmt.Errorf("nullwire-mcp: -preset: %v", err)
	}
	egress, err := newEgressPolicy(cfg.AllowedUpstreamHosts, cfg.BlockedUpstreamHosts)
	if err != nil {
		return fmt.Errorf("nullwire-mcp: %v", err)
	}
	disabled, err := disabledToolSet(*disableTools)
	if err != nil {
		return fmt.Errorf("nullwire-mcp: %v", err)
	}
	tok, tokGenerated := *proxyToken, false
	envTok := os.Getenv(tokenEnv)
	_ = os.Unsetenv(tokenEnv) // keep it out of any process this one starts
	if tok == "" {
		tok = envTok
	}
	switch {
	case tok == "auto":
		if tok, err = newProxyToken(); err != nil {
			return fmt.Errorf("nullwire-mcp: cannot make a proxy token: %v", err)
		}
		tokGenerated = true
	case tok != "":
		if err := validProxyToken(tok); err != nil {
			return fmt.Errorf("nullwire-mcp: %v", err)
		}
	}
	var attestSigningKey *ecdsa.PrivateKey
	if *attestKey != "" {
		if attestSigningKey, err = loadP256PrivateKeyFile(*attestKey); err != nil {
			return fmt.Errorf("nullwire-mcp: -attest-key: %v", err)
		}
	}
	scrub, err := NewScrubberWithConfig(cfg)
	if err != nil {
		return fmt.Errorf("nullwire-mcp: %v", err)
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
			return fmt.Errorf("nullwire-mcp: %v", err)
		}
	}
	dialer := newDialerBlocks(dnsServers, egress, &upstreamBlocks{
		allowMetadata: cfg.AllowMetadataUpstream,
		blockCGNAT:    cfg.BlockCGNATUpstream,
		blockLinkV6:   cfg.BlockLinkLocalUpstream,
	})

	rootCAs, caSource, err := buildRootCAs(*cacert, onTermux())
	if err != nil {
		return fmt.Errorf("nullwire-mcp: %v", err)
	}
	clientCrt, err := buildClientCert(*clientCert, *clientKey)
	if err != nil {
		return fmt.Errorf("nullwire-mcp: %v", err)
	}
	tlsCfg := buildTLSConfig(rootCAs, clientCrt)

	app := &App{
		ring: NewRingBuffer(), scrub: scrub, egress: egress, disabledTools: disabled, ignoreURLSubstrings: cfg.IgnoreURLSubstrings, allowUninspectable: *allowUninspectable, maxBody: maxBody, wsDeflate: *wsDeflate,
		transport: &http.Transport{Proxy: nil, DisableCompression: true, MaxIdleConns: 256, MaxIdleConnsPerHost: 128, ReadBufferSize: 32 << 10, WriteBufferSize: 32 << 10, IdleConnTimeout: 60 * time.Second, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 120 * time.Second, DialContext: dialer.DialContext, TLSClientConfig: tlsCfg, ForceAttemptHTTP2: true, HTTP2: transportHTTP2Config()},
	}
	app.stdout, app.stderr = stdout, stderr
	app.setProxyToken(tok)
	app.att = attestInfo{
		started: time.Now().UTC(), policySHA: polSHA, policySigned: polSigned, presets: activePresets,
		egressAllow: len(cfg.AllowedUpstreamHosts), egressBlock: len(cfg.BlockedUpstreamHosts),
		out: *attestOut, key: attestSigningKey,
	}
	if *target != "" {
		def, named, err := parseTargets(*target)
		if err != nil {
			return fmt.Errorf("nullwire-mcp: -target: %v", err)
		}
		app.target = def
		app.upstreams = named
	}
	if *targetMap != "" {
		gw, err := parseTargetMap(*targetMap)
		if err != nil {
			return fmt.Errorf("nullwire-mcp: -target-map: %v", err)
		}
		for n := range gw {
			if _, dup := app.upstreams[n]; dup {
				return fmt.Errorf("nullwire-mcp: -target-map: name %q is also used in -target", n)
			}
		}
		app.gwMap = gw
	}

	var ln net.Listener
	sockPath := ""
	if *listen != "" {
		if sockPath, err = parseListen(*listen); err != nil {
			return fmt.Errorf("nullwire-mcp: %v", err)
		}
		if ln, err = listenUnix(sockPath); err != nil {
			return fmt.Errorf("nullwire-mcp: %v", err)
		}
		app.listener = "unix"
		app.sockPath = sockPath
	} else {
		if ln, err = net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", *port)); err != nil {
			return fmt.Errorf("nullwire-mcp: cannot listen: %v", err)
		}
		tcpAddr, ok := ln.Addr().(*net.TCPAddr)
		if !ok || !tcpAddr.IP.IsLoopback() {
			ln.Close()
			return errors.New("nullwire-mcp: refusing to run on non-loopback")
		}
		app.port = tcpAddr.Port
	}
	// finish writes the -attest-out report and removes the unix socket file.
	finish := func() {
		if err := app.writeAttestFile(); err != nil {
			app.Logf("cannot write -attest-out: %v", err)
		}
		if sockPath != "" {
			_ = os.Remove(sockPath)
		}
	}

	app.startCapture()
	app.startBarTicker()
	// drain stops the capture workers after they finish every queued flow, then
	// stops the bar ticker with one last redraw. It runs before the ring and the
	// taint table are wiped, so no queued flow is pushed after the wipe.
	drain := func() {
		app.stopCapture()
		app.stopBarTicker()
	}

	srv := &http.Server{Handler: app, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, Protocols: serverProtocols(), HTTP2: serverHTTP2Config()}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			app.Logf("proxy server stopped: %v", err)
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	defer signal.Stop(sigs)
	defer close(done)
	go func() {
		select {
		case <-sigs:
		case <-done:
			return
		}
		app.Logf("signal received; wiping RAM")
		drain()
		finish()
		app.ring.Clear()
		app.scrub.taint.clear()
		_ = srv.Close()
		// The tag key is wiped only here, at shutdown: ResetCounters and
		// clear_ram_buffer must keep it, or tags would change mid-session.
		clear(app.scrub.nonce)
		runtime.KeepAlive(app.scrub.nonce)
		os.Exit(0)
	}()

	app.Bar()
	if dnsNotice != "" {
		app.Logf("%s", dnsNotice)
	}
	if caSource != "" {
		app.Logf("TLS roots: %s", caSource)
	}
	if sockPath != "" {
		app.Logf("MCP stdio server ready; proxy listening on unix socket %s (mode 600)", sockPath)
	} else {
		app.Logf("MCP stdio server ready; proxy listening on 127.0.0.1:%d", app.port)
	}
	switch {
	case tok != "" && tokGenerated && sockPath == "":
		app.Logf("proxy token required. Use HTTP_PROXY=http://nw:%s@127.0.0.1:%d (or send the header %s: %s)", tok, app.port, tokenHeader, tok)
	case tok != "" && tokGenerated:
		app.Logf("proxy token required. Send Proxy-Authorization (any user, password %s) or the header %s: %s", tok, tokenHeader, tok)
	case tok != "":
		app.Logf("proxy token required (Proxy-Authorization password, or the header %s)", tokenHeader)
	}
	for _, n := range app.gatewayNames() {
		if u := app.gwMap[n]; u != nil {
			app.Logf("gateway route %s/%s/ -> %s", gwBase, n, u.Host)
		}
	}

	scanner := bufio.NewScanner(stdin)
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
	drain()
	finish()
	app.ring.Clear()
	app.scrub.taint.clear()
	_ = srv.Close()
	return nil
}
