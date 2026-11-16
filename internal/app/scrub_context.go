package app

import (
	"regexp"
	"strings"
)

// ScrubContext says where a piece of text came from, because the same text
// deserves different rules in different places.
//
// A header value or a URL is one short value at a time, so there a long
// random-looking run is almost always a secret: those contexts use stricter
// rules. A body is free text (prose, JSON, logs), where a long random-looking
// run is often just data, so ContextBody keeps the looser rules and avoids
// false positives.
type ScrubContext uint8

const (
	ContextBody   ScrubContext = iota // free text; the default
	ContextHeader                     // one HTTP header value
	ContextQuery                      // a query string, or what follows the path of a URL
	ContextPath                       // the path of a URL
)

// scrubOpts is the full set of switches for one scrubbing run.
type scrubOpts struct {
	allowB64    bool         // decode base64 runs (off for text that was itself decoded)
	ctx         ScrubContext // where the text came from
	skipEntropy bool         // skip the randomness heuristics (hex and entropy)
	skipIP      bool         // leave IP addresses alone
}

// entropyMax is the longest run the randomness check will consider.
func (o scrubOpts) entropyMax() int {
	if o.ctx == ContextBody {
		return entropyMaxLen
	}
	return entropyMaxLenWide
}

// strictMax is the longest value a secret-named field may hold and still be
// redacted by the field rule.
func (o scrubOpts) strictMax() int {
	if o.ctx == ContextBody {
		return strictFieldMax
	}
	return strictFieldMaxWide
}

// entropyExemptHeaders carry random-looking values that are identifiers or
// content hashes, not secrets. They are still scrubbed by every deterministic
// rule; only the randomness heuristics skip them.
var entropyExemptHeaders = map[string]bool{
	"etag":             true,
	"if-none-match":    true,
	"if-match":         true,
	"x-request-id":     true,
	"x-correlation-id": true,
	"traceparent":      true,
	"tracestate":       true,
	"x-amz-id-2":       true,
	"x-amz-cf-id":      true,
	"x-amz-request-id": true,
	"cf-ray":           true,
}

// scrubHeaderValue scrubs one header value (lname is the lower-cased name).
func (s *Scrubber) scrubHeaderValue(lname, v string) (string, int) {
	return s.scrubLayersOpts(v, scrubOpts{
		allowB64:    true,
		ctx:         ContextHeader,
		skipEntropy: entropyExemptHeaders[lname],
	})
}

// ScrubURL scrubs a URL. The path gets the wide limits of ContextQuery but not
// the hex rule: a path often holds a content digest or commit id, which is an
// identifier, and low-entropy hex there is not a secret. Everything from the
// first "?" or "#" on is scrubbed as a query string, where a hex run is a
// webhook secret or a signature far more often than not.
func (s *Scrubber) ScrubURL(raw string) (string, int) {
	i := strings.IndexAny(raw, "?#")
	if i < 0 {
		return s.ScrubTextIn(raw, ContextPath)
	}
	head, n1 := s.ScrubTextIn(raw[:i], ContextPath)
	tail, n2 := s.ScrubTextIn(raw[i:], ContextQuery)
	return head + tail, n1 + n2
}

// ---------------------------------------------------------------------------
// Stage 1: unwrap URL-encoding and escaped JSON quotes, on a copy.

// unwrapMaxLen is the longest text the unwrap pass will look at.
const unwrapMaxLen = 1 << 20

func unwrapHexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// needsUnwrap reports whether in holds a percent-escape ("%41"), an escaped
// quote, backslash or slash (`\"`, `\\`, `\/`) or an ASCII "\uXXXX" escape.
// It does not allocate, so ordinary text never pays for the unwrap pass.
func needsUnwrap(in string) bool {
	if strings.IndexByte(in, '%') < 0 && strings.IndexByte(in, '\\') < 0 {
		return false
	}
	for i := 0; i+1 < len(in); i++ {
		switch in[i] {
		case '%':
			if i+2 < len(in) && unwrapHexVal(in[i+1]) >= 0 && unwrapHexVal(in[i+2]) >= 0 {
				return true
			}
		case '\\':
			if in[i+1] == '"' || in[i+1] == '\\' || in[i+1] == '/' {
				return true
			}
			if _, ok := unicodeEscapeASCII(in, i); ok {
				return true
			}
		}
	}
	return false
}

// unicodeEscapeASCII decodes a JSON "\uXXXX" escape at in[i:] when it stands
// for an ASCII byte (\u003d is "=", \u0026 is "&"). Serializers such as Go's
// encoding/json write <, >, & and = that way, which splits a key=value or URL.
// Escapes for non-ASCII characters and surrogates are left alone.
func unicodeEscapeASCII(in string, i int) (byte, bool) {
	if i+6 > len(in) || in[i] != '\\' || in[i+1] != 'u' {
		return 0, false
	}
	v := 0
	for k := 2; k < 6; k++ {
		h := unwrapHexVal(in[i+k])
		if h < 0 {
			return 0, false
		}
		v = v<<4 | h
	}
	if v >= 0x80 {
		return 0, false
	}
	return byte(v), true
}

// unwrapEscapes decodes one level of "%XX", `\"`, `\\`, `\/` and ASCII
// "\uXXXX". It returns the decoded text and a map from each decoded byte to where it started in the
// original: idx has len(dec)+1 entries, and decoded bytes dec[a:b] came from
// in[idx[a]:idx[b]].
// idx32 narrows a text offset for the offset map. unwrapEscapes only sees text
// of at most unwrapMaxLen bytes, which is far below the int32 limit.
func idx32(i int) int32 {
	return int32(i) // #nosec G115 -- callers keep len(in) at or below unwrapMaxLen
}

func unwrapEscapes(in string) (string, []int32) {
	dec := make([]byte, 0, len(in))
	idx := make([]int32, 0, len(in)+1)
	for i := 0; i < len(in); {
		c := in[i]
		switch {
		case c == '%' && i+2 < len(in) && unwrapHexVal(in[i+1]) >= 0 && unwrapHexVal(in[i+2]) >= 0:
			dec = append(dec, byte(unwrapHexVal(in[i+1])<<4|unwrapHexVal(in[i+2])))
			idx = append(idx, idx32(i))
			i += 3
		case c == '\\' && i+1 < len(in) && (in[i+1] == '"' || in[i+1] == '\\' || in[i+1] == '/'):
			dec = append(dec, in[i+1])
			idx = append(idx, idx32(i))
			i += 2
		case c == '\\' && i+6 <= len(in) && in[i+1] == 'u':
			if u, ok := unicodeEscapeASCII(in, i); ok {
				dec = append(dec, u)
				idx = append(idx, idx32(i))
				i += 6
				continue
			}
			dec = append(dec, c)
			idx = append(idx, idx32(i))
			i++
		default:
			dec = append(dec, c)
			idx = append(idx, idx32(i))
			i++
		}
	}
	idx = append(idx, idx32(len(in)))
	return string(dec), idx
}

// secretSpan is a stretch of the decoded text to redact. kind is the tag kind;
// empty means TOKEN.
type secretSpan struct {
	start, end int
	kind       string
}

// reUserInfoWide is reUserInfo for decoded text: the password may hold a
// decoded "@" ("p%40ss" becomes "p@ss"), so it runs to the LAST "@" before the
// first "/", "?", "#" or space.
var reUserInfoWide = regexp.MustCompile(`(://[^/\s:@]+:)([^/\s"'<>?#]+)(@)`)

// scrubUnwrapped finds secrets that are hidden by URL-encoding or by escaped
// JSON quotes. It decodes a read-only copy, runs the deterministic rules on
// the copy, and replaces the matching stretch of the ORIGINAL text with a tag.
// Everything outside the secrets is untouched, so escaped JSON stays valid
// JSON. The tag is made from the decoded (canonical) secret, so the raw and
// the encoded form of one secret get the same tag.
func (s *Scrubber) scrubUnwrapped(in string, ctx ScrubContext) (string, int) {
	if len(in) > unwrapMaxLen || !needsUnwrap(in) {
		return in, 0
	}
	dec, idx := unwrapEscapes(in)

	var spans []secretSpan
	addKind := func(a, b int, kind string) {
		if b > a {
			spans = append(spans, secretSpan{a, b, kind})
		}
	}
	add := func(a, b int) { addKind(a, b, "") }
	if s.vendorGate.Match(dec) {
		for _, vr := range s.vendorRules {
			for _, m := range vr.re.FindAllStringIndex(dec, -1) {
				if vr.weak && !weakVendorMatchOK(dec[m[0]:m[1]], vr.prefixes) {
					continue
				}
				add(m[0], m[1])
			}
		}
	}
	if strings.Contains(dec, "eyJ") {
		for _, m := range s.reJWT.FindAllStringIndex(dec, -1) {
			add(m[0], m[1])
		}
	}
	for _, m := range s.reAPIKey.FindAllStringIndex(dec, -1) {
		add(m[0], m[1])
	}
	// The three rules below capture the secret as group 2 (the text up to it is
	// group 1). They apply the same false-positive guards as scrubLayersOpts.
	for r, re := range [...]interface {
		FindAllStringSubmatchIndex(string, int) [][]int
	}{s.reJSONSecret, s.reQuerySecret, s.reBearer} {
		for _, m := range re.FindAllStringSubmatchIndex(dec, -1) {
			if len(m) < 6 || m[4] < 0 {
				continue
			}
			prefix, v := dec[m[2]:m[3]], dec[m[4]:m[5]]
			// Also test the text as written: decoding turns the placeholder
			// "%DB_PASSWORD%" into "\xdb_PASSWORD%", which no longer looks like one.
			orig := in[idx[m[4]]:idx[m[5]]]
			if strings.HasPrefix(v, "[REDACTED_") || isAllowMarkOnly(v) || isPlaceholderValue(v) || isPlaceholderValue(orig) {
				continue
			}
			if r < 2 && benignBareKey(prefix, v) {
				continue
			}
			if r == 2 && proseAfterScheme(prefix, v, ctx) {
				continue
			}
			add(m[4], m[5])
		}
	}
	if strings.Contains(dec, "-----BEGIN") {
		for _, m := range s.rePEM.FindAllStringIndex(dec, -1) {
			addKind(m[0], m[1], "KEY")
		}
	}
	if strings.Contains(dec, "://") && strings.Contains(dec, "@") {
		for _, m := range reUserInfoWide.FindAllStringSubmatchIndex(dec, -1) {
			if len(m) < 6 || m[4] < 0 {
				continue
			}
			orig := in[idx[m[4]]:idx[m[5]]]
			if v := dec[m[4]:m[5]]; strings.HasPrefix(v, "[REDACTED_") || isAllowMarkOnly(v) || isPlaceholderValue(v) || isPlaceholderValue(orig) {
				continue
			}
			add(m[4], m[5])
		}
	}
	for _, sp := range awsSecretKeySpans(dec) {
		addKind(sp.start, sp.end, "KEY")
	}
	for _, sp := range panSpans(dec) {
		addKind(sp.start, sp.end, "PAN")
	}
	if len(spans) == 0 {
		return in, 0
	}

	// Sort by start (few spans, so insertion sort), then drop overlaps.
	for i := 1; i < len(spans); i++ {
		for j := i; j > 0 && spans[j].start < spans[j-1].start; j-- {
			spans[j], spans[j-1] = spans[j-1], spans[j]
		}
	}
	var b strings.Builder
	count, last, lastDec := 0, 0, 0
	for _, sp := range spans {
		if sp.start < lastDec {
			continue
		}
		from, to := int(idx[sp.start]), int(idx[sp.end])
		if from < last || to < from {
			continue
		}
		b.WriteString(in[last:from])
		kind := sp.kind
		if kind == "" {
			kind = "TOKEN"
		}
		b.WriteString(s.tag(kind, dec[sp.start:sp.end]))
		s.Tokens.Add(1)
		count++
		last, lastDec = to, sp.end
	}
	if count == 0 {
		return in, 0
	}
	b.WriteString(in[last:])
	return b.String(), count
}

// ---------------------------------------------------------------------------
// Cheap checks that let a rule be skipped without allocating.

func isB64Byte(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '_' || c == '-'
}

// hasBase64Run reports whether in holds a run that scrubBase64 would try to
// decode, so the base64 pass (which copies its input) is skipped otherwise.
func hasBase64Run(in string) bool {
	start := -1
	for i := 0; i <= len(in); i++ {
		if i < len(in) && isB64Byte(in[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			if i-start >= 24 && isBase64Like(in[start:i]) {
				return true
			}
			start = -1
		}
	}
	return false
}

// maybeIPv4 reports whether in has a digit, a dot and a digit in a row, which
// every IPv4 address does, so the IPv4 pass can be skipped otherwise.
func maybeIPv4(in string) bool {
	for i := 1; i+1 < len(in); i++ {
		if in[i] == '.' && in[i-1] >= '0' && in[i-1] <= '9' && in[i+1] >= '0' && in[i+1] <= '9' {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Stage 3: hex webhook secrets in headers and query strings.

func isHexDigitByte(c byte) bool { return unwrapHexVal(c) >= 0 }

// scrubHexSecrets redacts standalone runs of exactly 32, 40 or 64 hex digits
// (the size of MD5, SHA-1 and SHA-256 based webhook secrets and signatures).
// The general randomness check wants an entropy of 3.0 for hex; here a lower
// floor is enough, because in a header or a query string such a value is
// almost never anything else. Only used for ContextHeader and ContextQuery.
func (s *Scrubber) scrubHexSecrets(in string) (string, int) {
	if len(in) < 32 {
		return in, 0
	}
	var b strings.Builder
	count, last := 0, 0
	for i := 0; i < len(in); {
		if !isHexDigitByte(in[i]) {
			i++
			continue
		}
		j := i
		for j < len(in) && isHexDigitByte(in[j]) {
			j++
		}
		if n := j - i; n == 32 || n == 40 || n == 64 {
			beforeOK := i == 0 || !isWordByte(in[i-1])
			afterOK := j == len(in) || !isWordByte(in[j])
			if beforeOK && afterOK && shannonEntropyBits(in[i:j]) >= entropyHexWebhookMin {
				b.WriteString(in[last:i])
				b.WriteString(s.tag("TOKEN", in[i:j]))
				s.Tokens.Add(1)
				count++
				last = j
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
