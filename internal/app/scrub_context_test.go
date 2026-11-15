package app

import (
	"net/http"
	"strings"
	"testing"
)

const ctxTestBody = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"

// randomToken returns n pseudo-random characters from a set with no vowels, so
// it always looks like a machine-made key (high entropy, low vowel ratio).
func randomToken(n int) string {
	const set = "bcdfghjklmnpqrstvwxzBCDFGHJKLMNPQRSTVWXZ0123456789"
	var x uint32 = 12345
	b := make([]byte, n)
	for i := range b {
		x = x*1103515245 + 12345
		b[i] = set[int(x>>16)%len(set)]
	}
	return string(b)
}

func newCtxScrubber(t *testing.T) *Scrubber {
	t.Helper()
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A secret written with a percent-escape gets the same tag as the plain one,
// and none of it is left behind.
func TestUnwrapPercentEncodedSecret(t *testing.T) {
	s := newCtxScrubber(t)
	plain, nPlain := s.ScrubText("see sk_live_" + ctxTestBody + " end")
	enc, nEnc := s.ScrubText("see %73k_live_" + ctxTestBody + " end")
	if nPlain < 1 || nEnc < 1 {
		t.Fatalf("both forms must be redacted, got plain=%d encoded=%d (%q / %q)", nPlain, nEnc, plain, enc)
	}
	if plain != enc {
		t.Errorf("raw and encoded forms should produce the same tag:\n raw:     %q\n encoded: %q", plain, enc)
	}
	if strings.Contains(enc, ctxTestBody[8:]) {
		t.Errorf("secret left in output: %q", enc)
	}
}

// Digits encoded one by one ("%39%38...") do not hide a key.
func TestUnwrapEncodedDigits(t *testing.T) {
	s := newCtxScrubber(t)
	in := "key=%41KIA%31%32%33%34%35%36%37%38%39%30ABCDEF&x=1"
	out, n := s.ScrubText(in)
	if n < 1 || strings.Contains(out, "ABCDEF") || strings.Contains(out, "AKIA") {
		t.Errorf("encoded AWS key not redacted: %q (%d)", out, n)
	}
}

// Double-escaped JSON (a JSON document inside a JSON string) is scanned, and
// the escaping around the redacted value is left exactly as it was.
func TestUnwrapEscapedJSONKeepsEscaping(t *testing.T) {
	s := newCtxScrubber(t)
	in := `{\"api_key\":\"plainvalue123456\",\"ok\":true}`
	out, n := s.ScrubText(in)
	if n < 1 || strings.Contains(out, "plainvalue123456") {
		t.Fatalf("value not redacted: %q (%d)", out, n)
	}
	if !strings.HasPrefix(out, `{\"api_key\":\"[REDACTED_TOKEN#`) || !strings.HasSuffix(out, `]\",\"ok\":true}`) {
		t.Errorf("JSON escaping must survive unchanged: %q", out)
	}
}

// Text with neither a percent-escape nor an escaped quote never reaches the
// unwrap pass.
func TestNeedsUnwrap(t *testing.T) {
	for in, want := range map[string]bool{
		"plain text":          false,
		"100% sure":           false,
		"a%2":                 false,
		"line\\nbreak":        false,
		"%41":                 true,
		`say \"hi\"`:          true,
		`path\\to`:            true,
		"token=%7Bvalue%7D":   true,
		"trailing percent %":  false,
		"back\\":              false,
	} {
		if got := needsUnwrap(in); got != want {
			t.Errorf("needsUnwrap(%q) = %v, want %v", in, got, want)
		}
	}
}

// Long random values are redacted in a header or a query, but left alone in a
// body, where a long run is often just data.
func TestContextEntropyLimit(t *testing.T) {
	s := newCtxScrubber(t)
	tok := randomToken(300)
	in := "v=" + tok

	if out, n := s.ScrubTextIn(in, ContextBody); n != 0 || out != in {
		t.Errorf("body context should leave a 300-character run alone: %q (%d)", out, n)
	}
	for _, ctx := range []ScrubContext{ContextHeader, ContextQuery, ContextPath} {
		out, n := s.ScrubTextIn(in, ctx)
		if n < 1 || strings.Contains(out, tok[:40]) {
			t.Errorf("context %d should redact a 300-character random value: %q (%d)", ctx, out, n)
		}
	}
}

// 32, 40 and 64 hex digits with modest entropy are webhook-style secrets in a
// header or query; in a body they stay under the normal entropy rule.
func TestContextHexWebhookSecrets(t *testing.T) {
	s := newCtxScrubber(t)
	for name, hex := range map[string]string{
		"md5-size":    strings.Repeat("abcdefab", 4),
		"sha1-size":   strings.Repeat("abcde", 8),
		"sha256-size": strings.Repeat("abcdefab", 8),
	} {
		in := "v=" + hex
		if out, n := s.ScrubTextIn(in, ContextBody); n != 0 {
			t.Errorf("%s: body context should not redact low-entropy hex: %q", name, out)
		}
		out, n := s.ScrubTextIn(in, ContextQuery)
		if n < 1 || strings.Contains(out, hex) {
			t.Errorf("%s: query context should redact it: %q (%d)", name, out, n)
		}
	}
	// A hex run of another length is not a webhook secret.
	odd := strings.Repeat("abcde", 7)
	if out, n := s.ScrubTextIn("id="+odd, ContextQuery); n != 0 {
		t.Errorf("35 hex digits should be left alone: %q", out)
	}
}

// Identifier headers are exempt from the randomness checks; the same value in
// an ordinary header is redacted.
func TestEntropyExemptHeaders(t *testing.T) {
	s := newCtxScrubber(t)
	val := randomToken(64)
	h := http.Header{}
	h.Set("X-Request-Id", val)
	h.Set("X-Correlation-Id", val)
	h.Set("ETag", val)
	h.Set("If-None-Match", val)
	h.Set("If-Match", val)
	h.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	h.Set("X-Amz-Id-2", val)
	h.Set("X-Amz-Cf-Id", val)
	h.Set("X-Amz-Request-Id", val)
	h.Set("Cf-Ray", val)
	h.Set("Tracestate", val)
	m, _ := s.ScrubHeaders(h)

	for _, name := range []string{"X-Request-Id", "X-Correlation-Id", "Etag", "If-None-Match", "If-Match",
		"X-Amz-Id-2", "X-Amz-Cf-Id", "X-Amz-Request-Id", "Cf-Ray", "Tracestate"} {
		if m[name] != val {
			t.Errorf("%s should not be touched by the entropy check, got %q", name, m[name])
		}
	}
	other, _ := s.ScrubHeaders(http.Header{"X-Other": {val}})
	if other["X-Other"] == val {
		t.Errorf("ordinary header should be redacted, got %q", other["X-Other"])
	}
	if got := m["Traceparent"]; got != "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" {
		t.Errorf("Traceparent should be left alone, got %q", got)
	}
	if strings.Contains(m["X-Other"], val[:20]) {
		t.Errorf("the same value in an ordinary header should be redacted: %q", m["X-Other"])
	}
}

// Skipping the base64 and IPv4 passes must not change what is found: the cheap
// checks may only say "no" when the full rule would find nothing.
func TestCheapChecksMatchTheirRules(t *testing.T) {
	for in, want := range map[string]bool{
		"nothing here":                 false,
		"short abc123":                 false,
		"QWxhZGRpbjpvcGVuIHNlc2FtZQ==": true,  // 26 base64 characters, mixed case
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaa": false, // one case, no digit: not base64-like
		"Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1":  true,
	} {
		if got := hasBase64Run(in); got != want {
			t.Errorf("hasBase64Run(%q) = %v, want %v", in, got, want)
		}
	}
	for in, want := range map[string]bool{
		"no dots":     false,
		"v1.2":        true,
		"example.com": false,
		"10.0.0.1":    true,
		"a.b 1 . 2":   false,
	} {
		if got := maybeIPv4(in); got != want {
			t.Errorf("maybeIPv4(%q) = %v, want %v", in, got, want)
		}
	}
}

// Stage 1 replaces a secret that was hidden by URL-encoding with a tag. The
// field rules that run next must leave that tag alone: tagging a tag would
// corrupt it or overwrite the canonical tag, and count one secret twice.
func TestUnwrapDoesNotRetagStageOneTags(t *testing.T) {
	s := newCtxScrubber(t)
	const key = "AKIA1234567890ABCDEF"
	sk := "sk_live_" + ctxTestBody
	for name, tc := range map[string]struct{ in, want string }{
		"query":    {"key=%41KIA1234567890ABCDEF&x=1", "key=" + s.tag("TOKEN", key) + "&x=1"},
		"json":     {`{"api_key":"%73k_live_` + ctxTestBody + `"}`, `{"api_key":"` + s.tag("TOKEN", sk) + `"}`},
		"userinfo": {"https://user:%73k_live_" + ctxTestBody + "@host/x", "https://user:" + s.tag("TOKEN", sk) + "@host/x"},
	} {
		out, n := s.ScrubText(tc.in)
		if out != tc.want {
			t.Errorf("%s:\n got  %q\n want %q", name, out, tc.want)
		}
		if n != 1 {
			t.Errorf("%s: counted %d redactions for one secret", name, n)
		}
		if strings.Contains(reTag.ReplaceAllString(out, ""), "REDACTED") {
			t.Errorf("%s: a tag was damaged: %q", name, out)
		}
	}
	// The plain form of the same JSON secret gets the same tag as the encoded one.
	plain, _ := s.ScrubText(`{"api_key":"` + sk + `"}`)
	enc, _ := s.ScrubText(`{"api_key":"%73k_live_` + ctxTestBody + `"}`)
	if plain != enc {
		t.Errorf("plain and encoded forms should match:\n plain   %q\n encoded %q", plain, enc)
	}
}

// A URL path keeps low-entropy hex (a digest or commit id); the same run in the
// query string is still redacted as a webhook-style secret.
func TestScrubURLTreatsPathAndQueryApart(t *testing.T) {
	s := newCtxScrubber(t)
	hex := strings.Repeat("abcde", 8) // 40 hex digits, entropy below the general rule
	path := "https://example.com/blobs/" + hex
	if out, n := s.ScrubURL(path); n != 0 || out != path {
		t.Errorf("a hex run in the path should be left alone: %q (%d)", out, n)
	}
	query := "https://example.com/hook?v=" + hex
	out, n := s.ScrubURL(query)
	if n < 1 || strings.Contains(out, hex) {
		t.Errorf("a hex run in the query should be redacted: %q (%d)", out, n)
	}
	if !strings.HasPrefix(out, "https://example.com/hook?v=") {
		t.Errorf("the rest of the URL should be kept: %q", out)
	}
	// A secret in the path is still caught by the deterministic rules.
	sk := "https://example.com/pay/sk_live_" + ctxTestBody
	if out, n := s.ScrubURL(sk); n < 1 || strings.Contains(out, ctxTestBody[8:]) {
		t.Errorf("a vendor key in the path should be redacted: %q (%d)", out, n)
	}
}