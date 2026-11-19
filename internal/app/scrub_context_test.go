package app

import (
	"net/http"
	"reflect"
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

// unwrapEscapes decodes one level of escaping and keeps a map back to the
// original text. These cases pin down both, including the edges.
func TestUnwrapEscapesEdges(t *testing.T) {
	cases := []struct {
		name, in, dec string
		idx           []int32
	}{
		{"nothing to decode", "ab", "ab", []int32{0, 1, 2}},
		{"escaped backslash before a closing quote", `a\\"b`, `a"b`, []int32{0, 3, 4, 5}},
		{"escaped backslash before an escaped quote", `x\\\"y`, `x"y`, []int32{0, 3, 5, 6}},
		{"escaped backslash before a percent-encoded quote", `x\\%22`, `x"`, []int32{0, 3, 6}},
		{"escaped backslash elsewhere is one backslash", `a\\b`, `a\b`, []int32{0, 1, 3, 4}},
		{"escaped slash", `a\/b`, `a/b`, []int32{0, 1, 3, 4}},
		{"ASCII unicode escape", `x\u003dy`, `x=y`, []int32{0, 1, 7, 8}},
		{"non-ASCII unicode escape is left alone", `a\u00e9b`, `a\u00e9b`, []int32{0, 1, 2, 3, 4, 5, 6, 7, 8}},
		{"invalid unicode escape is left alone", `\uZZZZ`, `\uZZZZ`, []int32{0, 1, 2, 3, 4, 5, 6}},
		{"short unicode escape is left alone", `\u00`, `\u00`, []int32{0, 1, 2, 3, 4}},
		{"percent escape at the very end", "%41", "A", []int32{0, 3}},
		{"two percent escapes", "%41%7a", "Az", []int32{0, 3, 6}},
		{"truncated percent escape at the end", "a%2", "a%2", []int32{0, 1, 2, 3}},
		{"percent without hex digits", "%zz", "%zz", []int32{0, 1, 2, 3}},
		{"trailing backslash", `a\`, `a\`, []int32{0, 1, 2}},
	}
	for _, c := range cases {
		dec, idx := unwrapEscapes(c.in)
		if dec != c.dec {
			t.Errorf("%s: dec = %q, want %q", c.name, dec, c.dec)
		}
		if !reflect.DeepEqual(idx, c.idx) {
			t.Errorf("%s: idx = %v, want %v", c.name, idx, c.idx)
		}
		if len(idx) != len(dec)+1 {
			t.Errorf("%s: idx must have len(dec)+1 entries, got %d for %d bytes", c.name, len(idx), len(dec))
		}
	}
	for in, want := range map[string]bool{`a\u003d`: true, `a\u00e9`: false, `\uZZZZ`: false, `\u00`: false} {
		if got := needsUnwrap(in); got != want {
			t.Errorf("needsUnwrap(%q) = %v, want %v", in, got, want)
		}
	}
}

// Secrets hidden by URL-encoding are found by the rules that run on the
// decoded copy (cloud keys, card numbers, vendor keys, secret fields and
// arrays, the user's own patterns), and the matching stretch of the ORIGINAL
// text is replaced.
func TestUnwrappedExtraSpansFindEncodedSecrets(t *testing.T) {
	s := newCtxScrubber(t)
	awsEnc := strings.ReplaceAll(awsExampleSecret, "/", "%2F")
	azure := "abc8Q~" + strings.Repeat("Zq9", 11)
	cases := []struct {
		name, in string
		gone     []string
		prefix   string
		suffix   string
		tag      string
	}{
		{"AWS secret key on its own", "used " + awsEnc + " here", []string{"EXAMPLEKEY", "bPxRfi"}, "used ", " here", ""},
		{"AWS secret key under its name", "aws_secret_access_key=" + awsEnc, []string{"EXAMPLEKEY", "bPxRfi"}, "aws_secret_access_key=", "", ""},
		{"password in a connection string", "Server=db;Password=Sup3rS3cret%21;Port=1", []string{"Sup3rS3cret"}, "Server=db;Password=", ";Port=1", ""},
		{"Azure AD client secret", "v%3D" + azure, []string{"Zq9Zq9Zq9"}, "v%3D", "", ""},
		{"password array", "%7B%22password%22%3A%5B%22Sup3rS3cretValue%22%2C%22second-Secret-9%22%5D%7D",
			[]string{"Sup3rS3cretValue", "second-Secret-9"}, "%7B%22password%22%3A%5B%22", "%22%5D%7D", ""},
		{"card number", "card%3D4111%2D1111%2D1111%2D1111 ok", []string{"4111"}, "card%3D", " ok", "[REDACTED_PAN#"},
		{"vendor key", "ref%3D%73k_live_" + ctxTestBody, []string{ctxTestBody[8:]}, "ref%3D", "", ""},
		{"secret-named field", "custom_secret%3Dabcd1234efgh5678", []string{"abcd1234efgh5678"}, "custom_secret%3D", "", ""},
	}
	for _, c := range cases {
		out, n := s.scrubUnwrapped(c.in, ContextBody)
		if n < 1 {
			t.Errorf("%s: nothing redacted: %q", c.name, out)
			continue
		}
		for _, g := range c.gone {
			if strings.Contains(out, g) {
				t.Errorf("%s: %q is still in the output: %q", c.name, g, out)
			}
		}
		if !strings.Contains(out, "[REDACTED_") || !strings.HasPrefix(out, c.prefix) || !strings.HasSuffix(out, c.suffix) {
			t.Errorf("%s: the text around the secret must be kept as written: %q", c.name, out)
		}
		if c.tag != "" && !strings.Contains(out, c.tag) {
			t.Errorf("%s: want a %s tag: %q", c.name, c.tag, out)
		}
	}

	// The same secrets go through the full pipeline too.
	for _, c := range cases {
		out, n := s.ScrubText(c.in)
		if n < 1 {
			t.Errorf("%s (ScrubText): nothing redacted: %q", c.name, out)
		}
		for _, g := range c.gone {
			if strings.Contains(out, g) {
				t.Errorf("%s (ScrubText): %q is still in the output: %q", c.name, g, out)
			}
		}
	}

	// The user's own patterns run on the decoded text as well.
	custom, err := NewScrubberWithConfig(&SecretsConfig{ExtraRegexPatterns: []ExtraPattern{{Name: "internal", Pattern: `INTERNAL-[0-9]{6}`}}})
	if err != nil {
		t.Fatal(err)
	}
	out, n := custom.scrubUnwrapped("ref%3A INTERNAL-123456 ok", ContextBody)
	if n != 1 || strings.Contains(out, "123456") || !strings.HasPrefix(out, "ref%3A ") || !strings.HasSuffix(out, " ok") {
		t.Errorf("custom pattern: %q (%d)", out, n)
	}

	// The raw and the encoded form of one card number get the same tag.
	plain, _ := s.ScrubText("card=4111-1111-1111-1111 ok")
	enc, _ := s.ScrubText("card%3D4111%2D1111%2D1111%2D1111 ok")
	if tagOf := func(x string) string { return reTag.FindString(x) }; tagOf(plain) == "" || tagOf(plain) != tagOf(enc) {
		t.Errorf("same card, different tags:\n plain   %q\n encoded %q", plain, enc)
	}
}

// A placeholder such as %DB_PASSWORD% reads as a percent-escape ("%DB"), so it
// reaches the unwrap pass, where decoding wrecks it. The placeholder is tested
// as it was written, so it is still left alone, in every rule that has a guard.
func TestUnwrapKeepsPercentPlaceholders(t *testing.T) {
	s := newCtxScrubber(t)
	for _, in := range []string{
		"password=%DB_PASSWORD%",
		"Server=db;Password=%DB_PASSWORD%;Port=1",
		`{"password":"%DB_PASSWORD%"}`,
		"https://user:%DB_PASSWORD%@host/x",
		"client_secret=%DB_PASSWORD%",
	} {
		if out, n := s.scrubUnwrapped(in, ContextBody); out != in || n != 0 {
			t.Errorf("scrubUnwrapped(%q) = %q (%d), want it unchanged", in, out, n)
		}
	}
	const placeholder = "password=%DB_PASSWORD%"
	if out, n := s.ScrubTextIn(placeholder, ContextBody); out != placeholder || n != 0 {
		t.Errorf("ScrubTextIn(%q) = %q (%d), want it unchanged", placeholder, out, n)
	}
	// A real value in the same place is still redacted.
	for _, in := range []string{"Server=db;Password=Sup3rS3cret%21;Port=1", "password=%DB_real_Sup3rS3cret"} {
		if out, n := s.ScrubTextIn(in, ContextBody); n < 1 || strings.Contains(out, "Sup3rS3cret") {
			t.Errorf("ScrubTextIn(%q) = %q (%d), want the secret redacted", in, out, n)
		}
	}
}

// "Bearer" is always a credential, even when English follows it. "Basic" and
// "Token" followed by a lower-case word are prose in a body, but in a header,
// a query or a path the value after the scheme is a credential.
func TestProseAfterScheme(t *testing.T) {
	for _, c := range []struct {
		scheme, tok string
		ctx         ScrubContext
		want        bool
	}{
		{"Bearer", "authentication", ContextBody, false},
		{"bearer", "authentication", ContextBody, false},
		{"BEARER", "required", ContextHeader, false},
		{"Basic", "authentication", ContextBody, true},
		{"Token", "provided", ContextBody, true},
		{"Token", "", ContextBody, true},
		{"Basic", "authentication", ContextHeader, false},
		{"Token", "provided", ContextQuery, false},
		{"Token", "provided", ContextPath, false},
		{"Basic", "Authentication", ContextBody, false},
		{"Token", "provided1", ContextBody, false},
		{"Token", "not-prose", ContextBody, false},
	} {
		if got := proseAfterScheme(c.scheme, c.tok, c.ctx); got != c.want {
			t.Errorf("proseAfterScheme(%q, %q, %d) = %v, want %v", c.scheme, c.tok, c.ctx, got, c.want)
		}
	}
}

func TestBearerFollowedByProseInEachContext(t *testing.T) {
	s := newCtxScrubber(t)

	// Bearer is a credential in a body and in a header alike.
	for _, ctx := range []ScrubContext{ContextBody, ContextHeader} {
		out, n := s.ScrubTextIn("Bearer authentication required", ctx)
		if n < 1 || strings.Contains(out, "authentication") {
			t.Errorf("context %d: Bearer followed by prose must still be redacted: %q (%d)", ctx, out, n)
		}
	}

	// Basic and Token are prose in a body but credentials in a header.
	for _, in := range []string{"Basic authentication required", "Invalid token provided", "Token expired yesterday"} {
		if out, n := s.ScrubTextIn(in, ContextBody); out != in || n != 0 {
			t.Errorf("body %q must be left alone: %q (%d)", in, out, n)
		}
	}
	if out, n := s.ScrubTextIn("Basic authentication required", ContextHeader); n < 1 || strings.Contains(out, "authentication") {
		t.Errorf("header: the value after Basic is a credential: %q (%d)", out, n)
	}

	// The same holds for text that is only visible after URL-decoding.
	if out, n := s.scrubUnwrapped("Basic%20authentication required", ContextBody); out != "Basic%20authentication required" || n != 0 {
		t.Errorf("decoded body prose: %q (%d)", out, n)
	}
	if out, n := s.scrubUnwrapped("Basic%20authentication required", ContextHeader); n < 1 || strings.Contains(out, "authentication") ||
		!strings.HasPrefix(out, "Basic%20") || !strings.HasSuffix(out, " required") {
		t.Errorf("decoded header value: %q (%d)", out, n)
	}
	for _, ctx := range []ScrubContext{ContextBody, ContextHeader} {
		if out, n := s.scrubUnwrapped("Bearer%20authentication required", ctx); n < 1 || strings.Contains(out, "authentication") {
			t.Errorf("context %d: decoded Bearer prose must be redacted: %q (%d)", ctx, out, n)
		}
	}
}

func TestQuoteFollows(t *testing.T) {
	cases := []struct {
		in   string
		i    int
		want bool
	}{
		{`"`, 0, true},
		{`a"`, 1, true},
		{`\"`, 0, true},
		{`\`, 0, false},    // a backslash at the very end
		{`\\`, 0, false},   // an escaped backslash is not a quote
		{`%22`, 0, true},   // URL-encoded quote
		{`%2`, 0, false},   // cut percent-escape
		{`%23`, 0, false},  // another percent-escape
		{`%2f`, 0, false},  // another percent-escape
		{`abc`, 0, false},  // ordinary text
		{`abc`, 3, false},  // index at the end
		{`abc`, 10, false}, // index past the end
		{``, 0, false},
	}
	for _, c := range cases {
		if got := quoteFollows(c.in, c.i); got != c.want {
			t.Errorf("quoteFollows(%q, %d) = %v, want %v", c.in, c.i, got, c.want)
		}
	}
}

func TestUnicodeEscapeASCII(t *testing.T) {
	cases := []struct {
		in   string
		i    int
		want byte
		ok   bool
	}{
		{`\u003d`, 0, '=', true},
		{`\u0026`, 0, '&', true},
		{`\u0041`, 0, 'A', true},
		{`\u007f`, 0, 0x7f, true},
		{`xx\u003d`, 2, '=', true},
		{`\u0000`, 0, 0, true},
		{`\u00e9`, 0, 0, false},   // not ASCII
		{`\u0080`, 0, 0, false},   // first non-ASCII value
		{`\ud800`, 0, 0, false},   // surrogate
		{`\uZZZZ`, 0, 0, false},   // not hex
		{`\u00zz`, 0, 0, false},   // hex ends early
		{`\u003`, 0, 0, false},    // too short
		{`\x003d`, 0, 0, false},   // not a \u escape
		{`au003d`, 0, 0, false},   // no backslash
		{`abc\u003d`, 0, 0, false}, // i does not point at a backslash
		{``, 0, 0, false},
	}
	for _, c := range cases {
		got, ok := unicodeEscapeASCII(c.in, c.i)
		if got != c.want || ok != c.ok {
			t.Errorf("unicodeEscapeASCII(%q, %d) = (%q, %v), want (%q, %v)", c.in, c.i, got, ok, c.want, c.ok)
		}
	}
}

func TestUnwrapEscapedQuotePatterns(t *testing.T) {
	// \\ followed by each kind of quote is left out of the decoded text, so it
	// cannot read as an escaped quote and swallow the next field.
	for _, in := range []string{`a\\"b`, `a\\\"b`, `a\\%22b`} {
		dec, idx := unwrapEscapes(in)
		if len(idx) != len(dec)+1 {
			t.Errorf("%q: idx has %d entries for %d bytes", in, len(idx), len(dec))
		}
		if strings.Contains(dec, `\\`) {
			t.Errorf("%q: dec = %q still holds a double backslash", in, dec)
		}
	}
}

// ---------------------------------------------------------------------------
// coverage: unwrap edge paths
// ---------------------------------------------------------------------------

// Malformed or non-ASCII escapes are kept as written, and idx always has one
// more entry than dec.
func TestRcovUnwrapEscapesKeepsMalformedEscapes(t *testing.T) {
	for _, in := range []string{`a\uZZZZb`, `\ud83d\ude00`, `x\u00`, `100%2`, `\u00e9`} {
		dec, idx := unwrapEscapes(in)
		if len(idx) != len(dec)+1 {
			t.Errorf("%q: idx has %d entries for %d bytes", in, len(idx), len(dec))
		}
		if dec != in {
			t.Errorf("unwrapEscapes(%q) = %q, want it unchanged", in, dec)
		}
	}
	if dec, _ := unwrapEscapes(`\u0041%41`); dec != "AA" {
		t.Errorf(`unwrapEscapes(\u0041%%41) = %q, want "AA"`, dec)
	}
}

// The extra passes keep the false-positive guards: placeholders and short
// "key" values are left alone, a real secret next to a placeholder is not.
func TestRcovUnwrapExtraSpansSkipGuards(t *testing.T) {
	s := newCtxScrubber(t)
	for _, in := range []string{
		"client_secret%3Dxxxxxxxxxxxxxxxxxxxx",
		"Server=db;Password=xxxxxxxx;Port=1%3B",
		"%7B%22password%22%3A%5B%22xxxxxxxxxxxx%22%5D%7D",
		"%7B%22key%22%3A%5B%22short%22%5D%7D",
	} {
		if out, n := s.scrubUnwrapped(in, ContextBody); out != in || n != 0 {
			t.Errorf("scrubUnwrapped(%q) = %q (%d), want it unchanged", in, out, n)
		}
	}
	in := "%7B%22password%22%3A%5B%22xxxxxxxxxxxx%22%2C%22Sup3rS3cretValue%22%5D%7D"
	out, n := s.scrubUnwrapped(in, ContextBody)
	if n < 1 || strings.Contains(out, "Sup3rS3cretValue") || !strings.Contains(out, "xxxxxxxxxxxx") {
		t.Errorf("mixed array: %q (%d)", out, n)
	}
}
