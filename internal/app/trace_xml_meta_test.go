package app

import (
	"net/http"
	"strings"
	"testing"
)

func TestTraceAndCorrelationIDsSurvive(t *testing.T) {
	s := mustScrubber()
	id := "4bf92f3577b34da6a3ce929d0e0e4736"
	for _, name := range []string{"X-Trace-Id", "B3"} {
		h := http.Header{}
		h.Set(name, id)
		key := http.CanonicalHeaderKey(name)
		if m, _ := s.ScrubHeaders(h); m[key] != id {
			t.Errorf("%s changed: %q", name, m[key])
		}
	}
	for _, q := range []string{"trace_id", "traceId", "request_id", "requestId", "correlation_id", "correlationId", "span_id", "spanId", "parent_id"} {
		in := "https://example.com/v1/check?" + q + "=" + id
		if out, n := s.ScrubURL(in); n != 0 || out != in {
			t.Errorf("?%s= value redacted: %q", q, out)
		}
	}
	// Credentials named session_id or token are still redacted.
	for _, q := range []string{"session_id", "token"} {
		if out, n := s.ScrubURL("https://example.com/v1/check?" + q + "=" + id); n < 1 || strings.Contains(out, id) {
			t.Errorf("?%s= hex value not redacted: %q", q, out)
		}
	}
}

func TestBenignXMLMetadataElementsSurvive(t *testing.T) {
	s := mustScrubber()
	for _, in := range []string{
		"<Auth><TokenCount>42</TokenCount></Auth>",
		"<Auth><PasswordLength>16</PasswordLength></Auth>",
		"<Auth><AuthMethod>oauth2</AuthMethod></Auth>",
		"<Auth><SecretName>prod-db</SecretName></Auth>",
		"<Auth><Token><Scope>read</Scope></Token></Auth>",
	} {
		if out, n := s.ScrubText(in); n != 0 || out != in {
			t.Errorf("metadata element changed: %q -> %q (%d)", in, out, n)
		}
	}
	secret := "Zq8Xv3LmP0aTr9YkB2nWd6HsJ4cFe7Gu"
	in := "<Auth><Token>" + secret + "</Token></Auth>"
	if out, n := s.ScrubText(in); n < 1 || strings.Contains(out, secret) {
		t.Errorf("secret token not redacted: %q", out)
	}
}

func TestXMLNameWords(t *testing.T) {
	for in, want := range map[string]string{
		"XMLToken":       "xml,token",
		"PasswordExpiry": "password,expiry",
		"wsse:Password":  "wsse,password",
		"Token2Id":       "token2,id",
		"a_b-c.d":        "a,b,c,d",
		"token":          "token",
		"":               "",
	} {
		if got := strings.Join(xmlNameWords(in), ","); got != want {
			t.Errorf("xmlNameWords(%q) = %q, want %q", in, got, want)
		}
	}
	if !xmlBenignLeaf("TokenType") || xmlBenignLeaf("TokenPrototype") {
		t.Error("benign words are matched whole, not as substrings")
	}
}

func TestScrubXMLTreeDepthLimit(t *testing.T) {
	s := mustScrubber()
	pw := "hunter2hunter2"
	secret := "<Credentials><Value>" + pw + "</Value></Credentials>"
	nest := func(depth int) string {
		return strings.Repeat("<d>", depth) + secret + strings.Repeat("</d>", depth)
	}
	// 126 wrappers + Credentials + Value = 128 open elements: still followed.
	n := 0
	if out := s.scrubXMLTree(nest(xmlTreeMaxDepth-2), &n); n != 1 || strings.Contains(out, pw) {
		t.Errorf("at the limit: n=%d out=%q", n, out)
	}
	// One more wrapper and Value would be the 129th element: the pass stops there.
	n = 0
	deep := nest(xmlTreeMaxDepth - 1)
	if out := s.scrubXMLTree(deep, &n); n != 0 || out != deep {
		t.Errorf("past the limit: n=%d, changed=%v", n, out != deep)
	}
	// Far past the limit the tree pass changes nothing and does not fail.
	n = 0
	deeper := nest(3 * xmlTreeMaxDepth)
	if out := s.scrubXMLTree(deeper, &n); n != 0 || out != deeper {
		t.Errorf("far past the limit: n=%d, changed=%v", n, out != deeper)
	}
}

func TestScrubXMLTreeMalformedAndEscaped(t *testing.T) {
	s := mustScrubber()
	pw := "hunter2hunter2"

	// A document that breaks off: what was read before the break is still scrubbed.
	n := 0
	out := s.scrubXMLTree("<a><Credentials><Value>"+pw+"</Value></Credentials></a><b", &n)
	if n != 1 || strings.Contains(out, pw) || !strings.HasSuffix(out, "</a><b") {
		t.Errorf("truncated document: n=%d out=%q", n, out)
	}
	// Garbage never panics and changes nothing.
	for _, in := range []string{"<<<>>>", "<a", "</a>", "<a></b></a>", "<!-- c -->", "<?xml version=\"1.0\"?", "&lt;", "<a b='c>"} {
		n = 0
		if out := s.scrubXMLTree(in, &n); n != 0 || out != in {
			t.Errorf("%q: n=%d out=%q", in, n, out)
		}
	}
	// Text without markup or escaped markup is not parsed at all.
	n = 0
	if out := s.scrubXMLTree("plain text only", &n); n != 0 || out != "plain text only" {
		t.Errorf("plain text: n=%d out=%q", n, out)
	}
	// So is a document over the size limit.
	big := "<a>" + strings.Repeat("x", xmlTreeMaxInput) + "</a>"
	n = 0
	if out := s.scrubXMLTree(big, &n); n != 0 || len(out) != len(big) {
		t.Errorf("oversized document: n=%d", n)
	}

	// Escaped markup as text, with and without a secret; a short escape is not read.
	n = 0
	esc := "&lt;Password&gt;" + pw + "&lt;/Password&gt;"
	if out := s.scrubXMLTree(esc, &n); n < 1 || strings.Contains(out, pw) || !strings.Contains(out, "&lt;Password&gt;") {
		t.Errorf("escaped secret: n=%d out=%q", n, out)
	}
	n = 0
	harmless := "&lt;b&gt;hello world text&lt;/b&gt;"
	if out := s.scrubXMLTree(harmless, &n); n != 0 || out != harmless {
		t.Errorf("harmless escaped markup: n=%d out=%q", n, out)
	}
	n = 0
	if out := s.scrubXMLTree("<m>&lt;a&gt;</m>", &n); n != 0 || out != "<m>&lt;a&gt;</m>" {
		t.Errorf("short escaped markup: n=%d out=%q", n, out)
	}
}

func TestScrubXMLTreeSkips(t *testing.T) {
	s := mustScrubber()
	for _, in := range []string{
		"<Password>${DB_PASS}</Password>",
		"<Password>[REDACTED_TOKEN#1]</Password>",
		"<Password>   </Password>",
		"<Token><Format>JWT</Format></Token>",
		"<d><![CDATA[   ]]></d>",
		"<d><![CDATA[just some ordinary text]]></d>",
	} {
		n := 0
		if out := s.scrubXMLTree(in, &n); n != 0 || out != in {
			t.Errorf("%q: n=%d out=%q", in, n, out)
		}
	}
	// CDATA under a secret element is a secret as a whole.
	n := 0
	if out := s.scrubXMLTree("<Secret><![CDATA[hunter2hunter2]]></Secret>", &n); n != 1 || strings.Contains(out, "hunter2") {
		t.Errorf("cdata secret: n=%d out=%q", n, out)
	}
}
