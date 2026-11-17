package app

import (
	"net/http"
	"strings"
	"testing"
)

func TestTraceAndCorrelationIDsSurvive(t *testing.T) {
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
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
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
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
