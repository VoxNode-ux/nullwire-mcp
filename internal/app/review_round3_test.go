package app

import (
	"net/http"
	"strings"
	"testing"
)

func TestDSNWithUserInfoCountsOnce(t *testing.T) {
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	before := s.Tokens.Load()
	out, n := s.ScrubText("dsn=postgres://app:Sup3rS3cretPw@db.example.com:5432/app")
	if strings.Contains(out, "Sup3rS3cretPw") {
		t.Fatalf("password leaked: %q", out)
	}
	if n != 1 || s.Tokens.Load()-before != 1 {
		t.Errorf("redactions = %d, counter delta = %d; want 1 and 1 (%q)", n, s.Tokens.Load()-before, out)
	}
}

func TestLegacySkKeyNarrowedToAlphanumeric(t *testing.T) {
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	if in := "id sk-checkout-payment-panel-v2 end"; true {
		if out, n := s.ScrubText(in); n != 0 || out != in {
			t.Errorf("kebab id changed: %q -> %q", in, out)
		}
	}
	key := "sk-" + strings.Repeat("A1b2", 8)
	if out, n := s.ScrubText("key " + key); n < 1 || strings.Contains(out, key) {
		t.Errorf("legacy key not redacted: %q", out)
	}
}

func TestAzureSASSignatureRedacted(t *testing.T) {
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	for _, sig := range []string{"Zx9Yw%2FkQ7pL3mN8vB2cD5fG1hJ4sA6tU0eR%3D", "Zx9Yw/kQ7pL3mN8vB2cD5fG1hJ4sA6tU0eR+8="} {
		in := "https://acct.blob.core.windows.net/c/b?sv=2022-11-02&se=2026-12-01&sp=r&sig=" + sig
		out, n := s.ScrubText(in)
		if n < 1 || strings.Contains(out, sig) || strings.Contains(out, "kQ7pL3mN8") {
			t.Errorf("SAS signature not redacted: %q", out)
		}
	}
}

func TestHexIdentifiersInHeadersAndQueriesSurvive(t *testing.T) {
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	trace := "80f198ee56343ba864fe8b2a57d3eff7"
	for _, name := range []string{"X-B3-TraceId", "Sentry-Trace"} {
		h := http.Header{}
		h.Set(name, trace)
		key := http.CanonicalHeaderKey(name)
		if m, _ := s.ScrubHeaders(h); m[key] != trace {
			t.Errorf("%s changed: %q", name, m[key])
		}
	}
	sha := "9fceb02d0ae598e95dc970b74767f19372d61af8"
	for _, q := range []string{"sha", "commit_sha", "digest"} {
		in := "https://example.com/v1/check?" + q + "=" + sha
		if out, n := s.ScrubURL(in); n != 0 || out != in {
			t.Errorf("?%s= value redacted: %q", q, out)
		}
	}
	// A bare hex value under an unrelated name is still redacted.
	if out, n := s.ScrubURL("https://example.com/hook?x=" + sha); n < 1 || strings.Contains(out, sha) {
		t.Errorf("unnamed hex secret not redacted: %q", out)
	}
}