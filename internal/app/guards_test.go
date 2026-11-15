package app

import (
	"net/http"
	"strings"
	"testing"
)

func TestPANTagInCurlExport(t *testing.T) {
	if got := envFor("PAN"); got != "NULLWIRE_CARD_NUMBER" {
		t.Fatalf("envFor(PAN) = %q", got)
	}
	if !reTag.MatchString("[REDACTED_PAN#abc123]") {
		t.Fatal("reTag must accept PAN")
	}
}

func TestResetCountersClearsTaintRing(t *testing.T) {
	s, _ := NewScrubber()
	secret := "Zq8Xv3LmP0aTr9YkB2nWd6HsJ4cFe7Gu"
	_ = s.tag("TOKEN", secret)
	if out, n := s.scrubTainted("x=" + secret); n != 1 {
		t.Fatalf("ring should match before reset: %q", out)
	}
	s.ResetCounters()
	if out, n := s.scrubTainted("x=" + secret); n != 0 {
		t.Fatalf("ring should be empty after reset: %q", out)
	}
}

func TestTaintRingDoesNotOverrideExemptHeaders(t *testing.T) {
	s, _ := NewScrubber()
	val := "Zq8Xv3LmP0aTr9YkB2nWd6HsJ4cFe7Gu"
	_ = s.tag("TOKEN", val)
	h := http.Header{}
	h.Set("X-Request-Id", val)
	m, _ := s.ScrubHeaders(h)
	if m["X-Request-Id"] != val {
		t.Fatalf("exempt header was redacted by the ring: %q", m["X-Request-Id"])
	}
}

func TestCloudRulesKeepPlaceholders(t *testing.T) {
	s, _ := NewScrubber()
	for _, in := range []string{
		"Server=db;Password=${DB_PASS};Uid=app",
		"Server=db;Password=******;Uid=app",
		"aws_secret_access_key=${AWS_SECRET_ACCESS_KEY}",
	} {
		if out, _ := s.ScrubTextIn(in, ContextBody); out != in {
			t.Errorf("placeholder redacted: %q -> %q", in, out)
		}
	}
}

func TestBareKeyAndProseFalsePositives(t *testing.T) {
	s, _ := NewScrubber()
	keep := []string{
		`{"Key": "uploads/2026/avatar.png"}`,
		`{"key": "submit"}`,
		`{"key": "user:123"}`,
		`?key=dark-mode`,
		`Invalid token provided`,
		`basic authentication required`,
	}
	for _, in := range keep {
		if out, _ := s.ScrubTextIn(in, ContextBody); out != in {
			t.Errorf("over-redacted: %q -> %q", in, out)
		}
	}
	// real values are still caught
	for _, in := range []string{
		`{"key": "Zq8Xv3LmP0aTr9YkB2nWd6HsJ4cFe7Gu"}`,
		`Authorization: Bearer Zq8Xv3LmP0aTr9YkB2nWd6HsJ`,
		`Basic dXNlcjpwYXNzd29yZDEyMw==`,
	} {
		if out, n := s.ScrubTextIn(in, ContextBody); n == 0 {
			t.Errorf("missed: %q -> %q", in, out)
		}
	}
}

func TestResourceIDsAndVersionsSurvive(t *testing.T) {
	s, _ := NewScrubber()
	keep := []string{
		"id=req_01J9XK2M8P4Q7R5T",
		"id=cus_R7kM2pQ9vX4wY1zA",
		"id=vpc-0a1b2c3d4e5f67890",
		"id=01ARZ3NDEKTSV4RRFFQ69G5FAV",
		"integrity=sha256-47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
		"User-Agent: Chrome/120.0.6099.109",
	}
	for _, in := range keep {
		if out, _ := s.ScrubTextIn(in, ContextBody); out != in {
			t.Errorf("over-redacted: %q -> %q", in, out)
		}
	}
	if out, n := s.ScrubTextIn("host 10.1.2.3 up", ContextBody); n != 1 || strings.Contains(out, "10.1.2.3") {
		t.Errorf("plain IPv4 must still be redacted: %q", out)
	}
	// a Stripe client secret contains _secret_ and is still a secret
	if out, n := s.ScrubTextIn("pi_3Qx9Kp2LmN4oPqRs_secret_Zq8Xv3LmP0aTr9Yk", ContextBody); n == 0 {
		t.Errorf("client secret missed: %q", out)
	}
}

func TestBase64ImageDoesNotExhaustSecretBudget(t *testing.T) {
	s, _ := NewScrubber()
	// Five ~67 KB runs separated by spaces: each is under b64MaxEncoded (88 KB)
	// so it is decoded, and together they are over b64Budget (256 KB) of
	// binary-looking base64. The secret after them must still be found.
	chunk := strings.Repeat("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4", 1200) // 67,200 bytes
	img := strings.Join([]string{chunk, chunk, chunk, chunk, chunk}, " ")
	secret := "Zm9vOnNrX2xpdmVfYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=" // base64 of a key
	out, n := s.ScrubTextIn("data:image/png;base64,"+img+" tok="+secret, ContextBody)
	if n == 0 || strings.Contains(out, secret) {
		t.Errorf("secret after binary base64 images was not redacted (n=%d)", n)
	}
}
