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

func TestProseAfterSchemeContexts(t *testing.T) {
	for _, c := range []struct {
		scheme, tok string
		ctx         ScrubContext
		want        bool
	}{
		{"Basic", "invalid", ContextBody, true},
		{"token", "expired", ContextBody, true},
		{"Basic", "Invalid", ContextBody, false},
		{"Basic", "abc1", ContextBody, false},
		{"Basic", "a_b", ContextBody, false},
		{"Bearer", "invalid", ContextBody, false},
		{"BEARER", "invalid", ContextBody, false},
		{"Basic", "invalid", ContextHeader, false},
		{"Basic", "invalid", ContextQuery, false},
	} {
		if got := proseAfterScheme(c.scheme, c.tok, c.ctx); got != c.want {
			t.Errorf("proseAfterScheme(%q, %q, %v) = %v, want %v", c.scheme, c.tok, c.ctx, got, c.want)
		}
	}
}

func TestBenignBareKeyVariants(t *testing.T) {
	long := "Sup3rS3cretValueZZ"
	for _, c := range []struct {
		prefix, val string
		want        bool
	}{
		{`"key": "`, "short", true},
		{`"key":"`, "a/b/c/long/path/value", true},
		{`key=`, "id:12345678901234", true},
		{`"Key" : `, "two words in a value", true},
		{`  KEY:`, "tiny", true},
		{`"key":[`, "short", true},
		{`"key": "`, `back\slash-long-value`, true},
		{`"key": "`, long, false},
		{`"key": "`, strings.Repeat("a", 11), true},
		{`"key": "`, strings.Repeat("a", 12), false},
		{`"apikey": "`, "short", false},
		{`"api_key": "`, "short", false},
		{`"keys": "`, "short", false},
		{``, "short", false},
		{`"`, "short", false},
		{`=`, "short", false},
	} {
		if got := benignBareKey(c.prefix, c.val); got != c.want {
			t.Errorf("benignBareKey(%q, %q) = %v, want %v", c.prefix, c.val, got, c.want)
		}
	}
}

func TestBenignResourceIDsAndULIDs(t *testing.T) {
	for _, s := range []string{
		"req_abc123", "msg_x", "resp_x", "ch_x", "cus_x", "in_x", "sub_x", "pi_x", "pm_x", "evt_x", "cs_x",
		"i-0abc", "vpc-0abc", "ami-0abc", "subnet-0abc", "sg-0abc",
		"sha256-abcdef", "sha384-abcdef", "sha512-abcdef",
		"01ARZ3NDEKTSV4RRFFQ69G5FAV",
	} {
		if !benignResourceID(s) {
			t.Errorf("%q should be a benign resource id", s)
		}
	}
	for _, s := range []string{
		"pi_abc_secret_xyz", "cs_live_secret_abc", "", "token_abc", "i-1abc", "sha1-abc",
		"81ARZ3NDEKTSV4RRFFQ69G5FAV",  // first character past 7
		"01ARZ3NDEKTSV4RRFFQ69G5FAI",  // I is not Crockford base32
		"01ARZ3NDEKTSV4RRFFQ69G5FAL",  // L
		"01ARZ3NDEKTSV4RRFFQ69G5FAO",  // O
		"01ARZ3NDEKTSV4RRFFQ69G5FAU",  // U
		"01arz3ndektsv4rrffq69g5fav",  // lower case
		"01ARZ3NDEKTSV4RRFFQ69G5FA",   // 25 characters
		"01ARZ3NDEKTSV4RRFFQ69G5FAVX", // 27 characters
		"01ARZ3NDEKTSV4RRFFQ69G5FA-",  // a symbol
	} {
		if benignResourceID(s) {
			t.Errorf("%q must not be a benign resource id", s)
		}
	}
	if isULID("") || !isULID("7ZZZZZZZZZZZZZZZZZZZZZZZZZ") || isULID("8ZZZZZZZZZZZZZZZZZZZZZZZZZ") {
		t.Error("isULID boundaries")
	}
}

func TestReplaceIPv4Skips(t *testing.T) {
	s := fxApp(t).scrub
	for name, in := range map[string]string{
		"version after Product/":  "Chrome/120.0.6099.109",
		"loopback":                "connect 127.0.0.1 now",
		"unspecified":             "bind 0.0.0.0 now",
		"no address":              "nothing here",
		"leading zeros":           "host 01.02.03.04 end",
		"version in a longer UA":  "ua Mozilla/5.0 Safari/537.36 Edge/120.0.2210.91",
	} {
		count := 0
		if out := replaceIPv4(s, in, &count); out != in || count != 0 {
			t.Errorf("%s: %q -> %q (%d)", name, in, out, count)
		}
	}
	// An address in a URL path is not a product version.
	count := 0
	out := replaceIPv4(s, "GET /api/10.20.30.40 and /x/Chrome/8.8.4.4 end", &count)
	if count != 2 || strings.Contains(out, "10.20.30.40") || strings.Contains(out, "8.8.4.4") {
		t.Errorf("addresses in paths: %q (%d)", out, count)
	}
}
