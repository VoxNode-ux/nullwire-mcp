package app

import (
	"strings"
	"testing"
)

func TestIsPlaceholderValue(t *testing.T) {
	yes := []string{"${OPENAI_API_KEY}", "${{ secrets.TOKEN }}", "{{api_key}}", "%API_KEY%", "******", "xxxxxxxx", "XXXXXXXX", "true", "null", "changeme", "..."}
	no := []string{"", "sk_live_abc123", "%a b%", "xxxxxxxy", "hunter2", "50%off%"}
	for _, v := range yes {
		if !isPlaceholderValue(v) {
			t.Errorf("%q should be a placeholder", v)
		}
	}
	for _, v := range no {
		if isPlaceholderValue(v) {
			t.Errorf("%q should not be a placeholder", v)
		}
	}
}

func TestIsAllowMarkOnly(t *testing.T) {
	if !isAllowMarkOnly(allowMark + "0\x00") || !isAllowMarkOnly(allowMark + "12\x00") {
		t.Error("plain placeholders should match")
	}
	for _, v := range []string{"REAL_SECRET_" + allowMark + "0\x00", allowMark + "\x00", allowMark + "a\x00", allowMark + "0", ""} {
		if isAllowMarkOnly(v) {
			t.Errorf("%q should not match", v)
		}
	}
}

func TestSecretishKeyCarveOuts(t *testing.T) {
	for _, k := range []string{"public_key", "Primary-Key", "keyId", "token_url", "withCredentials", "author", "monkey", "secret_name"} {
		if secretishKey(k) {
			t.Errorf("%q should not be secret-ish", k)
		}
	}
	for _, k := range []string{"api_key", "access_token", "client_secret", "sig", "x_sig", "stripeKey", "password"} {
		if !secretishKey(k) {
			t.Errorf("%q should be secret-ish", k)
		}
	}
}

func TestPlaceholderValuesSurviveScrub(t *testing.T) {
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	keep := []string{
		`{"api_key": "${OPENAI_API_KEY}"}`,
		`{"password": "{{ db_password }}"}`,
		`token=%API_TOKEN%`,
		`{"secret": "********"}`,
		`<Password>${DB_PASS}</Password>`,
		`{"password": ["${A}", "******"]}`,
	}
	for _, in := range keep {
		if out, _ := s.ScrubTextIn(in, ContextBody); out != in {
			t.Errorf("placeholder was redacted: %q -> %q", in, out)
		}
	}
	// carved-out field names are not caught by the strict-field rule...
	if out, n := s.scrubStrictFieldsMax("publickey=Ab3dEf6hIj9L", strictFieldMax); n != 0 {
		t.Errorf("publickey redacted: %q", out)
	}
	// ...but a real secret field still is.
	if out, n := s.scrubStrictFieldsMax("stripekey=Ab3dEf6hIj9L", strictFieldMax); n != 1 || strings.Contains(out, "Ab3dEf6hIj9L") {
		t.Errorf("stripekey not redacted: %q", out)
	}
}

func TestNewVendorPrefixesRedact(t *testing.T) {
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{
		"k=glffct-Ab3dEf6hIj9LmN0pQrSt",
		"k=p8e-Ab3dEf6hIj9LmN0pQrSt",
		"k=bedrock-api-key-Ab3dEf6hIj9LmN0pQrSt",
	} {
		out, n := s.ScrubTextIn(in, ContextBody)
		if n == 0 || strings.Contains(out, "Ab3dEf6hIj9L") {
			t.Errorf("not redacted: %q -> %q", in, out)
		}
	}
}

// Bug #1: a secret-named field whose value is an ignore_patterns placeholder
// must keep the exempt text, not get re-tagged by a Stage 2 rule.
func TestIgnoredPatternInSecretFieldsSurvives(t *testing.T) {
	s, err := NewScrubberWithConfig(&SecretsConfig{IgnorePatterns: []string{`pk_test_[A-Za-z0-9]{24}`}})
	if err != nil {
		t.Fatal(err)
	}
	const keep = "pk_test_123456789012345678901234"
	for _, in := range []string{
		`{"api_key": "` + keep + `"}`,
		`?token=` + keep,
		`<secret>` + keep + `</secret>`,
		`https://user:` + keep + `@host`,
		`api_key: pre-` + keep,
	} {
		out, _ := s.ScrubTextIn(in, ContextBody)
		if !strings.Contains(out, keep) {
			t.Errorf("exempt value lost: %q -> %q", in, out)
		}
	}
}
