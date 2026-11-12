package main

import (
	"strings"
	"testing"
)

// validSecretShape limits fuzz input to values the scrubber is designed to
// catch: long enough for the Bearer rule, and only the characters its
// patterns accept. Anything else is skipped, so a failure always means a real
// gap in a rule we claim to cover, not a value outside the rules.
func validSecretShape(s string) bool {
	if len(s) < 8 || len(s) > 200 {
		return false
	}
	// Our own tag text. A "secret" containing it would match the output by design.
	if strings.Contains(s, "REDACTED") {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.ContainsRune("._~+/=-", c):
		default:
			return false
		}
	}
	return true
}

// FuzzScrubberNoLeak checks the core promise: a secret placed in a known
// location never survives scrubbing, whatever its exact characters are.
func FuzzScrubberNoLeak(f *testing.F) {
	f.Add("abcdefghijklmnop")
	f.Add("sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	f.Add("my_secret_token_123")
	f.Fuzz(func(t *testing.T, secret string) {
		if !validSecretShape(secret) {
			t.Skip()
		}
		s, err := NewScrubber()
		if err != nil {
			t.Fatal(err)
		}
		inputs := []string{
			"Authorization: Bearer " + secret,
			`{"access_token":"` + secret + `","ok":true}`,
			"https://api.test/x?api_key=" + secret + "&a=1",
		}
		for _, in := range inputs {
			out, _ := s.ScrubText(in)
			if strings.Contains(out, secret) {
				t.Fatalf("secret survived scrubbing\ninput:  %q\noutput: %q", in, out)
			}
		}
	})
}

// FuzzScrubberDeterministic checks the correlation promise: the same value
// always gets the same tag within one scrubber, so the agent can compare
// requests.
func FuzzScrubberDeterministic(f *testing.F) {
	f.Add("abcdefghijklmnop")
	f.Fuzz(func(t *testing.T, secret string) {
		if !validSecretShape(secret) {
			t.Skip()
		}
		s, err := NewScrubber()
		if err != nil {
			t.Fatal(err)
		}
		in := "Authorization: Bearer " + secret
		a, _ := s.ScrubText(in)
		b, _ := s.ScrubText(in)
		if a != b {
			t.Fatalf("same input gave different tags:\n%q\n%q", a, b)
		}
	})
}

// FuzzScrubberNoPanic feeds arbitrary bytes. The proxy scrubs untrusted
// traffic, so a panic here would be a denial of service.
func FuzzScrubberNoPanic(f *testing.F) {
	f.Add("GET / HTTP/1.1\r\nCookie: a=b\r\n\r\n")
	f.Fuzz(func(t *testing.T, in string) {
		s, err := NewScrubber()
		if err != nil {
			t.Fatal(err)
		}
		_, _ = s.ScrubText(in)
	})
}
