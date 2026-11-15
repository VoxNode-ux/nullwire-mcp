package app

import (
	"strings"
	"testing"
)

func TestScrubPANs(t *testing.T) {
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	redact := []string{
		"card 4111111111111111 end",
		"card=4111-1111-1111-1111;",
		"pan 5500 0000 0000 0004.",
		"amex 378282246310005",
		"disc 6011111111111117",
	}
	for _, in := range redact {
		out, n := s.scrubPANs(in)
		if n != 1 || !strings.Contains(out, "[REDACTED_PAN#") {
			t.Errorf("%q -> %q (%d)", in, out, n)
		}
	}
	keep := []string{
		"ts 1700000000123456789",      // nanosecond timestamp
		"order 4111111111111112",      // fails Luhn
		"id 12345678901234567",        // no network prefix
		"x_4111111111111111",          // glued to an identifier
		"v 1.4111111111111111",        // fractional part
		"short 411111111111",          // too short
	}
	for _, in := range keep {
		if out, n := s.scrubPANs(in); n != 0 || out != in {
			t.Errorf("%q changed: %q", in, out)
		}
	}
}
