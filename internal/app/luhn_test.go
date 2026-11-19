package app

import (
	"strings"
	"testing"
)

func TestScrubPANs(t *testing.T) {
	s := mustScrubber()
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

// pbDigits returns the digit values (0-9) of s followed by zeros, as panNetworkOK and luhnValid expect.
func pbDigits(s string) ([]byte, int) {
	d := make([]byte, 20)
	for i := 0; i < len(s); i++ {
		d[i] = s[i] - '0'
	}
	return d, len(s)
}

func TestLuhnAndNetworkBoundaries(t *testing.T) {
	for in, want := range map[string]bool{
		"4111111111111111": true,
		"4111111111111112": false,
		"378282246310005":  true,
		"0":                true,
		"18":               true,
		"19":               false,
	} {
		d, n := pbDigits(in)
		if got := luhnValid(d, n); got != want {
			t.Errorf("luhnValid(%s) = %v, want %v", in, got, want)
		}
	}
	for _, c := range []struct {
		digits string
		want   bool
	}{
		{"411111111111", false},         // 12 digits: too short
		{"41111111111111111111", false}, // 20 digits: too long
		{"4111111111111", true},         // Visa, 13
		{"4111111111111111", true},      // Visa, 16
		{"4111111111111111111", true},   // Visa, 19
		{"411111111111111", false},      // Visa, 15
		{"5100000000000000", true},      // Mastercard 51
		{"5500000000000000", true},      // Mastercard 55
		{"5600000000000000", false},     // not Mastercard
		{"2221000000000000", true},      // Mastercard 2-series, low end
		{"2720000000000000", true},      // Mastercard 2-series, high end
		{"2721000000000000", false},     // just past the range
		{"2220000000000000", false},     // just before the range
		{"340000000000000", true},       // Amex
		{"370000000000000", true},       // Amex
		{"3400000000000000", false},     // Amex with 16 digits
		{"6011000000000000", true},      // Discover 6011
		{"6500000000000000", true},      // Discover 65
		{"6500000000000000000", true},   // Discover, 19
		{"601100000000000", false},      // Discover, 15
		{"9111111111111111", false},     // unknown network
		{"3000000000000000", false},     // unknown network
	} {
		d, n := pbDigits(c.digits)
		if got := panNetworkOK(d, n); got != c.want {
			t.Errorf("panNetworkOK(%s) = %v, want %v", c.digits, got, c.want)
		}
	}
}

func TestPANSpansEdgeCases(t *testing.T) {
	cases := []struct {
		name, in string
		want     int
	}{
		{"too short for any card", "4111 1111", 0},
		{"plain visa", "card 4111111111111111 ok", 1},
		{"dashes", "4111-1111-1111-1111", 1},
		{"spaces", "4111 1111 1111 1111", 1},
		{"double separator", "4111  1111 1111 1111", 0},
		{"trailing separator", "4111-1111-1111-1111-", 1},
		{"twenty-plus digits", "41111111111111111111111", 0},
		{"after a letter", "x4111111111111111", 0},
		{"before a letter", "4111111111111111x", 0},
		{"after a decimal point", "3.4111111111111111", 0},
		{"before a decimal point and digit", "4111111111111111.5", 0},
		{"before a sentence-ending dot", "4111111111111111.", 1},
		{"after a dot that is not a decimal", "a. 4111111111111111", 1},
		{"two cards", "4111111111111111 and 5500005555555559", 2},
		{"amex", "378282246310005", 1},
		{"discover", "6011111111111117", 1},
		{"mastercard 2-series", "2223003122003222", 1},
		{"13-digit visa", "4222222222222", 1},
		{"fails luhn", "4111111111111112", 0},
		{"timestamp", "1699999999999999", 0},
		{"no digits", "no digits in this long line of text", 0},
	}
	for _, c := range cases {
		if got := panSpans(c.in); len(got) != c.want {
			t.Errorf("%s: panSpans(%q) found %d, want %d", c.name, c.in, len(got), c.want)
		}
	}
	// The span covers the digits and their separators, not the text around them.
	in := "pay 4111-1111-1111-1111 now"
	if sp := panSpans(in); len(sp) != 1 || in[sp[0].start:sp[0].end] != "4111-1111-1111-1111" {
		t.Errorf("span = %v", sp)
	}
	s := mustScrubber()
	if out, n := s.scrubPANs("no card here"); out != "no card here" || n != 0 {
		t.Errorf("no card: %q, %d", out, n)
	}
	out, n := s.scrubPANs("a 4111111111111111 b 4111111111111111 c")
	if n != 2 || strings.Contains(out, "4111") || !strings.HasPrefix(out, "a ") || !strings.HasSuffix(out, " c") {
		t.Errorf("two PANs: %q, %d", out, n)
	}
}
