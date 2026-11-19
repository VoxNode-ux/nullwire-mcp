package app

import (
	"math/rand"
	"strings"
	"testing"
)

// ungatedTail is the reference: the IPv6, IPv4 and card-number rules exactly as
// scrubLayersOpts ran them before the PAN gate existed. IPv6 and IPv4 keep
// their original gates (a text with fewer than two ':' holds no IPv6 address;
// maybeIPv4 is the long-standing IPv4 pre-check). The PAN rule runs on every
// input.
func ungatedTail(s *Scrubber, out string, skipIP bool) (string, int) {
	count := 0
	if !skipIP && strings.Count(out, ":") >= 2 {
		var n int
		out, n = s.scrubIPv6(out)
		count += n
	}
	if !skipIP && maybeIPv4(out) {
		out = replaceIPv4(s, out, &count)
	}
	var nPAN int
	out, nPAN = s.scrubPANs(out)
	count += nPAN
	return out, count
}

func checkTail(t *testing.T, s *Scrubber, in string) {
	t.Helper()
	for _, skipIP := range []bool{false, true} {
		wantOut, wantN := ungatedTail(s, in, skipIP)
		gotOut, gotN := s.scrubTail(in, skipIP)
		if gotOut != wantOut || gotN != wantN {
			t.Fatalf("scrubTail differs from the ungated rules (skipIP=%v)\n in:   %q\n want: %q (%d)\n got:  %q (%d)",
				skipIP, clipTail(in), clipTail(wantOut), wantN, clipTail(gotOut), gotN)
		}
	}
	// The gate on its own: it may never be false where panSpans matches.
	if len(panSpans(in)) > 0 && !hasPANChain(in) {
		t.Fatalf("hasPANChain false but panSpans matches %q", clipTail(in))
	}
}

func clipTail(s string) string {
	if len(s) > 120 {
		return s[:60] + "..." + s[len(s)-60:]
	}
	return s
}

func TestHasPANChain(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"hello world", false},
		{"4111111111111111", true},
		{"4111 1111 1111 1111", true},
		{"4111-1111-1111-1111", true},
		{"4111  1111 1111 1111", false}, // two spaces break the chain
		{"4111 -1111 1111 1111", false},
		{"411111111111", false}, // 12 digits
		{"4111111111111", true}, // 13 digits
		{"4111.1111.1111.1111", false},
		{"4111:1111:1111:1111", false},
		{"1 2 3 4 5 6 7 8 9 0 1 2 3", true}, // 13 digits, single separators
		{"-4111111111111", true},
	}
	for _, c := range cases {
		if got := hasPANChain(c.in); got != c.want {
			t.Errorf("hasPANChain(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// Fixed cases, including the ones the old static table held.
func TestScrubTailMatchesUngated(t *testing.T) {
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{
		"", "hello world", "a:b", "fe80::1", "10.0.0.1", "v1.2", "a.b",
		"4111111111111111", "4111 1111 1111 1111", "4111-1111-1111-1111",
		"4111  1111 1111 1111", "411111111111", "4111.1111.1111.1111",
		"order 4111 1111 1111 1111 shipped to 10.0.0.1 via fe80::1 ok",
		"5500 0000 0000 0004 and 3400-0000-0000-009 and 6011000000000004",
		"x4111111111111111", "4111111111111111x", "1.4111111111111111",
		"2001:db8::ff00:42:8329", "::1 ::", "12:34:56",
	} {
		checkTail(t, s, in)
	}
}

// Random texts over an alphabet that is all structure: digits, separators,
// dots, colons, hex letters. Fixed seed, so a failure repeats.
func TestScrubTailRandomDifferential(t *testing.T) {
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	r := rand.New(rand.NewSource(20260619))
	alpha := []byte("0123456789 -.:abcdefx4")
	n := 20000
	if testing.Short() {
		n = 2000
	}
	for i := 0; i < n; i++ {
		b := make([]byte, r.Intn(90))
		for j := range b {
			// digits twice as likely, so 13+ chains appear often
			if r.Intn(3) > 0 {
				b[j] = '0' + byte(r.Intn(10))
			} else {
				b[j] = alpha[r.Intn(len(alpha))]
			}
		}
		checkTail(t, s, string(b))
	}
}

// The scrub-first, cut-second rule: texts reach the tail rules up to
// reqBody+scrubWindow bytes long, cut wherever the limit falls. Put a card
// number, an IPv4 and an IPv6 address on both sides of every cut that matters
// and straddling it, then compare the gated and ungated rules on the text
// whole and on each cut.
func TestScrubTailCutBoundary(t *testing.T) {
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	const reqBody = 32 << 10
	cuts := []int{reqBody, reqBody + scrubWindow}
	items := []string{
		"4111 1111 1111 1111", "4111111111111111", "4111-1111-1111-1111",
		"10.20.30.40", "fe80::1ff:fe23:4567:890a", "2001:db8::1",
	}
	for _, cut := range cuts {
		for _, it := range items {
			for off := -len(it) - 1; off <= 1; off++ { // from fully before the cut to fully after it
				pos := cut + off
				var sb strings.Builder
				sb.WriteString(strings.Repeat("x ", pos/2))
				sb.WriteString(" " + it + " ")
				sb.WriteString(strings.Repeat("y ", 64))
				text := sb.String()
				checkTail(t, s, text)
				for _, c := range cuts {
					if c < len(text) {
						checkTail(t, s, text[:c])
					}
				}
			}
		}
	}
}

func FuzzScrubTailGates(f *testing.F) {
	for _, seed := range []string{
		"", "4111 1111 1111 1111", "10.0.0.1", "fe80::1", "4111  1111 1111 1111",
		"1 2 3 4 5 6 7 8 9 0 1 2 3", "a:b:c", "4111.1111.1111.1111",
		strings.Repeat("x", 32<<10-8) + "4111 1111 1111 1111",
		strings.Repeat("x", 32<<10+scrubWindow-6) + "10.0.0.1",
	} {
		f.Add(seed)
	}
	s, err := NewScrubber()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, in string) {
		checkTail(t, s, in)
	})
}
