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

// refPANChain and refMaybeIPv4 are the byte-by-byte rules that hasPANChain
// (stride-12 probe) and maybeIPv4 (IndexByte jumps) replaced. The fast
// versions must agree with them on every input.
func refPANChain(in string) bool {
	chain := 0
	prevDigit := false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if c >= '0' && c <= '9' {
			if chain++; chain >= 13 {
				return true
			}
			prevDigit = true
			continue
		}
		if (c == ' ' || c == '-') && prevDigit {
			prevDigit = false
			continue
		}
		chain, prevDigit = 0, false
	}
	return false
}

func refMaybeIPv4(in string) bool {
	for i := 1; i+1 < len(in); i++ {
		if in[i] == '.' && in[i-1] >= '0' && in[i-1] <= '9' && in[i+1] >= '0' && in[i+1] <= '9' {
			return true
		}
	}
	return false
}

// forEachString calls fn with every string over alpha of length 0..maxLen.
func forEachString(alpha string, maxLen int, fn func(string)) {
	buf := make([]byte, maxLen)
	for n := 0; n <= maxLen; n++ {
		idx := make([]int, n)
		for {
			for i, k := range idx {
				buf[i] = alpha[k]
			}
			fn(string(buf[:n]))
			i := n - 1
			for i >= 0 {
				if idx[i]++; idx[i] < len(alpha) {
					break
				}
				idx[i] = 0
				i--
			}
			if i < 0 {
				break
			}
		}
	}
}

// Every string over small alphabets, so no chain shape or position is skipped.
func TestHasPANChainExhaustive(t *testing.T) {
	check := func(in string) {
		if got, want := hasPANChain(in), refPANChain(in); got != want {
			t.Fatalf("hasPANChain(%q) = %v, reference says %v", in, got, want)
		}
	}
	forEachString("1-", 17, check)
	forEachString("1x", 16, check)
	if !testing.Short() {
		forEachString("1 -", 13, check)
	}
}

func TestMaybeIPv4Exhaustive(t *testing.T) {
	check := func(in string) {
		if got, want := maybeIPv4(in), refMaybeIPv4(in); got != want {
			t.Fatalf("maybeIPv4(%q) = %v, reference says %v", in, got, want)
		}
	}
	forEachString("1.x", 10, check)
	forEachString("1. ", 10, check)
}

// A chain of every shape slid across every offset mod 12, with and without
// trailing text: the stride-12 probe must catch it wherever it falls.
func TestHasPANChainEveryStrideOffset(t *testing.T) {
	cases := []struct {
		chain string
		want  bool
	}{
		{"4111111111111", true},
		{"4111 1111 1111 1111", true},
		{"4111-1111-1111-1111", true},
		{"1 2 3 4 5 6 7 8 9 0 1 2 3", true},
		{"411111111111", false},
		{"4111  1111 1111 1111", false},
		{"4111 -1111 1111 1111", false},
		{"4111.1111.1111.1111", false},
	}
	for _, c := range cases {
		chain, want := c.chain, c.want
		for pad := 0; pad <= 60; pad++ {
			for _, tail := range []int{0, 1, 5, 13, 24} {
				for _, lead := range []string{"x", "-", " ", "9  "} {
					in := strings.Repeat(lead, pad) + chain + strings.Repeat("x", tail)
					got, ref := hasPANChain(in), refPANChain(in)
					if got != ref {
						t.Fatalf("hasPANChain(%q) = %v, reference says %v", in, got, ref)
					}
					if lead == "x" && got != want {
						t.Fatalf("hasPANChain(%q) = %v, want %v", in, got, want)
					}
				}
			}
		}
	}
}

// Random texts shaped like card numbers: noise, 8..17 digits with random
// single or double separators, noise. Fixed seed, so a failure repeats.
func TestHasPANChainRandomStructured(t *testing.T) {
	r := rand.New(rand.NewSource(20261120))
	const noise = "x.:a "
	n := 300000
	if testing.Short() {
		n = 30000
	}
	for i := 0; i < n; i++ {
		var b []byte
		for j := r.Intn(40); j > 0; j-- {
			b = append(b, noise[r.Intn(len(noise))])
		}
		for d, digits := 0, 8+r.Intn(10); d < digits; d++ {
			b = append(b, byte('0'+r.Intn(10))) // #nosec G115 -- r.Intn(10) is 0..9
			switch r.Intn(6) {
			case 0:
				b = append(b, ' ')
			case 1:
				b = append(b, '-')
			case 2:
				if r.Intn(4) == 0 {
					b = append(b, ' ', '-')
				}
			}
		}
		for j := r.Intn(40); j > 0; j-- {
			b = append(b, noise[r.Intn(len(noise))])
		}
		in := string(b)
		if got, want := hasPANChain(in), refPANChain(in); got != want {
			t.Fatalf("hasPANChain(%q) = %v, reference says %v", in, got, want)
		}
	}
}

// The whole tail (IPv6, IPv4, card numbers) with each kind of match slid
// across every offset, alone and together: nothing may be missed versus the
// ungated rules.
func TestScrubTailEveryStrideOffset(t *testing.T) {
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	parts := []string{
		"4111 1111 1111 1111", "4111111111111111", "4111-1111-1111-1111",
		"5500 0000 0000 0004", "10.0.0.1", "192.168.1.20", "fe80::1", "2001:db8::8a2e:370:7334",
	}
	for pad := 0; pad < 40; pad++ {
		lead := strings.Repeat("x", pad)
		for _, p := range parts {
			checkTail(t, s, lead+p)
			checkTail(t, s, lead+p+" tail "+p)
		}
		checkTail(t, s, lead+strings.Join(parts, " | "))
	}
}
