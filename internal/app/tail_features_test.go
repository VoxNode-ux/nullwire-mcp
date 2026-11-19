package app

import "testing"

func TestScanTailFeatures(t *testing.T) {
	cases := []struct {
		in                      string
		colons, dotDigit, panCh bool
	}{
		{"", false, false, false},
		{"hello world", false, false, false},
		{"a:b", false, false, false},
		{"fe80::1", true, false, false},
		{"10.0.0.1", false, true, false},
		{"v1.2", false, true, false},
		{"a.b", false, false, false},
		{"4111111111111111", false, false, true},
		{"4111 1111 1111 1111", false, false, true},
		{"4111-1111-1111-1111", false, false, true},
		{"4111  1111 1111 1111", false, false, false}, // two spaces break the chain
		{"411111111111", false, false, false},           // 12 digits
		{"4111.1111.1111.1111", false, true, false},
	}
	for _, c := range cases {
		f := scanTailFeatures(c.in)
		if f.colons != c.colons || f.dotDigit != c.dotDigit || f.panChain != c.panCh {
			t.Errorf("scanTailFeatures(%q) = %+v", c.in, f)
		}
		// the flags must never be false where the real rule would match
		if len(panSpans(c.in)) > 0 && !f.panChain {
			t.Errorf("panChain false but panSpans matches %q", c.in)
		}
		if maybeIPv4(c.in) && !f.dotDigit {
			t.Errorf("dotDigit false but maybeIPv4 true for %q", c.in)
		}
	}
}
