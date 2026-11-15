package app

import (
	"strings"
	"testing"
)

func TestTaintRingCatchesPaddedSecret(t *testing.T) {
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	secret := "Zq8Xv3LmP0aTr9YkB2nWd6HsJ4cFe7GuQ1oIhN5b" // 40 chars
	_ = s.tag("TOKEN", secret)
	in := "value=00000000_" + secret + "_trailing"
	out, n := s.scrubTainted(in)
	if n != 1 || strings.Contains(out, secret) {
		t.Fatalf("got %q (%d)", out, n)
	}
}

func TestTaintRingShortSecretNotSplit(t *testing.T) {
	s, _ := NewScrubber()
	_ = s.tag("TOKEN", "Zq8Xv3LmP0aTr9YkB2nW") // 20 chars: whole value only
	in := "Zq8Xv3LmP0aT and Zq8Xv3LmP0aTr9Yk"
	if out, n := s.scrubTainted(in); n != 0 || out != in {
		t.Fatalf("short secret was matched by a piece: %q", out)
	}
}

func TestTaintRingBounded(t *testing.T) {
	r := newTaintRing(make([]byte, 32))
	for i := 0; i < 5*taintCap; i++ {
		r.add(strings.Repeat("a", 16) + string(rune('A'+i%26)) + strings.Repeat("b", i%40))
		r.add(strings.Repeat("x", 16) + itoa(i))
	}
	if len(r.set) > taintCap {
		t.Fatalf("set grew to %d", len(r.set))
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}
