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

func TestTaintRingIgnoresPeriodicHex(t *testing.T) {
	s, _ := NewScrubber()
	_ = s.tag("TOKEN", strings.Repeat("abcde", 8))
	if out, n := s.scrubTainted("id=" + strings.Repeat("abcde", 7)); n != 0 {
		t.Fatalf("periodic hex matched the ring: %q", out)
	}
}
func TestTaintRingCatchesBase64AndJWTShapes(t *testing.T) {
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	// A 39-character key (below the old 40-character sub-window minimum), seen again inside a longer run.
	aiza := "AIzaSyD4kLm9PqR2sTuV6wXy8zAbCdEfGhIjKlM"
	_ = s.tag("TOKEN", aiza)
	if out, n := s.scrubTainted("k=pad00pad" + aiza + "tail"); n != 1 || strings.Contains(out, aiza) {
		t.Errorf("39-char key not caught: %q (%d)", out, n)
	}
	// A secret holding "/", "+" and "=" is matched whole instead of being split at them.
	b64 := "q8Xv3L/mP0aTr9Yk+B2nWd6HsJ4cFe7GuQ1oIhN5bZw="
	_ = s.tag("KEY", b64)
	if out, n := s.scrubTainted("blob: " + b64 + " end"); n != 1 || strings.Contains(out, "mP0aTr9Yk") {
		t.Errorf("base64 secret not caught whole: %q (%d)", out, n)
	}
	// A JWT signature seen alone after the whole token was redacted.
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"
	_ = s.tag("TOKEN", jwt)
	sig := jwt[strings.LastIndex(jwt, ".")+1:]
	if out, n := s.scrubTainted("sig " + sig); n != 1 || strings.Contains(out, sig) {
		t.Errorf("JWT signature not caught: %q (%d)", out, n)
	}
}
