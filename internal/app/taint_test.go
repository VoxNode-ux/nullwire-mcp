package app

import (
	"strings"
	"testing"
)

func TestTaintRingCatchesPaddedSecret(t *testing.T) {
	s := mustScrubber()
	secret := "Zq8Xv3LmP0aTr9YkB2nWd6HsJ4cFe7GuQ1oIhN5b" // 40 chars
	_ = s.tag("TOKEN", secret)
	in := "value=00000000_" + secret + "_trailing"
	out, n := s.scrubTainted(in)
	if n != 1 || strings.Contains(out, secret) {
		t.Fatalf("got %q (%d)", out, n)
	}
}

func TestTaintRingShortSecretNotSplit(t *testing.T) {
	s := mustScrubber()
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
	s := mustScrubber()
	_ = s.tag("TOKEN", strings.Repeat("abcde", 8))
	if out, n := s.scrubTainted("id=" + strings.Repeat("abcde", 7)); n != 0 {
		t.Fatalf("periodic hex matched the ring: %q", out)
	}
}
func TestTaintRingCatchesBase64AndJWTShapes(t *testing.T) {
	s := mustScrubber()
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

func taintSecret(i int) string {
	return lcgString(16, lcgBase64, uint32(i)*7919+1) + itoa(i)
}

func TestTaintRingEvictsOldestAndClears(t *testing.T) {
	r := newTaintRing(make([]byte, 32))
	first := taintSecret(1)
	r.add(first)
	if !r.hasFull(first) {
		t.Fatal("a stored secret must be found")
	}
	for i := 2; i <= taintCap+10; i++ {
		r.add(taintSecret(i))
	}
	if r.hasFull(first) {
		t.Error("the oldest secret must be evicted once the ring is full")
	}
	if !r.hasFull(taintSecret(taintCap + 10)) {
		t.Error("the newest secret must be stored")
	}
	if got := int(r.size.Load()); got != taintCap || len(r.set) != taintCap {
		t.Errorf("size = %d, set = %d, want %d", got, len(r.set), taintCap)
	}
	// Adding a secret that is already stored changes nothing.
	r.add(taintSecret(taintCap + 10))
	if got := int(r.size.Load()); got != taintCap {
		t.Errorf("duplicate changed the size to %d", got)
	}

	r.clear()
	if r.size.Load() != 0 || len(r.set) != 0 || r.pos != 0 || r.filled != 0 || r.hasFull(taintSecret(taintCap+10)) {
		t.Errorf("clear left state behind: size=%d set=%d pos=%d filled=%d", r.size.Load(), len(r.set), r.pos, r.filled)
	}
	r.add(first) // the ring works again after clearing
	if !r.hasFull(first) || r.size.Load() != 1 {
		t.Error("the ring must accept secrets after clear")
	}
	var none *taintRing
	none.clear() // a nil ring is fine
}

func TestTaintAddIgnoresWeakAndShortSecrets(t *testing.T) {
	r := newTaintRing(nil)
	r.add("short")
	r.add(strings.Repeat("a", 40))      // no randomness
	r.add(strings.Repeat("ab12", 10))   // periodic
	if r.size.Load() != 0 {
		t.Errorf("weak secrets were stored: %d", r.size.Load())
	}
	if r.hasFull("short") || r.hasFull(strings.Repeat("a", 40)) {
		t.Error("hasFull must reject short and low-entropy text")
	}
}

func TestTaintWindowHitBounds(t *testing.T) {
	r := newTaintRing(make([]byte, 16))
	secret := lcgString(40, lcgBase64, 99)
	r.add(secret)
	if off, ok := r.windowHit("zz" + secret); !ok || off != 2 {
		t.Errorf("windowHit = %d, %v; want 2, true", off, ok)
	}
	if _, ok := r.windowHit(secret[:taintWin-1]); ok {
		t.Error("a run shorter than one window cannot hit")
	}
	if _, ok := r.windowHit(strings.Repeat("a", taintMaxScan+1)); ok {
		t.Error("a run longer than taintMaxScan is not scanned")
	}
	if _, ok := r.windowHit(strings.Repeat("a", 60)); ok {
		t.Error("a run with no randomness cannot hit")
	}
	if _, ok := r.windowHit(lcgString(60, lcgBase64, 12345)); ok {
		t.Error("unrelated random text must not hit")
	}
}

func TestTaintSpans(t *testing.T) {
	r := newTaintRing(make([]byte, 32))
	secret := lcgString(40, lcgBase64, 7)
	r.add(secret)
	// Leading dots and trailing colons are not part of the secret.
	if got := r.spans("..." + secret + ":"); len(got) != 1 || got[0] != [2]int{3, 43} {
		t.Errorf("trimmed run: %v", got)
	}
	if got := r.spans("....:::"); got != nil {
		t.Errorf("only punctuation: %v", got)
	}
	// A secret next to a key=: only the secret is marked.
	if got := r.spans("key=" + secret); len(got) != 1 || got[0] != [2]int{4, 44} {
		t.Errorf("key=secret: %v", got)
	}
	// Base64 padding stays with the secret.
	padded := lcgString(32, lcgBase64, 8) + "=="
	r.add(padded)
	if got := r.spans("tok:" + padded); len(got) != 1 || got[0] != [2]int{4, 4 + len(padded)} {
		t.Errorf("padded secret: %v", got)
	}
	// A segment that already holds a redaction tag is left alone.
	if got := r.spans("key=REDACTED_TOKEN_abcdefghijkl"); got != nil {
		t.Errorf("redacted segment: %v", got)
	}
	// A stored window inside a longer run is cut at "/" and ".".
	if got := r.spans("host.example/" + "zz" + secret + "/path"); len(got) != 1 {
		t.Errorf("window in a longer run: %v", got)
	}
}

func TestScrubTaintedNoOps(t *testing.T) {
	s := mustScrubber()
	in := "some text with " + lcgString(30, lcgBase64, 5)
	if out, n := s.scrubTainted(in); out != in || n != 0 {
		t.Errorf("empty ring: %q, %d", out, n)
	}
	secret := lcgString(40, lcgBase64, 6)
	_ = s.tag("TOKEN", secret)
	if out, n := s.scrubTainted("tiny"); out != "tiny" || n != 0 {
		t.Errorf("short input: %q, %d", out, n)
	}
	// A run that already holds a tag is not looked at again.
	tagged := "x[REDACTED_TOKEN#abcdef]" + secret[:10]
	if out, n := s.scrubTainted(tagged); out != tagged || n != 0 {
		t.Errorf("tagged run: %q, %d", out, n)
	}
	// The same secret twice in one text is redacted both times.
	out, n := s.scrubTainted("a " + secret + " b " + secret + " c")
	if n != 2 || strings.Contains(out, secret) {
		t.Errorf("two occurrences: %q, %d", out, n)
	}
	s.taint.clear()
	if out, n := s.scrubTainted("a " + secret); n != 0 || out != "a "+secret {
		t.Errorf("after clear: %q, %d", out, n)
	}
}
