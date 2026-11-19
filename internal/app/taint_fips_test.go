package app

import (
	"bytes"
	"crypto/fips140"
	"os"
	"strings"
	"testing"
)

const fipsTestSecret = "Zq8Xv3LmP0aTr9YkB2nWd6HsQ5jFc1UeG7oIb4Nt" // 40 chars, high entropy

func fipsTestNonce(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// CI sets NULLWIRE_REQUIRE_FIPS=1 next to GODEBUG=fips140=only, so a run that
// silently lost the FIPS module fails here instead of passing without proof.
func TestFIPSModeIsActiveWhenRequired(t *testing.T) {
	if os.Getenv("NULLWIRE_REQUIRE_FIPS") != "1" {
		t.Skip("NULLWIRE_REQUIRE_FIPS is not set")
	}
	if !fips140.Enabled() {
		t.Fatal("NULLWIRE_REQUIRE_FIPS=1 but crypto/fips140.Enabled() is false")
	}
}

func TestNewTaintRingFollowsFIPSMode(t *testing.T) {
	if got := newTaintRing(fipsTestNonce(1)).fips; got != fips140.Enabled() {
		t.Fatalf("taint ring fips=%v, process fips=%v", got, fips140.Enabled())
	}
}

// Both hashes must behave the same way for the scrubber: a secret that was
// redacted once is found again whole, as a window inside a longer run, and not
// at all after clear.
func TestTaintBothHashModesBehaveAlike(t *testing.T) {
	for _, fips := range []bool{false, true} {
		name := "siphash"
		if fips {
			name = "hmac"
		}
		t.Run(name, func(t *testing.T) {
			r := newTaintRingMode(fipsTestNonce(7), fips)
			r.add(fipsTestSecret)
			if r.size.Load() == 0 {
				t.Fatal("nothing stored")
			}
			if !r.hasFull(fipsTestSecret) {
				t.Error("the whole secret is not recognised")
			}
			if r.hasFull(fipsTestSecret + "x") {
				t.Error("a different value matched")
			}
			if sp := r.spans("pad." + fipsTestSecret); len(sp) == 0 {
				t.Error("the secret inside a longer run was not found")
			}
			inner := "AAAA" + fipsTestSecret[:36] + "BBBB" // holds the stored windows at offsets 0 and 12
			if off, ok := r.windowHit(inner); !ok || off < 0 {
				t.Errorf("stored window not found: %d %v", off, ok)
			}
			if r.hasFull("Another1Secret2Value3Here4") {
				t.Error("an unseen value matched")
			}
			r.clear()
			if r.size.Load() != 0 || r.hasFull(fipsTestSecret) {
				t.Error("clear left a hash behind")
			}
		})
	}
}

func TestTaintHMACIsKeyedAndStable(t *testing.T) {
	a := newTaintRingMode(fipsTestNonce(1), true)
	b := newTaintRingMode(fipsTestNonce(1), true)
	c := newTaintRingMode(fipsTestNonce(2), true)
	if a.hash(fipsTestSecret) != b.hash(fipsTestSecret) {
		t.Error("same key, same text must give the same hash")
	}
	if a.hash(fipsTestSecret) == c.hash(fipsTestSecret) {
		t.Error("different keys must give different hashes")
	}
	if a.hash(fipsTestSecret) == a.hash(fipsTestSecret+"x") {
		t.Error("different text must give a different hash")
	}
	if a.hash("") == 0 && a.hash("a") == 0 {
		t.Error("hash looks constant")
	}
}

func TestTaintHMACKeyIsAlways32Bytes(t *testing.T) {
	for _, nonce := range [][]byte{nil, make([]byte, 3), fipsTestNonce(9), make([]byte, 64)} {
		r := newTaintRingMode(nonce, true)
		if len(r.key) != 32 {
			t.Fatalf("nonce of %d bytes: key length %d", len(nonce), len(r.key))
		}
		r.add(fipsTestSecret) // must not panic on a short nonce
	}
	if r := newTaintRingMode(fipsTestNonce(1), false); r.key != nil {
		t.Error("SipHash mode must not allocate an HMAC key")
	}
}

func TestTaintFIPSClearWipesKeyAndPool(t *testing.T) {
	r := newTaintRingMode(fipsTestNonce(5), true)
	r.add(fipsTestSecret)
	before := r.hash(fipsTestSecret)
	r.clear()
	if !bytes.Equal(r.key, make([]byte, 32)) || r.k0 != 0 || r.k1 != 0 {
		t.Error("clear left key material behind")
	}
	if r.hash(fipsTestSecret) == before {
		t.Error("the old key still hashes after clear")
	}
}

func TestTaintHMACHashKeepsNoPlaintextInPool(t *testing.T) {
	r := newTaintRingMode(fipsTestNonce(3), true)
	r.hash(fipsTestSecret)
	m := r.pool.Get().(*taintMAC)
	if len(m.buf) != 0 || strings.Contains(string(m.buf[:cap(m.buf)]), fipsTestSecret[:16]) {
		t.Error("the pooled context still holds the hashed text")
	}
	if m.sum != [32]byte{} {
		t.Error("the pooled context still holds a digest")
	}
}

func TestTaintHashScrubberEndToEnd(t *testing.T) {
	for _, fips := range []bool{false, true} {
		s, err := NewScrubber()
		if err != nil {
			t.Fatal(err)
		}
		s.taint = newTaintRingMode(s.nonce, fips)
		s.taint.add(fipsTestSecret)
		out, n := s.scrubTainted("echo " + fipsTestSecret + " done")
		if n != 1 || strings.Contains(out, fipsTestSecret) {
			t.Errorf("fips=%v: n=%d out=%q", fips, n, out)
		}
	}
}

func BenchmarkTaintHash(b *testing.B) {
	for _, fips := range []bool{false, true} {
		name := "siphash"
		if fips {
			name = "hmac-sha256"
		}
		r := newTaintRingMode(fipsTestNonce(1), fips)
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = r.hash(fipsTestSecret[:24])
			}
		})
	}
}
