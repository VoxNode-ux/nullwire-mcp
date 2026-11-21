package vendors

import (
	"math/rand"
	"strings"
	"testing"
)

func naiveContains(text string, lits []string) bool {
	for _, l := range lits {
		if strings.Contains(text, strings.ToLower(l)) {
			return true
		}
	}
	return false
}

// The gate must agree with a plain substring search for every real literal and
// for a set of texts that do and do not contain one.
func TestGateAgreesWithSubstringSearch(t *testing.T) {
	var lits []string
	lits = append(lits, DefaultVendorPrefixes...)
	lits = append(lits, DefaultWeakVendorPrefixes...)
	lits = append(lits, DefaultDSNPrefixes...)
	g := NewGate(lits)

	for _, l := range lits {
		text := "xx " + strings.ToLower(l) + " yy"
		if !g.Match(text) {
			t.Errorf("gate missed literal %q", l)
		}
	}
	for _, text := range []string{
		"", "x", "hello world, 12345", "the quick brown fox", "nothing to see here",
		"found akia in the middle", "a bearer token appears", "postgres://user@host/db",
		"overlap: xoxe.xoxp-1 and sk-ant-x", "mixed.CASE should not match unless lowered",
	} {
		lower := strings.ToLower(text)
		if got, want := g.Match(lower), naiveContains(lower, lits); got != want {
			t.Errorf("gate=%v naive=%v for %q", got, want, text)
		}
	}
}

func TestGateEmptyAndNil(t *testing.T) {
	var nilGate *Gate
	if nilGate.Match("akia") {
		t.Error("a nil gate must match nothing")
	}
	if NewGate(nil, []string{""}).Match("anything") {
		t.Error("a gate with no literals must match nothing")
	}
}
// Match lower-cases as it reads, so mixed-case text needs no lower-cased copy
// and the check allocates nothing.
func TestGateIsCaseInsensitiveAndAllocFree(t *testing.T) {
	g := NewGate(DefaultVendorPrefixes, DefaultDSNPrefixes)
	for _, text := range []string{"found AKIA in text", "Postgres://User@Host/db", "XOXB-1234 here", "V4.LOCAL.abc"} {
		if !g.Match(text) {
			t.Errorf("gate should match %q regardless of case", text)
		}
	}
	if g.Match("nothing that looks like a prefix") {
		t.Error("unexpected match")
	}
	if n := testing.AllocsPerRun(100, func() { g.Match("Some MIXED Case text with AKIA inside it") }); n != 0 {
		t.Errorf("Match allocated %v times, want 0", n)
	}
}

// The default gate keeps a 16-bit table and folds ASCII case in the class table.
func TestGateUsesSixteenBitTables(t *testing.T) {
	g := NewGate(DefaultVendorPrefixes, DefaultWeakVendorPrefixes, DefaultDSNPrefixes)
	if g.wide != nil || len(g.next) != len(g.hit)*g.width {
		t.Fatalf("want a 16-bit table: wide=%v, next=%d, states=%d, width=%d", g.wide != nil, len(g.next), len(g.hit), g.width)
	}
	for c := byte('A'); c <= 'Z'; c++ {
		if g.class[c] != g.class[c+'a'-'A'] {
			t.Fatalf("class[%q] = %d, class[%q] = %d", c, g.class[c], c+'a'-'A', g.class[c+'a'-'A'])
		}
	}
}

// More than 65535 states cannot use 16-bit ids, so the gate keeps the wide
// table; it must still agree with a plain substring search.
func TestGateWideFallbackAgreesWithNaive(t *testing.T) {
	r := rand.New(rand.NewSource(20261120))
	const alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
	lits := make([]string, 6000)
	for i := range lits {
		b := make([]byte, 24)
		for j := range b {
			b[j] = alpha[r.Intn(len(alpha))]
		}
		lits[i] = string(b)
	}
	g := NewGate(lits)
	if g.wide == nil || g.next != nil {
		t.Fatalf("want the wide table for %d states", len(g.hit))
	}
	for i := 0; i < len(lits); i += 31 {
		if !g.Match("zz " + strings.ToUpper(lits[i]) + " zz") {
			t.Fatalf("wide gate missed %q", lits[i])
		}
	}
	for i := 0; i < 200; i++ {
		b := make([]byte, 40)
		for j := range b {
			b[j] = alpha[r.Intn(len(alpha))]
		}
		if got, want := g.Match(string(b)), naiveContains(string(b), lits); got != want {
			t.Fatalf("Match(%q) = %v, want %v", b, got, want)
		}
	}
}

// BenchmarkNewGate is the cost of building the default gate; B/op includes
// the build-time 32-bit table.
func BenchmarkNewGate(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = NewGate(DefaultVendorPrefixes, DefaultWeakVendorPrefixes, DefaultDSNPrefixes)
	}
}
