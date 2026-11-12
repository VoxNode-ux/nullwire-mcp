package vendors

import (
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