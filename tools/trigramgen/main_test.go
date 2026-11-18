package main

import (
	"strings"
	"testing"

	"github.com/VoxNode-ux/nullwire-mcp/tools/internal/corpus"
)

func trainedFromSynthetic(t *testing.T) []entry {
	t.Helper()
	benign, secret := newCounts(), newCounts()
	for _, s := range corpus.Benign(60000, corpus.SeedTrain) {
		addToken(benign, s)
	}
	for _, s := range corpus.Secrets(30000, corpus.SeedTrain) {
		addToken(secret, s)
	}
	es := train(benign, secret)
	if len(es) == 0 {
		t.Fatal("empty table")
	}
	return es
}

func TestTrainBudgetSortedAndRange(t *testing.T) {
	es := trainedFromSynthetic(t)
	if len(es) > maxEntries || len(es)*4 > maxBytes {
		t.Fatalf("%d entries / %d bytes exceed budget", len(es), len(es)*4)
	}
	for i, e := range es {
		if e.score < lo || e.score > hi || abs(e.score) < minAbs {
			t.Errorf("entry %d score %d out of range or weak", i, e.score)
		}
		if i > 0 && es[i-1].key >= e.key {
			t.Fatalf("entries not strictly sorted at %d", i)
		}
		if e.count < minCount {
			t.Errorf("entry %d has only %v observations", i, e.count)
		}
	}
}

func TestTrainPolarityBenignPositive(t *testing.T) {
	val := map[uint32]int{}
	for _, e := range trainedFromSynthetic(t) {
		val[e.key] = e.score
	}
	key := func(s string) uint32 { return uint32(s[0])<<14 | uint32(s[1])<<7 | uint32(s[2]) }
	if v, ok := val[key("ing")]; ok && v <= 0 {
		t.Errorf("trigram ing = %d, want positive (benign)", v)
	}
}

func TestPackRoundTrip(t *testing.T) {
	for s := lo; s <= hi; s++ {
		w := pack(0x1abcd, s)
		if w>>8 != 0x1abcd || int(w&0xff)+lo != s {
			t.Errorf("pack score %d -> %#x", s, w)
		}
	}
}

func TestRenderDataOnly(t *testing.T) {
	src, err := render([]entry{{key: 1, score: 3}, {key: 2, score: -4}})
	if err != nil {
		t.Fatal(err)
	}
	out := string(src)
	if strings.Contains(out, "func ") || !strings.Contains(out, "var trigramTable = []uint32{") {
		t.Errorf("not a pure data file:\n%s", out)
	}
}

func TestSecretCorpusHasNoJWTPrefixOrHeavySeparators(t *testing.T) {
	for _, s := range corpus.Secrets(5000, corpus.SeedTrain) {
		if strings.Contains(s, "eyJ") {
			t.Fatalf("secret %q has eyJ", s)
		}
		if n := strings.Count(s, "_") + strings.Count(s, "-"); n > 2 {
			t.Fatalf("secret %q has %d separators", s, n)
		}
		if len(s) < 16 || len(s) > 64 {
			t.Fatalf("secret %q has length %d", s, len(s))
		}
	}
}

func TestCorporaAreDeterministicAndDisjointSeeds(t *testing.T) {
	a, b := corpus.Secrets(50, corpus.SeedTrain), corpus.Secrets(50, corpus.SeedTrain)
	for i := range a {
		if a[i] != b[i] {
			t.Fatal("secrets differ between calls")
		}
	}
	h := map[string]bool{}
	for _, s := range corpus.Secrets(2000, corpus.SeedTrain) {
		h[s] = true
	}
	for _, s := range corpus.Secrets(2000, corpus.SeedHoldout) {
		if h[s] {
			t.Fatalf("holdout secret %q also in training", s)
		}
	}
}

func TestRcovTrainNeedsBothClassesAndAbs(t *testing.T) {
	benign, secret := newCounts(), newCounts()
	if got := train(benign, secret); got != nil {
		t.Errorf("empty classes: %v, want nil", got)
	}
	benign[int('a')<<14|int('b')<<7|int('c')] = 100
	if got := train(benign, secret); got != nil {
		t.Errorf("no secret class: %v, want nil", got)
	}
	if abs(-3) != 3 || abs(4) != 4 || abs(0) != 0 {
		t.Error("abs is wrong")
	}
}

func TestRcovAddTokenIgnoresNonASCII(t *testing.T) {
	c := newCounts()
	addToken(c, "ab\xc3\xa9cd") // every triple touching the non-ASCII byte is skipped
	var total uint32
	for _, v := range c {
		total += v
	}
	if total != 0 {
		t.Errorf("counted %d triples, want 0", total)
	}
	addToken(c, "ab") // too short for any triple
	addToken(c, "abc")
	if c[int('a')<<14|int('b')<<7|int('c')] != 1 {
		t.Error("abc was not counted")
	}
}