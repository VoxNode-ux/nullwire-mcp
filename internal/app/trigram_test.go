package app

import (
	"hash/fnv"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// packTri packs a test entry like tools/trigramgen does.
func packTri(a, b, c byte, score int) uint32 {
	return (uint32(a)<<14|uint32(b)<<7|uint32(c))<<8 | uint32(score+4) // #nosec G115 -- test scores are within [-4,6]
}

func withTable(t *testing.T, tab []uint32) {
	t.Helper()
	old := trigramTable
	trigramTable = tab
	t.Cleanup(func() { trigramTable = old })
}

func TestTrigramTableSorted(t *testing.T) {
	if len(trigramTable) > 16384 {
		t.Fatalf("trigramTable has %d entries, budget 16384", len(trigramTable))
	}
	for i := 0; i+1 < len(trigramTable); i++ {
		if trigramTable[i]>>8 >= trigramTable[i+1]>>8 {
			t.Fatalf("trigramTable not strictly sorted at %d", i)
		}
	}
	for i, e := range trigramTable {
		if e&0xff > 10 {
			t.Fatalf("entry %d has biased score %d > 10", i, e&0xff)
		}
	}
}

func TestTrigramMeanLookupAndClamp(t *testing.T) {
	withTable(t, []uint32{packTri('a', 'b', 'c', 6), packTri('b', 'c', 'd', -4), packTri('x', 'y', 'z', 3)})
	if got := trigramMean("abc"); got != 6 {
		t.Errorf("abc = %v, want 6", got)
	}
	if got := trigramMean("abcd"); got != 1 { // (6-4)/2
		t.Errorf("abcd = %v, want 1", got)
	}
	if got := trigramMean("xyzq"); got != 1.5 { // (3+0)/2
		t.Errorf("xyzq = %v, want 1.5", got)
	}
	if trigramMean("ab") != 0 || trigramMean("") != 0 {
		t.Error("short strings must score 0")
	}
	if trigramMean("abc\xc3\xa9") != 2 { // abc=6, two non-ASCII triples skipped (count 0), mean over 3 -> 2
		t.Errorf("non-ASCII handling: %v", trigramMean("abc\xc3\xa9"))
	}
	for _, s := range []string{"abcabcabc", "xyzxyzxyz", "bcdbcdbcd"} {
		if m := trigramMean(s); m < trigramLo || m > trigramHi {
			t.Errorf("%q mean %v outside [%v,%v]", s, m, trigramLo, trigramHi)
		}
	}
}

func TestTrigramEmptyTableLeavesScoreUnchanged(t *testing.T) {
	s := "Zq8Xv3LmP0aTr9YkB2nWd6HsJ4cFe7Gu"
	withTable(t, nil)
	base := tokenLogOdds(s)
	want := combineScore(maxWindowEntropy(s), bigramMean(s), vowelRatio(s), float64(min(len(s), maxLenW)))
	if base != want {
		t.Fatalf("empty table changed score: %v vs %v", base, want)
	}
}

func TestTrigramEscalationOnlyInsideBand(t *testing.T) {
	// Every trigram of "aaaaaaaa" is strongly benign.
	withTable(t, []uint32{packTri('a', 'a', 'a', 6)})
	for _, s := range []string{"getUserAccountBalanceFromCache", "Zq8Xv3LmP0aTr9YkB2nWd6HsJ4cFe7Gu", "aaaaaaaaaaaaaaaa", "abcdefgh12345678"} {
		base := combineScore(maxWindowEntropy(s), bigramMean(s), vowelRatio(s), float64(min(len(s), maxLenW)))
		got := tokenLogOdds(s)
		if math.Abs(base) >= trigramBand {
			if got != base {
				t.Errorf("%q outside band was changed: %v -> %v", s, base, got)
			}
			continue
		}
		mean := (1-trigramAlpha)*bigramMean(s) + trigramAlpha*trigramMean(s)
		if want := combineScore(maxWindowEntropy(s), mean, vowelRatio(s), float64(min(len(s), maxLenW))); got != want {
			t.Errorf("%q inside band: got %v want %v", s, got, want)
		}
	}
}

func TestTrigramNoAllocs(t *testing.T) {
	withTable(t, []uint32{packTri('a', 'b', 'c', 5), packTri('q', '8', 'X', -4)})
	s := "00000000_Zq8Xv3LmP0aTr9YkB2nWd6HsJ4cFe7Gu"
	if n := testing.AllocsPerRun(100, func() { _ = trigramMean(s) }); n != 0 {
		t.Fatalf("trigramMean allocs = %v", n)
	}
	if n := testing.AllocsPerRun(100, func() { _ = tokenLogOdds(s) }); n != 0 {
		t.Fatalf("tokenLogOdds allocs = %v", n)
	}
}

// Holdout evaluation. Benign tokens come from repo files whose path hash falls
// in the holdout split of tools/corpus (hash % 5 == 0), which the generate
// lines keep out of training; secrets come from a seed training never uses.
// It only runs once a trigramTable is generated and requires the escalation
// not to lose F1 or raise the false-positive rate compared with bigram-only.
func TestTrigramHoldoutNotWorseThanBaseline(t *testing.T) {
	if len(trigramTable) == 0 {
		t.Skip("no trigram table generated; escalation is off")
	}
	var benign []string
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == ".git" || n == "node_modules" || n == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		base := filepath.Base(path)
		if strings.HasSuffix(path, "_test.go") || base == "bigram_trained.go" || base == "trigram_trained.go" {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".go", ".md", ".txt", ".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml":
		default:
			return nil
		}
		rel, _ := filepath.Rel("../..", path)
		h := fnv.New32a()
		_, _ = h.Write([]byte(filepath.ToSlash(rel)))
		if h.Sum32()%5 != 0 {
			return nil
		}
		data, err := os.ReadFile(path) // #nosec G304 G122 -- test reads repo files under the module root
		if err != nil {
			return err
		}
		benign = append(benign, holdoutTokens(string(data))...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(benign) < 500 {
		t.Skipf("only %d holdout benign tokens", len(benign))
	}
	secrets := holdoutSecrets(5000)

	eval := func(on bool) (f1, fpr float64) {
		old := trigramTable
		if !on {
			trigramTable = nil
		}
		defer func() { trigramTable = old }()
		tp, fn, fp, tn := 0, 0, 0, 0
		for _, s := range secrets {
			if tokenLogOdds(s) > 0 {
				tp++
			} else {
				fn++
			}
		}
		for _, s := range benign {
			if tokenLogOdds(s) > 0 {
				fp++
			} else {
				tn++
			}
		}
		f1 = 2 * float64(tp) / float64(2*tp+fp+fn)
		fpr = float64(fp) / float64(fp+tn)
		return
	}
	f1Off, fprOff := eval(false)
	f1On, fprOn := eval(true)
	t.Logf("holdout (%d benign, %d secrets): bigram-only F1=%.4f FPR=%.4f; with trigram F1=%.4f FPR=%.4f",
		len(benign), len(secrets), f1Off, fprOff, f1On, fprOn)
	if f1On < f1Off || fprOn > fprOff {
		t.Fatalf("trigram escalation regressed on holdout: F1 %.4f -> %.4f, FPR %.4f -> %.4f; empty trigram_trained.go or retune trigramBand/trigramAlpha",
			f1Off, f1On, fprOff, fprOn)
	}
}

func holdoutTokens(text string) []string {
	var out []string
	start := -1
	for i := 0; i <= len(text); i++ {
		if i < len(text) {
			c := text[i]
			if c == '_' || c == '-' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				if start < 0 {
					start = i
				}
				continue
			}
		}
		if start >= 0 {
			if l := i - start; l >= 4 && l <= 64 {
				out = append(out, text[start:i])
			}
			start = -1
		}
	}
	return out
}

// holdoutSecrets mirrors tools/internal/corpus.Secrets with a seed (7919)
// that training (seed 1) never uses.
func holdoutSecrets(n int) []string {
	x := uint64(7919)
	next := func() uint64 { // xorshift64*
		x ^= x >> 12
		x ^= x << 25
		x ^= x >> 27
		return x * 2685821657736338717
	}
	const hex = "0123456789abcdef"
	const hexUp = "0123456789ABCDEF"
	const b62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	out := make([]string, 0, n)
	for i := 0; len(out) < n; i++ {
		l := 16 + int(next()%49) // #nosec G115 -- value is 0..48
		alpha := b62
		switch i % 4 {
		case 0:
			alpha = hex
		case 1:
			alpha = hexUp
		}
		b := make([]byte, l)
		for j := range b {
			b[j] = alpha[next()%uint64(len(alpha))]
		}
		if i%4 == 3 { // base64url: at most two '-' / '_'
			for k := int(next() % 3); k > 0; k-- { // #nosec G115 -- value is 0..2
				b[next()%uint64(l)] = "-_"[next()%2]
			}
		}
		if s := string(b); !strings.Contains(s, "eyJ") {
			out = append(out, s)
		}
	}
	return out
}
