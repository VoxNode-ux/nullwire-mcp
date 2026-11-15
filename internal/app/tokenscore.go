package app

import "math"

//go:generate go run ../../tools/bigramgen -benign ../.. -synthetic 20000 -out bigram_trained.go

// Token scoring that replaces the hard entropy/vowel cliffs with one smooth
// log-odds score: positive means "looks like a secret".
//
// Terms: sliding-window max Shannon entropy (24 bytes, catches secrets padded
// with low-entropy filler), mean first-order bigram score (identifier-like
// text such as camelCase and snake_case scores high, random text near zero),
// vowel ratio and length.

// useLogOdds switches looksLikeTokenMax between the log-odds score and the
// older fixed thresholds. Flip it off to compare behaviour.
var useLogOdds = true

const entropyWindow = 24

// Weights. Tune against your corpus with the bench and fuzz tests.
const (
	wEntropy = 4.0
	cEntropy = 3.9
	wBigram  = 0.9
	wVowel   = 12.0
	cVowel   = 0.25
	wLen     = 0.05
	cLen     = 24.0
	maxLenW  = 64
)

var (
	// bigram[a<<7|b] is the evidence (int8) that the pair a,b belongs to
	// natural text or code identifiers. Seeded from character-class rules and
	// common English/code pairs. "go generate" trains it on a real corpus and
	// writes the pairs it has enough evidence for to bigram_trained.go, which
	// overrides the seed values.
	bigram [128 * 128]int8
	// plogp[c] = c*log2(c), for incremental window entropy.
	plogp [entropyWindow + 1]float64
)

func bgClass(c byte) int {
	switch {
	case c >= 'a' && c <= 'z':
		return 0
	case c >= 'A' && c <= 'Z':
		return 1
	case c >= '0' && c <= '9':
		return 2
	case c == '_' || c == '-':
		return 3
	}
	return 4
}

func init() {
	for c := 1; c <= entropyWindow; c++ {
		plogp[c] = float64(c) * math.Log2(float64(c))
	}
	// class-pair priors: rows lower, upper, digit, separator, other
	prior := [5][5]int8{
		{1, 2, -2, 3, 0},
		{3, -1, -2, 1, 0},
		{-2, -2, 0, 0, 0},
		{3, 1, 0, -4, 0},
		{0, 0, 0, 0, 0},
	}
	for a := 0; a < 128; a++ {
		for b := 0; b < 128; b++ {
			bigram[a<<7|b] = prior[bgClass(byte(a))][bgClass(byte(b))]
		}
	}
	common := []string{
		"th", "he", "in", "er", "an", "re", "on", "at", "en", "nd", "ti", "es", "or", "te", "of", "ed",
		"is", "it", "al", "ar", "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le", "ve", "co",
		"me", "de", "hi", "ri", "ro", "ic", "ne", "ea", "ra", "ce", "li", "ch", "ll", "be", "ma", "si",
		"om", "ur", "ge", "et", "ct", "ut", "ex", "pr", "un", "ac", "ad", "ig", "ol", "ie", "ca", "ss",
	}
	for _, p := range common {
		a, b := p[0], p[1]
		for _, x := range [2]byte{a, a - 'a' + 'A'} {
			for _, y := range [2]byte{b, b - 'a' + 'A'} {
				if bigram[int(x)<<7|int(y)] < 6 {
					bigram[int(x)<<7|int(y)] = 6
				}
			}
		}
	}
	// Pairs with enough evidence in the trained corpus (see bigram_trained.go)
	// replace the seed values, including the common-pair floor above.
	for _, e := range trainedBigram {
		if e.a < 128 && e.b < 128 {
			bigram[int(e.a)<<7|int(e.b)] = e.v
		}
	}
}

// bigramMean is the mean bigram evidence of s (0 for fewer than two bytes).
// Non-ASCII bytes count as 0. No allocation.
func bigramMean(s string) float64 {
	if len(s) < 2 {
		return 0
	}
	sum := 0
	for i := 1; i < len(s); i++ {
		a, b := s[i-1], s[i]
		if a < 128 && b < 128 {
			sum += int(bigram[int(a)<<7|int(b)])
		}
	}
	return float64(sum) / float64(len(s)-1)
}

// maxWindowEntropy is the highest Shannon entropy (bits per byte) of any
// entropyWindow-byte window of s, or the entropy of s if it is shorter. The
// window slides with incremental counts, so it costs O(len) and allocates nothing.
func maxWindowEntropy(s string) float64 {
	n := len(s)
	if n == 0 {
		return 0
	}
	if n <= entropyWindow {
		return shannonEntropyBits(s)
	}
	var cnt [256]int
	sum := 0.0 // sum of c*log2(c) over the window
	add := func(c byte) {
		sum -= plogp[cnt[c]]
		cnt[c]++
		sum += plogp[cnt[c]]
	}
	del := func(c byte) {
		sum -= plogp[cnt[c]]
		cnt[c]--
		sum += plogp[cnt[c]]
	}
	for i := 0; i < entropyWindow; i++ {
		add(s[i])
	}
	w := float64(entropyWindow)
	best := math.Log2(w) - sum/w
	for i := entropyWindow; i < n; i++ {
		del(s[i-entropyWindow])
		add(s[i])
		if h := math.Log2(w) - sum/w; h > best {
			best = h
		}
	}
	return best
}

// tokenLogOdds returns the log-odds score that s is a secret (> 0 means yes).
func tokenLogOdds(s string) float64 {
	n := len(s)
	if n > maxLenW {
		n = maxLenW
	}
	z := wEntropy * (maxWindowEntropy(s) - cEntropy)
	z -= wBigram * bigramMean(s)
	z -= wVowel * (vowelRatio(s) - cVowel)
	z += wLen * (float64(n) - cLen)
	return z
}
