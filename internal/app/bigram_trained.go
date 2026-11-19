package app

// bigramEntry is one trained bigram value: evidence (int8) that the byte pair
// a,b belongs to natural text or code identifiers (positive) or to random
// secrets (negative).
type bigramEntry struct {
	a, b byte
	v    int8
}

// trainedBigram holds the pairs with enough evidence in the training corpus.
// It is empty until "go generate ./internal/app" runs tools/bigramgen, so an
// untrained build behaves exactly as before.
var trainedBigram = []bigramEntry{}
