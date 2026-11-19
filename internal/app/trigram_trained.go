package app

// trigramTable holds trained trigram evidence, sorted by key. Each word is
// (a<<14|b<<7|c)<<8 | (score-lo) for the ASCII bytes a,b,c: positive scores
// mean benign identifier text, negative scores mean random secrets. It is
// empty until "go generate ./internal/app" runs tools/trigramgen and the
// holdout test shows an improvement, so the borderline escalation is off and
// an untrained build behaves exactly as before.
var trigramTable = []uint32{}
