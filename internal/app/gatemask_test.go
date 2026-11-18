package app

import (
	"math/rand"
	"strings"
	"testing"
)

// The mask gate must agree with the lower-case + containsAny checks it replaced.
func TestScrubGateMatchesLegacyChecks(t *testing.T) {
	legacy := func(in string) uint32 {
		lower := strings.ToLower(in)
		var m uint32
		if strings.Contains(lower, "eyj") {
			m |= gateJWT
		}
		if containsAny(lower, []string{"sk-", "ghp_", "github_pat_", "aiza", "xox", "akia"}) {
			m |= gateAPIKey
		}
		if containsAny(lower, []string{"bearer", "basic", "token"}) {
			m |= gateBearer
		}
		if containsAny(lower, []string{"token", "secret", "password", "passwd", "session_id", "api_key", "apikey", "key=", `"key"`}) {
			m |= gateSecretKey
		}
		if containsAny(lower, xmlSecretHints) {
			m |= gateXML
		}
		if containsAny(lower, cloudGate) {
			m |= gateCloud
		}
		if strings.Contains(lower, "pass") || strings.Contains(lower, "pwd") {
			m |= gateCloudPass
		}
		return m
	}
	words := []string{"Bearer ", "TOKEN", "sk-", "GHP_", "eyJ", "password", "PWD=", `"key"`, "key=", "xox", "AKIA", "<a>", "Authorization", "sessionid", "x", " ", "abc", "SharedAccess", "pass", "\n"}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 5000; i++ {
		var b strings.Builder
		for k := rng.Intn(8); k >= 0; k-- {
			b.WriteString(words[rng.Intn(len(words))])
		}
		in := b.String()
		if got, want := scrubGate.Match(in), legacy(in); got != want {
			t.Fatalf("%q: got %07b want %07b", in, got, want)
		}
	}
}

func TestScrubGateNoAllocs(t *testing.T) {
	in := strings.Repeat("hello world, nothing to see here. ", 50)
	if n := testing.AllocsPerRun(100, func() { _ = scrubGate.Match(in) }); n != 0 {
		t.Fatalf("allocs = %v, want 0", n)
	}
}

func BenchmarkScrubGate(b *testing.B) {
	in := strings.Repeat("GET /api/v1/items?id=42 HTTP/1.1 Host: example.com ", 40)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = scrubGate.Match(in)
	}
}

func TestMaskGateSmallAutomaton(t *testing.T) {
	const (
		bitA uint32 = 1 << iota
		bitB
		bitC
	)
	g := newMaskGate(
		maskGroup{bitA, []string{"he", "SHE", ""}},      // an empty literal is ignored; case is folded
		maskGroup{bitB, []string{"his", "hers"}},
		maskGroup{bitC, []string{"z"}},
	)
	for in, want := range map[string]uint32{
		"":             0,
		"nothing":      0,
		"he":           bitA,
		"HE":           bitA,
		"ushers":       bitA | bitB, // "she" and "he" end inside "ushers", and "hers" ends it
		"this":         bitB,        // "his"
		"xhisx":        bitB,
		"Z":            bitC,
		"she z his":    bitA | bitB | bitC,
		"h":            0,
		"h-e":          0,
		"héé":          0, // non-ASCII bytes fall in the "unused" class
	} {
		if got := g.Match(in); got != want {
			t.Errorf("Match(%q) = %03b, want %03b", in, got, want)
		}
	}
	// A gate with no literals matches nothing and does not stop early on empty text.
	empty := newMaskGate(maskGroup{bitA, nil})
	if got := empty.Match("anything at all"); got != 0 {
		t.Errorf("literal-free gate matched %03b", got)
	}
	// The scan stops as soon as every bit has been seen.
	all := newMaskGate(maskGroup{bitA, []string{"a"}}, maskGroup{bitB, []string{"b"}})
	if got := all.Match("ab" + strings.Repeat("a", 1000)); got != bitA|bitB {
		t.Errorf("early stop: %03b", got)
	}
}
