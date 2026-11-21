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

// ASCII case is folded into the class table when the automaton is built, and
// the transition table is 16-bit.
func TestMaskGateTablesAreFoldedAndSixteenBit(t *testing.T) {
	for name, groups := range map[string][]maskGroup{"scrub": scrubGate.groups, "secretKey": secretKeyGate.groups} {
		g := newMaskGate(groups...)
		if len(g.out) > 65535 {
			t.Fatalf("%s: %d states do not fit in 16 bits", name, len(g.out))
		}
		if len(g.next) != len(g.out)*g.width {
			t.Fatalf("%s: next has %d entries, want %d states x %d classes", name, len(g.next), len(g.out), g.width)
		}
		for c := byte('A'); c <= 'Z'; c++ {
			if g.class[c] != g.class[c+'a'-'A'] {
				t.Fatalf("%s: class[%q] = %d, class[%q] = %d", name, c, g.class[c], c+'a'-'A', g.class[c+'a'-'A'])
			}
		}
	}
}

// Mixed-case texts built from pieces of the real literals: every bit must
// match a plain lower-cased substring search.
func TestMaskGatesAgreeWithNaiveOnMixedCase(t *testing.T) {
	for name, groups := range map[string][]maskGroup{"scrub": scrubGate.groups, "secretKey": secretKeyGate.groups} {
		g := newMaskGate(groups...)
		var pool []string
		for _, grp := range groups {
			pool = append(pool, grp.lits...)
		}
		if len(pool) == 0 {
			t.Fatalf("%s: no literals to build texts from", name)
		}
		naive := func(text string) uint32 {
			lower := strings.ToLower(text)
			var m uint32
			for _, grp := range groups {
				for _, lit := range grp.lits {
					if lit != "" && strings.Contains(lower, strings.ToLower(lit)) {
						m |= grp.bit
					}
				}
			}
			return m
		}
		r := rand.New(rand.NewSource(20261120))
		n := 20000
		if testing.Short() {
			n = 2000
		}
		for i := 0; i < n; i++ {
			var sb strings.Builder
			for j := r.Intn(6); j >= 0; j-- {
				if r.Intn(3) == 0 {
					sb.WriteString(" .-_=\"x9")
					continue
				}
				lit := pool[r.Intn(len(pool))]
				lit = lit[:1+r.Intn(len(lit))]
				for k := 0; k < len(lit); k++ {
					c := lit[k]
					if r.Intn(2) == 0 && c >= 'a' && c <= 'z' {
						c -= 'a' - 'A'
					}
					sb.WriteByte(c)
				}
			}
			text := sb.String()
			if got, want := g.Match(text), naive(text); got != want {
				t.Fatalf("%s: Match(%q) = %b, want %b", name, text, got, want)
			}
		}
	}
}

// BenchmarkScrubGateInit is the cost of building both mask gates (what the
// first scan pays); B/op includes the build-time 32-bit table.
func BenchmarkScrubGateInit(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = newMaskGate(scrubGate.groups...)
		_ = newMaskGate(secretKeyGate.groups...)
	}
}
