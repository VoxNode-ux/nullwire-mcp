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
