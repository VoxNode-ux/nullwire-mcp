package app

import (
	"strings"
	"testing"
)

// BenchmarkScrubTailOld runs the three pre-checks as scrubLayersOpts did before
// the PAN gate: IPv6 and IPv4 gates, and the full panSpans pass for cards.
// BenchmarkScrubTailNew runs what scrubTail does now: the same IPv6 gate
// (strings.Count), an IndexByte-first IPv4 gate and the early-exit
// hasPANChain. The names start with BenchmarkScrub so the benchmarks workflow
// (-bench='Scrub') runs them.

var tailBenchInputs = map[string]string{
	"Clean":  strings.Repeat("The quick brown fox jumps over the lazy dog. ", 1500),
	"JSON":   strings.Repeat(`{"id":"u_1","name":"demo","ok":true,"n":42},`, 1500),
	"Digits": strings.Repeat("order 4111 1111 1111 1111 shipped to 10.0.0.1 via fe80::1 ", 800),
}

// The two shapes the fast gates could find hardest: many dots with no digit
// beside them, and many short digit chains that never reach 13.
func init() {
	tailBenchInputs["Dots"] = strings.Repeat("a.b.c.d.e.f.g.h. ", 2500)
	tailBenchInputs["ShortChains"] = strings.Repeat("1234  5678  ", 3500)
}

func BenchmarkScrubTailOld(b *testing.B) {
	for name, in := range tailBenchInputs {
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(in)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = strings.Count(in, ":") >= 2
				_ = maybeIPv4(in)
				_ = len(panSpans(in))
			}
		})
	}
}

func BenchmarkScrubTailNew(b *testing.B) {
	for name, in := range tailBenchInputs {
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(in)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = strings.Count(in, ":") >= 2
				_ = strings.IndexByte(in, '.') >= 0 && maybeIPv4(in)
				_ = hasPANChain(in)
			}
		})
	}
}

// BenchmarkScrubPANChain and BenchmarkScrubIPv4Gate run the old byte loop
// (Ref) and the current gate (New) on every input, so a regression on any
// shape shows up here.
func BenchmarkScrubPANChain(b *testing.B) {
	for name, in := range tailBenchInputs {
		b.Run(name+"/Ref", func(b *testing.B) {
			b.SetBytes(int64(len(in)))
			for i := 0; i < b.N; i++ {
				_ = refPANChain(in)
			}
		})
		b.Run(name+"/New", func(b *testing.B) {
			b.SetBytes(int64(len(in)))
			for i := 0; i < b.N; i++ {
				_ = hasPANChain(in)
			}
		})
	}
}

func BenchmarkScrubIPv4Gate(b *testing.B) {
	for name, in := range tailBenchInputs {
		b.Run(name+"/Ref", func(b *testing.B) {
			b.SetBytes(int64(len(in)))
			for i := 0; i < b.N; i++ {
				_ = refMaybeIPv4(in)
			}
		})
		b.Run(name+"/New", func(b *testing.B) {
			b.SetBytes(int64(len(in)))
			for i := 0; i < b.N; i++ {
				_ = maybeIPv4(in)
			}
		})
	}
}
