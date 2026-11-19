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
