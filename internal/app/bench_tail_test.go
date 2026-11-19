package app

import (
	"strings"
	"testing"
)

// These compare the three separate scans scrubLayersOpts used to run before
// the IPv6, IPv4 and card-number rules with the single scanTailFeatures pass
// that replaced them. The names start with BenchmarkScrub so the benchmarks
// workflow (-bench='Scrub') runs them. Keep scanTailFeatures only if
// "New" is not slower than "Old" on the inputs you care about.

var tailBenchInputs = map[string]string{
	"Clean": strings.Repeat("The quick brown fox jumps over the lazy dog. ", 1500),
	"JSON":  strings.Repeat(`{"id":"u_1","name":"demo","ok":true,"n":42},`, 1500),
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
				_ = scanTailFeatures(in)
			}
		})
	}
}
