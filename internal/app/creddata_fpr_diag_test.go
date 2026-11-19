package app

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

// TestCredDataFPRByStage is an offline diagnostic (skipped unless CREDDATA_TSV
// is set). The file holds "T|F<TAB>value" lines. For every value it names the
// first stage that flags it, by ablation, so the FPs of the benchmark can be
// split by rule stage before any threshold is touched. Nothing here ships.
func TestCredDataFPRByStage(t *testing.T) {
	path := os.Getenv("CREDDATA_TSV")
	if path == "" {
		t.Skip("CREDDATA_TSV not set")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s := mustScrubber()
	ctx := ContextBody
	counts := map[string]map[string]int{"T": {}, "F": {}}
	total := map[string]int{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		label, val, ok := strings.Cut(sc.Text(), "\t")
		if !ok || (label != "T" && label != "F") {
			continue
		}
		total[label]++
		line := "CRED=" + val
		stage := "clean"
		if _, n := s.scrubUnwrapped(line, ctx); n > 0 {
			stage = "1-unwrap"
		} else if _, n := s.scrubLayersOpts(line, scrubOpts{ctx: ctx, skipEntropy: true, skipIP: true}); n > 0 {
			stage = "2-vendor/dsn/jwt/key rules"
		} else if _, n := s.scrubLayersOpts(line, scrubOpts{ctx: ctx, skipEntropy: true}); n > 0 {
			stage = "2-ipv4/ipv6/pan"
		} else if _, n := s.scrubLayersOpts(line, scrubOpts{ctx: ctx, skipEntropy: true, allowB64: true}); n > 0 {
			stage = "2-base64/encodedText"
		} else if out, _ := s.scrubLayersOpts(line, scrubOpts{ctx: ctx, skipEntropy: true, allowB64: true}); true {
			if _, n := s.scrubHighEntropyMax(out, scrubOpts{ctx: ctx}.entropyMax()); n > 0 {
				stage = "3-scrubHighEntropyMax"
			} else if _, n := s.scrubLayersOpts(line, scrubOpts{ctx: ctx, allowB64: true}); n > 0 {
				stage = "3-tainted/hex"
			}
		}
		counts[label][stage]++
	}
	for _, l := range []string{"F", "T"} {
		keys := make([]string, 0, len(counts[l]))
		for k := range counts[l] {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return counts[l][keys[i]] > counts[l][keys[j]] })
		kind := map[string]string{"F": "FALSE-POSITIVE", "T": "TRUE-POSITIVE"}[l]
		fmt.Printf("== %s stage breakdown (total %d)\n", kind, total[l])
		for _, k := range keys {
			fmt.Printf("  %-32s %6d  %.2f%%\n", k, counts[l][k], 100*float64(counts[l][k])/float64(max(total[l], 1)))
		}
	}
}
