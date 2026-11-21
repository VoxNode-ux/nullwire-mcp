package app

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
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
	// CREDDATA_KEY sets the key name put in front of every value (default
	// "CRED", which looks like a secret-named field). Run it again with a
	// neutral name such as "X" to see how much of the FPR comes from the key.
	key := os.Getenv("CREDDATA_KEY")
	if key == "" {
		key = "CRED"
	}
	// CREDDATA_SAMPLES=N writes up to N example values per label and stage to
	// CREDDATA_SAMPLES_OUT (default stage-samples.tsv), to see what triggers.
	maxSamples, _ := strconv.Atoi(os.Getenv("CREDDATA_SAMPLES"))
	samplesOut := os.Getenv("CREDDATA_SAMPLES_OUT")
	if samplesOut == "" {
		samplesOut = "stage-samples.tsv"
	}
	samples := map[string][]string{}
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
		line := key + "=" + val
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
		if k := label + "\t" + stage; len(samples[k]) < maxSamples {
			samples[k] = append(samples[k], val)
		}
	}
	if maxSamples > 0 {
		var b strings.Builder
		keys := make([]string, 0, len(samples))
		for k := range samples {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			for _, v := range samples[k] {
				b.WriteString(k + "\t" + v + "\n")
			}
		}
		if err := os.WriteFile(samplesOut, []byte(b.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fmt.Printf("== key name used: %q\n", key)
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
