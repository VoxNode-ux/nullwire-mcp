package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// historyHints are cheap keywords that make a history line worth scrubbing.
var historyHints = []string{
	"bearer", "token", "secret", "password", "passwd", "api_key", "apikey", "api-key",
	"authorization", "auth", "credential", "key=", "ghp_", "github_pat_", "sk-", "akia", "xox", "aiza", "glpat-",
}

func historyPaths() []string {
	home, _ := os.UserHomeDir()
	appData := os.Getenv("APPDATA")
	var candidates []string
	if home != "" {
		candidates = append(candidates,
			filepath.Join(home, ".bash_history"), filepath.Join(home, ".zsh_history"),
			filepath.Join(home, ".histfile"), filepath.Join(home, ".local", "share", "fish", "fish_history"),
		)
	}
	if runtime.GOOS == "windows" && appData != "" {
		candidates = append(candidates, filepath.Join(appData, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt"))
	}

	var out []string
	seen := map[string]bool{}
	for _, p := range candidates {
		if seen[p] {
			continue
		}
		seen[p] = true
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			out = append(out, p)
		}
	}
	return out
}

// scanHistoryFile reports how many history lines contain secrets. It never
// prints the lines themselves: a line that holds one secret may well hold
// others the scrubber does not recognise.
func scanHistoryFile(s *Scrubber, path string, report *strings.Builder) (ok bool, hits, tokens int) {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(report, "✗ %s: %v\n", path, err)
		return false, 0, 0
	}
	defer f.Close()
	fmt.Fprintf(report, "✓ %s\n", path)

	sc := newLineScanner(f, 512*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if !containsAny(strings.ToLower(line), historyHints) {
			continue
		}
		if _, n := s.ScrubText(line); n > 0 {
			fmt.Fprintf(report, "   line %-5d %d secret(s) found (text not shown)\n", lineNo, n)
			hits++
			tokens += n
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(report, "   (stopped reading at line %d: %v)\n", lineNo+1, err)
	}
	if hits == 0 {
		fmt.Fprintf(report, "   (no secrets found)\n")
	}
	return true, hits, tokens
}

func newLineScanner(r io.Reader, max int) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), max)
	return sc
}
