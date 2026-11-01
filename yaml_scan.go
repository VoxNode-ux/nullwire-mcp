package main

import (
	"fmt"
	"regexp"
	"strings"
)

var yamlKeyValue = regexp.MustCompile(`^\s*(?:-\s*)?([A-Za-z0-9_.-]+)\s*:\s*(.*)$`)

// scanYAMLFile checks "key: value" lines. It is a line scanner, not a YAML
// parser: block scalars (| and >) and multi-line strings are skipped.
func scanYAMLFile(s *Scrubber, path string, report *strings.Builder) (ok bool, hits, tokens int) {
	raw, err := readScanFile(path)
	if err != nil {
		fmt.Fprintf(report, "✗ %s: %v\n", path, err)
		return false, 0, 0
	}
	fmt.Fprintf(report, "✓ %s\n", path)

	for i, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		m := yamlKeyValue.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key, val := m[1], strings.TrimSpace(m[2])
		if idx := strings.Index(val, " #"); idx != -1 {
			val = strings.TrimSpace(val[:idx])
		}
		val = strings.Trim(val, `"'`)
		switch val {
		case "", "|", ">", "|-", ">-", "|+", ">+":
			continue
		}
		if shown, n, found := scanKV(s, key, ": ", val); found {
			fmt.Fprintf(report, "   line %-4d %-32s → %s\n", i+1, key, shown)
			hits++
			tokens += n
		}
	}
	if hits == 0 {
		fmt.Fprintf(report, "   (no secrets found)\n")
	}
	return true, hits, tokens
}
