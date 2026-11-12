package main

import (
	"fmt"
	"regexp"
	"strings"
)

var tomlKeyValue = regexp.MustCompile(`^\s*([A-Za-z0-9_.-]+)\s*=\s*["']([^"']*)["']`)
var tomlInlineTable = regexp.MustCompile(`^\s*([A-Za-z0-9_.-]+)\s*=\s*\{(.*)\}\s*$`)

func scanTOMLFile(s *Scrubber, path string, report *strings.Builder) (ok bool, hits, tokens int) {
	raw, err := readScanFile(path)
	if err != nil {
		fmt.Fprintf(report, "✗ %s: %v\n", path, err)
		return false, 0, 0
	}
	fmt.Fprintf(report, "✓ %s\n", path)

	// show prints one finding and reports whether the value was a secret.
	show := func(lineNo int, name, value string) {
		if value == "" {
			return
		}
		shown, n, found := scanKV(s, lastSegment(name), "=", value)
		if !found {
			return
		}
		fmt.Fprintf(report, "   line %-4d %s → %s\n", lineNo, name, shown)
		hits++
		tokens += n
	}

	currentTable := ""
	for i, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			currentTable = strings.Trim(trimmed, "[]")
			continue
		}
		qualify := func(parts ...string) string {
			if currentTable == "" {
				return strings.Join(parts, ".")
			}
			return currentTable + "." + strings.Join(parts, ".")
		}
		if m := tomlInlineTable.FindStringSubmatch(line); m != nil {
			key, body := m[1], m[2]
			for _, pair := range strings.Split(body, ",") {
				kv := strings.SplitN(pair, "=", 2)
				if len(kv) != 2 {
					continue
				}
				k := strings.TrimSpace(strings.Trim(strings.TrimSpace(kv[0]), `"'`))
				v := strings.TrimSpace(strings.Trim(strings.TrimSpace(kv[1]), `"'`))
				show(i+1, qualify(key, k), v)
			}
			continue
		}
		if m := tomlKeyValue.FindStringSubmatch(line); m != nil {
			show(i+1, qualify(m[1]), m[2])
		}
	}
	if hits == 0 {
		fmt.Fprintf(report, "   (no secrets found)\n")
	}
	return true, hits, tokens
}
