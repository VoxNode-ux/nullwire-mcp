package scan

import (
	"fmt"
	"regexp"
	"strings"
)

var yamlListItem = regexp.MustCompile(`^\s*-\s+(.+)$`)
var yamlKeyValue = regexp.MustCompile(`^\s*(?:-\s*)?([A-Za-z0-9_.-]+)\s*:\s*(.*)$`)

// ScanYAMLFile checks "key: value" lines. It is a line scanner, not a YAML
// parser: block scalars (| and >) and multi-line strings are skipped.
func ScanYAMLFile(s Scrubber, path string, report *strings.Builder) (ok bool, hits, tokens int) {
	raw, err := readScanFile(path)
	if err != nil {
		fmt.Fprintf(report, "✗ %s: %v\n", path, err)
		return false, 0, 0
	}
	fmt.Fprintf(report, "✓ %s\n", path)

	report1 := func(lineNo int, key, val string) {
		switch val {
		case "", "|", ">", "|-", ">-", "|+", ">+":
			return
		}
		if shown, n, found := scanKV(s, key, ": ", val); found {
			fmt.Fprintf(report, "   line %-4d %-32s → %s\n", lineNo, key, shown)
			hits++
			tokens += n
		}
	}

	parentKey, parentIndent := "", -1 // the last "key:" with nothing after it, which owns the list items below
	for i, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if m := yamlKeyValue.FindStringSubmatch(line); m != nil {
			key, val := m[1], yamlValue(m[2])
			if val == "" && !strings.HasPrefix(trimmed, "-") {
				parentKey, parentIndent = key, indent
				continue
			}
			if indent <= parentIndent && !strings.HasPrefix(trimmed, "-") {
				parentKey, parentIndent = "", -1
			}
			// Flow sequence: key: ["a", "b"]
			if strings.HasPrefix(val, "[") && strings.HasSuffix(val, "]") {
				for _, item := range strings.Split(val[1:len(val)-1], ",") {
					report1(i+1, key, strings.Trim(strings.TrimSpace(item), `"'`))
				}
				continue
			}
			report1(i+1, key, strings.Trim(val, `"'`))
			continue
		}
		if m := yamlListItem.FindStringSubmatch(line); m != nil {
			key := parentKey
			if key == "" {
				key = "item"
			}
			report1(i+1, key, strings.Trim(yamlValue(m[1]), `"'`))
		}
	}
	if hits == 0 {
		fmt.Fprintf(report, "   (no secrets found)\n")
	}
	return true, hits, tokens
}

// yamlValue trims a value and drops a trailing " #" comment.
func yamlValue(v string) string {
	v = strings.TrimSpace(v)
	if idx := strings.Index(v, " #"); idx != -1 {
		v = strings.TrimSpace(v[:idx])
	}
	return v
}
