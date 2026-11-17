package scan

import (
	"fmt"
	"regexp"
	"strings"
)

var tomlAnyKeyValue = regexp.MustCompile(`^\s*([A-Za-z0-9_."'-]+)\s*=\s*(.*)$`)

// stripTOMLComment removes a trailing # comment, ignoring # inside quotes.
func stripTOMLComment(s string) string {
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == '\\' && q == '"' {
				i++
			} else if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '#':
			return strings.TrimRight(s[:i], " \t")
		}
	}
	return strings.TrimRight(s, " \t")
}

// tomlStrings returns the contents of every quoted string in s.
func tomlStrings(s string) []string {
	var out []string
	for i := 0; i < len(s); i++ {
		q := s[i]
		if q != '"' && q != '\'' {
			continue
		}
		j := i + 1
		for j < len(s) && s[j] != q {
			if q == '"' && s[j] == '\\' {
				j++
			}
			j++
		}
		if j >= len(s) {
			break
		}
		out = append(out, s[i+1:j])
		i = j
	}
	return out
}

// tomlDepth returns how many [ or { are still open in s, ignoring quoted text.
func tomlDepth(s string) int {
	depth := 0
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == '\\' && q == '"' {
				i++
			} else if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '[' || c == '{':
			depth++
		case c == ']' || c == '}':
			depth--
		}
	}
	return depth
}

// splitTOMLTop splits s on commas that are outside quotes and nested brackets.
func splitTOMLTop(s string) []string {
	var parts []string
	depth, start := 0, 0
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == '\\' && q == '"' {
				i++
			} else if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '[' || c == '{':
			depth++
		case c == ']' || c == '}':
			depth--
		case c == ',' && depth == 0:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

// tomlInlineBlocks returns the bodies of the top-level { } blocks of s (quoted
// text is skipped) and s with those blocks cut out.
func tomlInlineBlocks(s string) (bodies []string, rest string) {
	var out strings.Builder
	var q byte
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if q != 0 {
			if depth == 0 {
				out.WriteByte(c)
			}
			if c == '\\' && q == '"' && i+1 < len(s) {
				i++
				if depth == 0 {
					out.WriteByte(s[i])
				}
			} else if c == q {
				q = 0
			}
			continue
		}
		switch {
		case c == '"' || c == '\'':
			q = c
			if depth == 0 {
				out.WriteByte(c)
			}
		case c == '{':
			if depth == 0 {
				start = i + 1
			}
			depth++
		case c == '}' && depth > 0:
			depth--
			if depth == 0 {
				bodies = append(bodies, s[start:i])
				out.WriteByte(' ')
			}
		default:
			if depth == 0 {
				out.WriteByte(c)
			}
		}
	}
	return bodies, out.String()
}

// tomlScalar returns the text of a quoted scalar, or the bare text otherwise.
func tomlScalar(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}

func scanTOMLFile(s Scrubber, path string, report *strings.Builder) (ok bool, hits, tokens int) {
	raw, err := readScanFile(path)
	if err != nil {
		fmt.Fprintf(report, "✗ %s: %v\n", path, err)
		return false, 0, 0
	}
	fmt.Fprintf(report, "✓ %s\n", path)

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
	qualify := func(parts ...string) string {
		if currentTable == "" {
			return strings.Join(parts, ".")
		}
		return currentTable + "." + strings.Join(parts, ".")
	}
	// inline scans the body of one inline table, { a = "x", b = ["y"] }, under base.
	inline := func(lineNo int, base, body string) {
		for _, pair := range splitTOMLTop(body) {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) != 2 {
				continue
			}
			k := strings.TrimSpace(strings.Trim(strings.TrimSpace(kv[0]), `"'`))
			pv := strings.TrimSpace(kv[1])
			if strings.HasPrefix(pv, "[") {
				for _, str := range tomlStrings(pv) {
					show(lineNo, qualify(base, k), str)
				}
				continue
			}
			show(lineNo, qualify(base, k), tomlScalar(pv))
		}
	}
	lines := strings.Split(string(raw), "\n")
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			if h := stripTOMLComment(trimmed); strings.HasSuffix(h, "]") {
				currentTable = strings.TrimSpace(strings.Trim(h, "[]"))
				continue
			}
		}
		m := tomlAnyKeyValue.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		name := qualify(strings.Trim(m[1], `"'`))
		val := strings.TrimSpace(m[2])
		startLine := i + 1

		switch {
		case strings.HasPrefix(val, `"""`) || strings.HasPrefix(val, `'''`):
			delim, rest := val[:3], val[3:]
			parts := []string{rest}
			if idx := strings.Index(rest, delim); idx >= 0 {
				parts = []string{rest[:idx]}
			} else {
				for i+1 < len(lines) {
					i++
					if idx := strings.Index(lines[i], delim); idx >= 0 {
						parts = append(parts, lines[i][:idx])
						break
					}
					parts = append(parts, lines[i])
				}
			}
			show(startLine, name, strings.TrimSpace(strings.Join(parts, "\n")))
		case strings.HasPrefix(val, "["):
			text := stripTOMLComment(val)
			for tomlDepth(text) > 0 && i+1 < len(lines) {
				i++
				text += "\n" + stripTOMLComment(lines[i])
			}
			// [{ token = "x" }]: each inline table keeps the key context (items.token).
			bodies, rest := tomlInlineBlocks(text)
			for _, body := range bodies {
				inline(startLine, strings.Trim(m[1], `"'`), body)
			}
			for _, str := range tomlStrings(rest) {
				show(startLine, name, str)
			}
		case strings.HasPrefix(val, "{"):
			v := stripTOMLComment(val)
			if !strings.HasSuffix(v, "}") {
				continue
			}
			inline(startLine, strings.Trim(m[1], `"'`), v[1:len(v)-1])
		default:
			v := stripTOMLComment(val)
			if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') {
				show(startLine, name, tomlScalar(v))
			}
		}
	}
	if hits == 0 {
		fmt.Fprintf(report, "   (no secrets found)\n")
	}
	return true, hits, tokens
}
