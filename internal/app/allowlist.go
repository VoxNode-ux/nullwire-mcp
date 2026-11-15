package app

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The allowlist lets a user stop a false positive in BODIES without making the
// defaults weaker for anyone else. It is empty unless the user's
// -secrets-config file sets "ignore_fields" or "ignore_patterns"; with neither
// set, nothing in this file runs.
//
//   - ignore_fields: names of fields whose VALUE is left as it is. A field is
//     found as a JSON member ("name": "value" or "name": 3), as name=value (a
//     query string, a form, an env file), or as an XML element. The field-name
//     rules and the randomness checks no longer touch the value. A recognised
//     secret format inside it (a vendor key, a JWT, a private key, a password
//     in a URL) is still redacted.
//   - ignore_patterns: regular expressions. Text that matches one is left
//     completely alone, for known harmless values such as a public test key.
//
// Headers and URLs are not affected: they have ignore_headers and
// ignore_url_substrings.

const (
	maxIgnoreFields   = 200
	maxIgnorePatterns = 100
	maxIgnorePattern  = 512
	maxFieldName      = 128

	// allowMark starts the placeholder that holds an exempt piece of text while
	// the rules run. NUL never occurs in the character classes the rules use.
	allowMark = "\x00NW"
)

type allowlist struct {
	fields   []*regexp.Regexp // each has three groups: before the value, the value, after it
	patterns []*regexp.Regexp
}

// newAllowlist checks and compiles the two lists. It returns nil when both are
// empty. Errors say which entry is wrong.
func newAllowlist(fields, patterns []string) (*allowlist, error) {
	if len(fields) == 0 && len(patterns) == 0 {
		return nil, nil
	}
	if len(fields) > maxIgnoreFields {
		return nil, fmt.Errorf("ignore_fields has %d entries, the limit is %d", len(fields), maxIgnoreFields)
	}
	if len(patterns) > maxIgnorePatterns {
		return nil, fmt.Errorf("ignore_patterns has %d entries, the limit is %d", len(patterns), maxIgnorePatterns)
	}
	a := &allowlist{}

	if len(fields) > 0 {
		seen := make(map[string]bool, len(fields))
		names := make([]string, 0, len(fields))
		for i, f := range fields {
			f = strings.TrimSpace(f)
			if f == "" {
				return nil, fmt.Errorf("ignore_fields[%d] is empty", i)
			}
			if len(f) > maxFieldName {
				return nil, fmt.Errorf("ignore_fields[%d] is longer than %d characters", i, maxFieldName)
			}
			for j := 0; j < len(f); j++ {
				if f[j] < 0x20 || f[j] == 0x7f {
					return nil, fmt.Errorf("ignore_fields[%d] (%q) has a control character", i, f)
				}
			}
			lf := strings.ToLower(f)
			if !seen[lf] {
				seen[lf] = true
				names = append(names, regexp.QuoteMeta(lf))
			}
		}
		alt := strings.Join(names, "|")
		for _, src := range []string{
			// "name": "value"
			`(?i)("(?:` + alt + `)"\s*:\s*")((?:[^"\\]|\\.)*)(")`,
			// "name": 3, true, null
			`(?i)("(?:` + alt + `)"\s*:\s*)([^\s,"{}\[\]][^\s,}\]]*)()`,
			// name=value in a query string, a form or an env file
			`(?i)((?:^|[?&;,{\s])(?:` + alt + `)=)([^&\s#;,"']+)()`,
			// <name>value</name>
			`(?i)(<(?:[A-Za-z0-9_.-]+:)?(?:` + alt + `)(?:\s[^<>]*)?>)([^<]*)(</)`,
		} {
			re, err := regexp.Compile(src)
			if err != nil {
				return nil, fmt.Errorf("ignore_fields: %v", err)
			}
			a.fields = append(a.fields, re)
		}
	}

	for i, p := range patterns {
		if p == "" {
			return nil, fmt.Errorf("ignore_patterns[%d] is empty", i)
		}
		if len(p) > maxIgnorePattern {
			return nil, fmt.Errorf("ignore_patterns[%d] is longer than %d characters", i, maxIgnorePattern)
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("ignore_patterns[%d] (%q): %v", i, p, err)
		}
		if re.MatchString("") {
			return nil, fmt.Errorf("ignore_patterns[%d] (%q) matches the empty string, which would exempt everything", i, p)
		}
		if re.MatchString("\x01") {
			return nil, fmt.Errorf("ignore_patterns[%d] (%q) matches any character, which would exempt everything; make it more specific", i, p)
		}
		a.patterns = append(a.patterns, re)
	}
	return a, nil
}

// scrubWithAllowlist is the body path when an allowlist is set: exempt text is
// swapped for placeholders, every rule runs on the rest, and the exempt text is
// put back.
func (s *Scrubber) scrubWithAllowlist(in string, o scrubOpts) (string, int) {
	a := s.allow
	if in == "" || strings.Contains(in, allowMark) {
		return s.scrubLayersOpts(in, o)
	}
	var kept []string
	count := 0
	hold := func(text string) string {
		kept = append(kept, text)
		return allowMark + strconv.Itoa(len(kept)-1) + "\x00"
	}

	work := in
	for _, re := range a.fields {
		idx := re.FindAllStringSubmatchIndex(work, -1)
		if len(idx) == 0 {
			continue
		}
		var b strings.Builder
		last := 0
		for _, m := range idx {
			var g [4]string
			for k := 0; k < 4 && 2*k+1 < len(m); k++ {
				if m[2*k] >= 0 {
					g[k] = work[m[2*k]:m[2*k+1]]
				}
			}
			// The value is not judged by its field name or its randomness, but a
			// recognised secret format inside it is still redacted.
			v, n := s.scrubLayersOpts(g[2], scrubOpts{ctx: ContextBody, skipEntropy: true, skipIP: true})
			count += n
			b.WriteString(work[last:m[0]])
			b.WriteString(hold(g[1] + v + g[3]))
			last = m[1]
		}
		b.WriteString(work[last:])
		work = b.String()
	}
	for _, re := range a.patterns {
		work = re.ReplaceAllStringFunc(work, func(m string) string {
			if m == "" {
				return m
			}
			return hold(m)
		})
	}

	out, n := s.scrubLayersOpts(work, o)
	count += n
	if len(kept) > 0 && strings.Contains(out, allowMark) {
		pairs := make([]string, 0, 2*len(kept))
		for i, k := range kept {
			pairs = append(pairs, allowMark+strconv.Itoa(i)+"\x00", k)
		}
		out = strings.NewReplacer(pairs...).Replace(out)
	}
	return out, count
}
