package scan

import (
	"fmt"
	"regexp"
	"strings"
)

// envSecretNames matches variable and key names that normally hold secrets.
// AUTH only counts as a whole word or next to _ or -, so AUTHOR is not flagged.
var envSecretNames = regexp.MustCompile(`(?i)(SECRET|TOKEN|PASSWORD|PASSWD|PASSPHRASE|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|(SIGNING|ENCRYPTION|DECRYPTION|MASTER|AUTH|LICENSE|SSH|GPG|PGP|HMAC|JWT|DEPLOY)[_-]?KEY|CREDENTIAL|BEARER|AUTHORIZATION|^AUTH$|AUTH[_-]|[_-]AUTH|(^|[_-])(PWD|PASS)($|[_-])|SESSION[_-]?(ID|KEY|TOKEN))`)

const HiddenValue = "(name looks secret; value hidden)"

func scanEnvFile(s Scrubber, path string, report *strings.Builder) (ok bool, hits, tokens, ips int) {
	raw, err := readScanFile(path)
	if err != nil {
		fmt.Fprintf(report, "✗ %s: %v\n", path, err)
		return false, 0, 0, 0
	}
	fmt.Fprintf(report, "✓ %s\n", path)
	for i, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, val, found := strings.Cut(trimmed, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(key), "export "))
		val = envValue(val)
		if val == "" {
			continue
		}
		shown, n, found := scanKV(s, key, "=", val)
		if !found {
			continue
		}
		fmt.Fprintf(report, "   line %-4d %-32s → %s\n", i+1, key, shown)
		hits++
		tokens += n
	}
	if hits == 0 {
		fmt.Fprintf(report, "   (no secrets found)\n")
	}
	return true, hits, tokens, 0
}

func envFileNames(name string) bool {
	n := strings.ToLower(name)
	return n == ".env" || n == ".envrc" || strings.HasPrefix(n, ".env.") || strings.HasSuffix(n, ".env")
}

// envValue returns the value part of a KEY=value line. Quoted values end at the
// closing quote (anything after it, such as a # comment, is dropped); unquoted
// values end at the first " #" or tab-#, so the comment is removed before any
// quote trimming.
func envValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if q := v[0]; q == '"' || q == '\'' {
		for i := 1; i < len(v); i++ {
			if q == '"' && v[i] == '\\' {
				i++
				continue
			}
			if v[i] == q {
				return v[1:i]
			}
		}
		return strings.TrimSpace(v[1:]) // no closing quote
	}
	if i := strings.Index(v, " #"); i >= 0 {
		v = v[:i]
	} else if i := strings.Index(v, "\t#"); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}
