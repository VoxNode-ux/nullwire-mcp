package app

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Compliance redaction presets (-preset / "presets" in -secrets-config).
//
// Presets are off by default. Each adds low-false-positive detectors on top of
// the always-on rules:
//
//	pci-dss  context-gated CVV/CVC/CID and track 1/2 data (card numbers
//	         themselves are always redacted by the Luhn rule in luhn.go)
//	hipaa    context-gated US SSN with SSA validation
//	gdpr     IBAN with country-length and ISO 7064 mod 97-10 checks
//
// Every redaction is tagged [REDACTED_TOKEN#...] so shellQuote and the tag
// checks treat them like any other secret.

const (
	presetPCI   = "pci-dss"
	presetHIPAA = "hipaa"
	presetGDPR  = "gdpr"
)

var presetNames = []string{presetPCI, presetHIPAA, presetGDPR}

// normalizePresets lower-cases, de-duplicates and expands "all". Unknown
// names are an error.
func normalizePresets(in []string) ([]string, error) {
	seen := map[string]bool{}
	for _, p := range in {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if p == "all" {
			for _, n := range presetNames {
				seen[n] = true
			}
			continue
		}
		ok := false
		for _, n := range presetNames {
			if p == n {
				ok = true
			}
		}
		if !ok {
			return nil, fmt.Errorf("unknown preset %q (valid: %s, all)", p, strings.Join(presetNames, ", "))
		}
		seen[p] = true
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// splitPresetFlag turns the comma-separated -preset value into a list.
func splitPresetFlag(spec string) []string {
	var out []string
	for _, p := range strings.Split(spec, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

type presetSet struct{ pci, hipaa, gdpr bool }

func (p presetSet) enabled() bool { return p.pci || p.hipaa || p.gdpr }

func newPresetSet(names []string) presetSet {
	var p presetSet
	for _, n := range names {
		switch n {
		case presetPCI:
			p.pci = true
		case presetHIPAA:
			p.hipaa = true
		case presetGDPR:
			p.gdpr = true
		}
	}
	return p
}

// ---- PCI-DSS: CVV / CVC / CID / track data --------------------------------

// reCardKey finds a card-security field name followed by ':' or '='. The
// value is read by hand after the match. The left boundary is checked in code
// (RE2 has no lookbehind), so "lcid" or "acidity" never count.
var reCardKey = regexp.MustCompile(`(?i)(?:cvv|cvc|cid|csc|cvn)(?:2|_?code|_?value|_?number)?|track[_-]?[12](?:[_-]?data)?`)

var reCardKeyAssign = regexp.MustCompile(`^["'\\]*\s*[:=]\s*["'\\]*`)

// reTrackValue matches track 1 (%B...^NAME^...?), track 2 (;PAN=...?) or any
// other run of 8+ characters up to a delimiter.
var reTrackValue = regexp.MustCompile(`^(?:%?[A-Za-z][0-9]{1,19}\^[^^"'\n]{2,26}\^[^"'\n?]*\??|;?[0-9]{12,19}=[^"'\s,&}?]*\??|[^"'\s,&}\\]{8,})`)

func isLetterByte(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// cardKeyBoundary reports whether a key found at in[i:] starts a field name:
// the byte before it is not a letter or digit, or it is an upper-case letter
// that follows a lower-case one (cardCvv).
func cardKeyBoundary(in string, i int) bool {
	if i == 0 {
		return true
	}
	p := in[i-1]
	if !isLetterByte(p) && !isDigit(p) {
		return true
	}
	return in[i] >= 'A' && in[i] <= 'Z' && p >= 'a' && p <= 'z'
}

func cardSecuritySpans(in string) []secretSpan {
	if len(in) < 5 {
		return nil
	}
	var spans []secretSpan
	for _, m := range reCardKey.FindAllStringIndex(in, -1) {
		if !cardKeyBoundary(in, m[0]) {
			continue
		}
		key := strings.ToLower(in[m[0]:m[1]])
		as := reCardKeyAssign.FindStringIndex(in[m[1]:])
		if as == nil {
			continue
		}
		vs := m[1] + as[1]
		if strings.HasPrefix(key, "track") {
			if loc := reTrackValue.FindStringIndex(in[vs:]); loc != nil && !strings.HasPrefix(in[vs:vs+loc[1]], "[REDACTED_") {
				spans = append(spans, secretSpan{start: vs, end: vs + loc[1]})
			}
			continue
		}
		ve := vs
		for ve < len(in) && isDigit(in[ve]) {
			ve++
		}
		if n := ve - vs; n < 3 || n > 4 {
			continue
		}
		if ve < len(in) && (isWordByte(in[ve]) || (in[ve] == '.' && ve+1 < len(in) && isDigit(in[ve+1]))) {
			continue
		}
		spans = append(spans, secretSpan{start: vs, end: ve})
	}
	return spans
}

// ---- HIPAA: context-gated US SSN -------------------------------------------

// ssnValid applies the SSA rules: area not 000, 666 or 900-999; group not 00;
// serial not 0000. s is "AAA-GG-SSSS".
func ssnValid(s string) bool {
	if len(s) != 11 || s[3] != '-' || s[6] != '-' {
		return false
	}
	area := int(s[0]-'0')*100 + int(s[1]-'0')*10 + int(s[2]-'0')
	if area == 0 || area == 666 || area >= 900 {
		return false
	}
	if s[4] == '0' && s[5] == '0' {
		return false
	}
	return s[7:] != "0000"
}

// ssnKeywords are the words that make a nearby number an SSN. They match as
// whole words, with '_' and '-' counting as separators ("ssn", "patient_ssn",
// "social_security_number", "TIN:"); "string" or "tinker" do not match.
var ssnKeywords = []string{"ssn", "social security", "social_security", "social-security", "socialsecurity", "tin", "taxpayer"}

const ssnWindowBefore, ssnWindowAfter = 48, 24

func ssnContext(in string, start, end int) bool {
	lo := start - ssnWindowBefore
	if lo < 0 {
		lo = 0
	}
	if nl := strings.LastIndexByte(in[lo:start], '\n'); nl >= 0 {
		lo += nl + 1
	}
	hi := end + ssnWindowAfter
	if hi > len(in) {
		hi = len(in)
	}
	if nl := strings.IndexByte(in[end:hi], '\n'); nl >= 0 {
		hi = end + nl
	}
	// Lower-case the two sides only; the number itself is skipped.
	for _, w := range [2]string{strings.ToLower(in[lo:start]), strings.ToLower(in[end:hi])} {
		for _, kw := range ssnKeywords {
			for from := 0; ; {
				i := strings.Index(w[from:], kw)
				if i < 0 {
					break
				}
				i += from
				j := i + len(kw)
				if (i == 0 || !isAlnumByte(w[i-1])) && (j == len(w) || !isAlnumByte(w[j])) {
					return true
				}
				from = i + 1
			}
		}
	}
	return false
}

func isAlnumByte(c byte) bool { return isLetterByte(c) || isDigit(c) }

func ssnSpans(in string) []secretSpan {
	if len(in) < 11 || strings.IndexByte(in, '-') < 0 {
		return nil
	}
	var spans []secretSpan
	for i := 0; i+11 <= len(in); i++ {
		if !isDigit(in[i]) || (i > 0 && (isAlnumByte(in[i-1]) || in[i-1] == '-')) {
			continue
		}
		c := in[i : i+11]
		if !isDigit(c[0]) || !isDigit(c[1]) || !isDigit(c[2]) || c[3] != '-' || !isDigit(c[4]) || !isDigit(c[5]) ||
			c[6] != '-' || !isDigit(c[7]) || !isDigit(c[8]) || !isDigit(c[9]) || !isDigit(c[10]) {
			continue
		}
		if i+11 < len(in) && (isAlnumByte(in[i+11]) || in[i+11] == '-') {
			continue
		}
		if !ssnValid(c) || !ssnContext(in, i, i+11) {
			continue
		}
		spans = append(spans, secretSpan{start: i, end: i + 11})
		i += 10
	}
	return spans
}

// ---- GDPR: IBAN -------------------------------------------------------------

var ibanLen = map[string]int{
	"AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22, "BI": 27,
	"BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DJ": 27, "DK": 18, "DO": 28,
	"EE": 20, "EG": 29, "ES": 24, "FI": 18, "FK": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23,
	"GL": 18, "GR": 27, "GT": 28, "HN": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26,
	"IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21,
	"LY": 25, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20, "MR": 27, "MT": 31, "MU": 30, "NI": 28,
	"NL": 18, "NO": 15, "OM": 23, "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22,
	"RU": 33, "SA": 24, "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "SO": 23, "ST": 25,
	"SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20, "YE": 30,
}

// ibanValid checks an already-normalised (upper-case, no spaces) IBAN:
// country, length for that country, then ISO 7064 mod 97-10.
func ibanValid(s string) bool {
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	if n, ok := ibanLen[s[:2]]; !ok || n != len(s) {
		return false
	}
	if !isDigit(s[2]) || !isDigit(s[3]) {
		return false
	}
	rem := 0
	for i := 0; i < len(s); i++ {
		c := s[(i+4)%len(s)]
		switch {
		case isDigit(c):
			rem = (rem*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			v := int(c-'A') + 10
			rem = (rem*100 + v) % 97
		default:
			return false
		}
	}
	return rem == 1
}

func upperByte(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - 'a' + 'A'
	}
	return c
}

// ibanSpans finds IBANs written compact ("GB82WEST...") or in groups of four
// separated by single spaces ("GB82 WEST 1234 ..."), in either case.
func ibanSpans(in string) []secretSpan {
	if len(in) < 15 {
		return nil
	}
	var spans []secretSpan
	for i := 0; i+4 <= len(in); {
		if !isLetterByte(in[i]) || !isLetterByte(in[i+1]) || !isDigit(in[i+2]) || !isDigit(in[i+3]) ||
			(i > 0 && (isAlnumByte(in[i-1]) || in[i-1] == '-')) {
			i++
			continue
		}
		// Read the first alphanumeric run, then optional groups of four.
		var norm []byte
		j := i
		for j < len(in) && isAlnumByte(in[j]) && len(norm) < 40 {
			norm = append(norm, upperByte(in[j]))
			j++
		}
		end := j
		bestEnd := -1
		if len(norm) > 4 && ibanValid(string(norm)) {
			bestEnd = end
		}
		if len(norm) == 4 {
			// grouped form: AAAA BBBB CCCC ... last group 1-4 characters. Each
			// group is checked as it is added, so a following word is never
			// swallowed into an IBAN whose last group was already full.
			for end < len(in) && in[end] == ' ' && end+1 < len(in) && isAlnumByte(in[end+1]) {
				k := end + 1
				g := 0
				for k < len(in) && isAlnumByte(in[k]) && g < 5 {
					g++
					k++
				}
				if g > 4 || (k < len(in) && isAlnumByte(in[k])) {
					break
				}
				for q := end + 1; q < k; q++ {
					norm = append(norm, upperByte(in[q]))
				}
				end = k
				if ibanValid(string(norm)) {
					bestEnd = end
				}
				if g < 4 || len(norm) >= 34 {
					break
				}
			}
		}
		if bestEnd >= 0 && (bestEnd == len(in) || (!isAlnumByte(in[bestEnd]) && in[bestEnd] != '-')) {
			spans = append(spans, secretSpan{start: i, end: bestEnd})
			i = bestEnd
			continue
		}
		if j > i {
			i = j
		} else {
			i++
		}
	}
	return spans
}

// ---- wiring -----------------------------------------------------------------

// presetSpans returns every span the enabled presets find in in. Spans may
// overlap; callers drop overlaps. kind is always TOKEN.
func (s *Scrubber) presetSpans(in string) []secretSpan {
	if !s.presets.enabled() {
		return nil
	}
	var spans []secretSpan
	if s.presets.pci {
		spans = append(spans, cardSecuritySpans(in)...)
	}
	if s.presets.hipaa {
		spans = append(spans, ssnSpans(in)...)
	}
	if s.presets.gdpr {
		spans = append(spans, ibanSpans(in)...)
	}
	return spans
}

// scrubPresets redacts what the enabled presets find. It does nothing, and
// allocates nothing, when no preset is on.
func (s *Scrubber) scrubPresets(in string) (string, int) {
	spans := s.presetSpans(in)
	if len(spans) == 0 {
		return in, 0
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	var b strings.Builder
	last, n := 0, 0
	for _, sp := range spans {
		if sp.start < last || sp.end > len(in) || sp.end <= sp.start {
			continue
		}
		b.WriteString(in[last:sp.start])
		b.WriteString(s.tag("TOKEN", in[sp.start:sp.end]))
		s.Tokens.Add(1)
		last = sp.end
		n++
	}
	if n == 0 {
		return in, 0
	}
	b.WriteString(in[last:])
	return b.String(), n
}
