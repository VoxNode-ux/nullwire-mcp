package main

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Extra redaction layers: JSON arrays of secrets, XML elements, and secrets
// hidden inside base64.

var reQuotedString = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)

// reB64Candidate finds runs that could be base64 (standard or URL-safe).
var reB64Candidate = regexp.MustCompile(`[A-Za-z0-9+/_-]{24,}={0,2}`)

// xmlSecretHints are cheap keywords: XML scrubbing only runs when one of them
// appears in the text.
var xmlSecretHints = []string{"password", "passwd", "pwd", "secret", "token", "apikey", "api_key", "api-key", "authorization", "credential", "privatekey", "private_key", "accesskey", "access_key", "sessionid", "session_id"}

const (
	b64MaxEncoded = 88 * 1024  // longest base64 run that is decoded
	b64Budget     = 256 * 1024 // most base64 text decoded in one call
)

// scrubJSONSecretArrays redacts every string in an array that sits under a
// secret-looking key: "password": ["a", "b"].
func (s *Scrubber) scrubJSONSecretArrays(in string, count *int) string {
	return s.reJSONSecretArr.ReplaceAllStringFunc(in, func(m string) string {
		g := s.reJSONSecretArr.FindStringSubmatch(m)
		if g == nil {
			return m
		}
		items := reQuotedString.ReplaceAllStringFunc(g[2], func(q string) string {
			inner := q[1 : len(q)-1]
			if inner == "" || strings.HasPrefix(inner, "[REDACTED_") {
				return q
			}
			*count++
			s.Tokens.Add(1)
			return `"` + s.tag("TOKEN", inner) + `"`
		})
		return g[1] + items + g[3]
	})
}

// scrubXMLSecrets redacts the text of XML elements whose name suggests a
// secret, including namespaced ones such as <wsse:Password>.
func (s *Scrubber) scrubXMLSecrets(in string, count *int) string {
	return s.reXML.ReplaceAllStringFunc(in, func(m string) string {
		g := s.reXML.FindStringSubmatch(m)
		if g == nil {
			return m
		}
		trimmed := strings.TrimSpace(g[2])
		if trimmed == "" || strings.HasPrefix(trimmed, "[REDACTED_") {
			return m
		}
		*count++
		s.Tokens.Add(1)
		return g[1] + s.tag("TOKEN", g[2]) + g[3]
	})
}

// isBase64Like reports whether a run looks like base64 rather than a word or
// a number: long enough and mixing lower case with capitals or digits.
func isBase64Like(s string) bool {
	if len(s) < 24 {
		return false
	}
	var lower, upper, digit bool
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9':
			digit = true
		}
	}
	return (lower && (upper || digit)) || (upper && digit)
}

// mostlyText reports whether b is valid UTF-8 with hardly any control bytes,
// so decoded images and other binary data are left alone.
func mostlyText(b []byte) bool {
	if len(b) < 8 || !utf8.Valid(b) {
		return false
	}
	control := 0
	for _, c := range b {
		if c < 0x20 && c != '\n' && c != '\r' && c != '\t' {
			control++
		}
	}
	return control*20 < len(b)
}

func decodeBase64Text(s string) ([]byte, bool) {
	trimmed := strings.TrimRight(s, "=")
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(trimmed); err == nil && mostlyText(b) {
			return b, true
		}
	}
	return nil, false
}

// scrubBase64 decodes base64-looking runs and redacts the whole run when the
// decoded text holds a secret. Runs that decode to nothing readable, or to
// text with no secret, are left as they were.
func (s *Scrubber) scrubBase64(in string, count *int) string {
	budget := b64Budget
	return reB64Candidate.ReplaceAllStringFunc(in, func(m string) string {
		if budget <= 0 || len(m) > b64MaxEncoded || !isBase64Like(m) {
			return m
		}
		budget -= len(m)
		decoded, ok := decodeBase64Text(m)
		if !ok {
			return m
		}
		if _, n := s.scrubLayers(string(decoded), false); n == 0 {
			return m
		}
		*count++
		s.Tokens.Add(1)
		return s.tag("TOKEN", m)
	})
}
