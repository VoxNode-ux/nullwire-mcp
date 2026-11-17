package app

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"math/big"
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
	b64Waste      = 4 * 1024 * 1024 // most base64 that decodes to binary, per call
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
			if inner == "" || strings.HasPrefix(inner, "[REDACTED_") || isAllowMarkOnly(inner) || isPlaceholderValue(inner) || benignBareKey(g[1], inner) {
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
		if xmlBenignLeaf(xmlOpenLocalName(g[1])) {
			return m
		}
		inner := g[2]
		if strings.HasPrefix(inner, "<![CDATA[") {
			inner = strings.TrimSuffix(strings.TrimPrefix(inner, "<![CDATA["), "]]>")
		}
		trimmed := strings.TrimSpace(inner)
		if trimmed == "" || strings.HasPrefix(trimmed, "[REDACTED_") || isAllowMarkOnly(trimmed) || isPlaceholderValue(trimmed) {
			return m
		}
		*count++
		s.Tokens.Add(1)
		return g[1] + s.tag("TOKEN", inner) + g[3]
	})
}

// xmlOpenLocalName returns the local element name of an opening tag such as <wsse:Password Type="x">.
func xmlOpenLocalName(tag string) string {
	t := strings.TrimPrefix(tag, "<")
	if i := strings.IndexAny(t, " \t\r\n>"); i >= 0 {
		t = t[:i]
	}
	if i := strings.LastIndexByte(t, ':'); i >= 0 {
		t = t[i+1:]
	}
	return t
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
	waste := b64Waste // runs that decode to binary are charged here instead
	return reB64Candidate.ReplaceAllStringFunc(in, func(m string) string {
		if budget <= 0 || waste <= 0 || len(m) > b64MaxEncoded || !isBase64Like(m) {
			return m
		}
		decoded, ok := decodeBase64Text(m)
		if !ok {
			waste -= len(m)
			return m
		}
		budget -= len(m)
		if _, n := s.scrubLayers(string(decoded), false); n == 0 {
			return m
		}
		*count++
		s.Tokens.Add(1)
		return s.tag("TOKEN", m)
	})
}

// ---------------------------------------------------------------------------
// Secrets hidden in hex, Base32 and Base58.
//
// Same idea as scrubBase64: find a run, decode it, and redact the whole run
// when the decoded text holds a secret. These alphabets also fit ordinary
// words, hashes and ids, so the decoded bytes must be strictly printable text
// (valid UTF-8, no control bytes). A hash or a random id decodes to binary and
// is left alone. Base24 is not handled; it only matters for license keys.

var (
	// an even number of hex digits, at least 12 bytes
	reHexCandidate = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}){12,}\b`)
	// RFC 4648 Base32 in upper case, padded or not
	reB32Candidate = regexp.MustCompile(`\b[A-Z2-7]{24,}={0,6}`)
	// Bitcoin-style Base58: no 0, O, I or l
	reB58Candidate = regexp.MustCompile(`\b[1-9A-HJ-NP-Za-km-z]{20,}\b`)
)

const (
	hexMaxEncoded = 64 * 1024
	b32MaxEncoded = 64 * 1024
	b58MaxEncoded = 512 // Base58 decoding is quadratic, so runs stay short

	b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
)

var b58Index = func() (t [256]int8) {
	for i := range t {
		t[i] = -1
	}
	for i := 0; i < len(b58Alphabet); i++ {
		t[b58Alphabet[i]] = int8(i)
	}
	return t
}()

// isPrintableText is the strict check for decoded text: valid UTF-8, at least
// 8 bytes, and no control bytes other than tab and line breaks.
func isPrintableText(b []byte) bool {
	if len(b) < 8 || !utf8.Valid(b) {
		return false
	}
	for _, c := range b {
		if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}

func decodeHexText(s string) ([]byte, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || !isPrintableText(b) {
		return nil, false
	}
	return b, true
}

func decodeBase32Text(s string) ([]byte, bool) {
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(s, "="))
	if err != nil || !isPrintableText(b) {
		return nil, false
	}
	return b, true
}

func decodeBase58Text(s string) ([]byte, bool) {
	n, digit, base := new(big.Int), new(big.Int), big.NewInt(58)
	for i := 0; i < len(s); i++ {
		v := b58Index[s[i]]
		if v < 0 {
			return nil, false
		}
		n.Mul(n, base)
		n.Add(n, digit.SetInt64(int64(v)))
	}
	zeros := 0 // each leading "1" stands for a 0x00 byte
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	out := append(make([]byte, zeros), n.Bytes()...)
	if !isPrintableText(out) {
		return nil, false
	}
	return out, true
}

type encodedTextDecoder struct {
	re     *regexp.Regexp
	maxLen int
	decode func(string) ([]byte, bool)
}

var encodedTextDecoders = []encodedTextDecoder{
	{reHexCandidate, hexMaxEncoded, decodeHexText},
	{reB32Candidate, b32MaxEncoded, decodeBase32Text},
	{reB58Candidate, b58MaxEncoded, decodeBase58Text},
}

// hasEncodedRun reports whether in holds 20 letters or digits in a row, the
// least any of the three decoders looks at, so the passes are skipped (and
// nothing is copied) for text without one.
func hasEncodedRun(in string) bool {
	run := 0
	for i := 0; i < len(in); i++ {
		c := in[i]
		if (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			if run++; run >= 20 {
				return true
			}
			continue
		}
		run = 0
	}
	return false
}

// scrubEncodedText decodes hex, Base32 and Base58 runs and redacts the whole
// run when the decoded text holds a secret. Runs that decode to nothing
// readable, or to text with no secret, are left as they were. Like
// scrubBase64 it has a budget, so a body full of candidates costs a bounded
// amount.
func (s *Scrubber) scrubEncodedText(in string, count *int) string {
	budget := b64Budget
	waste := b64Waste // runs that do not decode to text are charged here instead
	for _, d := range encodedTextDecoders {
		in = d.re.ReplaceAllStringFunc(in, func(m string) string {
			if budget <= 0 || waste <= 0 || len(m) > d.maxLen {
				return m
			}
			decoded, ok := d.decode(m)
			if !ok {
				waste -= len(m)
				return m
			}
			budget -= len(m)
			if _, n := s.scrubLayers(string(decoded), false); n == 0 {
				return m
			}
			*count++
			s.Tokens.Add(1)
			return s.tag("TOKEN", m)
		})
	}
	return in
}
