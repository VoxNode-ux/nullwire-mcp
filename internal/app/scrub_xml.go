package app

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"
	"unicode"
)

// The regular expression in scrubXMLSecrets handles the common case, a secret
// element with plain text or one CDATA block directly inside it. scrubXMLTree
// reads the document with encoding/xml and covers what a regular expression
// cannot follow:
//
//   - markup nested inside a secret element: <Credentials><Value>x</Value></Credentials>
//   - CDATA blocks, whose text is scrubbed as a document of its own, so JSON or
//     XML carried inside <![CDATA[ ... ]]> is searched too
//   - XML escaped as text: &lt;Password&gt;x&lt;/Password&gt;
//
// It only ever replaces whole text or CDATA tokens, found by their byte offsets
// in the input, so nothing outside them changes, and a document that stops
// being well formed simply ends the pass early.

const (
	xmlTreeMaxInput = 4 * 1024 * 1024 // longest text read as a document
	xmlTreeMaxDepth = 128             // deepest element nesting followed
	xmlEscapedMin   = 12              // shortest text read as escaped markup
)

// benignXMLWords are whole words of an element name that mark it as metadata
// next to a secret, not the secret itself: <TokenType>, <PasswordExpiry>, <Token><Format>.
// The name is split into words first (see xmlNameWords), so <TokenPrototype> is not
// mistaken for <TokenType>.
var benignXMLWords = map[string]bool{
	"type": true, "types": true, "expiry": true, "expiration": true, "expire": true, "expires": true,
	"lifetime": true, "algorithm": true, "encoding": true, "format": true, "version": true,
	"username": true, "created": true, "timestamp": true,
	"count": true, "length": true, "name": true, "method": true, "policy": true, "provider": true,
	"scheme": true, "scope": true, "issuer": true, "audience": true, "status": true, "enabled": true,
}

func xmlSecretName(local string) bool {
	l := strings.ToLower(local)
	for _, h := range xmlSecretHints {
		if strings.Contains(l, h) {
			return true
		}
	}
	return false
}

// xmlNameWords splits an element name into lower-case words at _ - . : separators,
// at lower-to-upper camelCase boundaries, and between an acronym and a following
// word ("XMLToken" -> xml, token).
func xmlNameWords(name string) []string {
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	rs := []rune(name)
	for i, r := range rs {
		switch {
		case r == '_' || r == '-' || r == '.' || r == ':':
			flush()
			continue
		case unicode.IsUpper(r) && len(cur) > 0:
			prev := rs[i-1]
			nextLower := i+1 < len(rs) && unicode.IsLower(rs[i+1])
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
				flush()
			}
		}
		cur = append(cur, r)
	}
	flush()
	return words
}

// xmlBenignLeaf reports whether the element name (any case) contains a whole benign word.
func xmlBenignLeaf(local string) bool {
	for _, w := range xmlNameWords(local) {
		if benignXMLWords[w] {
			return true
		}
	}
	return false
}

type xmlFrame struct {
	name        string // lower-case local name
	benign      bool   // the name holds a whole benign word (type, expiry, ...)
	inSecret    bool   // this element or an ancestor has a secret-looking name
	underSecret bool   // a strict ancestor has one
}

type xmlEdit struct {
	start, end int
	text       string
}

func (s *Scrubber) scrubXMLTree(in string, count *int) string {
	if len(in) > xmlTreeMaxInput || (strings.IndexByte(in, '<') < 0 && !strings.Contains(in, "&lt;")) {
		return in
	}
	dec := xml.NewDecoder(strings.NewReader(in))
	dec.Strict = false
	// Bytes are used as they are; the offsets below refer to the input itself.
	dec.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }

	stack := make([]xmlFrame, 0, 16)
	var edits []xmlEdit
loop:
	for {
		start := int(dec.InputOffset())
		tok, err := dec.RawToken()
		if err != nil {
			break
		}
		end := int(dec.InputOffset())
		if start < 0 || end > len(in) || start >= end {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if len(stack) >= xmlTreeMaxDepth {
				break loop
			}
			f := xmlFrame{name: strings.ToLower(t.Name.Local), benign: xmlBenignLeaf(t.Name.Local)}
			if len(stack) > 0 {
				top := stack[len(stack)-1]
				f.inSecret, f.underSecret = top.inSecret, top.inSecret
			}
			if xmlSecretName(t.Name.Local) {
				f.inSecret = true
			}
			stack = append(stack, f)
		case xml.EndElement:
			name := strings.ToLower(t.Name.Local)
			for i := len(stack) - 1; i >= 0; i-- {
				if stack[i].name == name {
					stack = stack[:i]
					break
				}
			}
		case xml.CharData:
			raw := in[start:end]
			cdata := strings.HasPrefix(raw, "<![CDATA[")
			inner := raw
			if cdata {
				inner = strings.TrimSuffix(strings.TrimPrefix(raw, "<![CDATA["), "]]>")
			}
			trimmed := strings.TrimSpace(inner)
			if trimmed == "" || strings.HasPrefix(trimmed, "[REDACTED_") || isAllowMarkOnly(trimmed) || isPlaceholderValue(trimmed) {
				continue
			}
			if n := len(stack); n > 0 && stack[n-1].inSecret && !stack[n-1].benign {
				*count++
				s.Tokens.Add(1)
				edits = append(edits, xmlEdit{start, end, s.tag("TOKEN", inner)})
				continue
			}
			if cdata {
				if out, n := s.scrubLayers(inner, false); n > 0 {
					*count += n
					edits = append(edits, xmlEdit{start, end, "<![CDATA[" + out + "]]>"})
				}
				continue
			}
			if len(trimmed) >= xmlEscapedMin && strings.Contains(raw, "&lt;") {
				// t holds the text with its entities resolved.
				if out, n := s.scrubLayers(string(t), false); n > 0 {
					var esc bytes.Buffer
					if err := xml.EscapeText(&esc, []byte(out)); err == nil {
						*count += n
						edits = append(edits, xmlEdit{start, end, esc.String()})
					}
				}
			}
		}
	}
	if len(edits) == 0 {
		return in
	}
	var b strings.Builder
	last := 0
	for _, e := range edits {
		b.WriteString(in[last:e.start])
		b.WriteString(e.text)
		last = e.end
	}
	b.WriteString(in[last:])
	return b.String()
}
