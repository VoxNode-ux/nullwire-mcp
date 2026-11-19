package app

import (
	"encoding/json"
	"strings"
)

// A single-pass structural walk over a JSON document. It follows the object
// key path with a small stack, so a string value is judged by the name of the
// key that owns it (auth.credentials.secret is redacted, ui.theme.primary_key
// is not) and not by what the text around it happens to look like.
//
// It only acts on a document that is balanced from first byte to last. A
// truncated, malformed or non-JSON body is returned unchanged here, so the
// regexp rules, scrubStrictFieldsMax and the Stage-3 passes that run after it
// still see it exactly as before. Nothing in this file replaces them.

// jsonHintGate lets scrubJSONTree skip JSON bodies that have no key it could
// act on. The literals are fragments of what secretishKey accepts.
var jsonHintGate = lazyGate(maskGroup{1, []string{
	"key", "secret", "passw", "pwd", "token", "auth", "credential", "session", "sig", "private", "cookie", "bearer",
}})

// looksLikeJSONDoc reports whether in, ignoring leading white space, starts
// like a JSON object or array.
func looksLikeJSONDoc(in string) bool {
	for i := 0; i < len(in); i++ {
		switch in[i] {
		case ' ', '\t', '\n', '\r':
		case '{', '[':
			return true
		default:
			return false
		}
	}
	return false
}

type jsonFrame struct {
	obj       bool
	expectKey bool
	ks, ke    int  // the current key, as a range of the raw text
	keyEsc    bool // the raw key holds a backslash
}

// strongSecretKey is a key whose name says outright that the value is a
// secret, so a short value is redacted too. Weaker hints (auth, session,
// cookie, ...) go through the same value filters as scrubStrictFieldsMax.
func strongSecretKey(k string) bool {
	k = strings.ReplaceAll(strings.ToLower(k), "-", "_")
	for _, suf := range []string{"password", "passwd", "pwd", "secret", "token", "private_key", "privatekey", "api_key", "apikey", "secret_key"} {
		if strings.HasSuffix(k, suf) {
			return true
		}
	}
	return false
}

// Ancestor keys that tell an ambiguous leaf ("key", "token") what it is.
// UI and display objects hold lookup keys and theme tokens; credential
// objects hold secrets.
var (
	benignAncestorKeys = map[string]bool{
		"ui": true, "theme": true, "themes": true, "style": true, "styles": true, "css": true,
		"layout": true, "i18n": true, "l10n": true, "locale": true, "locales": true,
		"translations": true, "translation": true, "display": true, "view": true, "views": true,
		"colors": true, "palette": true, "fonts": true,
	}
	secretAncestorKeys = map[string]bool{
		"auth": true, "authentication": true, "credentials": true, "credential": true, "secrets": true,
		"security": true, "oauth": true, "login": true, "session": true, "sessions": true,
		"passwords": true, "private": true,
	}
)

// ambiguousLeafKey is a key whose own name does not say whether it is a
// secret: a bare "key" or "token".
func ambiguousLeafKey(k string) bool {
	k = strings.ToLower(k)
	return k == "key" || k == "token"
}

// ancestorContext reads the object keys above frame d on the stack and says
// whether one of them marks a display/UI object and whether one marks a
// credentials object. A credentials ancestor wins when both are present.
func ancestorContext(in string, stack []jsonFrame, d int) (benign, secret bool) {
	for i := 0; i < d; i++ {
		if !stack[i].obj {
			continue
		}
		k := strings.ReplaceAll(strings.ToLower(jsonKeyText(in, stack[i])), "-", "_")
		if secretAncestorKeys[k] {
			secret = true
		} else if benignAncestorKeys[k] {
			benign = true
		}
	}
	return benign && !secret, secret
}

// jsonKeyText returns the key held by f, decoding escapes when it has any.
func jsonKeyText(in string, f jsonFrame) string {
	raw := in[f.ks:f.ke]
	if !f.keyEsc {
		return raw
	}
	var k string
	if json.Unmarshal([]byte(`"`+raw+`"`), &k) != nil {
		return ""
	}
	return k
}

// jsonSecretValue decides whether the string value raw (the text between its
// quotes) under key is redacted.
func jsonSecretValue(key, raw string, ancBenign, ancSecret bool) bool {
	if key == "" || !secretishKey(key) || raw == "" {
		return false
	}
	val := raw
	if strings.IndexByte(raw, '\\') >= 0 {
		var d string
		if json.Unmarshal([]byte(`"`+raw+`"`), &d) != nil {
			return false
		}
		val = d
	}
	if strings.HasPrefix(val, "[REDACTED_") || hasAllowMark(val) || isAllowMarkOnly(val) || isPlaceholderValue(val) {
		return false
	}
	// A value that starts with an explicit secret prefix, or that a format
	// validator affirms, is a secret under any key and any parent.
	if hasStructuredPrefix(val) || validatedSecret(val) || strings.HasPrefix(val, "-----BEGIN") ||
		(strongSecretKey(key) && derKeyParses(val)) {
		return true
	}
	if ambiguousLeafKey(key) {
		switch {
		case ancSecret: // auth.credentials.key: a credential
			return len(val) >= 6
		case ancBenign: // ui.theme.key: a lookup key or a theme token
			return false
		}
	}
	if benignBareKey(key, val) {
		return false
	}
	if strongSecretKey(key) {
		return len(val) >= 6
	}
	// A weaker hint: the filters of scrubStrictFieldsMax.
	if len(val) < 12 || len(val) > 256 || strings.ContainsAny(val, " \t\\:") {
		return false
	}
	if strings.ContainsAny(val, "/.") && !strictSlashDotOK(val) {
		return false
	}
	return true
}

// scrubJSONTree redacts string values under secret-looking keys in a valid
// JSON document. Only the text between the quotes is replaced, by a tag that
// needs no escaping, so the surrounding JSON stays exactly as it was.
func (s *Scrubber) scrubJSONTree(in string, count *int) string {
	if len(in) < 8 || !looksLikeJSONDoc(in) || jsonHintGate.Match(in) == 0 {
		return in
	}
	var spans [][2]int
	var stack []jsonFrame
	started := false
	n := len(in)
	for i := 0; i < n; {
		c := in[i]
		switch c {
		case ' ', '\t', '\n', '\r':
			i++
		case '{', '[':
			if started && len(stack) == 0 {
				return in // a second top-level value: not one document
			}
			started = true
			stack = append(stack, jsonFrame{obj: c == '{', expectKey: c == '{'})
			i++
		case '}', ']':
			if len(stack) == 0 || stack[len(stack)-1].obj != (c == '}') {
				return in
			}
			stack = stack[:len(stack)-1]
			i++
		case ',':
			if len(stack) == 0 {
				return in
			}
			if top := &stack[len(stack)-1]; top.obj {
				top.expectKey = true
			}
			i++
		case ':':
			if len(stack) == 0 || !stack[len(stack)-1].obj {
				return in
			}
			stack[len(stack)-1].expectKey = false
			i++
		case '"':
			if len(stack) == 0 {
				return in
			}
			j, esc := i+1, false
			for j < n && in[j] != '"' {
				if in[j] == '\\' {
					esc = true
					j++
				}
				j++
			}
			if j >= n {
				return in // an unterminated string: truncated body
			}
			top := &stack[len(stack)-1]
			if top.obj && top.expectKey {
				top.ks, top.ke, top.keyEsc = i+1, j, esc
			} else {
				// The owner of a value is the nearest object's current key;
				// an array takes the key of the object that holds it.
				for d := len(stack) - 1; d >= 0; d-- {
					if stack[d].obj {
						key := jsonKeyText(in, stack[d])
						var ab, as bool
						if ambiguousLeafKey(key) {
							ab, as = ancestorContext(in, stack, d)
						}
						if jsonSecretValue(key, in[i+1:j], ab, as) {
							spans = append(spans, [2]int{i + 1, j})
						}
						break
					}
				}
			}
			i = j + 1
		default:
			if len(stack) == 0 {
				return in
			}
			i++ // number, true, false, null
		}
	}
	if len(stack) != 0 || len(spans) == 0 || !json.Valid([]byte(in)) {
		return in
	}
	var b strings.Builder
	last := 0
	for _, sp := range spans {
		raw := in[sp[0]:sp[1]]
		val := raw
		if strings.IndexByte(raw, '\\') >= 0 {
			var d string
			if json.Unmarshal([]byte(`"`+raw+`"`), &d) == nil {
				val = d
			}
		}
		b.WriteString(in[last:sp[0]])
		b.WriteString(s.tag("TOKEN", val))
		s.Tokens.Add(1)
		*count++
		last = sp[1]
	}
	b.WriteString(in[last:])
	return b.String()
}
