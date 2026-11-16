package app

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"strings"
)

// GraphQL requests all look alike in a flow list: POST /graphql. graphqlNote
// reads the operation out of the request, so the note says what the call was,
// for example "GraphQL mutation Login." or "GraphQL batch of 3: query A, ...".
//
// It understands a JSON body, a batch (a JSON array of them), the
// application/graphql body type, a GET query string, and persisted queries
// (extensions.persistedQuery), where only the operation name is sent.
//
// The note is stored as it is written, not scrubbed afterwards, so a name only
// reaches it if it is a plain GraphQL name ([_A-Za-z][_0-9A-Za-z]*, at most 64
// characters) that also passes through the scrubber unchanged. Anything else is
// shown as <invalid name> or <redacted>. Query text, variables and the
// persisted-query hash are never copied into the note.

const (
	gqlMaxBody   = 1 << 20 // largest body read as JSON
	gqlMaxName   = 64
	gqlMaxListed = 5   // operations named in a batch note
	gqlMaxItems  = 100 // batch entries examined
	gqlMaxOps    = 50  // operations read from one query document
)

// field is the first root field of the operation's selection set, used to
// describe an anonymous operation such as "query { viewer }".
type gqlOp struct{ kind, name, field string }

type gqlRequest struct {
	query     string
	opName    string
	persisted bool
	weakID    bool // a bare "id" next to "variables": GraphQL only on a /graphql path
}

func gqlFromObject(m map[string]any) (gqlRequest, bool) {
	var r gqlRequest
	r.query, _ = m["query"].(string)
	r.opName, _ = m["operationName"].(string)
	if ext, ok := m["extensions"].(map[string]any); ok {
		r.persisted = gqlIsPersisted(ext["persistedQuery"])
	}
	// Relay and Facebook style persisted documents: doc_id or queryId.
	if gqlIDSet(m["doc_id"]) || gqlIDSet(m["queryId"]) {
		r.persisted = true
	}
	if id, ok := m["id"].(string); ok && id != "" {
		_, vars := m["variables"].(map[string]any)
		r.weakID = vars
	}
	return r, r.query != "" || r.persisted
}

// gqlIDSet reports a usable document id: a non-empty string or a positive number.
func gqlIDSet(v any) bool {
	switch t := v.(type) {
	case string:
		return t != ""
	case float64:
		return t > 0
	}
	return false
}

// gqlIsPersisted reports an Apollo-style persistedQuery extension: an object
// with a version or a hash. Any other value under that name is not one.
func gqlIsPersisted(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	return gqlIDSet(m["sha256Hash"]) || gqlIDSet(m["version"])
}

// gqlBlockEnd returns the index of the closing """ of a block string whose
// content starts at s[0], or -1. \""" is an escaped triple quote, not the end.
func gqlBlockEnd(s string) int {
	for j := 0; j < len(s); j++ {
		switch {
		case s[j] == '\\' && strings.HasPrefix(s[j+1:], `"""`):
			j += 3
		case strings.HasPrefix(s[j:], `"""`):
			// A run of more than three quotes: the content ends with the
			// extra ones and the last three close the string.
			for j+3 < len(s) && s[j+3] == '"' {
				j++
			}
			return j
		}
	}
	return -1
}

func gqlFromURL(raw string) (gqlRequest, bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return gqlRequest{}, false
	}
	q := u.Query()
	r := gqlRequest{query: q.Get("query"), opName: q.Get("operationName")}
	r.persisted = q.Get("doc_id") != "" || q.Get("queryId") != ""
	if ext := q.Get("extensions"); ext != "" {
		var m map[string]any
		if json.Unmarshal([]byte(ext), &m) == nil {
			r.persisted = r.persisted || gqlIsPersisted(m["persistedQuery"])
		}
	}
	return r, r.query != "" || r.persisted
}

func isGraphQLContentType(ct string) bool {
	mt := strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(mt, ';'); i >= 0 {
		mt = strings.TrimSpace(mt[:i])
	}
	return mt == "application/graphql"
}

func gqlNameStart(c byte) bool { return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func gqlNameChar(c byte) bool  { return gqlNameStart(c) || (c >= '0' && c <= '9') }

func gqlValidName(s string) bool {
	if s == "" || len(s) > gqlMaxName || !gqlNameStart(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !gqlNameChar(s[i]) {
			return false
		}
	}
	return true
}

// gqlSkip moves past whitespace, commas and comments.
func gqlSkip(src string, i int) int {
	for i < len(src) {
		switch src[i] {
		case ' ', '\t', '\n', '\r', ',':
			i++
		case '#':
			for i < len(src) && src[i] != '\n' && src[i] != '\r' {
				i++
			}
		default:
			return i
		}
	}
	return i
}

// gqlOperations lists the top-level operations of a query document. It skips
// strings, block strings and comments, and only looks at the keywords outside
// every brace and parenthesis, so a field named "query" or a string such as
// "mutation X {" is not mistaken for an operation. Fragments are skipped.
func gqlOperations(src string) []gqlOp {
	var ops []gqlOp
	depth, header := 0, false // header: an operation or fragment keyword came before the next {
	var pending *gqlOp        // operation keyword seen, kept only once its { follows
	awaiting := -1            // op whose first root field has not been read yet
	i, n := 0, len(src)
	for i < n && len(ops) < gqlMaxOps {
		c := src[i]
		switch {
		case c == '#':
			i = gqlSkip(src, i)
		case c == '"':
			if strings.HasPrefix(src[i:], `"""`) {
				end := gqlBlockEnd(src[i+3:])
				if end < 0 {
					return ops
				}
				i += 3 + end + 3
				continue
			}
			i++
			for i < n && src[i] != '"' && src[i] != '\n' && src[i] != '\r' {
				if src[i] == '\\' && i+1 < n && src[i+1] != '\n' && src[i+1] != '\r' {
					i++
				}
				i++
			}
			if i < n && src[i] == '"' {
				i++
			}
		case c == '{':
			if depth == 0 {
				switch {
				case pending != nil:
					ops = append(ops, *pending)
				case !header:
					ops = append(ops, gqlOp{kind: "query"}) // shorthand: { ... }
				}
				if pending != nil || !header {
					awaiting = len(ops) - 1
				}
				pending, header = nil, false
			}
			depth++
			i++
		case c == '(' || c == '[':
			depth++
			i++
		case c == '}' || c == ')' || c == ']':
			if depth > 0 {
				depth--
			}
			i++
		case gqlNameStart(c):
			j := i + 1
			for j < n && gqlNameChar(src[j]) {
				j++
			}
			word := src[i:j]
			i = j
			if depth != 0 {
				if awaiting >= 0 && depth == 1 {
					start := i - len(word)
					if k := gqlSkip(src, i); k < n && src[k] == ':' {
						continue // an alias: the field name follows
					}
					if !strings.HasSuffix(strings.TrimRight(src[:start], " \t\r\n,"), "...") {
						ops[awaiting].field = word
					}
					awaiting = -1
				}
				continue
			}
			switch word {
			case "query", "mutation", "subscription":
				if header && pending == nil { // "fragment F on query {": a type name
					continue
				}
				header = true
				op := gqlOp{kind: word}
				if k := gqlSkip(src, i); k < n && gqlNameStart(src[k]) {
					e := k + 1
					for e < n && gqlNameChar(src[e]) {
						e++
					}
					op.name = src[k:e]
					i = e
				}
				pending = &op
			case "fragment":
				header, pending = true, nil
			}
		default:
			i++
		}
	}
	return ops
}

// gqlSafeName returns name when it is safe to put in a note. The int is how
// many redactions that took.
func (a *App) gqlSafeName(name string) (string, int) {
	if name == "" {
		return "", 0
	}
	if !gqlValidName(name) {
		return "<invalid name>", 0
	}
	if out, n := a.scrub.ScrubText(name); n > 0 || out != name {
		return "<redacted>", 1
	}
	return name, 0
}

// gqlLabel describes one request, such as "query GetUser" or "persisted
// operation Feed". It is "" when the request is not GraphQL.
func (a *App) gqlLabel(r gqlRequest) (string, int) {
	ops := gqlOperations(r.query)
	if len(ops) == 0 && !r.persisted {
		return "", 0
	}
	op := gqlOp{kind: "operation"}
	if len(ops) > 0 {
		op = ops[0]
	}
	name := r.opName
	if name == "" {
		name = op.name
	} else {
		found := false
		for _, o := range ops {
			if o.name == name {
				op, found = o, true
				break
			}
		}
		if !found && len(ops) > 1 {
			op.kind = "operation"
		}
	}
	shown, cnt := a.gqlSafeName(name)
	if shown == "" {
		shown = "(anonymous)"
		if f, _ := a.gqlSafeName(op.field); f != "" && !strings.HasPrefix(f, "<") {
			shown = "(anonymous: " + f + ")"
		}
	}
	prefix := ""
	if r.persisted && r.query == "" {
		prefix = "persisted "
	}
	more := ""
	if r.opName == "" && len(ops) > 1 {
		more = fmt.Sprintf(" (+%d more in document)", len(ops)-1)
	}
	return prefix + op.kind + " " + shown + more, cnt
}

// graphqlNote returns the note text (with a leading space) for a GraphQL
// request, or "" for anything else. body is the request body as text.
func (a *App) graphqlNote(method, rawURL, ct, body string) (string, int) {
	var reqs []gqlRequest
	batch, size := false, ""
	pathOK := gqlPathLooksGraphQL(rawURL)
	add := func(m map[string]any) {
		r, ok := gqlFromObject(m)
		if !ok && r.weakID && pathOK {
			r.persisted, ok = true, true
		}
		if ok {
			reqs = append(reqs, r)
		}
	}
	trimmed := strings.TrimSpace(body)
	cut := strings.HasSuffix(trimmed, truncMarker)
	trimmed = strings.TrimSpace(strings.TrimSuffix(trimmed, truncMarker))
	if len(trimmed) > gqlMaxBody {
		trimmed, cut = trimmed[:gqlMaxBody], true
	}
	switch {
	case trimmed == "":
	case isGraphQLContentType(ct):
		reqs = append(reqs, gqlRequest{query: trimmed})
	case trimmed[0] == '{' || trimmed[0] == '[':
		var v any
		if cut || json.Unmarshal([]byte(trimmed), &v) != nil {
			// Cut off by a capture limit or not valid JSON: read the top-level
			// keys that are there.
			objs, n, more := gqlScanBody(trimmed)
			batch = trimmed[0] == '['
			size = fmt.Sprint(n)
			if more || cut {
				size += "+"
			}
			for _, m := range objs {
				add(m)
			}
			break
		}
		switch t := v.(type) {
		case map[string]any:
			add(t)
		case []any:
			batch, size = true, fmt.Sprint(len(t))
			for i, item := range t {
				if i >= gqlMaxItems {
					break
				}
				if m, ok := item.(map[string]any); ok {
					add(m)
				}
			}
		}
	}
	if len(reqs) == 0 {
		if r, ok := gqlFromURL(rawURL); ok { // GET, or a POST that keeps these in the URL
			reqs = append(reqs, r)
		}
	}

	var labels []string
	redacted := 0
	for _, r := range reqs {
		l, c := a.gqlLabel(r)
		redacted += c
		if l != "" {
			labels = append(labels, l)
		}
	}
	if len(labels) == 0 {
		return "", 0
	}
	if !batch {
		return " GraphQL " + labels[0] + ".", redacted
	}
	extra := 0
	if len(labels) > gqlMaxListed {
		extra = len(labels) - gqlMaxListed
		labels = labels[:gqlMaxListed]
	}
	s := fmt.Sprintf(" GraphQL batch of %s: %s", size, strings.Join(labels, ", "))
	if extra > 0 {
		s += fmt.Sprintf(" (+%d more)", extra)
	}
	return s + ".", redacted
}

// gqlPathLooksGraphQL reports a URL whose path mentions graphql, which is what
// lets a bare "id" next to "variables" count as a persisted operation.
func gqlPathLooksGraphQL(raw string) bool {
	p := raw
	if u, err := url.Parse(raw); err == nil {
		p = u.Path
	} else if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	return strings.Contains(strings.ToLower(p), "graphql")
}

func gqlJSONWS(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	return i
}

// gqlJSONValueEnd returns the index just past the JSON value that starts at
// s[i]. ok is false when the text ends inside the value.
func gqlJSONValueEnd(s string, i int) (int, bool) {
	depth := 0
	for i < len(s) {
		switch s[i] {
		case '"':
			i++
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' {
					i++
				}
				i++
			}
			if i >= len(s) {
				return len(s), false
			}
			i++
			if depth == 0 {
				return i, true
			}
			continue
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth <= 0 {
				return i + 1, depth == 0
			}
		default:
			if depth == 0 { // a number, true, false or null
				for i < len(s) && !strings.ContainsRune(",}] \t\r\n", rune(s[i])) {
					i++
				}
				return i, i < len(s)
			}
		}
		i++
	}
	return len(s), false
}

// gqlObjectFields walks the top-level keys of the JSON object that starts at
// s[i], calling fn with each key and the span of its value. It reads what is
// there of an object that was cut off. complete is true when the closing }
// was reached; fn returns false to stop early.
func gqlObjectFields(s string, i int, fn func(key string, vs, ve int, ok bool) bool) (end int, complete bool) {
	i = gqlJSONWS(s, i+1)
	for i < len(s) {
		switch s[i] {
		case '}':
			return i + 1, true
		case ',':
			i = gqlJSONWS(s, i+1)
			continue
		case '"':
		default:
			return i, false
		}
		ke, ok := gqlJSONValueEnd(s, i)
		if !ok {
			return len(s), false
		}
		var key string
		if json.Unmarshal([]byte(s[i:ke]), &key) != nil {
			return ke, false
		}
		i = gqlJSONWS(s, ke)
		if i >= len(s) || s[i] != ':' {
			return i, false
		}
		i = gqlJSONWS(s, i+1)
		if i >= len(s) {
			return i, false
		}
		ve, ok := gqlJSONValueEnd(s, i)
		if ve <= i { // no value where one is due
			return i, false
		}
		if !fn(key, i, ve, ok) {
			return ve, false
		}
		if !ok {
			return len(s), false
		}
		i = gqlJSONWS(s, ve)
	}
	return len(s), false
}

// gqlScanObject reads the keys a GraphQL request uses from a JSON object that
// may be cut off. Only complete values are kept, except a cut-off "query"
// string, whose beginning is still enough to name the operation.
func gqlScanObject(s string, i int) (map[string]any, int, bool) {
	m := map[string]any{}
	end, complete := gqlObjectFields(s, i, func(key string, vs, ve int, ok bool) bool {
		raw := s[vs:ve]
		switch key {
		case "query", "operationName", "doc_id", "queryId", "id", "extensions":
			var v any
			switch {
			case ok:
				if json.Unmarshal([]byte(raw), &v) == nil {
					m[key] = v
				}
			case key == "query" && raw[0] == '"':
				inner := raw[1:]
				for tries := 0; tries < 8 && len(inner) > 0; tries++ {
					if json.Unmarshal([]byte(`"`+inner+`"`), &v) == nil {
						m[key] = v
						break
					}
					inner = inner[:len(inner)-1] // a cut escape sequence
				}
			}
		case "variables":
			if raw[0] == '{' {
				m[key] = map[string]any{}
			}
		}
		return true
	})
	return m, end, complete
}

// gqlScanBody reads a JSON object, or an array of them, that did not parse as
// a whole. n counts the array entries seen and more is true when the text
// ended before the array did.
func gqlScanBody(s string) (objs []map[string]any, n int, more bool) {
	if s[0] == '{' {
		m, _, _ := gqlScanObject(s, 0)
		return []map[string]any{m}, 1, false
	}
	i := gqlJSONWS(s, 1)
	for i < len(s) && n < gqlMaxItems {
		switch s[i] {
		case ']':
			return objs, n, false
		case ',':
			i = gqlJSONWS(s, i+1)
			continue
		}
		n++
		if s[i] == '{' {
			m, end, ok := gqlScanObject(s, i)
			objs = append(objs, m)
			if !ok {
				return objs, n, true
			}
			i = gqlJSONWS(s, end)
			continue
		}
		end, ok := gqlJSONValueEnd(s, i)
		if !ok {
			return objs, n, true
		}
		i = gqlJSONWS(s, end)
	}
	return objs, n, i < len(s) && s[i] != ']'
}

// gqlMultipartBody returns the "operations" field of a GraphQL multipart
// request (the file upload spec), read before the body is rewritten for
// storage. It is "" for any other body.
func gqlMultipartBody(ct, body string) string {
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil || !strings.HasPrefix(mt, "multipart/") || params["boundary"] == "" {
		return ""
	}
	mr := multipart.NewReader(strings.NewReader(body), params["boundary"])
	for i := 0; i < 20; i++ {
		part, err := mr.NextPart()
		if err != nil {
			return ""
		}
		if part.FormName() == "operations" {
			data, _ := io.ReadAll(io.LimitReader(part, gqlMaxBody))
			return string(data)
		}
	}
	return ""
}

// gqlResponseErrors counts the entries of a top-level "errors" array in a
// GraphQL response. more is true when the body was cut inside the array. Only
// the count is used: the error text is never copied.
func gqlResponseErrors(body string) (n int, more bool) {
	s := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(body), truncMarker))
	if s == "" || s[0] != '{' {
		return 0, false
	}
	gqlObjectFields(s, 0, func(key string, vs, ve int, ok bool) bool {
		if key != "errors" {
			return true
		}
		if s[vs] != '[' {
			return false
		}
		j := gqlJSONWS(s, vs+1)
		for j < len(s) && s[j] != ']' {
			if s[j] == ',' {
				j = gqlJSONWS(s, j+1)
				continue
			}
			n++
			e, eok := gqlJSONValueEnd(s, j)
			if !eok {
				more = true
				break
			}
			j = gqlJSONWS(s, e)
		}
		if j >= len(s) {
			more = true
		}
		return false
	})
	return n, more
}