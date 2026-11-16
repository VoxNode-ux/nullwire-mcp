package app

import (
	"encoding/json"
	"fmt"
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

type gqlOp struct{ kind, name string }

type gqlRequest struct {
	query     string
	opName    string
	persisted bool
}

func gqlFromObject(m map[string]any) (gqlRequest, bool) {
	var r gqlRequest
	r.query, _ = m["query"].(string)
	r.opName, _ = m["operationName"].(string)
	if ext, ok := m["extensions"].(map[string]any); ok {
		r.persisted = gqlIsPersisted(ext["persistedQuery"])
	}
	return r, r.query != "" || r.opName != "" || r.persisted
}

// gqlIsPersisted reports an Apollo-style persistedQuery extension: an object
// with a version or a hash. Any other value under that name is not one.
func gqlIsPersisted(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	_, hash := m["sha256Hash"]
	_, version := m["version"]
	return hash || version
}

// gqlBlockEnd returns the index of the closing """ of a block string whose
// content starts at s[0], or -1. \""" is an escaped triple quote, not the end.
func gqlBlockEnd(s string) int {
	for j := 0; j < len(s); j++ {
		switch {
		case s[j] == '\\' && strings.HasPrefix(s[j+1:], `"""`):
			j += 3
		case strings.HasPrefix(s[j:], `"""`):
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
	if ext := q.Get("extensions"); ext != "" {
		var m map[string]any
		if json.Unmarshal([]byte(ext), &m) == nil {
			r.persisted = gqlIsPersisted(m["persistedQuery"])
		}
	}
	return r, r.query != "" || r.opName != "" || r.persisted
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
		c := src[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',' {
			i++
		} else if c == '#' {
			for i < len(src) && src[i] != '\n' && src[i] != '\r' {
				i++
			}
		} else {
			break
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
			for i < n && src[i] != '"' && src[i] != '\n' {
				if src[i] == '\\' {
					i++
				}
				i++
			}
			i++
		case c == '{':
			if depth == 0 {
				if !header {
					ops = append(ops, gqlOp{kind: "query"}) // shorthand: { ... }
				}
				header = false
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
				continue
			}
			switch word {
			case "query", "mutation", "subscription":
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
				ops = append(ops, op)
			case "fragment":
				header = true
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
	if len(ops) == 0 && !r.persisted && r.opName == "" {
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
	}
	prefix := ""
	if r.persisted && r.query == "" {
		prefix = "persisted "
	}
	return prefix + op.kind + " " + shown, cnt
}

// graphqlNote returns the note text (with a leading space) for a GraphQL
// request, or "" for anything else. body is the request body as text.
func (a *App) graphqlNote(method, rawURL, ct, body string) (string, int) {
	var reqs []gqlRequest
	batch, size := false, 0
	trimmed := strings.TrimSpace(body)
	switch {
	case trimmed == "" || len(trimmed) > gqlMaxBody:
	case isGraphQLContentType(ct):
		reqs = append(reqs, gqlRequest{query: trimmed})
	case trimmed[0] == '{' || trimmed[0] == '[':
		var v any
		if json.Unmarshal([]byte(trimmed), &v) != nil {
			return "", 0
		}
		switch t := v.(type) {
		case map[string]any:
			if r, ok := gqlFromObject(t); ok {
				reqs = append(reqs, r)
			}
		case []any:
			batch, size = true, len(t)
			for i, item := range t {
				if i >= gqlMaxItems {
					break
				}
				if m, ok := item.(map[string]any); ok {
					if r, ok := gqlFromObject(m); ok {
						reqs = append(reqs, r)
					}
				}
			}
		}
	}
	if len(reqs) == 0 && strings.EqualFold(method, "GET") {
		if r, ok := gqlFromURL(rawURL); ok {
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
	s := fmt.Sprintf(" GraphQL batch of %d: %s", size, strings.Join(labels, ", "))
	if extra > 0 {
		s += fmt.Sprintf(" (+%d more)", extra)
	}
	return s + ".", redacted
}
