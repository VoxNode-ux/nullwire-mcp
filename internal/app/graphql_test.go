package app

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestGraphQLNote(t *testing.T) {
	app := fxApp(t)
	secret := "ghp_" + strings.Repeat("a1", 20)
	longBlock := `query A { f(x: """mutation B { y }""") }`
	cases := []struct {
		name, method, url, ct, body, want string
	}{
		{name: "named query", method: "POST",
			body: `{"operationName":"GetUser","query":"query GetUser($id: ID!) { user(id: $id) { name } }"}`,
			want: " GraphQL query GetUser."},
		{name: "shorthand is anonymous", method: "POST",
			body: `{"query":"{ me { id } }"}`, want: " GraphQL query (anonymous: me)."},
		{name: "name from the query text", method: "POST",
			body: `{"query":"mutation Login($p: String!) { login(password: $p) { token } }"}`,
			want: " GraphQL mutation Login."},
		{name: "subscription", method: "POST",
			body: `{"query":"subscription OnMsg { msg { id } }"}`, want: " GraphQL subscription OnMsg."},
		{name: "operationName picks one of several", method: "POST",
			body: `{"operationName":"B","query":"query A { a } mutation B { b }"}`,
			want: " GraphQL mutation B."},
		{name: "fragments and comments are skipped", method: "POST",
			body: `{"query":"# note\nfragment F on User { id }\nquery Q { ...F }"}`,
			want: " GraphQL query Q."},
		{name: "strings are not read as operations", method: "POST",
			body: `{"query":` + jsonString(`query A { f(x: "mutation B {") }`) + `}`,
			want: " GraphQL query A."},
		{name: "block strings are not read as operations", method: "POST",
			body: `{"query":` + jsonString(longBlock) + `}`, want: " GraphQL query A."},
		{name: "a field called query is not an operation", method: "POST",
			body: `{"query":"query Real { query { id } }"}`, want: " GraphQL query Real."},
		{name: "batch", method: "POST",
			body: `[{"operationName":"A","query":"query A { a }"},{"query":"mutation B { b }"},{"hello":1}]`,
			want: " GraphQL batch of 3: query A, mutation B."},
		{name: "persisted query without text", method: "POST",
			body: `{"operationName":"Feed","extensions":{"persistedQuery":{"version":1,"sha256Hash":"0123456789abcdef"}}}`,
			want: " GraphQL persisted operation Feed."},
		{name: "persisted query with text", method: "POST",
			body: `{"operationName":"Feed","query":"query Feed { feed { id } }","extensions":{"persistedQuery":{"version":1,"sha256Hash":"0123456789abcdef"}}}`,
			want: " GraphQL query Feed."},
		{name: "GET query string", method: "GET",
			url:  "http://x/graphql?operationName=Foo&query=query%20Foo%7Ba%7D",
			want: " GraphQL query Foo."},
		{name: "GET persisted", method: "GET",
			url:  `http://x/graphql?operationName=Foo&extensions=%7B%22persistedQuery%22%3A%7B%22version%22%3A1%7D%7D`,
			want: " GraphQL persisted operation Foo."},
		{name: "application/graphql body", method: "POST", ct: "application/graphql; charset=utf-8",
			body: "query FromText { a }", want: " GraphQL query FromText."},
		{name: "name with spaces is not shown", method: "POST",
			body: `{"operationName":"alice smith","query":"query X { a }"}`,
			want: " GraphQL query <invalid name>."},
		{name: "name that is a token is redacted", method: "POST",
			body: `{"operationName":"` + secret + `","query":"query X { a }"}`,
			want: " GraphQL query <redacted>."},
		{name: "search API with a query field", method: "POST", body: `{"query":"cats"}`},
		{name: "unrelated JSON", method: "POST", body: `{"hello":1}`},
		{name: "not JSON", method: "POST", body: `{broken`},
		{name: "empty", method: "POST"},
	}
	for _, c := range cases {
		got, _ := app.graphqlNote(c.method, c.url, c.ct, c.body)
		if got != c.want {
			t.Errorf("%s: note = %q, want %q", c.name, got, c.want)
		}
		if strings.Contains(got, secret) {
			t.Errorf("%s: the note leaked the token", c.name)
		}
	}
}

func jsonString(s string) string {
	s = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
	return `"` + s + `"`
}

func TestGraphQLBatchNoteIsBounded(t *testing.T) {
	app := fxApp(t)
	var items []string
	for i := 0; i < 20; i++ {
		items = append(items, `{"query":"query Q`+strings.Repeat("x", i%3)+` { a }"}`)
	}
	got, _ := app.graphqlNote("POST", "", "", "["+strings.Join(items, ",")+"]")
	if !strings.HasPrefix(got, " GraphQL batch of 20: ") || !strings.HasSuffix(got, "(+15 more).") {
		t.Errorf("note = %q", got)
	}
}

func TestGraphQLNoteInEntries(t *testing.T) {
	app := fxApp(t)
	app.capture(rawFlow{
		started: time.Now(), method: "POST", url: "http://127.0.0.1:9/graphql",
		reqHeaders: http.Header{"Content-Type": {"application/json"}},
		reqBody:    []byte(`{"query":"mutation Login($p: String!){ login(password:$p){ token } }","variables":{"p":"hunter2-hunter2"}}`),
		status:     200,
	})
	e := app.ring.ListRecent(1, "POST", "/graphql")[0]
	if !strings.Contains(e.Note, "GraphQL mutation Login.") {
		t.Errorf("note = %q", e.Note)
	}
	if strings.Contains(e.Note, "hunter2") {
		t.Errorf("variables must not reach the note: %q", e.Note)
	}
}

func FuzzGraphQLNoteNoPanic(f *testing.F) {
	f.Add("POST", `{"query":"query A { a }"}`)
	f.Add("POST", `[{"operationName":"x"}]`)
	f.Add("GET", `query { a(b: """`)
	f.Fuzz(func(t *testing.T, method, body string) {
		app := fxApp(t)
		_, _ = app.graphqlNote(method, "http://x/graphql?query="+body, "application/graphql", body)
		_ = gqlOperations(body)
	})
}

func TestGQLFromURL(t *testing.T) {
	cases := []struct {
		name, raw     string
		query, opName string
		persisted, ok bool
	}{
		{"query and name", "http://x/graphql?query=%7Ba%7D&operationName=Foo", "{a}", "Foo", false, true},
		{"doc_id on a graphql path", "http://x/graphql?doc_id=123", "", "", true, true},
		{"doc_id elsewhere is ignored", "http://x/other?doc_id=123", "", "", false, false},
		{"doc_id next to operationName", "http://x/other?doc_id=123&operationName=Op", "", "Op", true, true},
		{"queryId next to variables", "http://x/other?queryId=9&variables=%7B%7D", "", "", true, true},
		{"persistedQuery extension", "http://x/g?extensions=%7B%22persistedQuery%22%3A%7B%22sha256Hash%22%3A%22abc%22%7D%7D", "", "", true, true},
		{"extension that is not JSON", "http://x/g?extensions=notjson", "", "", false, false},
		{"extension without persistedQuery", "http://x/g?extensions=%7B%7D", "", "", false, false},
		{"bad URL", "http://x/%zz", "", "", false, false},
		{"no GraphQL fields", "http://x/graphql", "", "", false, false},
	}
	for _, c := range cases {
		r, ok := gqlFromURL(c.raw)
		if ok != c.ok || r.query != c.query || r.opName != c.opName || r.persisted != c.persisted {
			t.Errorf("%s: got (%+v, %v)", c.name, r, ok)
		}
	}
}

func TestGQLIsPersistedAndIDSet(t *testing.T) {
	for name, tc := range map[string]struct {
		v    any
		want bool
	}{
		"nil":             {nil, false},
		"string":          {"x", false},
		"empty object":    {map[string]any{}, false},
		"version":         {map[string]any{"version": float64(1)}, true},
		"hash":            {map[string]any{"sha256Hash": "abc"}, true},
		"zero version":    {map[string]any{"version": float64(0)}, false},
		"empty hash":      {map[string]any{"sha256Hash": ""}, false},
		"wrong hash type": {map[string]any{"sha256Hash": true}, false},
	} {
		if got := gqlIsPersisted(tc.v); got != tc.want {
			t.Errorf("gqlIsPersisted(%s) = %v, want %v", name, got, tc.want)
		}
	}
	for v, want := range map[any]bool{"a": true, "": false, float64(2): true, float64(0): false, 5: true, 0: false, int64(7): true, int64(-1): false, true: false, nil: false} {
		if got := gqlIDSet(v); got != want {
			t.Errorf("gqlIDSet(%#v) = %v, want %v", v, got, want)
		}
	}
}

func TestGQLBlockEnd(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{`abc"""rest`, 3},
		{`no end`, -1},
		{`a\"""b"""`, 6},
		{`a""""`, 2},
		{`"""`, 0},
		{``, -1},
	}
	for _, c := range cases {
		if got := gqlBlockEnd(c.in); got != c.want {
			t.Errorf("gqlBlockEnd(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestGQLMultipartBody(t *testing.T) {
	ct := "multipart/form-data; boundary=XYZ"
	ops := `{"query":"query Up { a }"}`
	part := func(name, val string) string {
		return "--XYZ\r\nContent-Disposition: form-data; name=\"" + name + "\"\r\n\r\n" + val + "\r\n"
	}
	body := part("operations", ops) + part("map", "{}") + "--XYZ--\r\n"
	if got := gqlMultipartBody(ct, body); got != ops {
		t.Errorf("operations first: got %q", got)
	}
	body = part("map", "{}") + part("operations", ops) + "--XYZ--\r\n"
	if got := gqlMultipartBody(ct, body); got != ops {
		t.Errorf("operations second: got %q", got)
	}
	if got := gqlMultipartBody(ct, part("map", "{}")+"--XYZ--\r\n"); got != "" {
		t.Errorf("no operations part: got %q", got)
	}
	for name, c := range map[string]string{
		"not multipart":    "application/json",
		"no boundary":      "multipart/form-data",
		"unparseable type": "%%%",
		"empty":            "",
	} {
		if got := gqlMultipartBody(c, body); got != "" {
			t.Errorf("%s: got %q", name, got)
		}
	}
}

func TestGQLResponseErrors(t *testing.T) {
	cases := []struct {
		name, body string
		n          int
		more       bool
	}{
		{"two errors", `{"data":null,"errors":[{"message":"a"},{"message":"b"}]}`, 2, false},
		{"empty list", `{"errors":[]}`, 0, false},
		{"no errors key", `{"data":{}}`, 0, false},
		{"errors is not a list", `{"errors":null}`, 0, false},
		{"not an object", `[1]`, 0, false},
		{"empty body", ``, 0, false},
		{"cut inside an error", `{"errors":[{"message":"a"},{"mess`, 2, true},
		{"cut after the last error", `{"errors":[{"a":1}` + truncMarker, 1, true},
		{"whitespace around", "  {\"errors\":[{\"a\":1}]}  ", 1, false},
		{"scalar entries", `{"errors":["x","y","z"]}`, 3, false},
	}
	for _, c := range cases {
		if n, more := gqlResponseErrors(c.body); n != c.n || more != c.more {
			t.Errorf("%s: got (%d, %v), want (%d, %v)", c.name, n, more, c.n, c.more)
		}
	}
}

func TestGQLScanBodyPartialJSON(t *testing.T) {
	// An object missing its closing brace still gives the keys that are there.
	objs, n, more := gqlScanBody(`{"query":"query A { a }","variables":{"p":1}`)
	if len(objs) == 0 {
		t.Fatal("no object scanned")
	}
	if len(objs) != 1 || n != 1 || more || objs[0]["query"] != "query A { a }" {
		t.Errorf("object: %v %d %v", objs, n, more)
	}
	if _, ok := objs[0]["variables"].(map[string]any); !ok {
		t.Errorf("variables should be kept as an empty object, got %v", objs[0]["variables"])
	}

	// A query string cut in the middle keeps its beginning.
	objs, _, _ = gqlScanBody(`{"operationName":"Foo","query":"query Foo { a(b: \"x`)
	if len(objs) == 0 {
		t.Fatal("no object scanned for the cut query")
	}
	if q, _ := objs[0]["query"].(string); !strings.HasPrefix(q, "query Foo") || objs[0]["operationName"] != "Foo" {
		t.Errorf("cut query: %v", objs[0])
	}
	// ... and a cut escape sequence is trimmed off.
	objs, _, _ = gqlScanBody(`{"query":"query A { a } \`)
	if len(objs) == 0 {
		t.Fatal("no object scanned for the cut escape")
	}
	if objs[0]["query"] != "query A { a } " {
		t.Errorf("cut escape: %q", objs[0]["query"])
	}

	// A batch that ends inside its third entry.
	objs, n, more = gqlScanBody(`[{"query":"query A { a }"},{"query":"mutation B { b }"},{"quer`)
	if len(objs) != 3 || n != 3 || !more {
		t.Errorf("cut batch: %d objects, n=%d, more=%v", len(objs), n, more)
	}
	// A complete array, and one with a scalar entry.
	if objs, n, more = gqlScanBody(`[{"query":"query A { a }"}]`); len(objs) != 1 || n != 1 || more {
		t.Errorf("complete array: %d %d %v", len(objs), n, more)
	}
	if objs, n, more = gqlScanBody(`[1,{"query":"query A { a }"}]`); len(objs) != 1 || n != 2 || more {
		t.Errorf("scalar entry: %d %d %v", len(objs), n, more)
	}
	if objs, n, more = gqlScanBody(`[12`); len(objs) != 0 || n != 1 || !more {
		t.Errorf("cut scalar: %d %d %v", len(objs), n, more)
	}
	// Only the first gqlMaxItems entries are looked at.
	if _, n, more = gqlScanBody("[" + strings.Repeat("1,", 100) + "1]"); n != gqlMaxItems || !more {
		t.Errorf("item limit: n=%d more=%v", n, more)
	}
	// A key without a colon ends the object quietly.
	if objs, _, _ = gqlScanBody(`{"query" "x"}`); len(objs) != 1 || len(objs[0]) != 0 {
		t.Errorf("missing colon: %v", objs)
	}
}

func TestGraphQLNotePartialAndBatchBodies(t *testing.T) {
	app := fxApp(t)
	cases := []struct{ name, body, want string }{
		{"missing closing brace", `{"operationName":"Foo","query":"query Foo { a }"`, " GraphQL query Foo."},
		{"cut batch", `[{"query":"query A { a }"},{"query":"mutation B { b }"}` + truncMarker, " GraphQL batch of 2+: query A, mutation B."},
		{"cut object", `{"query":"query Cut { a }` + truncMarker, " GraphQL query Cut."},
	}
	for _, c := range cases {
		if got, _ := app.graphqlNote("POST", "", "", c.body); got != c.want {
			t.Errorf("%s: note = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestGraphQLMultipartAndResponseErrorsInEntries(t *testing.T) {
	app := fxApp(t)
	ops := `{"query":"query Up($f: Upload!) { up(file: $f) }"}`
	body := "--XYZ\r\nContent-Disposition: form-data; name=\"operations\"\r\n\r\n" + ops + "\r\n" +
		"--XYZ\r\nContent-Disposition: form-data; name=\"map\"\r\n\r\n{}\r\n--XYZ--\r\n"
	app.capture(rawFlow{
		started: time.Now(), method: "POST", url: "http://127.0.0.1:9/graphql",
		reqHeaders:  http.Header{"Content-Type": {"multipart/form-data; boundary=XYZ"}},
		reqBody:     []byte(body),
		respHeaders: http.Header{"Content-Type": {"application/json"}},
		respBody:    []byte(`{"data":null,"errors":[{"message":"bad"},{"message":"worse"}]}`),
		status:      200,
	})
	e := app.ring.ListRecent(1, "POST", "/graphql")[0]
	if !strings.Contains(e.Note, "GraphQL query Up.") || !strings.Contains(e.Note, "GraphQL errors: 2.") {
		t.Errorf("note = %q", e.Note)
	}
}

func TestGQLOperationsEdgeCases(t *testing.T) {
	cases := []struct {
		name, src string
		want      []gqlOp
	}{
		{"fragment keeps a type named query out", `fragment F on query { a } query Q { b }`,
			[]gqlOp{{kind: "query", name: "Q", field: "b"}}},
		{"alias is skipped for the field name", `query { x: a }`, []gqlOp{{kind: "query", field: "a"}}},
		{"fragment spread is skipped", `{ ...F b }`, []gqlOp{{kind: "query", field: "b"}}},
		{"inline fragment is not a root field", `{ ... on User { id } name }`, []gqlOp{{kind: "query"}}},
		{"leading comment and shorthand", "# c\r\n{ a }", []gqlOp{{kind: "query", field: "a"}}},
		{"stray closers at depth 0", `} ) ] { a }`, []gqlOp{{kind: "query", field: "a"}}},
		{"unterminated block string stops the scan", `query A { f(x: """abc`, []gqlOp{{kind: "query", name: "A", field: "f"}}},
		{"block string is skipped", `query A { f(x: """ query B { } """) }`, []gqlOp{{kind: "query", name: "A", field: "f"}}},
		{"string with escaped quote", `query A { f(x: "a\"b { ") }`, []gqlOp{{kind: "query", name: "A", field: "f"}}},
		{"string cut by a newline", "query A { f(x: \"abc\n) }", []gqlOp{{kind: "query", name: "A", field: "f"}}},
		{"string ending in a backslash", `query A { f(x: "a\`, []gqlOp{{kind: "query", name: "A", field: "f"}}},
		{"no operations", `hello world`, nil},
		{"empty", ``, nil},
	}
	for _, c := range cases {
		got := gqlOperations(c.src)
		if len(got) != len(c.want) {
			t.Errorf("%s: gqlOperations = %v, want %v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: op %d = %+v, want %+v", c.name, i, got[i], c.want[i])
			}
		}
	}
	if got := gqlOperations(strings.Repeat("query A { a } ", gqlMaxOps+10)); len(got) != gqlMaxOps {
		t.Errorf("operations are capped at %d, got %d", gqlMaxOps, len(got))
	}
}

func TestGQLJSONValueEnd(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{`"abc"`, 5, true},
		{`"abc`, 4, false},
		{`"a\"b" rest`, 6, true},
		{`{"a":"b"} x`, 9, true},
		{`{"a":"b`, 7, false},
		{`[1,[2,3]] x`, 9, true},
		{`[1,[2`, 5, false},
		{`}`, 1, false},
		{`12,`, 2, true},
		{`12`, 2, false},
		{`true}`, 4, true},
		{``, 0, false},
	}
	for _, c := range cases {
		if end, ok := gqlJSONValueEnd(c.in, 0); end != c.want || ok != c.ok {
			t.Errorf("gqlJSONValueEnd(%q) = (%d, %v), want (%d, %v)", c.in, end, ok, c.want, c.ok)
		}
	}
}

func TestGQLObjectFieldsEdgeCases(t *testing.T) {
	collect := func(s string) (keys []string, end int, complete bool) {
		end, complete = gqlObjectFields(s, 0, func(key string, vs, ve int, ok bool) bool {
			keys = append(keys, key)
			return true
		})
		return
	}
	if keys, _, complete := collect(`{ "a" : 1 , "b" : "x" , "c" : [1,2] }`); !complete || strings.Join(keys, ",") != "a,b,c" {
		t.Errorf("complete object: keys=%v complete=%v", keys, complete)
	}
	for name, in := range map[string]string{
		"key is not a string": `{ x }`,
		"unterminated key":    `{"abc`,
		"invalid key escape":  `{"\q": 1}`,
		"key then EOF":        `{"a"`,
		"no colon":            `{"a" 1}`,
		"colon then EOF":      `{"a":`,
		"colon then spaces":   `{"a":   `,
		"no value":            `{"a":,"b":1}`,
		"value cut":           `{"a":"unterminated`,
		"empty text":          ``,
		"only the brace":      `{`,
	} {
		if _, _, complete := collect(in); complete {
			t.Errorf("%s: %q must not be complete", name, in)
		}
	}
	// fn returning false stops the walk after the first key.
	var seen []string
	end, complete := gqlObjectFields(`{"a":1,"b":2}`, 0, func(key string, vs, ve int, ok bool) bool {
		seen = append(seen, key)
		return false
	})
	if complete || len(seen) != 1 || end != 6 {
		t.Errorf("early stop: seen=%v end=%d complete=%v", seen, end, complete)
	}
}

func TestGQLScanObjectEdgeCases(t *testing.T) {
	// variables that is not an object is dropped; unknown keys are ignored.
	m, _, _ := gqlScanObject(`{"variables":[1],"other":{"a":1},"id":"abc"}`, 0)
	if _, ok := m["variables"]; ok || m["id"] != "abc" || len(m) != 1 {
		t.Errorf("m = %v", m)
	}
	// A cut query whose start is not a string is dropped.
	if m, _, _ = gqlScanObject(`{"query":{"a`, 0); len(m) != 0 {
		t.Errorf("cut object-valued query: %v", m)
	}
	// A cut \u escape is trimmed until the string parses; nothing parses here.
	if m, _, _ = gqlScanObject(`{"query":"\u12`, 0); len(m) != 0 {
		t.Errorf("cut unicode escape: %v", m)
	}
	// A cut \u escape after some text keeps the text.
	if m, _, _ = gqlScanObject(`{"query":"query A { a } \u12`, 0); m["query"] != "query A { a } " {
		t.Errorf("cut unicode escape after text: %q", m["query"])
	}
	// Complete values of every known key are kept.
	m, _, complete := gqlScanObject(`{"operationName":"Foo","doc_id":"1","queryId":2,"extensions":{"a":1}}`, 0)
	if !complete || len(m) != 4 || m["operationName"] != "Foo" {
		t.Errorf("m = %v complete=%v", m, complete)
	}
}

func TestGQLScanBodyEdgeCases(t *testing.T) {
	if objs, n, more := gqlScanBody(`[]`); len(objs) != 0 || n != 0 || more {
		t.Errorf("empty array: %d %d %v", len(objs), n, more)
	}
	if objs, n, more := gqlScanBody(`[{"query":"query A { a }"}`); len(objs) != 1 || n != 1 || more {
		t.Errorf("array without closing bracket: %d %d %v", len(objs), n, more)
	}
	if objs, n, more := gqlScanBody(`[[1,2`); len(objs) != 0 || n != 1 || !more {
		t.Errorf("cut nested array: %d %d %v", len(objs), n, more)
	}
	if objs, n, more := gqlScanBody(`[ "s" , 1 , {"query":"query A { a }"} ]`); len(objs) != 1 || n != 3 || more {
		t.Errorf("mixed array: %d %d %v", len(objs), n, more)
	}
}

func TestGraphQLNoteStreamingFallbackAndLimits(t *testing.T) {
	app := fxApp(t)
	pad := strings.Repeat("x", gqlMaxBody+1024)

	// An object over gqlMaxBody is cut and read with the streaming fallback.
	got, _ := app.graphqlNote("POST", "", "", `{"operationName":"Big","query":"query Big { a }","pad":"`+pad+`"}`)
	if got != " GraphQL query Big." {
		t.Errorf("oversized object: %q", got)
	}
	// An oversized batch reports that it was cut.
	got, _ = app.graphqlNote("POST", "", "", `[{"query":"query A { a }"},{"query":"mutation B { b }"},{"pad":"`+pad+`"}]`)
	if got != " GraphQL batch of 3+: query A, mutation B." {
		t.Errorf("oversized batch: %q", got)
	}
	// A valid batch longer than gqlMaxItems only reads the first gqlMaxItems entries.
	items := strings.Repeat(`{"query":"query A { a }"},`, gqlMaxItems+1)
	got, _ = app.graphqlNote("POST", "", "", "["+strings.TrimSuffix(items, ",")+"]")
	want := " GraphQL batch of 101: query A, query A, query A, query A, query A (+95 more)."
	if got != want {
		t.Errorf("long batch: %q, want %q", got, want)
	}
	// Scalar and nested entries in a valid batch are skipped but counted.
	got, _ = app.graphqlNote("POST", "", "", `[1,"s",[2],{"query":"query A { a }"}]`)
	if got != " GraphQL batch of 4: query A." {
		t.Errorf("mixed valid batch: %q", got)
	}
}

func TestGraphQLNoteWeakIDAndLabels(t *testing.T) {
	app := fxApp(t)
	cases := []struct{ name, url, ct, body, want string }{
		{"bare id with variables on a graphql path", "http://x/api/graphql", "", `{"id":"abc","variables":{}}`,
			" GraphQL persisted operation (anonymous)."},
		{"bare id with variables elsewhere", "http://x/api/data", "", `{"id":"abc","variables":{}}`, ""},
		{"doc_id alone on a graphql path", "http://x/GraphQL", "", `{"doc_id":"123"}`,
			" GraphQL persisted operation (anonymous)."},
		{"doc_id alone elsewhere", "http://x/api", "", `{"doc_id":"123"}`, ""},
		{"doc_id with variables", "http://x/api", "", `{"doc_id":"123","variables":{},"operationName":"Feed"}`,
			" GraphQL persisted operation Feed."},
		{"operationName that is not in the document", "", "", `{"operationName":"Z","query":"query A { a } query B { b }"}`,
			" GraphQL operation Z."},
		{"several operations without a name", "", "", `{"query":"query A { a } query B { b } query C { c }"}`,
			" GraphQL query A (+2 more in document)."},
		{"root field name too long to show", "", "", `{"query":"{ ` + strings.Repeat("x", 70) + ` }"}`,
			" GraphQL query (anonymous)."},
		{"shorthand body, unparsable URL", "%zz", "application/graphql", "{ me }", " GraphQL query (anonymous: me)."},
		{"shorthand body, operationName in the URL", "http://x/q?operationName=Foo", "application/graphql", "{ me }", " GraphQL query Foo."},
	}
	for _, c := range cases {
		if got, _ := app.graphqlNote("POST", c.url, c.ct, c.body); got != c.want {
			t.Errorf("%s: note = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestGQLPathLooksGraphQLUnparsable(t *testing.T) {
	for raw, want := range map[string]bool{
		"%zz/graphql?q=1":     true,
		"%zz/other?graphql=1": false,
		"%zz/other":           false,
		"http://x/a/GraphQL":  true,
		"http://x/a/b":        false,
	} {
		if got := gqlPathLooksGraphQL(raw); got != want {
			t.Errorf("gqlPathLooksGraphQL(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestCovIsGraphQLContentType(t *testing.T) {
	for in, want := range map[string]bool{
		"application/graphql":                       true,
		" Application/GraphQL ; charset=utf-8":      true,
		"application/json":                          false,
		"application/graphql-response+json":         false,
		"":                                          false,
	} {
		if got := isGraphQLContentType(in); got != want {
			t.Errorf("isGraphQLContentType(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestCovGQLValidName(t *testing.T) {
	for in, want := range map[string]bool{
		"":                                false,
		"9a":                              false,
		"a-b":                             false,
		"a b":                             false,
		"_a1":                             true,
		"Query":                           true,
		strings.Repeat("a", gqlMaxName):   true,
		strings.Repeat("a", gqlMaxName+1): false,
	} {
		if got := gqlValidName(in); got != want {
			t.Errorf("gqlValidName(len %d) = %v, want %v", len(in), got, want)
		}
	}
}

func TestCovGQLSkip(t *testing.T) {
	for _, c := range []struct {
		in   string
		want int
	}{
		{"   ", 3},
		{" ,\t# c\nx", 7},
		{"# only a comment", 16},
		{"x", 0},
	} {
		if got := gqlSkip(c.in, 0); got != c.want {
			t.Errorf("gqlSkip(%q, 0) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestGQLResponseErrorsCountsAndCut(t *testing.T) {
	for _, c := range []struct {
		name, in string
		n        int
		more     bool
	}{
		{"complete", `{"errors":[{"message":"a"}]}`, 1, false},
		{"two complete", `{"errors":[{"message":"a"},{"message":"b"}]}`, 2, false},
		{"cut inside the array", `{"errors":[{"message":"a"},{"message":"b"}` + truncMarker, 2, true},
		{"errors is not an array", `{"errors":{"message":"a"}}`, 0, false},
		{"no errors key", `{"data":1}`, 0, false},
		{"not an object", `[1]`, 0, false},
		{"empty", ``, 0, false},
	} {
		if n, more := gqlResponseErrors(c.in); n != c.n || more != c.more {
			t.Errorf("%s: gqlResponseErrors = %d, %v; want %d, %v", c.name, n, more, c.n, c.more)
		}
	}
}

func TestGraphQLErrorCountShowsPlusWhenResponseIsCut(t *testing.T) {
	app := fxApp(t)
	app.capture(rawFlow{
		started: time.Now(), method: "POST", url: "http://127.0.0.1:9/graphql", status: 200,
		reqHeaders:  http.Header{"Content-Type": {"application/json"}},
		reqBody:     []byte(`{"query":"query Foo { a }"}`),
		respHeaders: http.Header{"Content-Type": {"application/json"}},
		respBody:    []byte(`{"data":null,"errors":[{"message":"a"},{"message":"b"}` + truncMarker),
	})
	es := app.ring.ListRecent(1, "POST", "/graphql")
	if len(es) != 1 {
		t.Fatalf("captured %d flows", len(es))
	}
	if !strings.Contains(es[0].Note, "GraphQL errors: 2+.") {
		t.Errorf("note = %q", es[0].Note)
	}
}
