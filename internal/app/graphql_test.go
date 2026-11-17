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
	if len(objs) != 1 || n != 1 || more || objs[0]["query"] != "query A { a }" {
		t.Errorf("object: %v %d %v", objs, n, more)
	}
	if _, ok := objs[0]["variables"].(map[string]any); !ok {
		t.Errorf("variables should be kept as an empty object, got %v", objs[0]["variables"])
	}

	// A query string cut in the middle keeps its beginning.
	objs, _, _ = gqlScanBody(`{"operationName":"Foo","query":"query Foo { a(b: \"x`)
	if q, _ := objs[0]["query"].(string); !strings.HasPrefix(q, "query Foo") || objs[0]["operationName"] != "Foo" {
		t.Errorf("cut query: %v", objs[0])
	}
	// ... and a cut escape sequence is trimmed off.
	objs, _, _ = gqlScanBody(`{"query":"query A { a } \`)
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
