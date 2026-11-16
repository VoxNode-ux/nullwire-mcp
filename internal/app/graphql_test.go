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
