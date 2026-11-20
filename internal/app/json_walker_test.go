package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestJSONWalkerCompoundKeys(t *testing.T) {
	s := mustScrubber()
	in := `{"signing_secret":"Zk3pQ9vLm2Xa","db_password":"hunter2hunter2","webhook_secret":"whsec_ab12","private_key":"MIIEvQIBADANBg","name":"demo"}`
	out, n := s.ScrubText(in)
	for _, leak := range []string{"Zk3pQ9vLm2Xa", "hunter2hunter2", "ab12", "MIIEvQIBADANBg"} {
		if strings.Contains(out, leak) {
			t.Errorf("leaked %q: %s", leak, out)
		}
	}
	if n < 4 || !json.Valid([]byte(out)) || !strings.Contains(out, `"name":"demo"`) {
		t.Errorf("n=%d out=%s", n, out)
	}
}

func TestJSONWalkerNestedHarmlessKeys(t *testing.T) {
	s := mustScrubber()
	in := `{"ui":{"theme":{"primary_key":"blue-700-accent","cache_key":"v2-main-page","routing_key":"orders.created","public_key":"pub-abc-123"}},"auth":{"credentials":{"secret":"s3cr3t-value-xyz"}}}`
	out, _ := s.ScrubText(in)
	for _, keep := range []string{"blue-700-accent", "v2-main-page", "orders.created", "pub-abc-123"} {
		if !strings.Contains(out, keep) {
			t.Errorf("harmless value %q was redacted: %s", keep, out)
		}
	}
	if strings.Contains(out, "s3cr3t-value-xyz") || !json.Valid([]byte(out)) {
		t.Errorf("secret leaked or JSON broken: %s", out)
	}
}

func TestJSONWalkerEscapesAndPlaceholders(t *testing.T) {
	s := mustScrubber()
	out, _ := s.ScrubText(`{"db_password":"pa\"ss\\word 123","token":"${API_TOKEN}","x":"a\nb"}`)
	if strings.Contains(out, "word 123") || !json.Valid([]byte(out)) {
		t.Errorf("escaped secret leaked or JSON broken: %s", out)
	}
	if !strings.Contains(out, "${API_TOKEN}") || !strings.Contains(out, `"x":"a\nb"`) {
		t.Errorf("placeholder or escapes changed: %s", out)
	}
}

func TestJSONWalkerTruncatedAndNonJSON(t *testing.T) {
	s := mustScrubber()
	var n int
	// The walker must refuse these and leave them as they are.
	for _, in := range []string{
		`{"signing_secret":"abcd1234efgh5678ijkl`,
		`{"signing_secret":"abcd1234efgh5678ijkl"`,
		`signing_secret: "abcd1234efgh5678ijkl"`,
		`{"a":1} {"signing_secret":"abcd1234efgh5678ijkl"}`,
	} {
		if got := s.scrubJSONTree(in, &n); got != in {
			t.Errorf("walker changed %q -> %q", in, got)
		}
	}
	// The existing rules still catch them.
	for _, in := range []string{
		`{"signing_secret":"abcd1234efgh5678ijkl`,
		`{"signing_secret":"abcd1234efgh5678ijkl"`,
	} {
		if out, _ := s.ScrubText(in); strings.Contains(out, "abcd1234efgh5678ijkl") {
			t.Errorf("fallback missed %q: %q", in, out)
		}
	}
}

func TestNonceSurvivesReset(t *testing.T) {
	s := mustScrubber()
	before := append([]byte(nil), s.nonce...)
	t1 := s.tag("TOKEN", "x")
	s.ResetCounters()
	if !bytes.Equal(before, s.nonce) || s.tag("TOKEN", "x") != t1 {
		t.Fatal("ResetCounters changed the tag nonce")
	}
}

func TestJSONWalkerAncestorContext(t *testing.T) {
	s := mustScrubber()
	var n int
	// A credentials parent promotes an ambiguous leaf, even a short value.
	out, _ := s.ScrubText(`{"auth":{"credentials":{"key":"abc123xy","token":"tok-9f8e7d"}}}`)
	if strings.Contains(out, "abc123xy") || strings.Contains(out, "tok-9f8e7d") || !json.Valid([]byte(out)) {
		t.Errorf("credentials children leaked: %s", out)
	}
	// A UI parent exempts it in the walker...
	for _, in := range []string{
		`{"ui":{"theme":{"key":"primary-blue-700"}}}`,
		`{"ui":{"token":"dark-mode-xyz"}}`,
	} {
		if got := s.scrubJSONTree(in, &n); got != in {
			t.Errorf("walker redacted a UI value: %s", got)
		}
	}
	// ...but never a prefixed or validated secret.
	syn := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	in := `{"ui":{"token":"` + syn + `"}}`
	if got := s.scrubJSONTree(in, &n); strings.Contains(got, syn) {
		t.Errorf("prefixed token survived under ui: %s", got)
	}
	// With no hint above it, a bare token is still treated as before.
	if out, _ := s.ScrubText(`{"app":{"token":"abcdefgh1234"}}`); strings.Contains(out, "abcdefgh1234") {
		t.Errorf("unknown parent: %s", out)
	}
	// A credentials parent beats a UI grandparent.
	if got := s.scrubJSONTree(`{"ui":{"auth":{"key":"abc123xy"}}}`, &n); strings.Contains(got, "abc123xy") {
		t.Errorf("secret ancestor lost to benign one: %s", got)
	}
}

func TestDSNPlaceholderWiring(t *testing.T) {
	s := mustScrubber()
	keep := "postgres://app:your_password@db.example.com/x"
	if out, _ := s.ScrubText("dsn " + keep); !strings.Contains(out, "your_password") {
		t.Errorf("template DSN password was redacted: %s", out)
	}
	genuine := "postgres://app:Zx9Qw3Lp7Mn2@db.example.com/x"
	if out, _ := s.ScrubText("dsn " + genuine); strings.Contains(out, "Zx9Qw3Lp7Mn2") {
		t.Errorf("real DSN password leaked: %s", out)
	}
	prefixed := "postgres://app:ghp_abcdefghijklmnopqrstuvwxyz0123456789@db/x"
	if out, _ := s.ScrubText(prefixed); strings.Contains(out, "ghp_abcdef") {
		t.Errorf("prefixed password leaked: %s", out)
	}
}

func TestJSONWalkerPaginationCursors(t *testing.T) {
	s := mustScrubber()
	var n int
	for _, in := range []string{
		`{"next_page_token":"CAESAggBEAE","items":[]}`,
		`{"meta":{"page_token":"eyJwIjoyfQ","nextToken":"abc123def456"}}`,
	} {
		if got := s.scrubJSONTree(in, &n); got != in {
			t.Errorf("cursor was redacted: %s", got)
		}
	}
	// A real secret next to a cursor is still redacted.
	out, _ := s.ScrubText(`{"next_page_token":"CAESAggBEAE","signing_secret":"Zk3pQ9vLm2Xa"}`)
	if strings.Contains(out, "Zk3pQ9vLm2Xa") || !strings.Contains(out, "CAESAggBEAE") {
		t.Errorf("unexpected output: %s", out)
	}
}

const walkerSecret = "hunter2hunter2"

// An escaped key is decoded before it is judged, both as the owner of a value
// and as an ancestor of an ambiguous leaf.
func TestJSONWalkerEscapedKeys(t *testing.T) {
	s := mustScrubber()
	var n int

	// "\u0064b_password" is "db_password".
	in := `{"\u0064b_password":"` + walkerSecret + `","name":"demo"}`
	out := s.scrubJSONTree(in, &n)
	if strings.Contains(out, walkerSecret) || !json.Valid([]byte(out)) || n != 1 {
		t.Errorf("escaped owner key not redacted: n=%d %s", n, out)
	}
	if !strings.Contains(out, `"\u0064b_password"`) || !strings.Contains(out, `"name":"demo"`) {
		t.Errorf("surrounding JSON changed: %s", out)
	}

	// "\u0061uth" is "auth": a credentials ancestor promotes the bare "key".
	n = 0
	in = `{"\u0061uth":{"key":"abc123xy"}}`
	out = s.scrubJSONTree(in, &n)
	if strings.Contains(out, "abc123xy") || !json.Valid([]byte(out)) || n != 1 {
		t.Errorf("escaped ancestor key ignored: n=%d %s", n, out)
	}

	// An escaped benign ancestor ("\u0075i" is "ui") still exempts a bare key.
	n = 0
	in = `{"\u0075i":{"key":"primary-blue-700"}}`
	if got := s.scrubJSONTree(in, &n); got != in || n != 0 {
		t.Errorf("escaped UI ancestor was redacted: n=%d %s", n, got)
	}

	// An escaped value is decoded before it is judged and the span is replaced.
	n = 0
	in = `{"db_password":"hunter2\u0021hunter2"}`
	out = s.scrubJSONTree(in, &n)
	if strings.Contains(out, "hunter2") || !json.Valid([]byte(out)) || n != 1 {
		t.Errorf("escaped value leaked: n=%d %s", n, out)
	}
}

// An escape that does not decode is never a key or a value the walker acts on,
// and an invalid document is handed back unchanged.
func TestJSONWalkerBadEscapes(t *testing.T) {
	s := mustScrubber()
	var n int
	// An undecodable key, an undecodable value, and a bad \u escape elsewhere.
	for _, in := range []string{
		`{"bad\q":"abcd1234efgh5678","db_password":"` + walkerSecret + `"}`,
		`{"db_password":"ab\qcd1234efgh"}`,
		`{"db_password":"` + walkerSecret + `","x":"\u00zz"}`,
	} {
		if got := s.scrubJSONTree(in, &n); got != in {
			t.Errorf("walker changed an invalid document: %q -> %q", in, got)
		}
	}
	if n != 0 {
		t.Errorf("count moved to %d on documents that were refused", n)
	}
	if got := jsonKeyText(`bad\q`, jsonFrame{obj: true, ks: 0, ke: 5, keyEsc: true}); got != "" {
		t.Errorf("jsonKeyText of an undecodable key = %q, want empty", got)
	}
	if got := jsonKeyText(`a\u0062c`, jsonFrame{obj: true, ks: 0, ke: 8, keyEsc: true}); got != "abc" {
		t.Errorf("jsonKeyText = %q, want abc", got)
	}
	if got := jsonKeyText(`xxabcxx`, jsonFrame{obj: true, ks: 2, ke: 5}); got != "abc" {
		t.Errorf("jsonKeyText without escapes = %q, want abc", got)
	}
}

// Unbalanced, over-deep and otherwise malformed bodies fall back untouched so
// that the regexp rules still see them.
func TestJSONWalkerMalformedFallbacks(t *testing.T) {
	s := mustScrubber()
	var n int
	kv := `"db_password":"` + walkerSecret + `"`
	for _, c := range []struct{ name, in string }{
		{"extra closer", `{` + kv + `}}`},
		{"mismatched closer", `{` + kv + `]`},
		{"array closed by brace", `{` + kv + `,"a":[1}`},
		{"never closed", `{` + kv + `,"a":{"b":1}`},
		{"comma after document", `{` + kv + `},`},
		{"colon inside an array", `[` + kv + `]`},
		{"string after document", `{` + kv + `} "x"`},
		{"literal after document", `{` + kv + `} null`},
		{"array after document", `{` + kv + `}[1]`},
		{"escaped quote at end", `{"db_password":"` + walkerSecret + `\"}`},
	} {
		if got := s.scrubJSONTree(c.in, &n); got != c.in {
			t.Errorf("%s: walker changed %q -> %q", c.name, c.in, got)
		}
	}
	if n != 0 {
		t.Errorf("count moved to %d on documents that were refused", n)
	}
}

// A document nested deeper than encoding/json accepts is refused by the final
// json.Valid check, while a merely deep one is still handled.
func TestJSONWalkerDeepNesting(t *testing.T) {
	s := mustScrubber()
	obj := `{"db_password":"` + walkerSecret + `"}`

	var n int
	shallow := strings.Repeat("[", 100) + obj + strings.Repeat("]", 100)
	out := s.scrubJSONTree(shallow, &n)
	if strings.Contains(out, walkerSecret) || !json.Valid([]byte(out)) || n != 1 {
		t.Errorf("100-deep document: n=%d leaked or broken", n)
	}

	n = 0
	deep := strings.Repeat("[", 10001) + obj + strings.Repeat("]", 10001)
	if got := s.scrubJSONTree(deep, &n); got != deep || n != 0 {
		t.Errorf("document deeper than the json limit was changed (n=%d)", n)
	}
}

// Arrays inside objects belong to the key of the object that holds them.
func TestJSONWalkerArraysInObjects(t *testing.T) {
	s := mustScrubber()
	var n int

	out := s.scrubJSONTree(`{"secret":["s3cr3t-value-xyz","abcdefghij"],"name":"demo"}`, &n)
	if strings.Contains(out, "s3cr3t-value-xyz") || strings.Contains(out, "abcdefghij") || n != 2 || !json.Valid([]byte(out)) {
		t.Errorf("array under a secret key: n=%d %s", n, out)
	}

	// Numbers, booleans and null do not disturb the walk.
	n = 0
	out = s.scrubJSONTree(`{"secret":[1,true,null,-2.5e3,"abcdefgh"]}`, &n)
	if strings.Contains(out, "abcdefgh") || n != 1 || !json.Valid([]byte(out)) || !strings.Contains(out, `[1,true,null,-2.5e3,`) {
		t.Errorf("scalars in an array: n=%d %s", n, out)
	}

	// A nested object closes without losing the owner of the string after it.
	n = 0
	out = s.scrubJSONTree(`{"secret":[{"x":1},["abcdefgh"],"ijklmnop"]}`, &n)
	if strings.Contains(out, "abcdefgh") || strings.Contains(out, "ijklmnop") || n != 2 {
		t.Errorf("array nested in an array: n=%d %s", n, out)
	}

	// Objects inside an array inside an object use their own keys.
	n = 0
	out = s.scrubJSONTree(`{"items":[{"name":"x"},{"password":"`+walkerSecret+`"}]}`, &n)
	if strings.Contains(out, walkerSecret) || n != 1 || !strings.Contains(out, `"name":"x"`) {
		t.Errorf("objects in an array: n=%d %s", n, out)
	}

	// A top-level array of bare strings has no owning key, so nothing is acted on.
	n = 0
	in := `["password","` + walkerSecret + `"]`
	if got := s.scrubJSONTree(in, &n); got != in || n != 0 {
		t.Errorf("top-level array was changed: n=%d %s", n, got)
	}

	// A key whose value is a hint-free array is left alone.
	in = `{"token_note":["plain words here"],"secret":[]}`
	if got := s.scrubJSONTree(in, &n); got != in {
		t.Errorf("empty or benign arrays changed: %s", got)
	}
}

func TestStrongSecretKey(t *testing.T) {
	for _, k := range []string{
		"password", "DB_PASSWORD", "passwd", "pwd", "client-secret", "Client-Secret", "access_token",
		"private_key", "private-key", "PrivateKey", "api_key", "api-key", "ApiKey", "secret_key", "secret-key",
	} {
		if !strongSecretKey(k) {
			t.Errorf("strongSecretKey(%q) = false, want true", k)
		}
	}
	for _, k := range []string{"", "key", "keyboard", "auth", "session", "cookie", "tokens", "passwords", "secrets", "public_key"} {
		if strongSecretKey(k) {
			t.Errorf("strongSecretKey(%q) = true, want false", k)
		}
	}
}

func TestAncestorContextEdges(t *testing.T) {
	// The raw text is "ui" + "auth" + a hyphenated ancestor.
	in := "ui" + "auth" + "Locale"
	// Frames: ui, an array (skipped), auth, Locale (case is folded), and the
	// frame being judged, which is never read.
	stack := []jsonFrame{
		{obj: true, ks: 0, ke: 2},
		{obj: false},
		{obj: true, ks: 2, ke: 6},
		{obj: true, ks: 6, ke: 12},
		{obj: true, expectKey: true},
	}
	// d=0: nothing above the root. d=1,2: ui only, the array adds nothing.
	// d=3,4: a credentials ancestor beats a UI one and keeps winning below it.
	cases := []struct {
		d              int
		benign, secret bool
	}{
		{0, false, false},
		{1, true, false},
		{2, true, false},
		{3, false, true},
		{4, false, true},
	}
	for _, c := range cases {
		b, sec := ancestorContext(in, stack, c.d)
		if b != c.benign || sec != c.secret {
			t.Errorf("ancestorContext(d=%d) = (%v,%v), want (%v,%v)", c.d, b, sec, c.benign, c.secret)
		}
	}

	// Escaped ancestors are decoded; an undecodable one is read as no key.
	esc := `\u0075i`
	if b, sec := ancestorContext(esc, []jsonFrame{{obj: true, ks: 0, ke: len(esc), keyEsc: true}, {obj: true}}, 1); !b || sec {
		t.Errorf("escaped ui ancestor = (%v,%v)", b, sec)
	}
	bad := `\q`
	if b, sec := ancestorContext(bad, []jsonFrame{{obj: true, ks: 0, ke: len(bad), keyEsc: true}, {obj: true}}, 1); b || sec {
		t.Errorf("undecodable ancestor = (%v,%v), want neither", b, sec)
	}

	// Hyphens count as underscores, and every credentials spelling is a secret.
	for _, k := range []string{"auth", "Authentication", "credentials", "credential", "secrets", "security", "oauth", "login", "session", "sessions", "passwords", "private"} {
		if _, sec := ancestorContext(k, []jsonFrame{{obj: true, ks: 0, ke: len(k)}, {obj: true}}, 1); !sec {
			t.Errorf("%q should be a credentials ancestor", k)
		}
	}
}

func TestJSONSecretValueBranches(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	_ = pub
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8 := base64.StdEncoding.EncodeToString(der)

	cases := []struct {
		name, key, raw       string
		ancBenign, ancSecret bool
		want                 bool
	}{
		{"empty key", "", "abcdefghijkl", false, false, false},
		{"empty value", "db_password", "", false, false, false},
		{"not a secret-looking key", "username", "abcdefghijkl", false, false, false},
		{"already redacted", "db_password", "[REDACTED_TOKEN#abc123]", false, false, false},
		{"allowlist marker only", "db_password", allowMark + "12\x00", false, false, false},
		{"allowlist marker inside", "db_password", "pre" + allowMark + "12\x00post", false, false, false},
		{"template placeholder", "db_password", "${DB_PASSWORD}", false, false, false},
		{"escaped placeholder", "db_password", `\u0024{DB_PASSWORD}`, false, false, false},
		{"undecodable escape", "db_password", `ab\qcdef`, false, false, false},
		{"pem under a bare key in a UI object", "key", "-----BEGIN PRIVATE KEY-----", true, false, true},
		{"prefixed token under a UI parent", "token", "ghp_abcdefghijklmnopqrstuvwxyz0123456789", true, false, true},
		{"der private key", "private_key", pkcs8, false, false, true},
		{"credentials parent, long enough", "key", "abc123", false, true, true},
		{"credentials parent, too short", "key", "abc12", false, true, false},
		{"credentials parent, token", "token", "tok-9f8e7d", false, true, true},
		{"ui parent exempts a bare key", "key", "primary-blue-700", true, false, false},
		{"ui parent exempts a bare token", "token", "dark-mode-xyz", true, false, false},
		{"bare key, short word", "key", "short-val", false, false, false},
		{"bare key, path", "key", "uploads/2024/a-very-long-object-name.png", false, false, false},
		{"bare key, opaque and long", "key", "Zk3pQ9vLm2XaBc", false, false, true},
		{"strong key, minimal length", "db_password", "abcdef", false, false, true},
		{"strong key, too short", "db_password", "abcde", false, false, false},
		{"weak hint, plausible secret", "auth_header", "Zk3pQ9vLm2XaBc", false, false, true},
		{"weak hint, too short", "auth_header", "Zk3pQ9vLm2X", false, false, false},
		{"weak hint, too long", "auth_header", strings.Repeat("a", 257), false, false, false},
		{"weak hint, longest allowed", "auth_header", strings.Repeat("aB3", 85) + "x", false, false, true},
		{"weak hint, space", "auth_header", "Zk3pQ9vL m2XaBc", false, false, false},
		{"weak hint, colon", "auth_header", "Zk3pQ9vL:m2XaBc", false, false, false},
		{"weak hint, tab", "auth_header", "Zk3pQ9vL\tm2XaBc", false, false, false},
		{"weak hint, url", "auth_header", "https://example.com/callback", false, false, false},
		{"weak hint, absolute path", "auth_header", "/var/lib/app/state.db", false, false, false},
	}
	for _, c := range cases {
		if got := jsonSecretValue(c.key, c.raw, c.ancBenign, c.ancSecret); got != c.want {
			t.Errorf("%s: jsonSecretValue(%q, %q, %v, %v) = %v, want %v", c.name, c.key, c.raw, c.ancBenign, c.ancSecret, got, c.want)
		}
	}
}
