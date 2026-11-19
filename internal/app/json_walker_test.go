package app

import (
	"bytes"
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
	real := "postgres://app:Zx9Qw3Lp7Mn2@db.example.com/x"
	if out, _ := s.ScrubText("dsn " + real); strings.Contains(out, "Zx9Qw3Lp7Mn2") {
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
