package app

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newAllowScrubber(t *testing.T, cfg *SecretsConfig) *Scrubber {
	t.Helper()
	s, err := NewScrubberWithConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// With no allowlist, the defaults are exactly what they were.
func TestAllowlistOffByDefault(t *testing.T) {
	s := newAllowScrubber(t, &SecretsConfig{})
	if s.allow != nil {
		t.Fatal("no allowlist should exist without ignore_fields or ignore_patterns")
	}
	out, n := s.ScrubText(`{"password":"hunter2hunter2"}`)
	if n < 1 || strings.Contains(out, "hunter2") {
		t.Errorf("the default must still redact a password: %q (%d)", out, n)
	}
}

// An ignored field keeps its value, whatever the format: JSON, key=value, XML.
func TestIgnoreFieldsLeavesTheValueAlone(t *testing.T) {
	s := newAllowScrubber(t, &SecretsConfig{IgnoreFields: []string{"Password"}}) // not case-sensitive
	for name, in := range map[string]string{
		"json string": `{"password":"keep-this-plain-1","note":"x"}`,
		"json number": `{"password": 123456789012}`,
		"key=value":   `a=1&password=keep-this-plain-1&b=2`,
		"xml":         `<root><password>keep-this-plain-1</password></root>`,
	} {
		out, n := s.ScrubText(in)
		if out != in || n != 0 {
			t.Errorf("%s: the ignored field was changed:\n in  %q\n out %q (%d)", name, in, out, n)
		}
	}
}

// Other fields keep being redacted, so the exemption is only for the named field.
func TestIgnoreFieldsOnlyExemptsTheNamedField(t *testing.T) {
	s := newAllowScrubber(t, &SecretsConfig{IgnoreFields: []string{"password"}})
	out, n := s.ScrubText(`{"password":"keep-this-plain-1","api_key":"abcdefgh12345678"}`)
	if !strings.Contains(out, `"password":"keep-this-plain-1"`) {
		t.Errorf("the ignored field was changed: %q", out)
	}
	if n < 1 || strings.Contains(out, "abcdefgh12345678") {
		t.Errorf("another secret field must still be redacted: %q (%d)", out, n)
	}
}

// A recognised secret format inside an ignored field is still redacted.
func TestIgnoreFieldsStillRedactsKnownFormats(t *testing.T) {
	s := newAllowScrubber(t, &SecretsConfig{IgnoreFields: []string{"password"}})
	out, n := s.ScrubText(`{"password":"sk_live_` + ctxTestBody + `"}`)
	if n < 1 || strings.Contains(out, ctxTestBody[8:]) {
		t.Fatalf("a vendor key in an ignored field must still be redacted: %q (%d)", out, n)
	}
	if !strings.HasPrefix(out, `{"password":"[REDACTED_`) {
		t.Errorf("the field should stay, with its value redacted: %q", out)
	}
}

// ignore_patterns exempts exactly the text it matches and nothing else.
func TestIgnorePatterns(t *testing.T) {
	s := newAllowScrubber(t, &SecretsConfig{IgnorePatterns: []string{`sk_test_A1b2C3d4E5f6G7h8[A-Za-z0-9]+`}})
	testKey := "sk_test_" + ctxTestBody
	in := "public test key " + testKey + " for the docs"
	if out, n := s.ScrubText(in); out != in || n != 0 {
		t.Errorf("text matching an ignore pattern was changed: %q (%d)", out, n)
	}
	live := "sk_live_" + ctxTestBody
	out, n := s.ScrubText("key " + live)
	if n < 1 || strings.Contains(out, ctxTestBody[8:]) {
		t.Errorf("a key the pattern does not match must still be redacted: %q (%d)", out, n)
	}
}

// The allowlist is for bodies. Headers and URLs keep the defaults.
func TestAllowlistDoesNotApplyToHeadersOrQueries(t *testing.T) {
	s := newAllowScrubber(t, &SecretsConfig{
		IgnoreFields:   []string{"password"},
		IgnorePatterns: []string{`sk_test_A1b2C3d4E5f6G7h8[A-Za-z0-9]+`},
	})
	if out, n := s.ScrubTextIn("password=hunter2hunter2", ContextQuery); n < 1 || strings.Contains(out, "hunter2") {
		t.Errorf("a query string must keep the defaults: %q (%d)", out, n)
	}
	h := http.Header{}
	h.Set("X-Note", "sk_test_"+ctxTestBody)
	m, _ := s.ScrubHeaders(h)
	if strings.Contains(m["X-Note"], ctxTestBody[8:]) {
		t.Errorf("a header must keep the defaults: %q", m["X-Note"])
	}
}

// Placeholders must never leak into the output, and text that already holds
// the placeholder marker is handled without being exempted.
func TestAllowlistPlaceholdersNeverLeak(t *testing.T) {
	s := newAllowScrubber(t, &SecretsConfig{IgnoreFields: []string{"password"}, IgnorePatterns: []string{`FIXTURE-[0-9]{6}`}})
	out, _ := s.ScrubText(`{"password":"a-plain-value-1","ref":"FIXTURE-123456"}`)
	if strings.Contains(out, "\x00") {
		t.Errorf("a placeholder leaked into the output: %q", out)
	}
	if out != `{"password":"a-plain-value-1","ref":"FIXTURE-123456"}` {
		t.Errorf("exempt text should come back unchanged: %q", out)
	}
	in := "text with \x00NW0\x00 inside and password=hunter2hunter2"
	if out, n := s.ScrubText(in); n < 1 || strings.Contains(out, "hunter2") {
		// With the marker already in the text the allowlist stands aside, so the
		// default rules apply and nothing is exempted.
		t.Errorf("text holding the marker must fall back to the defaults: %q (%d)", out, n)
	}
}

func TestAllowlistConfigErrors(t *testing.T) {
	for name, c := range map[string]*SecretsConfig{
		"blank field":      {IgnoreFields: []string{" "}},
		"control char":     {IgnoreFields: []string{"a\x01b"}},
		"bad regex":        {IgnorePatterns: []string{"(unclosed"}},
		"empty pattern":    {IgnorePatterns: []string{""}},
		"matches empty":    {IgnorePatterns: []string{".*"}},
		"matches any char": {IgnorePatterns: []string{".+"}},
		"negated class":    {IgnorePatterns: []string{`[^"]+`}},
	} {
		if _, err := NewScrubberWithConfig(c); err == nil {
			t.Errorf("%s: a config like this must be refused", name)
		}
	}
}

func TestLoadSecretsConfigAllowlist(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte(`{"ignore_fields":["session_ttl","Key"],"ignore_patterns":["fixture-[a-z0-9]{12}"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := loadSecretsConfig(good)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.IgnoreFields) != 2 || len(c.IgnorePatterns) != 1 {
		t.Errorf("config not read: %+v", c)
	}

	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"ignore_patterns":["(oops"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = loadSecretsConfig(bad)
	if err == nil || !strings.Contains(err.Error(), "ignore_patterns[0]") || !strings.Contains(err.Error(), "-secrets-config") {
		t.Errorf("a bad pattern should be reported with its place in the file, got %v", err)
	}
}
