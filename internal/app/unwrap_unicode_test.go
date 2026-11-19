package app

import (
	"strings"
	"testing"
)

func TestUnwrapDecodesJSONUnicodeAndSlashEscapes(t *testing.T) {
	for in, want := range map[string]string{
		`token\u003dabc`:      "token=abc",
		`a\u0026b\u003cc\u003e`: "a&b<c>",
		`a\/b`:               "a/b",
		`\u00e9`:             `\u00e9`, // non-ASCII is left alone
		`\u12`:               `\u12`,   // truncated
		`\\u003d`:            `\u003d`, // an escaped backslash is not a unicode escape
	} {
		if got, _ := unwrapEscapes(in); got != want {
			t.Errorf("unwrapEscapes(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]bool{
		`a\u003db`: true,
		`a\/b`:     true,
		`\u00e9`:   false,
		`\u003`:    false,
	} {
		if got := needsUnwrap(in); got != want {
			t.Errorf("needsUnwrap(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestScrubFindsSecretSplitByUnicodeEscapes(t *testing.T) {
	s, _ := NewScrubber()
	secret := "Zq8Xv3LmP0aTr9YkB2nWd6HsJ4cFe7Gu"
	in := `GET /v?api_key\u003d` + secret + `\u0026x\u003d1`
	out, n := s.ScrubTextIn(in, ContextBody)
	if n == 0 || strings.Contains(out, secret) {
		t.Fatalf("secret behind \\u003d leaked: %q", out)
	}
	if !strings.Contains(out, `\u0026x\u003d1`) {
		t.Errorf("text outside the secret was changed: %q", out)
	}
}
