package scan

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestStripTOMLComment(t *testing.T) {
	cases := []struct{ in, want string }{
		{`a = "x # y" # c`, `a = "x # y"`},
		{`a = 'it # s' # c`, `a = 'it # s'`},
		{`a = "x\"#y" # c`, `a = "x\"#y"`},
		{"no comment  ", "no comment"},
		{"# only comment", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := stripTOMLComment(c.in); got != c.want {
			t.Errorf("stripTOMLComment(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestTOMLStrings(t *testing.T) {
	got := tomlStrings(`["a", 'b', "c\"d"]`)
	want := []string{"a", "b", `c\"d`}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := tomlStrings(`"unterminated`); len(got) != 0 {
		t.Errorf("unterminated string should give nothing, got %q", got)
	}
	if got := tomlStrings("no quotes here"); len(got) != 0 {
		t.Errorf("got %q", got)
	}
}

func TestTOMLDepth(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"[1, [2]", 1},
		{`{ a = "}" }`, 0},
		{`"["`, 0},
		{"]", -1},
		{`["a\"[", {`, 2},
	}
	for _, c := range cases {
		if got := tomlDepth(c.in); got != c.want {
			t.Errorf("tomlDepth(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestSplitTOMLTop(t *testing.T) {
	got := splitTOMLTop(`a = 1, b = [1, 2], c = "x,y", d = { e = 1, f = 2 }`)
	want := []string{"a = 1", " b = [1, 2]", ` c = "x,y"`, " d = { e = 1, f = 2 }"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := splitTOMLTop("single"); len(got) != 1 || got[0] != "single" {
		t.Errorf("got %q", got)
	}
	if got := splitTOMLTop(`'a,\', "b,c"`); len(got) != 2 {
		t.Errorf("quoted commas should not split: %q", got)
	}
}

func TestTOMLInlineBlocks(t *testing.T) {
	bodies, rest := tomlInlineBlocks(`[{ token = "a" }, { token = "b" }]`)
	if len(bodies) != 2 || strings.TrimSpace(bodies[0]) != `token = "a"` || strings.TrimSpace(bodies[1]) != `token = "b"` {
		t.Errorf("bodies = %q", bodies)
	}
	if strings.Contains(rest, "token") {
		t.Errorf("rest should have the blocks cut out: %q", rest)
	}

	bodies, rest = tomlInlineBlocks(`x = "keep {braces}", { a = "}" }`)
	if len(bodies) != 1 || strings.TrimSpace(bodies[0]) != `a = "}"` {
		t.Errorf("quoted brace handling: bodies = %q", bodies)
	}
	if !strings.Contains(rest, `"keep {braces}"`) {
		t.Errorf("quoted text outside a block must be kept: %q", rest)
	}

	if bodies, _ := tomlInlineBlocks(`"esc \" { not a block }"`); len(bodies) != 0 {
		t.Errorf("escaped quote handling: %q", bodies)
	}
	if bodies, rest := tomlInlineBlocks("no blocks"); len(bodies) != 0 || rest != "no blocks" {
		t.Errorf("got %q %q", bodies, rest)
	}
}

func TestTOMLScalar(t *testing.T) {
	cases := []struct{ in, want string }{
		{`"abc"`, "abc"},
		{`'x'`, "x"},
		{" bare ", "bare"},
		{`"`, `"`},
		{`"mismatch'`, `"mismatch'`},
	}
	for _, c := range cases {
		if got := tomlScalar(c.in); got != c.want {
			t.Errorf("tomlScalar(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestScanTOMLFile(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "c.toml", strings.Join([]string{
		`token = "` + marker + `"`,
		`name = "plain"`,
		`[server]`,
		`api_key = 'plain'`,
		`note = "x" # c`,
		`[auth]`,
		`list = ["a", "` + marker + `"]`,
		`inline = { password = "` + marker + `", other = "plain" }`,
		`items = [{ token = "` + marker + `" }]`,
		`multi = """`,
		marker,
		`"""`,
	}, "\n"))
	var rep strings.Builder
	ok, hits, tokens := scanTOMLFile(&fakeScrub{}, p, &rep)
	if !ok || hits != 6 || tokens != 5 {
		t.Errorf("got ok=%v hits=%d tokens=%d\n%s", ok, hits, tokens, rep.String())
	}
	if strings.Contains(rep.String(), marker) {
		t.Errorf("report leaked a secret:\n%s", rep.String())
	}
	for _, want := range []string{"token", "server.api_key", "auth.list", "auth.inline.password", "auth.items.token", "auth.multi"} {
		if !strings.Contains(rep.String(), want) {
			t.Errorf("report is missing %q:\n%s", want, rep.String())
		}
	}
}

func TestScanTOMLFileMultilineArray(t *testing.T) {
	p := writeFile(t, t.TempDir(), "c.toml", strings.Join([]string{
		`[tool]`,
		`hosts = [`,
		`  "` + marker + `", # c`,
		`  "plain",`,
		`]`,
		`single = '''` + marker + `'''`,
		`broken = { a = "` + marker + `"`,
	}, "\n"))
	var rep strings.Builder
	ok, hits, tokens := scanTOMLFile(&fakeScrub{}, p, &rep)
	if !ok || hits != 2 || tokens != 2 {
		t.Errorf("got ok=%v hits=%d tokens=%d\n%s", ok, hits, tokens, rep.String())
	}
}

func TestScanTOMLFileErrorsAndClean(t *testing.T) {
	dir := t.TempDir()
	var rep strings.Builder
	if ok, _, _ := scanTOMLFile(&fakeScrub{}, filepath.Join(dir, "missing.toml"), &rep); ok || !strings.Contains(rep.String(), "✗") {
		t.Errorf("missing file: %q", rep.String())
	}
	clean := writeFile(t, dir, "clean.toml", "# c\n\n[t]\na = 1\nb = \"x\"\n")
	rep.Reset()
	if ok, hits, _ := scanTOMLFile(&fakeScrub{}, clean, &rep); !ok || hits != 0 || !strings.Contains(rep.String(), "no secrets found") {
		t.Errorf("clean file: %q", rep.String())
	}
}

func TestStripTOMLCommentStateMultiline(t *testing.T) {
	// A multi-line string opened on this line keeps its # and its trailing spaces.
	out, ml := stripTOMLCommentState(`x = ["""a # b  `, 0)
	if out != `x = ["""a # b  ` || ml != '"' {
		t.Errorf("got %q, %q", out, ml)
	}
	// The next line closes it; the # after the closing quotes is a real comment.
	out, ml = stripTOMLCommentState(`c # d""" # e`, '"')
	if out != `c # d"""` || ml != 0 {
		t.Errorf("got %q, %q", out, ml)
	}
	// Single-quoted literal strings work the same way, and a lone quote does not open one.
	if out, ml = stripTOMLCommentState(`'''a # b`, 0); out != `'''a # b` || ml != '\'' {
		t.Errorf("got %q, %q", out, ml)
	}
	if got := stripTOMLComment(`a = "" # c`); got != `a = ""` {
		t.Errorf("empty string: got %q", got)
	}
}

func TestTOMLDepthStateMultiline(t *testing.T) {
	d, ml := tomlDepthState(`["""a ] {`, 0)
	if d != 1 || ml != '"' {
		t.Errorf("got depth %d, ml %q", d, ml)
	}
	d, ml = tomlDepthState(`b ] [ """]`, ml)
	if d != -1 || ml != 0 {
		t.Errorf("got depth %d, ml %q", d, ml)
	}
	if got := tomlDepth(`["""x ] y""", [`); got != 2 {
		t.Errorf("tomlDepth with a multi-line string = %d, want 2", got)
	}
}

func TestTOMLHelpersSkipMultilineStrings(t *testing.T) {
	if got := tomlStrings(`["""a "q" b""", 'c']`); !reflect.DeepEqual(got, []string{`a "q" b`, "c"}) {
		t.Errorf("tomlStrings = %q", got)
	}
	got := splitTOMLTop(`a = """x, y "z" , w""", b = 1`)
	if len(got) != 2 {
		t.Errorf("splitTOMLTop = %q", got)
	}
	bodies, rest := tomlInlineBlocks(`["""{ not a block }""", { a = 1 }]`)
	if len(bodies) != 1 || strings.TrimSpace(bodies[0]) != "a = 1" || !strings.Contains(rest, "{ not a block }") {
		t.Errorf("tomlInlineBlocks = %q, %q", bodies, rest)
	}
}

func TestScanTOMLFileNestedInlineAndMultilineInArray(t *testing.T) {
	p := writeFile(t, t.TempDir(), "c.toml", strings.Join([]string{
		`[auth]`,
		`nested = { creds = { token = "` + marker + `" }, other = "plain" }`,
		`deep = { a = { b = { c = "` + marker + `" } } }`,
		`mixed = { list = [{ key = "` + marker + `" }] }`,
		`hosts = [`,
		`  """`,
		`  has # hash and ] bracket`,
		`  ` + marker,
		`  """,`,
		`  "plain",`,
		`]`,
		`after = "` + marker + `"`,
	}, "\n"))
	var rep strings.Builder
	ok, hits, tokens := scanTOMLFile(&fakeScrub{}, p, &rep)
	if !ok || hits != 5 || tokens != 5 {
		t.Errorf("got ok=%v hits=%d tokens=%d\n%s", ok, hits, tokens, rep.String())
	}
	if strings.Contains(rep.String(), marker) {
		t.Errorf("report leaked a secret:\n%s", rep.String())
	}
	for _, want := range []string{"auth.nested.creds.token", "auth.deep.a.b.c", "auth.mixed.list.key", "auth.hosts", "auth.after"} {
		if !strings.Contains(rep.String(), want) {
			t.Errorf("report is missing %q:\n%s", want, rep.String())
		}
	}
}
