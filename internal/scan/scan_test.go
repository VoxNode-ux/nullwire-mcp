package scan

import (
	"archive/zip"
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeScrub is a deterministic Scrubber: the marker "s3cr3t" is the only
// secret it knows. It lets this package be tested without importing the app
// package (which would be an import cycle).
type fakeScrub struct{ tokens, ips uint64 }

const marker = "s3cr3t"

func (f *fakeScrub) ScrubText(in string) (string, int) {
	n := strings.Count(in, marker)
	if n == 0 {
		return in, 0
	}
	f.tokens += uint64(n)
	return strings.ReplaceAll(in, marker, "[R]"), n
}
func (f *fakeScrub) TokenCount() uint64 { return f.tokens }
func (f *fakeScrub) IPCount() uint64    { return f.ips }

func useFakeScrubber(t *testing.T) {
	t.Helper()
	old := NewScrubber
	NewScrubber = func() (Scrubber, error) { return &fakeScrub{}, nil }
	t.Cleanup(func() { NewScrubber = old })
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

type zipEntry struct {
	name string
	data []byte
}

func writeZip(t *testing.T, path string, entries []zipEntry) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.Create(e.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestScanKV(t *testing.T) {
	s := &fakeScrub{}
	cases := []struct {
		name, key, val string
		shown          string
		n              int
		found          bool
	}{
		{"secret value", "k", marker, "[R]", 1, true},
		{"secret name only", "db_password", "hunter2", HiddenValue, 0, true},
		{"nothing", "name", "hello", "", 0, false},
		{"key rewritten, value plain", marker + "_x", "plain", "", 0, false},
		{"key rewritten, name secret", marker + "_token", "plain", HiddenValue, 0, true},
		{"key and value rewritten", marker + "_x", marker, "[R]", 2, true},
	}
	for _, c := range cases {
		shown, n, found := scanKV(s, c.key, "=", c.val)
		if shown != c.shown || n != c.n || found != c.found {
			t.Errorf("%s: got (%q, %d, %v), want (%q, %d, %v)", c.name, shown, n, found, c.shown, c.n, c.found)
		}
	}
}

func TestPathHelpers(t *testing.T) {
	for in, want := range map[string]string{
		"env.GITHUB_TOKEN": "GITHUB_TOKEN",
		"args[3]":          "args",
		"a.b[2]":           "b",
		"plain":            "plain",
	} {
		if got := lastSegment(in); got != want {
			t.Errorf("lastSegment(%q) = %q, want %q", in, got, want)
		}
	}
	if joinPath("", "a") != "a" || joinPath("a", "b") != "a.b" {
		t.Error("joinPath wrong")
	}
	if trimPath("short") != "short" {
		t.Error("trimPath changed a short path")
	}
	long := strings.Repeat("x", 60)
	got := trimPath(long)
	if !strings.HasPrefix(got, "…") || !strings.HasSuffix(got, strings.Repeat("x", 49)) {
		t.Errorf("trimPath(long) = %q", got)
	}
}

func TestContainsAny(t *testing.T) {
	if !containsAny("hello world", []string{"zzz", "wor"}) {
		t.Error("expected a match")
	}
	if containsAny("hello", []string{"zzz", "yyy"}) || containsAny("hello", nil) {
		t.Error("unexpected match")
	}
}

func TestIsConfigFilename(t *testing.T) {
	for _, n := range []string{".mcp.json", "mcp.json", "my_mcp.json", "my-mcp.json", "Claude_Desktop_Config.json", "mcp_config.json"} {
		if !isConfigFilename(n) {
			t.Errorf("%q should be a config filename", n)
		}
	}
	for _, n := range []string{"package.json", "mcp.txt", "config.json"} {
		if isConfigFilename(n) {
			t.Errorf("%q should not be a config filename", n)
		}
	}
}

func TestReadScanFileTooLarge(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big.txt")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxScanFile + 1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err := readScanFile(p); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("want a size error, got %v", err)
	}
	if _, err := readScanFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("want an error for a missing file")
	}
	var rep strings.Builder
	if ok, _, _ := ScanYAMLFile(&fakeScrub{}, p, &rep); ok || !strings.Contains(rep.String(), "✗") {
		t.Errorf("oversize YAML should fail: %q", rep.String())
	}
}

func TestScanTotalsRecord(t *testing.T) {
	var tot scanTotals
	tot.record(true, 2, 3, 1)
	tot.record(false, 1, 1, 0)
	want := scanTotals{filesOK: 1, filesBad: 1, hits: 3, tokens: 4, ips: 1}
	if tot != want {
		t.Errorf("got %+v, want %+v", tot, want)
	}
}

func TestWalkTreeSkipsVendorDirs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "root.txt", "x")
	writeFile(t, dir, "a/b.txt", "x")
	writeFile(t, dir, "node_modules/skip.txt", "x")
	writeFile(t, dir, ".git/skip2.txt", "x")
	seen := map[string]bool{}
	walkTree(dir, func(path string, d fs.DirEntry) { seen[d.Name()] = true })
	if !seen["root.txt"] || !seen["b.txt"] || seen["skip.txt"] || seen["skip2.txt"] {
		t.Errorf("unexpected walk result: %v", seen)
	}
	walkTree(filepath.Join(dir, "missing"), func(string, fs.DirEntry) { t.Error("visited a missing root") })
}

func TestEnvValue(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{`"a # b" # c`, "a # b"},
		{`'` + marker + `'#x`, marker},
		{"abc # c", "abc"},
		{"abc\t# c", "abc"},
		{`"unterminated  `, "unterminated"},
		{`"a\"b"`, `a\"b`},
		{"abc#notcomment", "abc#notcomment"},
		{"  spaced  ", "spaced"},
	}
	for _, c := range cases {
		if got := envValue(c.in); got != c.want {
			t.Errorf("envValue(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEnvFileNames(t *testing.T) {
	for _, n := range []string{".env", ".ENV", ".envrc", ".env.local", "prod.env"} {
		if !envFileNames(n) {
			t.Errorf("%q should be an env file", n)
		}
	}
	for _, n := range []string{"env.txt", "myenv", "environment"} {
		if envFileNames(n) {
			t.Errorf("%q should not be an env file", n)
		}
	}
}

func TestScanEnvFile(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, ".env", strings.Join([]string{
		"# comment",
		"export API_TOKEN=\"" + marker + "\"",
		"PLAIN=hello # c",
		"DB_PASSWORD=hunter2",
		"EMPTY=",
		"NOEQUALS",
		"QUOTED=\"a # " + marker + "\"",
	}, "\n"))
	var rep strings.Builder
	ok, hits, tokens, ips := scanEnvFile(&fakeScrub{}, p, &rep)
	if !ok || hits != 3 || tokens != 2 || ips != 0 {
		t.Errorf("got ok=%v hits=%d tokens=%d ips=%d\n%s", ok, hits, tokens, ips, rep.String())
	}
	if strings.Contains(rep.String(), marker) || strings.Contains(rep.String(), "hunter2") {
		t.Errorf("report leaked a secret:\n%s", rep.String())
	}
	if !strings.Contains(rep.String(), HiddenValue) {
		t.Errorf("report should hide the value of DB_PASSWORD:\n%s", rep.String())
	}

	var rep2 strings.Builder
	if ok, _, _, _ := scanEnvFile(&fakeScrub{}, filepath.Join(dir, "missing.env"), &rep2); ok {
		t.Error("a missing file should not be ok")
	}
	clean := writeFile(t, dir, "clean.env", "A=1\n")
	var rep3 strings.Builder
	if _, hits, _, _ := scanEnvFile(&fakeScrub{}, clean, &rep3); hits != 0 || !strings.Contains(rep3.String(), "no secrets found") {
		t.Errorf("clean env file: %q", rep3.String())
	}
}

func TestYAMLValue(t *testing.T) {
	if got := yamlValue("a # c"); got != "a" {
		t.Errorf("got %q", got)
	}
	if got := yamlValue("a#c"); got != "a#c" {
		t.Errorf("got %q", got)
	}
	if got := yamlValue("  x  "); got != "x" {
		t.Errorf("got %q", got)
	}
}

func TestScanYAMLFile(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "c.yaml", strings.Join([]string{
		"# c",
		"token: " + marker,
		"name: plain",
		`password: "hunter2"`,
		"desc: |",
		"  block",
		"items:",
		"  - " + marker,
		"  - plain",
		`tags: ["a", "` + marker + `"]`,
		"- " + marker,
		"url: x # " + marker + " comment",
	}, "\n"))
	var rep strings.Builder
	ok, hits, tokens := ScanYAMLFile(&fakeScrub{}, p, &rep)
	if !ok || hits != 5 || tokens != 4 {
		t.Errorf("got ok=%v hits=%d tokens=%d\n%s", ok, hits, tokens, rep.String())
	}
	if strings.Contains(rep.String(), marker) {
		t.Errorf("report leaked a secret:\n%s", rep.String())
	}
	var rep2 strings.Builder
	if ok, _, _ := ScanYAMLFile(&fakeScrub{}, filepath.Join(dir, "missing.yaml"), &rep2); ok {
		t.Error("a missing file should not be ok")
	}
	clean := writeFile(t, dir, "clean.yml", "a: 1\n")
	var rep3 strings.Builder
	if _, hits, _ := ScanYAMLFile(&fakeScrub{}, clean, &rep3); hits != 0 || !strings.Contains(rep3.String(), "no secrets found") {
		t.Errorf("clean yaml: %q", rep3.String())
	}
}

func TestScanZipFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.zip")
	writeZip(t, p, []zipEntry{
		{"secret.txt", []byte("key=" + marker)},
		{"plain.txt", []byte("hello")},
		{"bin.dat", append([]byte{0}, []byte(marker)...)},
		{"dir/", nil},
		{"big.txt", bytes.Repeat([]byte("a"), zipMaxEntry+10)},
	})
	var rep strings.Builder
	ok, hits, tokens := ScanZipFile(&fakeScrub{}, p, &rep)
	if !ok || hits != 1 || tokens != 1 {
		t.Errorf("got ok=%v hits=%d tokens=%d\n%s", ok, hits, tokens, rep.String())
	}
	r := rep.String()
	if !strings.Contains(r, `"secret.txt"`) || strings.Contains(r, "plain.txt") || strings.Contains(r, "bin.dat") {
		t.Errorf("unexpected report:\n%s", r)
	}
	if !strings.Contains(r, "Zip Bomb Shield") || strings.Contains(r, marker) {
		t.Errorf("big entry should be skipped and text never shown:\n%s", r)
	}
}

func TestScanZipFileErrors(t *testing.T) {
	dir := t.TempDir()
	var rep strings.Builder
	if ok, _, _ := ScanZipFile(&fakeScrub{}, filepath.Join(dir, "missing.zip"), &rep); ok {
		t.Error("missing file should fail")
	}
	bad := writeFile(t, dir, "bad.zip", "not a zip")
	rep.Reset()
	if ok, _, _ := ScanZipFile(&fakeScrub{}, bad, &rep); ok || !strings.Contains(rep.String(), "not a valid ZIP") {
		t.Errorf("bad zip: %q", rep.String())
	}
	huge := filepath.Join(dir, "huge.zip")
	f, err := os.Create(huge)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(zipMaxArchive + 1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	rep.Reset()
	if ok, _, _ := ScanZipFile(&fakeScrub{}, huge, &rep); ok || !strings.Contains(rep.String(), "Zip Bomb Shield") {
		t.Errorf("huge zip: %q", rep.String())
	}
}

func TestScanZipFileLimits(t *testing.T) {
	dir := t.TempDir()

	many := make([]zipEntry, 0, zipMaxEntries+1)
	for i := 0; i < zipMaxEntries+1; i++ {
		many = append(many, zipEntry{name: "f" + itoa(i) + ".txt", data: []byte("x")})
	}
	p1 := filepath.Join(dir, "many.zip")
	writeZip(t, p1, many)
	var rep strings.Builder
	if ok, _, _ := ScanZipFile(&fakeScrub{}, p1, &rep); !ok || !strings.Contains(rep.String(), "stopped after") {
		t.Errorf("entry limit not reported: %q", rep.String())
	}

	var total []zipEntry
	for i := 0; i < 21; i++ {
		total = append(total, zipEntry{name: itoa(i) + ".txt", data: bytes.Repeat([]byte("a"), zipMaxEntry)})
	}
	p2 := filepath.Join(dir, "total.zip")
	writeZip(t, p2, total)
	rep.Reset()
	if ok, _, _ := ScanZipFile(&fakeScrub{}, p2, &rep); !ok || !strings.Contains(rep.String(), "archive total") {
		t.Errorf("total limit not reported: %q", rep.String())
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

func TestScanFileJSON(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "c.json", `{"env":{"API_TOKEN":"`+marker+`","name":"plain","password":"hunter2"},"args":["`+marker+`"]}`)
	var rep strings.Builder
	ok, hits, tokens, ips := ScanFile(&fakeScrub{}, p, &rep)
	if !ok || hits != 3 || tokens != 2 || ips != 0 {
		t.Errorf("got ok=%v hits=%d tokens=%d ips=%d\n%s", ok, hits, tokens, ips, rep.String())
	}
	bad := writeFile(t, dir, "bad.json", "{")
	rep.Reset()
	if ok, _, _, _ := ScanFile(&fakeScrub{}, bad, &rep); ok || !strings.Contains(rep.String(), "invalid JSON") {
		t.Errorf("invalid JSON: %q", rep.String())
	}
	rep.Reset()
	if ok, _, _, _ := ScanFile(&fakeScrub{}, filepath.Join(dir, "missing.json"), &rep); ok {
		t.Error("missing file should fail")
	}
	clean := writeFile(t, dir, "clean.json", `{"a":"b"}`)
	rep.Reset()
	if _, hits, _, _ := ScanFile(&fakeScrub{}, clean, &rep); hits != 0 || !strings.Contains(rep.String(), "no secrets found") {
		t.Errorf("clean json: %q", rep.String())
	}
}

func TestScanByType(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		".env":   "A_TOKEN=" + marker,
		"c.toml": `k = "` + marker + `"`,
		"c.yaml": "k: " + marker,
		"c.yml":  "k: " + marker,
		"c.json": `{"k":"` + marker + `"}`,
	}
	for name, content := range files {
		p := writeFile(t, dir, name, content)
		var rep strings.Builder
		ok, hits, _, _ := scanByType(&fakeScrub{}, p, &rep)
		if !ok || hits != 1 {
			t.Errorf("%s: ok=%v hits=%d\n%s", name, ok, hits, rep.String())
		}
	}
	zp := filepath.Join(dir, "c.zip")
	writeZip(t, zp, []zipEntry{{"a.txt", []byte(marker)}})
	var rep strings.Builder
	if ok, hits, _, _ := scanByType(&fakeScrub{}, zp, &rep); !ok || hits != 1 {
		t.Errorf("zip: ok=%v hits=%d", ok, hits)
	}
}

func TestScanHistoryFile(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, ".bash_history", strings.Join([]string{
		"export TOKEN=" + marker,
		"ls -la",
		"echo hello token",
		"curl -H 'Authorization: " + marker + "' http://x",
	}, "\n")+"\n")
	var rep strings.Builder
	ok, hits, tokens := ScanHistoryFile(&fakeScrub{}, p, &rep)
	if !ok || hits != 2 || tokens != 2 {
		t.Errorf("got ok=%v hits=%d tokens=%d\n%s", ok, hits, tokens, rep.String())
	}
	if strings.Contains(rep.String(), marker) || strings.Contains(rep.String(), "curl") {
		t.Errorf("history text must not be shown:\n%s", rep.String())
	}

	long := writeFile(t, dir, "long_history", "token="+marker+"\n"+strings.Repeat("a", 600*1024)+"\n")
	rep.Reset()
	if ok, hits, _ := ScanHistoryFile(&fakeScrub{}, long, &rep); !ok || hits != 1 || !strings.Contains(rep.String(), "stopped reading at line") {
		t.Errorf("long line: ok=%v hits=%d\n%s", ok, hits, rep.String())
	}
	rep.Reset()
	if ok, _, _ := ScanHistoryFile(&fakeScrub{}, filepath.Join(dir, "missing"), &rep); ok {
		t.Error("missing file should fail")
	}
	clean := writeFile(t, dir, "clean_history", "ls\n")
	rep.Reset()
	if _, hits, _ := ScanHistoryFile(&fakeScrub{}, clean, &rep); hits != 0 || !strings.Contains(rep.String(), "no secrets found") {
		t.Errorf("clean history: %q", rep.String())
	}
}

func TestHistoryAndDiscoverPaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "cfg"))
	hist := writeFile(t, home, ".bash_history", "ls\n")
	mcp := writeFile(t, home, ".mcp.json", `{"k":"v"}`)

	found := false
	for _, p := range historyPaths() {
		if p == hist {
			found = true
		}
	}
	if !found {
		t.Errorf("historyPaths() did not list %s", hist)
	}
	found = false
	for _, p := range discoverConfigPaths() {
		if p == mcp {
			found = true
		}
	}
	if !found {
		t.Errorf("discoverConfigPaths() did not list %s", mcp)
	}
}

func TestLooksLikeMCPConfig(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name, content string
		want          bool
	}{
		{"a.json", `{"mcpServers":{"x":{}}}`, true},
		{"b.json", `{"mcp":{"a":1}}`, true},
		{"c.json", `{"servers":{"a":{}}}`, true},
		{"d.json", `{"servers":{}}`, false},
		{"e.json", `{"mcp": nope`, false},
		{"f.json", `{"other":1}`, false},
	}
	for _, c := range cases {
		p := writeFile(t, dir, c.name, c.content)
		if got := looksLikeMCPConfig(p); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	if looksLikeMCPConfig(filepath.Join(dir, "missing.json")) {
		t.Error("missing file is not an MCP config")
	}
}

func TestRunToArgsAndErrors(t *testing.T) {
	var out, errw bytes.Buffer
	if code := RunTo(&out, &errw, nil); code != 2 {
		t.Errorf("no args: got %d, want 2", code)
	}
	if code := RunTo(&out, &errw, []string{"--nope"}); code != 2 {
		t.Errorf("bad flag: got %d, want 2", code)
	}
	if code := RunTo(&out, &errw, []string{"-h"}); code != 0 {
		t.Errorf("help: got %d, want 0", code)
	}

	old := NewScrubber
	NewScrubber = func() (Scrubber, error) { return nil, errors.New("boom") }
	t.Cleanup(func() { NewScrubber = old })
	errw.Reset()
	if code := RunTo(&out, &errw, []string{"x"}); code != 1 || !strings.Contains(errw.String(), "boom") {
		t.Errorf("scrubber error: got %d %q", code, errw.String())
	}
}

func TestRunToFiles(t *testing.T) {
	useFakeScrubber(t)
	dir := t.TempDir()
	hit := writeFile(t, dir, "hit.json", `{"k":"`+marker+`"}`)
	clean := writeFile(t, dir, "clean.json", `{"k":"v"}`)

	var out, errw bytes.Buffer
	if code := RunTo(&out, &errw, []string{hit}); code != 0 || !strings.Contains(out.String(), "1 files scanned · 1 secrets") {
		t.Errorf("hit: code=%d\n%s", code, out.String())
	}
	out.Reset()
	if code := RunTo(&out, &errw, []string{"--fail", hit}); code != 3 {
		t.Errorf("--fail with a secret: got %d, want 3", code)
	}
	if code := RunTo(&out, &errw, []string{"--fail", clean}); code != 0 {
		t.Errorf("--fail without a secret: got %d, want 0", code)
	}
	out.Reset()
	if code := RunTo(&out, &errw, []string{hit, hit}); code != 0 || !strings.Contains(out.String(), "1 files scanned") {
		t.Errorf("duplicates should be scanned once: code=%d\n%s", code, out.String())
	}
	out.Reset()
	if code := RunTo(&out, &errw, []string{filepath.Join(dir, "missing.json")}); code != 1 {
		t.Errorf("only a missing file: got %d, want 1", code)
	}
}

func TestRunToDirectoryAndDeep(t *testing.T) {
	useFakeScrubber(t)
	dir := t.TempDir()
	writeFile(t, dir, ".mcp.json", `{"mcpServers":{"x":{"env":{"A_TOKEN":"`+marker+`"}}}}`)
	writeFile(t, dir, ".env", "P_TOKEN="+marker)
	writeFile(t, dir, "a.toml", `k = "`+marker+`"`)
	writeFile(t, dir, "b.yaml", "k: "+marker)
	writeZip(t, filepath.Join(dir, "c.zip"), []zipEntry{{"x.txt", []byte(marker)}})
	writeFile(t, dir, "node_modules/.env", "P_TOKEN="+marker)
	writeFile(t, dir, "other.json", `{"k":"`+marker+`"}`)

	var out, errw bytes.Buffer
	code := RunTo(&out, &errw, []string{"--fail", "--deep", dir, "--toml", "--yaml", "--zip"})
	if code != 3 || !strings.Contains(out.String(), "5 files scanned · 5 secrets") {
		t.Errorf("deep: code=%d\n%s", code, out.String())
	}

	out.Reset()
	if code := RunTo(&out, &errw, []string{dir}); code != 0 || !strings.Contains(out.String(), "3 files scanned") {
		t.Errorf("directory argument: code=%d\n%s", code, out.String())
	}
}

func TestRunToHistory(t *testing.T) {
	useFakeScrubber(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	writeFile(t, home, ".bash_history", "export TOKEN="+marker+"\n")
	var out, errw bytes.Buffer
	if code := RunTo(&out, &errw, []string{"--history"}); code != 0 || !strings.Contains(out.String(), "1 secrets") {
		t.Errorf("history: code=%d\n%s", code, out.String())
	}
}
