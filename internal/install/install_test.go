package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEditJSONServers(t *testing.T) {
	entry := jsonEntry(serverCmd{command: "/bin/nw", args: []string{"-port", "9090"}}, false)
	raw := []byte(`{"theme":"dark","big":12345678901234567890,"mcpServers":{"other":{"command":"x","args":["a"],"env":{"K":"V"}}}}`)

	out, action, err := editJSONServers(raw, "mcpServers", "nullwire", entry)
	if err != nil || action != "added" {
		t.Fatalf("add: %v %q", err, action)
	}
	s := string(out)
	for _, keep := range []string{`"theme": "dark"`, `12345678901234567890`, `"K": "V"`, `"/bin/nw"`} {
		if !strings.Contains(s, keep) {
			t.Errorf("output lost %s:\n%s", keep, s)
		}
	}
	if !strings.HasSuffix(s, "\n") {
		t.Errorf("output should end with a newline")
	}

	if _, action, _ := editJSONServers(out, "mcpServers", "nullwire", entry); action != "unchanged" {
		t.Errorf("a second add should change nothing, got %q", action)
	}

	// An update keeps fields NullWire does not manage, such as env.
	withEnv := bytes.Replace(out, []byte(`"command": "/bin/nw"`), []byte(`"command": "/old/nw",
      "env": {"MODE": "x"}`), 1)
	out2, action, err := editJSONServers(withEnv, "mcpServers", "nullwire", entry)
	if err != nil || action != "updated" || !strings.Contains(string(out2), `"MODE": "x"`) || !strings.Contains(string(out2), `"/bin/nw"`) {
		t.Errorf("update: %v %q\n%s", err, action, out2)
	}

	out3, action, err := editJSONServers(out, "mcpServers", "nullwire", nil)
	if err != nil || action != "removed" || strings.Contains(string(out3), "nullwire") || !strings.Contains(string(out3), `"other"`) {
		t.Errorf("remove: %v %q\n%s", err, action, out3)
	}
	if _, action, _ := editJSONServers(out3, "mcpServers", "nullwire", nil); action != "absent" {
		t.Errorf("removing twice: %q", action)
	}

	if _, _, err := editJSONServers([]byte("{\n // comment\n \"mcpServers\": {}\n}"), "mcpServers", "nullwire", entry); err == nil {
		t.Errorf("a file with comments must be refused, not rewritten")
	}
	if _, _, err := editJSONServers([]byte(`{"mcpServers":[1]}`), "mcpServers", "nullwire", entry); err == nil {
		t.Errorf("a servers key that is not an object must be refused")
	}
	if out, action, err := editJSONServers(nil, "servers", "nullwire", jsonEntry(serverCmd{command: "c"}, true)); err != nil || action != "added" || !strings.Contains(string(out), `"type": "stdio"`) {
		t.Errorf("empty file: %v %q %s", err, action, out)
	}
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Errorf("result is not valid JSON: %v", err)
	}
}

func TestEditCodexTOML(t *testing.T) {
	cmd := serverCmd{command: `C:\tools\nw.exe`, args: []string{"-port", "9"}}
	raw := "model = \"gpt\"\n\n[mcp_servers.other]\ncommand = \"x\"\n"

	out, action, err := editCodexTOML(raw, "nullwire", cmd, false)
	if err != nil || action != "added" {
		t.Fatalf("add: %v %q", err, action)
	}
	for _, want := range []string{"model = \"gpt\"", "[mcp_servers.other]", "[mcp_servers.nullwire]", `command = "C:\\tools\\nw.exe"`, `args = ["-port", "9"]`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if _, action, _ := editCodexTOML(out, "nullwire", cmd, false); action != "unchanged" {
		t.Errorf("second add: %q", action)
	}

	// Update: keep other keys and sub-tables, replace command and a multi-line args array.
	old := "[mcp_servers.nullwire]\ncommand = \"/old\"\nargs = [\n  \"-x\",\n  \"-y\",\n]\nstartup_timeout_sec = 20\n\n[mcp_servers.nullwire.env]\nK = \"V\"\n"
	out2, action, err := editCodexTOML(old, "nullwire", serverCmd{command: "/new", args: []string{"-p"}}, false)
	if err != nil || action != "updated" {
		t.Fatalf("update: %v %q\n%s", err, action, out2)
	}
	for _, want := range []string{`command = "/new"`, `args = ["-p"]`, "startup_timeout_sec = 20", "[mcp_servers.nullwire.env]", `K = "V"`} {
		if !strings.Contains(out2, want) {
			t.Errorf("update lost %q:\n%s", want, out2)
		}
	}
	for _, gone := range []string{"/old", `"-x"`, `"-y"`} {
		if strings.Contains(out2, gone) {
			t.Errorf("update kept %q:\n%s", gone, out2)
		}
	}

	out3, action, err := editCodexTOML(out, "nullwire", cmd, true)
	if err != nil || action != "removed" || strings.Contains(out3, "nullwire") || !strings.Contains(out3, "[mcp_servers.other]") {
		t.Errorf("remove: %v %q\n%s", err, action, out3)
	}
	if _, _, err := editCodexTOML("", "bad name", cmd, false); err == nil {
		t.Errorf("an unusable name must be refused")
	}
}

// installEnv points every client path at a temporary home and hides the
// claude command, so a test can never touch real settings.
func installEnv(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("APPDATA", filepath.Join(home, "AppData"))
	t.Setenv("CODEX_HOME", "")
	t.Setenv("NULLWIRE_VIA_NPM", "")
	t.Setenv("PATH", t.TempDir())
	return home
}

func fakeBinary(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "nullwire-mcp")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestInstallEndToEnd(t *testing.T) {
	home := installEnv(t)
	bin := fakeBinary(t)
	cursor := filepath.Join(home, ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(cursor), 0o755); err != nil {
		t.Fatal(err)
	}
	original := `{"mcpServers":{"keep":{"command":"k"}}}`
	if err := os.WriteFile(cursor, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	run := func(args ...string) (string, int) {
		var out, errw bytes.Buffer
		code := runInstallTo(&out, &errw, args)
		return out.String() + errw.String(), code
	}

	// Dry run changes nothing.
	if out, code := run("--client", "cursor", "--binary", bin, "--dry-run", "--", "-port", "9090"); code != 0 || !strings.Contains(out, "would be added") {
		t.Fatalf("dry run: %d\n%s", code, out)
	}
	if b, _ := os.ReadFile(cursor); string(b) != original {
		t.Fatalf("a dry run modified the file:\n%s", b)
	}

	// Real install: entry written, original backed up, other servers kept.
	out, code := run("--client", "all", "--binary", bin, "--", "-port", "9090")
	if code != 0 || !strings.Contains(out, "Cursor") || !strings.Contains(out, "backup:") || !strings.Contains(out, "not found on this machine") {
		t.Fatalf("install: %d\n%s", code, out)
	}
	b, _ := os.ReadFile(cursor)
	for _, want := range []string{`"nullwire"`, `"keep"`, `"-port"`, `"9090"`, bin} {
		if !strings.Contains(string(b), strings.ReplaceAll(want, `\`, `\\`)) {
			t.Errorf("config is missing %s:\n%s", want, b)
		}
	}
	if bak, _ := os.ReadFile(cursor + ".nullwire-bak"); string(bak) != original {
		t.Errorf("the backup must hold the original file, got %q", bak)
	}
	if _, err := os.Stat(filepath.Join(home, ".codeium")); err == nil {
		t.Errorf("a client that is not installed must not get a config file")
	}

	if out, _ := run("--client", "cursor", "--binary", bin, "--", "-port", "9090"); !strings.Contains(out, "unchanged") {
		t.Errorf("second install should be unchanged:\n%s", out)
	}

	// Uninstall removes only our entry.
	if out, code := run("--client", "cursor", "--uninstall"); code != 0 || !strings.Contains(out, "removed") {
		t.Fatalf("uninstall: %d\n%s", code, out)
	}
	after, _ := os.ReadFile(cursor)
	if strings.Contains(string(after), "nullwire") || !strings.Contains(string(after), `"keep"`) {
		t.Errorf("uninstall result:\n%s", after)
	}

	// An explicit client with no config yet gets one created.
	if out, code := run("--client", "windsurf", "--binary", bin); code != 0 || !strings.Contains(out, "added") {
		t.Errorf("explicit client: %d\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(home, ".codeium", "windsurf", "mcp_config.json")); err != nil {
		t.Errorf("windsurf config was not created: %v", err)
	}
}

func TestInstallArgumentsAndNpx(t *testing.T) {
	installEnv(t)
	run := func(args ...string) (string, int) {
		var out, errw bytes.Buffer
		code := runInstallTo(&out, &errw, args)
		return out.String() + errw.String(), code
	}
	if out, code := run("--client", "cursor", "-port", "9090"); code != 2 {
		t.Errorf("a server flag without -- must be a usage error, got %d\n%s", code, out)
	}
	if out, code := run("--client", "cursor", "stray"); code != 2 || !strings.Contains(out, "after --") {
		t.Errorf("a stray argument must be refused: %d\n%s", code, out)
	}
	if _, code := run("--client", "nosuchclient"); code != 2 {
		t.Errorf("an unknown client must be refused, got %d", code)
	}
	if _, code := run("--name", "bad name!"); code != 2 {
		t.Errorf("a bad name must be refused, got %d", code)
	}
	if out, code := run("--client", "cursor", "--npx", "--dry-run"); code != 0 || !strings.Contains(out, "nullwire-mcp") || !strings.Contains(out, "npx") {
		t.Errorf("npx dry run: %d\n%s", code, out)
	}
	t.Setenv("NULLWIRE_VIA_NPM", "1")
	if out, _ := run("--client", "cursor", "--dry-run"); !strings.Contains(out, "npx") {
		t.Errorf("under the npm wrapper the npx form is used:\n%s", out)
	}
	if out, code := run("--list"); code != 0 || !strings.Contains(out, "claude-desktop") || !strings.Contains(out, "codex") {
		t.Errorf("list: %d\n%s", code, out)
	}
	if out, code := run("--print", "--binary", fakeBinary(t)); code != 0 || !strings.Contains(out, "mcpServers") || !strings.Contains(out, "[mcp_servers.nullwire]") {
		t.Errorf("print: %d\n%s", code, out)
	}
}

func TestInstallCodexAndVSCodeFormats(t *testing.T) {
	home := installEnv(t)
	bin := fakeBinary(t)
	var out, errw bytes.Buffer
	if code := runInstallTo(&out, &errw, []string{"--client", "codex,vscode", "--binary", bin}); code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out.String(), errw.String())
	}
	toml, _ := os.ReadFile(filepath.Join(home, ".codex", "config.toml"))
	if !strings.Contains(string(toml), "[mcp_servers.nullwire]") {
		t.Errorf("codex config:\n%s", toml)
	}
	vs, err := os.ReadFile(filepath.Join(home, ".config", "Code", "User", "mcp.json"))
	if err != nil {
		// macOS and Windows keep VS Code settings elsewhere; find the file the program chose.
		p, _ := underConfig("Code", "User", "mcp.json")()
		vs, err = os.ReadFile(p)
	}
	if err != nil || !strings.Contains(string(vs), `"servers"`) || !strings.Contains(string(vs), `"type": "stdio"`) {
		t.Errorf("vscode config: %v\n%s", err, vs)
	}
}

// fakeClaude puts a `claude` shell script on PATH. The script runs body, with
// the arguments in $1, $2, ... ($2 is "remove" or "add").
func fakeClaude(t *testing.T, body string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script stand-in for the claude command")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "claude"), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

func TestClaudeCodeArgs(t *testing.T) {
	o := installOptions{name: "nw", cmd: serverCmd{command: "/bin/nw", args: []string{"-port", "9"}}}
	got := claudeCodeArgs(o)
	if len(got) != 2 || strings.Join(got[0], " ") != "mcp remove nw --scope user" ||
		strings.Join(got[1], " ") != "mcp add --scope user nw -- /bin/nw -port 9" {
		t.Errorf("install args: %q", got)
	}
	o.uninstall = true
	if got := claudeCodeArgs(o); len(got) != 1 || strings.Join(got[0], " ") != "mcp remove nw --scope user" {
		t.Errorf("uninstall args: %q", got)
	}
}

func TestApplyClaudeCode(t *testing.T) {
	o := installOptions{name: "nw", cmd: serverCmd{command: "/bin/nw", args: []string{"-p"}}}

	t.Run("claude is not on PATH", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		_, err := applyClaudeCode(o)
		if err == nil || !strings.Contains(err.Error(), "claude mcp add --scope user nw -- /bin/nw -p") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("dry run", func(t *testing.T) {
		fakeClaude(t, "exit 1")
		d := o
		d.dryRun = true
		status, err := applyClaudeCode(d)
		if err != nil || status != "would run: claude mcp add --scope user nw -- /bin/nw -p" {
			t.Errorf("got (%q, %v)", status, err)
		}
	})
	t.Run("install and uninstall succeed", func(t *testing.T) {
		fakeClaude(t, "exit 0")
		if status, err := applyClaudeCode(o); err != nil || status != "added" {
			t.Errorf("install: (%q, %v)", status, err)
		}
		u := o
		u.uninstall = true
		if status, err := applyClaudeCode(u); err != nil || status != "removed" {
			t.Errorf("uninstall: (%q, %v)", status, err)
		}
	})
	t.Run("a failing remove before add is ignored", func(t *testing.T) {
		fakeClaude(t, `[ "$2" = "remove" ] && exit 1; exit 0`)
		if status, err := applyClaudeCode(o); err != nil || status != "added" {
			t.Errorf("got (%q, %v)", status, err)
		}
	})
	t.Run("a failing add is reported with its output", func(t *testing.T) {
		fakeClaude(t, `if [ "$2" = "add" ]; then echo boom; exit 1; fi; exit 0`)
		_, err := applyClaudeCode(o)
		if err == nil || !strings.Contains(err.Error(), "failed: boom") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("uninstall of a server that is not there", func(t *testing.T) {
		fakeClaude(t, "exit 1")
		u := o
		u.uninstall = true
		if status, err := applyClaudeCode(u); err != nil || status != "absent" {
			t.Errorf("got (%q, %v)", status, err)
		}
	})
}

func TestInstallClaudeCodeThroughRun(t *testing.T) {
	installEnv(t)
	fakeClaude(t, "exit 0")
	var out, errw bytes.Buffer
	if code := runInstallTo(&out, &errw, []string{"--client", "claude-code", "--binary", fakeBinary(t)}); code != 0 ||
		!strings.Contains(out.String(), "claude CLI") || !strings.Contains(out.String(), "added") {
		t.Errorf("code=%d\n%s%s", code, out.String(), errw.String())
	}
	out.Reset()
	if code := runInstallTo(&out, &errw, []string{"--client", "claude-code", "--uninstall"}); code != 0 || !strings.Contains(out.String(), "Removing") {
		t.Errorf("uninstall: code=%d\n%s", code, out.String())
	}
}

func TestResolveServerCmd(t *testing.T) {
	cmd, err := resolveServerCmd("", true, []string{"-port", "1"})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if cmd.command != "cmd" || strings.Join(cmd.args, " ") != "/c npx -y nullwire-mcp -port 1" {
			t.Errorf("npx on windows: %+v", cmd)
		}
	} else if cmd.command != "npx" || strings.Join(cmd.args, " ") != "-y nullwire-mcp -port 1" {
		t.Errorf("npx: %+v", cmd)
	}

	bin := fakeBinary(t)
	resolved, _ := filepath.EvalSymlinks(bin)
	if cmd, err := resolveServerCmd(bin, false, []string{"-x"}); err != nil || cmd.command != resolved || len(cmd.args) != 1 {
		t.Errorf("binary: (%+v, %v)", cmd, err)
	}
	if cmd, err := resolveServerCmd("", false, nil); err != nil || !filepath.IsAbs(cmd.command) {
		t.Errorf("this program: (%+v, %v)", cmd, err)
	}
	if _, err := resolveServerCmd(filepath.Join(t.TempDir(), "missing"), false, nil); err == nil || !strings.Contains(err.Error(), "is not a file") {
		t.Errorf("missing binary: %v", err)
	}
	if _, err := resolveServerCmd(t.TempDir(), false, nil); err == nil || !strings.Contains(err.Error(), "is not a file") {
		t.Errorf("a directory is not a binary: %v", err)
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(bin, link); err == nil {
			if cmd, err := resolveServerCmd(link, false, nil); err != nil || cmd.command != resolved {
				t.Errorf("a symlink should be resolved: (%+v, %v)", cmd, err)
			}
		}
	}
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()

	// A new file in a folder that does not exist yet: no backup.
	p := filepath.Join(dir, "a", "b", "c.json")
	if bak, err := writeFileAtomic(p, []byte("one")); err != nil || bak != "" {
		t.Fatalf("new file: (%q, %v)", bak, err)
	}
	if b, _ := os.ReadFile(p); string(b) != "one" {
		t.Errorf("content = %q", b)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
			t.Errorf("a new file should be private, mode %v", st.Mode().Perm())
		}
	}

	// The first overwrite keeps a copy of the original; later ones leave it alone.
	bak, err := writeFileAtomic(p, []byte("two"))
	if err != nil || !strings.HasSuffix(bak, ".nullwire-bak") {
		t.Fatalf("overwrite: (%q, %v)", bak, err)
	}
	if b, _ := os.ReadFile(bak); string(b) != "one" {
		t.Errorf("backup = %q, want the original", b)
	}
	if bak, err := writeFileAtomic(p, []byte("three")); err != nil || bak != "" {
		t.Fatalf("second overwrite: (%q, %v)", bak, err)
	}
	if b, _ := os.ReadFile(p + ".nullwire-bak"); string(b) != "one" {
		t.Errorf("the backup must keep the first original, got %q", b)
	}
	if b, _ := os.ReadFile(p); string(b) != "three" {
		t.Errorf("content = %q", b)
	}

	if runtime.GOOS != "windows" {
		// The mode of an existing file is kept.
		q := filepath.Join(dir, "mode.json")
		if err := os.WriteFile(q, []byte("x"), 0o640); err != nil {
			t.Fatal(err)
		}
		if _, err := writeFileAtomic(q, []byte("y")); err != nil {
			t.Fatal(err)
		}
		if st, _ := os.Stat(q); st.Mode().Perm() != 0o640 {
			t.Errorf("mode = %v, want 0640", st.Mode().Perm())
		}

		// A symlinked dotfile stays a symlink; the file it points to is updated.
		target := filepath.Join(dir, "real.json")
		link := filepath.Join(dir, "link.json")
		if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err == nil {
			if _, err := writeFileAtomic(link, []byte("new")); err != nil {
				t.Fatal(err)
			}
			if st, err := os.Lstat(link); err != nil || st.Mode()&os.ModeSymlink == 0 {
				t.Errorf("the symlink was replaced: %v %v", st, err)
			}
			if b, _ := os.ReadFile(target); string(b) != "new" {
				t.Errorf("target = %q", b)
			}
		}
	}
}

func TestWriteFileAtomicErrors(t *testing.T) {
	dir := t.TempDir()

	// The parent "folder" is a file.
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := writeFileAtomic(filepath.Join(file, "x.json"), []byte("y")); err == nil {
		t.Error("a path below a regular file must fail")
	}

	// The target is a directory: the rename fails and no temporary file is left.
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := writeFileAtomic(target, []byte("y")); err == nil {
		t.Error("replacing a directory must fail")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".nullwire-*.tmp")); len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}

	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		ro := filepath.Join(dir, "ro")
		if err := os.Mkdir(ro, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })
		if _, err := writeFileAtomic(filepath.Join(ro, "x.json"), []byte("y")); err == nil {
			t.Error("a read-only folder must fail")
		}
	}
}

func TestReadIfExists(t *testing.T) {
	dir := t.TempDir()
	if b, err := readIfExists(filepath.Join(dir, "missing")); b != nil || err != nil {
		t.Errorf("missing: (%q, %v)", b, err)
	}
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := readIfExists(p); string(b) != "data" || err != nil {
		t.Errorf("existing: (%q, %v)", b, err)
	}
	if _, err := readIfExists(dir); err == nil {
		t.Error("a directory cannot be read as a file")
	}
}

func TestApplyFile(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "mcp.json")
	spec := clientSpec{id: "x", label: "X", kind: "json", key: "mcpServers", path: func() (string, error) { return cfg, nil }}
	o := installOptions{name: "nw", cmd: serverCmd{command: "/bin/nw"}}

	if status, _, err := applyFile(spec, o); err != nil || status != "added" {
		t.Fatalf("add to a new file: (%q, %v)", status, err)
	}
	if status, _, err := applyFile(spec, o); err != nil || status != "unchanged" {
		t.Errorf("second add: (%q, %v)", status, err)
	}
	o.cmd.command = "/bin/other"
	if status, _, err := applyFile(spec, o); err != nil || !strings.HasPrefix(status, "updated (backup: ") {
		t.Errorf("update with a backup: (%q, %v)", status, err)
	}
	d := o
	d.uninstall, d.dryRun = true, true
	if status, _, err := applyFile(spec, d); err != nil || status != "would be removed" {
		t.Errorf("dry-run uninstall: (%q, %v)", status, err)
	}
	if b, _ := os.ReadFile(cfg); !strings.Contains(string(b), "nw") {
		t.Errorf("a dry run must not change the file:\n%s", b)
	}
	u := o
	u.uninstall = true
	if status, _, err := applyFile(spec, u); err != nil || status != "removed" {
		t.Errorf("uninstall: (%q, %v)", status, err)
	}
	if status, _, err := applyFile(spec, u); err != nil || status != "absent" {
		t.Errorf("uninstall twice: (%q, %v)", status, err)
	}

	// A file that is not plain JSON is refused and left as it is.
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{ // comment\n}"), 0o600); err != nil {
		t.Fatal(err)
	}
	badSpec := spec
	badSpec.path = func() (string, error) { return bad, nil }
	if _, p, err := applyFile(badSpec, o); err == nil || !strings.Contains(err.Error(), "not plain JSON") || p != bad {
		t.Errorf("comments: (%q, %v)", p, err)
	}
	if b, _ := os.ReadFile(bad); string(b) != "{ // comment\n}" {
		t.Errorf("the refused file was changed: %q", b)
	}

	// The path cannot be worked out, or cannot be read.
	errSpec := spec
	errSpec.path = func() (string, error) { return "", errors.New("no home") }
	if _, _, err := applyFile(errSpec, o); err == nil || !strings.Contains(err.Error(), "no home") {
		t.Errorf("path error: %v", err)
	}
	dirSpec := spec
	dirSpec.path = func() (string, error) { return dir, nil }
	if _, _, err := applyFile(dirSpec, o); err == nil {
		t.Error("a directory instead of a config file must fail")
	}

	// TOML clients go through the TOML editor.
	toml := filepath.Join(dir, "config.toml")
	tspec := clientSpec{id: "codex", label: "Codex", kind: "toml", path: func() (string, error) { return toml, nil }}
	if status, _, err := applyFile(tspec, o); err != nil || status != "added" {
		t.Errorf("toml add: (%q, %v)", status, err)
	}
	if b, _ := os.ReadFile(toml); !strings.Contains(string(b), "[mcp_servers.nw]") {
		t.Errorf("toml:\n%s", b)
	}
	if status, _, err := applyFile(tspec, u); err != nil || !strings.HasPrefix(status, "removed") {
		t.Errorf("toml remove: (%q, %v)", status, err)
	}
}

func TestDetected(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(file, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	at := func(p string) clientSpec {
		return clientSpec{kind: "json", path: func() (string, error) { return p, nil }}
	}
	if !at(file).detected() {
		t.Error("an existing config file means the client is installed")
	}
	if !at(filepath.Join(dir, "missing.json")).detected() {
		t.Error("an existing config folder means the client is installed")
	}
	if at(filepath.Join(dir, "no", "such", "cfg.json")).detected() {
		t.Error("nothing there means the client is not installed")
	}
	if (clientSpec{kind: "json", path: func() (string, error) { return "", errors.New("x") }}).detected() {
		t.Error("a path error means not detected")
	}
	cli := clientSpec{kind: "cli"}
	t.Setenv("PATH", t.TempDir())
	if cli.detected() {
		t.Error("no claude on PATH")
	}
	fakeClaude(t, "exit 0")
	if !cli.detected() {
		t.Error("claude on PATH")
	}
}

func TestInstallRunErrorsAndEdges(t *testing.T) {
	home := installEnv(t)
	run := func(args ...string) (string, int) {
		var out, errw bytes.Buffer
		code := runInstallTo(&out, &errw, args)
		return out.String() + errw.String(), code
	}
	if _, code := run("-h"); code != 0 {
		t.Errorf("help: got %d, want 0", code)
	}
	if _, code := run("--nope"); code != 2 {
		t.Errorf("unknown flag: got %d, want 2", code)
	}
	if out, code := run("--client", "cursor", "--binary", filepath.Join(home, "missing")); code != 1 || !strings.Contains(out, "is not a file") {
		t.Errorf("missing binary: %d\n%s", code, out)
	}
	// Nothing detected on this machine: say so, and succeed.
	if out, code := run("--binary", fakeBinary(t)); code != 0 || !strings.Contains(out, "No supported MCP clients were found") {
		t.Errorf("no clients: %d\n%s", code, out)
	}
	// An empty and a repeated client name are fine.
	if out, code := run("--client", " ,Cursor,cursor", "--binary", fakeBinary(t), "--dry-run"); code != 0 || !strings.Contains(out, "[dry run]") {
		t.Errorf("client list: %d\n%s", code, out)
	}

	// A config that cannot be edited is a failure for that client, and the exit code says so.
	cursor := filepath.Join(home, ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(cursor), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cursor, []byte("{ // comment\n}"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := run("--client", "cursor", "--binary", fakeBinary(t))
	if code != 1 || !strings.Contains(out, "✗") || strings.Contains(out, "Restart the client") {
		t.Errorf("a refused config: %d\n%s", code, out)
	}
	if b, _ := os.ReadFile(cursor); string(b) != "{ // comment\n}" {
		t.Errorf("the refused config was changed: %q", b)
	}

	// --list shows found and not found.
	if out, code := run("--list"); code != 0 || !strings.Contains(out, "found") || !strings.Contains(out, "cursor") {
		t.Errorf("list: %d\n%s", code, out)
	}
	// --print with the npx form.
	if out, code := run("--print", "--npx", "--name", "mine"); code != 0 || !strings.Contains(out, `"mine"`) || !strings.Contains(out, "[mcp_servers.mine]") {
		t.Errorf("print: %d\n%s", code, out)
	}
}

func TestTOMLHelpers(t *testing.T) {
	if got := tomlQuote("a\"b\\c\n\t\x01\x7f é"); got != `"a\"b\\c\n\t\u0001\u007F é"` {
		t.Errorf("tomlQuote = %s", got)
	}
	if got := tomlArray(nil); got != "[]" {
		t.Errorf("tomlArray(nil) = %s", got)
	}
	if got := tomlArray([]string{"a", `b"c`}); got != `["a", "b\"c"]` {
		t.Errorf("tomlArray = %s", got)
	}
	for line, want := range map[string]bool{
		`command = "x"`: true, "  args=[]": true, "commandx = 1": false, "#command = 1": false, "command": false,
	} {
		key := "command"
		if strings.Contains(line, "args") {
			key = "args"
		}
		if got := tomlKeyIs(line, key); got != want {
			t.Errorf("tomlKeyIs(%q, %q) = %v, want %v", line, key, got, want)
		}
	}
	if !isTOMLTableHeader("[a]") || !isTOMLTableHeader("  [a.b]") || isTOMLTableHeader("a = [1]") {
		t.Error("isTOMLTableHeader is wrong")
	}
}

func TestEditCodexTOMLEdges(t *testing.T) {
	cmd := serverCmd{command: "/b"}

	out, action, err := editCodexTOML("", "nw", cmd, false)
	if err != nil || action != "added" || out != "[mcp_servers.nw]\ncommand = \"/b\"\nargs = []\n" {
		t.Errorf("empty file: (%q, %q, %v)", out, action, err)
	}
	out, action, _ = editCodexTOML(`model = "x"`, "nw", cmd, false)
	if action != "added" || out != "model = \"x\"\n\n[mcp_servers.nw]\ncommand = \"/b\"\nargs = []\n" {
		t.Errorf("file without a final newline: (%q, %q)", out, action)
	}
	out, action, _ = editCodexTOML("[mcp_servers.\"nw\"]\ncommand = \"/old\"\n", "nw", cmd, false)
	if action != "updated" || !strings.Contains(out, "[mcp_servers.nw]") || strings.Contains(out, `"nw"]`) || strings.Contains(out, "/old") {
		t.Errorf("quoted header: (%q, %q)", out, action)
	}

	raw := "model = \"gpt\"\n\n[mcp_servers.nw]\ncommand = \"x\"\nargs = []\n\n[other]\na = 1\n"
	out, action, _ = editCodexTOML(raw, "nw", cmd, true)
	if action != "removed" || out != "model = \"gpt\"\n[other]\na = 1\n" {
		t.Errorf("remove in the middle: (%q, %q)", out, action)
	}
	if out, action, _ := editCodexTOML("[mcp_servers.nw]\ncommand = \"x\"", "nw", cmd, true); action != "removed" || out != "" {
		t.Errorf("remove the only table: (%q, %q)", out, action)
	}
	if out, action, _ := editCodexTOML("[mcp_servers.nw]\ncommand = \"x\"\n", "nw", cmd, true); action != "removed" || out != "\n" {
		t.Errorf("remove the only table, newline kept: (%q, %q)", out, action)
	}
	if out, action, _ := editCodexTOML("a = 1\n", "nw", cmd, true); action != "absent" || out != "a = 1\n" {
		t.Errorf("remove what is not there: (%q, %q)", out, action)
	}
}

func TestEditJSONServersEdges(t *testing.T) {
	entry := jsonEntry(serverCmd{command: "c", args: []string{"a"}}, false)
	if _, _, err := editJSONServers([]byte(`{"mcpServers":{}} {}`), "mcpServers", "nw", entry); err == nil || !strings.Contains(err.Error(), "after the JSON document") {
		t.Errorf("trailing data: %v", err)
	}
	if out, action, err := editJSONServers([]byte(`{"mcpServers":null}`), "mcpServers", "nw", entry); err != nil || action != "added" || !strings.Contains(string(out), `"nw"`) {
		t.Errorf("null servers: (%s, %q, %v)", out, action, err)
	}
	if _, action, _ := editJSONServers([]byte(`{}`), "mcpServers", "nw", nil); action != "absent" {
		t.Errorf("remove from an empty document: %q", action)
	}
	// An existing entry that is not an object is replaced.
	if out, action, err := editJSONServers([]byte(`{"mcpServers":{"nw":"junk"}}`), "mcpServers", "nw", entry); err != nil || action != "updated" || strings.Contains(string(out), "junk") {
		t.Errorf("non-object entry: (%s, %q, %v)", out, action, err)
	}
	typed := jsonEntry(serverCmd{command: "c"}, true)
	if typed["type"] != "stdio" {
		t.Errorf("typed entry: %v", typed)
	}
}

func rcovNeedsChmod(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a non-root POSIX user (permission bits)")
	}
}

// rcovLock sets mode on path and restores 0o700 at cleanup so TempDir can be removed.
func rcovLock(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o700) })
}

func TestRcovWriteFileAtomicReadOnlyDir(t *testing.T) {
	rcovNeedsChmod(t)
	dir := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(cfg, []byte(`{"keep":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rcovLock(t, dir, 0o555)

	// Existing file: the backup copy and the temporary file cannot be created.
	if bak, err := writeFileAtomic(cfg, []byte("new")); err == nil || bak != "" {
		t.Fatalf("existing file in a read-only folder: (%q, %v)", bak, err)
	}
	if b, _ := os.ReadFile(cfg); string(b) != `{"keep":true}` {
		t.Errorf("the config was changed: %q", b)
	}
	if _, err := os.Stat(cfg + ".nullwire-bak"); !os.IsNotExist(err) {
		t.Errorf("no backup can exist in a read-only folder: %v", err)
	}
	// A folder that has to be created below it: MkdirAll fails.
	if _, err := writeFileAtomic(filepath.Join(dir, "sub", "x.json"), []byte("y")); err == nil {
		t.Error("MkdirAll below a read-only folder must fail")
	}
}

func TestRcovApplyFileWriteAndReadFailures(t *testing.T) {
	rcovNeedsChmod(t)
	o := installOptions{name: "nw", cmd: serverCmd{command: "/bin/nw"}}
	mk := func(cfg string) clientSpec {
		return clientSpec{id: "x", label: "X", kind: "json", key: "mcpServers", path: func() (string, error) { return cfg, nil }}
	}

	// The write fails: the config sits in a read-only folder.
	dir := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(cfg, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rcovLock(t, dir, 0o555)
	if status, p, err := applyFile(mk(cfg), o); err == nil || status != "" || p != cfg {
		t.Errorf("write failure: (%q, %q, %v)", status, p, err)
	}

	// The read fails: the config itself is not readable.
	unreadable := filepath.Join(t.TempDir(), "mcp.json")
	if err := os.WriteFile(unreadable, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rcovLock(t, unreadable, 0)
	if status, p, err := applyFile(mk(unreadable), o); err == nil || status != "" || p != unreadable {
		t.Errorf("read failure: (%q, %q, %v)", status, p, err)
	}
}

func TestRcovApplyFileCorruptConfigs(t *testing.T) {
	dir := t.TempDir()
	o := installOptions{name: "nw", cmd: serverCmd{command: "/bin/nw"}}
	for i, c := range []struct{ name, body, want string }{
		{"servers is an array", `{"mcpServers":[1]}`, "is not an object"},
		{"top level array", `[1,2]`, "not plain JSON"},
		{"truncated", `{"mcpServers":{"nw":`, "not plain JSON"},
		{"junk", "}{", "not plain JSON"},
	} {
		cfg := filepath.Join(dir, "c"+string(rune('a'+i))+".json")
		if err := os.WriteFile(cfg, []byte(c.body), 0o600); err != nil {
			t.Fatal(err)
		}
		spec := clientSpec{id: "x", label: "X", kind: "json", key: "mcpServers", path: func() (string, error) { return cfg, nil }}
		status, p, err := applyFile(spec, o)
		if err == nil || !strings.Contains(err.Error(), c.want) || status != "" || p != cfg {
			t.Errorf("%s: (%q, %q, %v), want an error containing %q", c.name, status, p, err, c.want)
		}
		if b, _ := os.ReadFile(cfg); string(b) != c.body {
			t.Errorf("%s: the refused file was changed: %q", c.name, b)
		}
	}

	// A server name that cannot be a TOML key is refused for the TOML client.
	toml := filepath.Join(dir, "config.toml")
	tspec := clientSpec{id: "codex", label: "Codex", kind: "toml", path: func() (string, error) { return toml, nil }}
	bad := o
	bad.name = "bad name"
	if _, _, err := applyFile(tspec, bad); err == nil || !strings.Contains(err.Error(), "not usable in TOML") {
		t.Errorf("bad TOML name: %v", err)
	}
	if _, err := os.Stat(toml); !os.IsNotExist(err) {
		t.Errorf("nothing may be written for a refused name: %v", err)
	}
}

func TestRcovEditCodexTOMLMultilineAndUnterminatedArgs(t *testing.T) {
	cmd := serverCmd{command: "/b"}
	raw := "[mcp_servers.nw]\ncommand = \"/old\"\nargs = [\n  \"a\",\n  \"b\"\n]\nenv = \"keep\"\n\n[other]\nx = 1\n"
	out, action, err := editCodexTOML(raw, "nw", cmd, false)
	if err != nil || action != "updated" {
		t.Fatalf("multi-line args: (%q, %q, %v)", out, action, err)
	}
	for _, gone := range []string{`"a"`, `"b"`, "/old"} {
		if strings.Contains(out, gone) {
			t.Errorf("%s is still in:\n%s", gone, out)
		}
	}
	for _, kept := range []string{"args = []", `env = "keep"`, "[other]"} {
		if !strings.Contains(out, kept) {
			t.Errorf("%s is missing from:\n%s", kept, out)
		}
	}
	// An args array that never closes must not run past the table or panic.
	if _, action, err := editCodexTOML("[mcp_servers.nw]\nargs = [\n\"a\"\n", "nw", cmd, false); err != nil || action != "updated" {
		t.Errorf("unterminated args: (%q, %v)", action, err)
	}
	if _, _, err := editCodexTOML("", "bad name", cmd, false); err == nil || !strings.Contains(err.Error(), "not usable in TOML") {
		t.Errorf("bad name: %v", err)
	}
}

func TestRcovInstallRunUsageErrors(t *testing.T) {
	installEnv(t)
	bin := fakeBinary(t)
	for _, c := range []struct {
		name string
		args []string
	}{
		{"positional argument", []string{"stray"}},
		{"bad name", []string{"--name", "bad name"}},
		{"unknown client", []string{"--client", "nope", "--binary", bin}},
	} {
		var out, errw bytes.Buffer
		if code := runInstallTo(&out, &errw, c.args); code != 2 {
			t.Errorf("%s: exit %d, want 2\n%s%s", c.name, code, out.String(), errw.String())
		}
	}
}
