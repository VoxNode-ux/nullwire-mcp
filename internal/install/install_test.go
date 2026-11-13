package install

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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
