package install

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
)

// The install command registers NullWire in MCP clients' config files (and
// removes it again). It only runs when asked, backs up a file before the first
// change, writes through a temporary file, and refuses to touch a file it
// cannot parse as plain JSON.

// clientSpec describes one MCP client.
type clientSpec struct {
	id    string
	label string
	kind  string // "json", "toml" or "cli"
	key   string // json: the top-level object that holds the servers
	typed bool   // json: also write "type": "stdio"
	path  func() (string, error)
}

// serverCmd is the command a client should run to start NullWire.
type serverCmd struct {
	command string
	args    []string
}

type installOptions struct {
	name      string
	cmd       serverCmd
	uninstall bool
	dryRun    bool
}

var reServerName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func underHome(parts ...string) func() (string, error) {
	return func() (string, error) {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(append([]string{h}, parts...)...), nil
	}
}

func underConfig(parts ...string) func() (string, error) {
	return func() (string, error) {
		d, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(append([]string{d}, parts...)...), nil
	}
}

func codexConfigPath() (string, error) {
	if h := os.Getenv("CODEX_HOME"); h != "" {
		return filepath.Join(h, "config.toml"), nil
	}
	return underHome(".codex", "config.toml")()
}

func installClients() []clientSpec {
	return []clientSpec{
		{id: "claude-desktop", label: "Claude Desktop", kind: "json", key: "mcpServers", path: underConfig("Claude", "claude_desktop_config.json")},
		{id: "claude-code", label: "Claude Code", kind: "cli"},
		{id: "cursor", label: "Cursor", kind: "json", key: "mcpServers", path: underHome(".cursor", "mcp.json")},
		{id: "windsurf", label: "Windsurf", kind: "json", key: "mcpServers", path: underHome(".codeium", "windsurf", "mcp_config.json")},
		{id: "vscode", label: "VS Code (Copilot)", kind: "json", key: "servers", typed: true, path: underConfig("Code", "User", "mcp.json")},
		{id: "cline", label: "Cline", kind: "json", key: "mcpServers", path: underConfig("Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")},
		{id: "roo", label: "Roo Code", kind: "json", key: "mcpServers", path: underConfig("Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json")},
		{id: "gemini", label: "Gemini CLI", kind: "json", key: "mcpServers", path: underHome(".gemini", "settings.json")},
		{id: "codex", label: "Codex CLI", kind: "toml", path: codexConfigPath},
	}
}

// detected reports whether a client looks installed: its config file or the
// folder that holds it exists (for the Claude Code CLI, whether `claude` is on PATH).
func (c clientSpec) detected() bool {
	if c.kind == "cli" {
		_, err := exec.LookPath("claude")
		return err == nil
	}
	p, err := c.path()
	if err != nil {
		return false
	}
	if _, err := os.Stat(p); err == nil {
		return true
	}
	if st, err := os.Stat(filepath.Dir(p)); err == nil && st.IsDir() {
		return true
	}
	return false
}

// jsonEntry builds the server entry written into a JSON config.
func jsonEntry(c serverCmd, typed bool) map[string]any {
	args := make([]any, len(c.args))
	for i, a := range c.args {
		args[i] = a
	}
	e := map[string]any{"command": c.command, "args": args}
	if typed {
		e["type"] = "stdio"
	}
	return e
}

// editJSONServers adds, updates or removes one server in a JSON config. Other
// settings, numbers and unmanaged fields of the entry (such as env) are kept.
// entry == nil removes the server. action is one of added, updated, unchanged,
// removed or absent; when it is unchanged or absent the input is returned as is.
func editJSONServers(raw []byte, key, name string, entry map[string]any) (out []byte, action string, err error) {
	doc := map[string]any{}
	if len(bytes.TrimSpace(raw)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&doc); err != nil {
			return nil, "", fmt.Errorf("not plain JSON (comments or a syntax error?): %v", err)
		}
		if dec.More() {
			return nil, "", fmt.Errorf("unexpected data after the JSON document")
		}
	}
	servers := map[string]any{}
	if v, ok := doc[key]; ok && v != nil {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, "", fmt.Errorf("%q is not an object", key)
		}
		servers = m
	}

	cur, exists := servers[name]
	switch {
	case entry == nil:
		if !exists {
			return raw, "absent", nil
		}
		delete(servers, name)
		action = "removed"
	case !exists:
		servers[name] = entry
		action = "added"
	default:
		merged := map[string]any{}
		if m, ok := cur.(map[string]any); ok {
			for k, v := range m {
				merged[k] = v
			}
		}
		same := true
		for k, v := range entry {
			if !reflect.DeepEqual(merged[k], v) {
				same = false
			}
			merged[k] = v
		}
		if same {
			return raw, "unchanged", nil
		}
		servers[name] = merged
		action = "updated"
	}
	doc[key] = servers

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), action, nil
}

func tomlQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == '"':
			b.WriteString(`\"`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func tomlArray(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = tomlQuote(s)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

func isTOMLTableHeader(line string) bool {
	t := strings.TrimSpace(line)
	return strings.HasPrefix(t, "[")
}

func tomlKeyIs(line, key string) bool {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, key) {
		return false
	}
	rest := strings.TrimSpace(t[len(key):])
	return strings.HasPrefix(rest, "=")
}

// editCodexTOML adds, updates or removes [mcp_servers.<name>] in Codex's
// config.toml. Other keys inside the table are kept; sub-tables such as
// [mcp_servers.<name>.env] are left alone.
func editCodexTOML(raw, name string, cmd serverCmd, remove bool) (out, action string, err error) {
	if !reServerName.MatchString(name) {
		return "", "", fmt.Errorf("server name %q is not usable in TOML (letters, digits, - and _ only)", name)
	}
	header := "[mcp_servers." + name + "]"
	quoted := `[mcp_servers."` + name + `"]`
	lines := strings.Split(raw, "\n")

	start := -1
	for i, l := range lines {
		if t := strings.TrimSpace(l); t == header || t == quoted {
			start = i
			break
		}
	}
	end := len(lines)
	if start >= 0 {
		for j := start + 1; j < len(lines); j++ {
			if isTOMLTableHeader(lines[j]) {
				end = j
				break
			}
		}
	}

	if remove {
		if start < 0 {
			return raw, "absent", nil
		}
		from := start
		if from > 0 && strings.TrimSpace(lines[from-1]) == "" {
			from--
		}
		rest := append(append([]string{}, lines[:from]...), lines[end:]...)
		text := strings.Join(rest, "\n")
		if strings.HasSuffix(raw, "\n") && !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		return text, "removed", nil
	}

	block := []string{header, "command = " + tomlQuote(cmd.command), "args = " + tomlArray(cmd.args)}
	if start < 0 {
		text := raw
		if text != "" && !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		if text != "" {
			text += "\n"
		}
		return text + strings.Join(block, "\n") + "\n", "added", nil
	}

	// Keep the table's other keys; replace command and args.
	var kept []string
	for k := start + 1; k < end; k++ {
		l := lines[k]
		switch {
		case tomlKeyIs(l, "command"):
		case tomlKeyIs(l, "args"):
			if strings.Contains(l, "[") && !strings.Contains(l, "]") {
				for k+1 < end && !strings.Contains(lines[k], "]") {
					k++
				}
			}
		default:
			kept = append(kept, l)
		}
	}
	replaced := append(append([]string{}, block...), kept...)
	rest := append(append([]string{}, lines[:start]...), replaced...)
	rest = append(rest, lines[end:]...)
	text := strings.Join(rest, "\n")
	if text == raw {
		return raw, "unchanged", nil
	}
	return text, "updated", nil
}

// writeFileAtomic writes data through a temporary file in the same folder. If
// the file already exists, a copy is kept next to it the first time (the copy
// is never overwritten, so it always holds the original).
func writeFileAtomic(path string, data []byte) (backup string, err error) {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real // keep a symlinked dotfile a symlink
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	mode := os.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
		bak := path + ".nullwire-bak"
		if _, err := os.Stat(bak); os.IsNotExist(err) {
			if old, err := os.ReadFile(path); err == nil {
				if err := os.WriteFile(bak, old, mode); err == nil {
					backup = bak
				}
			}
		}
	}
	tmp, err := os.CreateTemp(dir, ".nullwire-*.tmp")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return "", err
	}
	if err := tmp.Chmod(mode); err != nil && runtime.GOOS != "windows" {
		_ = tmp.Close()
		cleanup()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return "", err
	}
	return backup, nil
}

func readIfExists(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	return b, err
}

// applyFile edits a JSON or TOML config. It returns a short status word.
func applyFile(spec clientSpec, o installOptions) (status, path string, err error) {
	path, err = spec.path()
	if err != nil {
		return "", "", err
	}
	raw, err := readIfExists(path)
	if err != nil {
		return "", path, err
	}
	var out []byte
	var action string
	if spec.kind == "toml" {
		var text string
		text, action, err = editCodexTOML(string(raw), o.name, o.cmd, o.uninstall)
		out = []byte(text)
	} else {
		var entry map[string]any
		if !o.uninstall {
			entry = jsonEntry(o.cmd, spec.typed)
		}
		out, action, err = editJSONServers(raw, spec.key, o.name, entry)
	}
	if err != nil {
		return "", path, err
	}
	if action == "unchanged" || action == "absent" {
		return action, path, nil
	}
	if o.dryRun {
		return "would be " + action, path, nil
	}
	backup, err := writeFileAtomic(path, out)
	if err != nil {
		return "", path, err
	}
	if backup != "" {
		return action + " (backup: " + backup + ")", path, nil
	}
	return action, path, nil
}

// claudeCodeArgs returns the Claude Code CLI commands for add or remove.
func claudeCodeArgs(o installOptions) [][]string {
	if o.uninstall {
		return [][]string{{"mcp", "remove", o.name, "--scope", "user"}}
	}
	add := append([]string{"mcp", "add", "--scope", "user", o.name, "--", o.cmd.command}, o.cmd.args...)
	return [][]string{{"mcp", "remove", o.name, "--scope", "user"}, add}
}

func applyClaudeCode(o installOptions) (status string, err error) {
	if _, err := exec.LookPath("claude"); err != nil {
		return "", fmt.Errorf("the claude command was not found; run: claude %s", strings.Join(claudeCodeArgs(o)[len(claudeCodeArgs(o))-1], " "))
	}
	cmds := claudeCodeArgs(o)
	if o.dryRun {
		return "would run: claude " + strings.Join(cmds[len(cmds)-1], " "), nil
	}
	for i, a := range cmds {
		out, err := exec.Command("claude", a...).CombinedOutput()
		last := i == len(cmds)-1
		if err != nil && (last || o.uninstall) {
			if o.uninstall {
				return "absent", nil
			}
			return "", fmt.Errorf("claude %s failed: %s", strings.Join(a, " "), strings.TrimSpace(string(out)))
		}
	}
	if o.uninstall {
		return "removed", nil
	}
	return "added", nil
}

// resolveServerCmd works out what a client should run. Under the npm wrapper
// (or with --npx) that is npx, because the downloaded binary lives in a cache.
func resolveServerCmd(binary string, useNpx bool, serverArgs []string) (serverCmd, error) {
	if useNpx {
		args := append([]string{"-y", "nullwire-mcp"}, serverArgs...)
		if runtime.GOOS == "windows" {
			return serverCmd{command: "cmd", args: append([]string{"/c", "npx"}, args...)}, nil
		}
		return serverCmd{command: "npx", args: args}, nil
	}
	if binary == "" {
		exe, err := os.Executable()
		if err != nil {
			return serverCmd{}, fmt.Errorf("cannot locate this program: %v (use --binary)", err)
		}
		binary = exe
	}
	abs, err := filepath.Abs(binary)
	if err != nil {
		return serverCmd{}, err
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real
	}
	if st, err := os.Stat(abs); err != nil || st.IsDir() {
		return serverCmd{}, fmt.Errorf("%s is not a file; check --binary", abs)
	}
	return serverCmd{command: abs, args: serverArgs}, nil
}

func Run(args []string) int { return runInstallTo(os.Stdout, os.Stderr, args) }

// runInstallTo is Run with explicit writers, for tests.
func runInstallTo(out, errw io.Writer, args []string) int {
	fset := flag.NewFlagSet("install", flag.ContinueOnError)
	fset.SetOutput(errw)
	clientFlag := fset.String("client", "all", "comma-separated clients, or all (every client found on this machine)")
	name := fset.String("name", "nullwire", "name to register the server under")
	binary := fset.String("binary", "", "path of the nullwire-mcp binary to register (default: this program)")
	useNpx := fset.Bool("npx", false, "register `npx -y nullwire-mcp` instead of a binary path")
	uninstall := fset.Bool("uninstall", false, "remove the server instead of adding it")
	dryRun := fset.Bool("dry-run", false, "show what would change without writing anything")
	list := fset.Bool("list", false, "list supported clients and whether they are installed here")
	printCfg := fset.Bool("print", false, "print a config snippet for clients that are not supported")
	fset.Usage = func() {
		fmt.Fprintf(errw, "usage: nullwire-mcp install [--client NAME,…|all] [--dry-run] [--uninstall] [--list] [--print] [--name N] [--binary PATH | --npx] [-- SERVER FLAGS…]\n")
		fmt.Fprintf(errw, "Server flags after -- are saved in the client's config, for example: install --client cursor -- -port 8081\n")
		fset.PrintDefaults()
	}
	// Everything after the first "--" belongs to the server, not to install.
	own, serverArgs := args, []string(nil)
	for i, a := range args {
		if a == "--" {
			own, serverArgs = args[:i], args[i+1:]
			break
		}
	}
	if err := fset.Parse(own); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fset.NArg() > 0 {
		fmt.Fprintf(errw, "nullwire-mcp install: unexpected argument %q (server flags go after --)\n", fset.Arg(0))
		return 2
	}
	if !reServerName.MatchString(*name) {
		fmt.Fprintf(errw, "nullwire-mcp install: --name must be 1 to 64 letters, digits, - or _\n")
		return 2
	}

	clients := installClients()
	if *list {
		for _, c := range clients {
			loc := "claude command"
			if c.kind != "cli" {
				if p, err := c.path(); err == nil {
					loc = p
				}
			}
			state := "not found"
			if c.detected() {
				state = "found"
			}
			fmt.Fprintf(out, "%-15s %-18s %-10s %s\n", c.id, c.label, state, loc)
		}
		return 0
	}

	useNpxFinal := *useNpx || (*binary == "" && os.Getenv("NULLWIRE_VIA_NPM") == "1")
	cmd, err := resolveServerCmd(*binary, useNpxFinal, serverArgs)
	if err != nil {
		fmt.Fprintf(errw, "nullwire-mcp install: %v\n", err)
		return 1
	}
	if *printCfg {
		entry, _ := json.MarshalIndent(map[string]any{"mcpServers": map[string]any{*name: jsonEntry(cmd, false)}}, "", "  ")
		fmt.Fprintf(out, "JSON clients (Zed, Continue, Amazon Q and others use a similar block):\n%s\n\n", entry)
		toml, _, _ := editCodexTOML("", *name, cmd, false)
		fmt.Fprintf(out, "TOML (Codex CLI):\n%s", toml)
		return 0
	}

	wanted := map[string]bool{}
	all := false
	for _, id := range strings.Split(*clientFlag, ",") {
		id = strings.ToLower(strings.TrimSpace(id))
		switch {
		case id == "":
		case id == "all":
			all = true
		default:
			known := false
			for _, c := range clients {
				if c.id == id {
					known = true
				}
			}
			if !known {
				fmt.Fprintf(errw, "nullwire-mcp install: unknown client %q (run --list)\n", id)
				return 2
			}
			wanted[id] = true
		}
	}

	o := installOptions{name: *name, cmd: cmd, uninstall: *uninstall, dryRun: *dryRun}
	verb := "Registering"
	if o.uninstall {
		verb = "Removing"
	}
	suffix := ""
	if o.dryRun {
		suffix = " [dry run]"
	}
	fmt.Fprintf(out, "%s %q (%s)%s\n", verb, o.name, strings.TrimSpace(cmd.command+" "+strings.Join(cmd.args, " ")), suffix)

	failures, handled := 0, 0
	for _, c := range clients {
		explicit := wanted[c.id]
		if !explicit && !all {
			continue
		}
		if !explicit && !c.detected() {
			fmt.Fprintf(out, "  –  %-18s not found on this machine\n", c.label)
			continue
		}
		var status, where string
		var err error
		if c.kind == "cli" {
			status, err = applyClaudeCode(o)
			where = "claude CLI"
		} else {
			status, where, err = applyFile(c, o)
		}
		handled++
		if err != nil {
			failures++
			fmt.Fprintf(out, "  ✗  %-18s %v\n", c.label, err)
			continue
		}
		fmt.Fprintf(out, "  ✓  %-18s %s  %s\n", c.label, status, where)
	}
	if handled == 0 {
		fmt.Fprintf(out, "No supported MCP clients were found. Name one with --client (see --list), or use --print for a snippet to paste.\n")
	} else if !o.dryRun && !o.uninstall && failures < handled {
		fmt.Fprintf(out, "Restart the client to pick up the change.\n")
	}
	if failures > 0 {
		return 1
	}
	return 0
}
