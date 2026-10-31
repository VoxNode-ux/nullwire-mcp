package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// maxScanFile is the largest file the scanner will read.
const maxScanFile = 4 << 20

// skipDirNames are directory names that are never entered while walking.
var skipDirNames = map[string]bool{
	"node_modules": true, ".git": true, "dist": true, "build": true,
	"vendor": true, ".cache": true, ".venv": true,
}

// readScanFile reads a file for scanning, refusing anything larger than
// maxScanFile before it is loaded.
func readScanFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > maxScanFile {
		return nil, fmt.Errorf("file is larger than %d MiB, skipped", maxScanFile>>20)
	}
	return os.ReadFile(path)
}

// scanTotals adds up the results of every scanned file.
type scanTotals struct{ filesOK, filesBad, hits, tokens, ips int }

func (t *scanTotals) record(ok bool, hits, tokens, ips int) {
	if ok {
		t.filesOK++
	} else {
		t.filesBad++
	}
	t.hits += hits
	t.tokens += tokens
	t.ips += ips
}

// scanByType picks the scanner from the file name.
func scanByType(s *Scrubber, path string, report *strings.Builder) (bool, int, int, int) {
	name := filepath.Base(path)
	lower := strings.ToLower(name)
	switch {
	case envFileNames(name):
		return scanEnvFile(s, path, report)
	case strings.HasSuffix(lower, ".toml"):
		ok, hits, tokens := scanTOMLFile(s, path, report)
		return ok, hits, tokens, 0
	case strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml"):
		ok, hits, tokens := scanYAMLFile(s, path, report)
		return ok, hits, tokens, 0
	case strings.HasSuffix(lower, ".zip"):
		ok, hits, tokens := scanZipFile(s, path, report)
		return ok, hits, tokens, 0
	default:
		return scanFile(s, path, report)
	}
}

// scanKV scrubs one "key<sep>value" pair so the field-name rules apply to it.
// found is true when the value held a secret, or when the key name alone says
// the value should be hidden. shown is what is safe to print.
func scanKV(s *Scrubber, key, sep, val string) (shown string, n int, found bool) {
	scrubbed, n := s.ScrubText(key + sep + val)
	if n > 0 {
		return strings.TrimPrefix(scrubbed, key+sep), n, true
	}
	if envSecretNames.MatchString(lastSegment(key)) {
		return hiddenValue, 0, true
	}
	return "", 0, false
}

// walkTree calls visit for every regular file under root, skipping the
// directories in skipDirNames (matched by exact name, never by substring).
func walkTree(root string, visit func(path string, d fs.DirEntry)) {
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != root && skipDirNames[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() {
			visit(path, d)
		}
		return nil
	})
}

func runScan(args []string) int { return runScanTo(os.Stdout, os.Stderr, args) }

// runScanTo is runScan with explicit output writers, so callers (and tests)
// never have to swap the process-wide os.Stdout.
func runScanTo(out, errw io.Writer, args []string) int {
	fset := flag.NewFlagSet("scan", flag.ContinueOnError)
	fset.SetOutput(errw)
	discover := fset.Bool("discover", false, "auto-discover common MCP config locations under $HOME")
	deep := fset.String("deep", "", "also walk this directory and scan MCP config JSON and .env files")
	history := fset.Bool("history", false, "also scan shell history files (bash, zsh, fish, PowerShell); history text is never shown")
	includeTOML := fset.Bool("toml", false, "also scan TOML config files (*.toml) in --deep directories")
	includeYAML := fset.Bool("yaml", false, "also scan YAML files (*.yaml, *.yml) in directories and --deep")
	includeZIP := fset.Bool("zip", false, "also scan ZIP archives (*.zip) in directories and --deep; entries over 1 MiB are skipped")
	fset.Usage = func() {
		fmt.Fprintf(errw, "usage: nullwire-mcp scan [--discover] [--deep DIR] [--history] [--toml] [--yaml] [--zip] [PATH ...]\n")
		fset.PrintDefaults()
	}
	if err := fset.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	paths := fset.Args()
	if *discover {
		paths = append(paths, discoverConfigPaths()...)
	}
	if len(paths) == 0 && *deep == "" && !*history {
		fset.Usage()
		return 2
	}

	scrub, err := NewScrubber()
	if err != nil {
		fmt.Fprintf(errw, "nullwire-mcp scan: %v\n", err)
		return 1
	}

	var t scanTotals
	report := &strings.Builder{}
	report.WriteString("⚡ nullwire-mcp scan\n")
	sort.Strings(paths)

	seen := map[string]bool{}
	once := func(path string) bool { // reports whether path has not been scanned yet
		abs, err := filepath.Abs(path)
		if err != nil {
			abs = path
		}
		if seen[abs] {
			return false
		}
		seen[abs] = true
		return true
	}

	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			fmt.Fprintf(report, "✗ %s: %v\n", p, err)
			t.filesBad++
			continue
		}
		if info.IsDir() {
			walkTree(p, func(path string, d fs.DirEntry) {
				name := d.Name()
				lower := strings.ToLower(name)
				wanted := isConfigFilename(name) || envFileNames(name) || strings.HasSuffix(lower, ".toml") ||
					(*includeYAML && (strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml"))) ||
					(*includeZIP && strings.HasSuffix(lower, ".zip"))
				if !wanted {
					return
				}
				if once(path) {
					t.record(scanByType(scrub, path, report))
				}
			})
			continue
		}
		if once(p) {
			t.record(scanByType(scrub, p, report))
		}
	}

	if *deep != "" {
		walkTree(*deep, func(path string, d fs.DirEntry) {
			name := d.Name()
			lower := strings.ToLower(name)
			switch {
			case strings.HasSuffix(lower, ".json"):
				if looksLikeMCPConfig(path) && once(path) {
					t.record(scanFile(scrub, path, report))
				}
			case envFileNames(name):
				if once(path) {
					t.record(scanEnvFile(scrub, path, report))
				}
			case *includeTOML && strings.HasSuffix(lower, ".toml"):
				if once(path) {
					ok, hits, tokens := scanTOMLFile(scrub, path, report)
					t.record(ok, hits, tokens, 0)
				}
			case *includeYAML && (strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml")):
				if once(path) {
					ok, hits, tokens := scanYAMLFile(scrub, path, report)
					t.record(ok, hits, tokens, 0)
				}
			case *includeZIP && strings.HasSuffix(lower, ".zip"):
				if once(path) {
					ok, hits, tokens := scanZipFile(scrub, path, report)
					t.record(ok, hits, tokens, 0)
				}
			}
		})
	}

	if *history {
		for _, p := range historyPaths() {
			if !once(p) {
				continue
			}
			ok, hits, tokens := scanHistoryFile(scrub, p, report)
			t.record(ok, hits, tokens, 0)
		}
	}

	fmt.Fprintf(report, "\n%d files scanned · %d secrets (%d tokens, %d IPs) · nothing written to disk\n",
		t.filesOK+t.filesBad, t.hits, t.tokens, t.ips)
	fmt.Fprint(out, report.String())
	if t.filesBad > 0 && t.filesOK == 0 {
		return 1
	}
	return 0
}

func isConfigFilename(name string) bool {
	n := strings.ToLower(name)
	return n == ".mcp.json" || strings.HasSuffix(n, "_mcp.json") || strings.HasSuffix(n, "-mcp.json") ||
		n == "mcp.json" || n == "claude_desktop_config.json" || n == "mcp_config.json"
}

func discoverConfigPaths() []string {
	home, _ := os.UserHomeDir()
	configDir, _ := os.UserConfigDir()
	var paths []string
	if configDir != "" {
		paths = append(paths,
			filepath.Join(configDir, "Claude", "claude_desktop_config.json"),
			filepath.Join(configDir, "claude", "claude_desktop_config.json"),
			filepath.Join(configDir, "Cursor", "mcp.json"), filepath.Join(configDir, "cursor", "mcp.json"),
			filepath.Join(configDir, "Codeium", "windsurf", "mcp_config.json"),
			filepath.Join(configDir, "continue", "config.json"),
			filepath.Join(configDir, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
			filepath.Join(configDir, "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"),
		)
	}
	if home != "" {
		paths = append(paths,
			filepath.Join(home, ".claude.json"), filepath.Join(home, ".claude", "settings.json"),
			filepath.Join(home, ".cursor", "mcp.json"), filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"),
			filepath.Join(home, ".mcp.json"), filepath.Join(home, ".config", "zed", "settings.json"),
			filepath.Join(home, ".config", "github-copilot", "mcp.json"), filepath.Join(home, ".codex", "config.toml"),
			filepath.Join(home, ".env"), filepath.Join(home, ".envrc"),
		)
	}
	paths = append(paths, ".mcp.json", filepath.Join(".claude", "settings.json"), ".env", ".envrc")

	var out []string
	seen := map[string]bool{}
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil || seen[abs] {
			continue
		}
		seen[abs] = true
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			out = append(out, p)
		}
	}
	return out
}

func looksLikeMCPConfig(path string) bool {
	raw, err := readScanFile(path)
	if err != nil {
		return false
	}
	if !bytes.Contains(raw, []byte(`"mcp`)) && !bytes.Contains(raw, []byte(`"servers"`)) {
		return false
	}
	var probe struct {
		MCPServers map[string]any `json:"mcpServers"`
		Servers    map[string]any `json:"servers"`
		MCP        map[string]any `json:"mcp"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}
	return len(probe.MCPServers) > 0 || len(probe.Servers) > 0 || len(probe.MCP) > 0
}

func scanFile(s *Scrubber, path string, report *strings.Builder) (ok bool, hits, tokens, ips int) {
	raw, err := readScanFile(path)
	if err != nil {
		fmt.Fprintf(report, "✗ %s: %v\n", path, err)
		return false, 0, 0, 0
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		fmt.Fprintf(report, "✗ %s: invalid JSON: %v\n", path, err)
		return false, 0, 0, 0
	}
	fmt.Fprintf(report, "✓ %s\n", path)
	tokBefore := s.Tokens.Load()
	ipBefore := s.IPs.Load()
	walkJSON(doc, "", func(jsonPath, value string) string {
		scrubbed, n := s.ScrubText(value)
		switch {
		case n > 0 && scrubbed != value:
			fmt.Fprintf(report, "   %-50s  →  %s\n", trimPath(jsonPath), scrubbed)
			hits++
		case value != "" && envSecretNames.MatchString(lastSegment(jsonPath)):
			fmt.Fprintf(report, "   %-50s  →  (name looks secret; value hidden)\n", trimPath(jsonPath))
			hits++
		}
		return value
	})
	tokens = int(s.Tokens.Load() - tokBefore)
	ips = int(s.IPs.Load() - ipBefore)
	if hits == 0 {
		fmt.Fprintf(report, "   (no secrets found)\n")
	}
	return true, hits, tokens, ips
}

func walkJSON(v any, path string, cb func(jsonPath, value string) string) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			x[k] = walkJSON(val, joinPath(path, k), cb)
		}
		return x
	case []any:
		for i, val := range x {
			x[i] = walkJSON(val, fmt.Sprintf("%s[%d]", path, i), cb)
		}
		return x
	case string:
		return cb(path, x)
	default:
		return v
	}
}

func joinPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}

// lastSegment returns the last key of a path like env.GITHUB_TOKEN or
// args[3], without the array index.
func lastSegment(p string) string {
	if i := strings.LastIndexByte(p, '.'); i >= 0 {
		p = p[i+1:]
	}
	if i := strings.IndexByte(p, '['); i >= 0 {
		p = p[:i]
	}
	return p
}

func trimPath(p string) string {
	if len(p) > 50 {
		return "…" + p[len(p)-49:]
	}
	return p
}
