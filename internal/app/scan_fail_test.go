package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VoxNode-ux/nullwire-mcp/internal/scan"
)

// The --fail flag is what the pre-commit hook relies on: exit code 3 when a
// secret is found, 0 when the files are clean, and no change without the flag.
func TestScanFailFlagExitCodes(t *testing.T) {
	dir := t.TempDir()
	dirty := filepath.Join(dir, ".env")
	clean := filepath.Join(dir, "clean.env")
	if err := os.WriteFile(dirty, []byte("API_TOKEN=abcdefgh\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clean, []byte("PORT=8080\nAUTHOR=jane\n"), 0600); err != nil {
		t.Fatal(err)
	}

	run := func(args ...string) (int, string) {
		var out, errw bytes.Buffer
		code := scan.RunTo(&out, &errw, args)
		return code, out.String() + errw.String()
	}

	if code, rep := run("--fail", dirty); code != 3 {
		t.Errorf("--fail with a secret: exit %d, want 3\n%s", code, rep)
	} else if strings.Contains(rep, "abcdefgh") {
		t.Errorf("report must not print the secret:\n%s", rep)
	}
	if code, rep := run("--fail", clean); code != 0 {
		t.Errorf("--fail on a clean file: exit %d, want 0\n%s", code, rep)
	}
	if code, rep := run(dirty); code != 0 {
		t.Errorf("without --fail a finding must keep exit 0, got %d\n%s", code, rep)
	}
}
