package protect

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/VoxNode-ux/nullwire-mcp/internal/scan"
)

// TestMain lets the test binary stand in for the server child process. When
// NULLWIRE_PROTECT_HELPER is set, the binary prints the arguments it was
// started with and exits with the code in NULLWIRE_PROTECT_EXIT.
func TestMain(m *testing.M) {
	if os.Getenv("NULLWIRE_PROTECT_HELPER") == "1" {
		fmt.Println("ARGS:" + strings.Join(os.Args[1:], " "))
		code, _ := strconv.Atoi(os.Getenv("NULLWIRE_PROTECT_EXIT"))
		os.Exit(code)
	}
	os.Exit(m.Run())
}

// fakeScrubber is the smallest scan.Scrubber: it hides nothing, so the
// scanner can only flag a value by its name.
type fakeScrubber struct{}

func (fakeScrubber) ScrubText(in string) (string, int) { return in, 0 }
func (fakeScrubber) TokenCount() uint64 { return 0 }
func (fakeScrubber) IPCount() uint64 { return 0 }

func setScrubber(t *testing.T, fn func() (scan.Scrubber, error)) {
	t.Helper()
	old := scan.NewScrubber
	scan.NewScrubber = fn
	t.Cleanup(func() { scan.NewScrubber = old })
}

func useFakeScrubber(t *testing.T) {
	t.Helper()
	setScrubber(t, func() (scan.Scrubber, error) { return fakeScrubber{}, nil })
}

// isolateHome points every home and config variable at an empty folder, so
// a scan never reads the real machine's files.
func isolateHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("APPDATA", filepath.Join(home, "AppData"))
	return home
}

// asServerChild makes the program that Run starts behave like the test
// helper above: print its arguments and exit with exitCode.
func asServerChild(t *testing.T, exitCode int) {
	t.Helper()
	t.Setenv("NULLWIRE_PROTECT_HELPER", "1")
	t.Setenv("NULLWIRE_PROTECT_EXIT", strconv.Itoa(exitCode))
}

// capture runs fn with os.Stdout and os.Stderr redirected, and returns what
// was written to each.
func capture(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW
	func() {
		defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()
		fn()
	}()
	_ = outW.Close()
	_ = errW.Close()
	o, _ := io.ReadAll(outR)
	e, _ := io.ReadAll(errR)
	_ = outR.Close()
	_ = errR.Close()
	return string(o), string(e)
}

// childArgs returns the arguments the helper child reported.
func childArgs(t *testing.T, stdout string) string {
	t.Helper()
	for _, line := range strings.Split(stdout, "\n") {
		if rest, ok := strings.CutPrefix(line, "ARGS:"); ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatalf("the server child printed no ARGS line; stdout was %q", stdout)
	return ""
}

func TestRunHelpExitsZero(t *testing.T) {
	var code int
	_, stderr := capture(t, func() { code = Run([]string{"-h"}) })
	if code != 0 {
		t.Fatalf("-h returned %d, want 0", code)
	}
	for _, want := range []string{"usage: nullwire-mcp protect", "-no-scan", "-deep"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("help text is missing %q:\n%s", want, stderr)
		}
	}
}

func TestRunRejectsUnknownFlag(t *testing.T) {
	var code int
	_, stderr := capture(t, func() { code = Run([]string{"--definitely-not-a-flag"}) })
	if code != 2 {
		t.Fatalf("unknown flag returned %d, want 2", code)
	}
	if !strings.Contains(stderr, "not defined") {
		t.Errorf("expected a flag error, got:\n%s", stderr)
	}
}

func TestRunRejectsStrayArgument(t *testing.T) {
	var code int
	_, stderr := capture(t, func() { code = Run([]string{"--no-scan", "stray"}) })
	if code != 2 {
		t.Fatalf("stray argument returned %d, want 2", code)
	}
	if !strings.Contains(stderr, `unexpected argument "stray"`) {
		t.Errorf("expected an unexpected-argument message, got:\n%s", stderr)
	}
}

func TestRunPassesEveryOptionToTheServer(t *testing.T) {
	asServerChild(t, 0)
	var code int
	stdout, _ := capture(t, func() {
		code = Run([]string{
			"--no-scan", "--port", "9191", "--target", "http://upstream.test",
			"--cacert", "/tmp/ca.pem", "--dns", "1.1.1.1",
			"--secrets-config", "/tmp/secrets.json", "--scrub-headers", "X-Foo",
			"--allow-uninspectable",
		})
	})
	if code != 0 {
		t.Fatalf("Run returned %d, want 0", code)
	}
	want := "-port 9191 -dns 1.1.1.1 -target http://upstream.test -cacert /tmp/ca.pem " +
		"-secrets-config /tmp/secrets.json -scrub-headers X-Foo -allow-uninspectable"
	if got := childArgs(t, stdout); got != want {
		t.Errorf("server arguments:\n got  %s\n want %s", got, want)
	}
}

func TestRunLeavesOutOptionsThatWereNotGiven(t *testing.T) {
	asServerChild(t, 0)
	var code int
	stdout, _ := capture(t, func() { code = Run([]string{"--no-scan"}) })
	if code != 0 {
		t.Fatalf("Run returned %d, want 0", code)
	}
	if got, want := childArgs(t, stdout), "-port 8080 -dns auto"; got != want {
		t.Errorf("server arguments:\n got  %s\n want %s", got, want)
	}
}

func TestRunReturnsTheServersExitCode(t *testing.T) {
	asServerChild(t, 7)
	var code int
	capture(t, func() { code = Run([]string{"--no-scan"}) })
	if code != 7 {
		t.Fatalf("Run returned %d, want the server's exit code 7", code)
	}
}

func TestRunScansBeforeStartingTheServer(t *testing.T) {
	useFakeScrubber(t)
	home := isolateHome(t)
	env := filepath.Join(home, ".env")
	if err := os.WriteFile(env, []byte("DB_PASSWORD=hunter2\nREGION=eu\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	asServerChild(t, 0)
	var code int
	stdout, stderr := capture(t, func() { code = Run(nil) })
	if code != 0 {
		t.Fatalf("Run returned %d, want 0", code)
	}
	for _, want := range []string{"pre-scan (exit 0)", "1 files scanned", "value hidden"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("pre-scan report is missing %q:\n%s", want, stderr)
		}
	}
	if strings.Contains(stderr, "hunter2") {
		t.Errorf("the pre-scan report leaked the secret value:\n%s", stderr)
	}
	if got, want := childArgs(t, stdout), "-port 8080 -dns auto"; got != want {
		t.Errorf("server arguments:\n got  %s\n want %s", got, want)
	}
}

func TestRunDeepAndHistoryScans(t *testing.T) {
	useFakeScrubber(t)
	isolateHome(t)
	deep := t.TempDir()
	files := map[string]string{
		".env.production": "STRIPE_SECRET=abc123\n",
		"app.toml":        "api_key = \"abc123\"\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(deep, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	asServerChild(t, 0)
	var code int
	stdout, stderr := capture(t, func() { code = Run([]string{"--deep", deep, "--history"}) })
	if code != 0 {
		t.Fatalf("Run returned %d, want 0", code)
	}
	for _, want := range []string{"pre-scan", ".env.production", "app.toml"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("pre-scan report is missing %q:\n%s", want, stderr)
		}
	}
	if strings.Contains(stderr, "abc123") {
		t.Errorf("the pre-scan report leaked a secret value:\n%s", stderr)
	}
	if got, want := childArgs(t, stdout), "-port 8080 -dns auto"; got != want {
		t.Errorf("server arguments:\n got  %s\n want %s", got, want)
	}
}

func TestRunScanQuietReportsTheExitCode(t *testing.T) {
	useFakeScrubber(t)
	isolateHome(t)
	var code int
	_, stderr := capture(t, func() { code = runScanQuiet([]string{"--discover"}) })
	if code != 2 {
		t.Fatalf("a scan with nothing to scan returned %d, want 2", code)
	}
	if !strings.Contains(stderr, "pre-scan (exit 2)") {
		t.Errorf("expected the exit code in the report, got:\n%s", stderr)
	}
}

func TestRunScanQuietReportsAScrubberFailure(t *testing.T) {
	setScrubber(t, func() (scan.Scrubber, error) { return nil, errors.New("no rules loaded") })
	isolateHome(t)
	deep := t.TempDir()
	var code int
	_, stderr := capture(t, func() { code = runScanQuiet([]string{"--deep", deep}) })
	if code != 1 {
		t.Fatalf("a scrubber failure returned %d, want 1", code)
	}
	if !strings.Contains(stderr, "no rules loaded") {
		t.Errorf("expected the failure in the report, got:\n%s", stderr)
	}
}

func TestReexecServeCannotLocateItself(t *testing.T) {
	old := executable
	executable = func() (string, error) { return "", errors.New("no path") }
	t.Cleanup(func() { executable = old })
	var code int
	_, stderr := capture(t, func() { code = reexecServe([]string{"-port", "1"}) })
	if code != 1 {
		t.Fatalf("reexecServe returned %d, want 1", code)
	}
	if !strings.Contains(stderr, "cannot locate self") {
		t.Errorf("expected a cannot-locate-self message, got:\n%s", stderr)
	}
}

func TestReexecServeStartFailure(t *testing.T) {
	old := executable
	executable = func() (string, error) { return filepath.Join(t.TempDir(), "missing-binary"), nil }
	t.Cleanup(func() { executable = old })
	var code int
	_, stderr := capture(t, func() { code = reexecServe([]string{"-port", "1"}) })
	if code != 1 {
		t.Fatalf("reexecServe returned %d, want 1", code)
	}
	if !strings.Contains(stderr, "nullwire-mcp protect:") {
		t.Errorf("expected a start-failure message, got:\n%s", stderr)
	}
}