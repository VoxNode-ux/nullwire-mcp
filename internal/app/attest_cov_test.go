package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// mutatedEnvelope builds a valid envelope, lets edit change it, and re-encodes it.
func mutatedEnvelope(t *testing.T, edit func(*attestEnvelope)) []byte {
	t.Helper()
	env, err := newTestApp(t).buildAttestation()
	if err != nil {
		t.Fatal(err)
	}
	var e attestEnvelope
	if err := json.Unmarshal(env, &e); err != nil {
		t.Fatal(err)
	}
	edit(&e)
	out, err := marshalCompact(e)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestVerifyAttestationErrorBranches(t *testing.T) {
	cases := []struct {
		name string
		edit func(*attestEnvelope)
		want string
	}{
		{"bad algorithm", func(e *attestEnvelope) { e.Signature.Algorithm = "RSA-SHA1" }, "unsupported algorithm"},
		{"empty algorithm", func(e *attestEnvelope) { e.Signature.Algorithm = "" }, "unsupported algorithm"},
		{"public key not hex", func(e *attestEnvelope) { e.Signature.PublicKey = "not hex at all" }, "neither PEM nor hex"},
		{"public key not a key", func(e *attestEnvelope) { e.Signature.PublicKey = "00ff" }, "public key:"},
		{"empty public key", func(e *attestEnvelope) { e.Signature.PublicKey = "" }, "public key"},
		{"signature not hex", func(e *attestEnvelope) { e.Signature.Signature = "zz" }, "does not match its signature"},
		{"signature empty", func(e *attestEnvelope) { e.Signature.Signature = "" }, "does not match its signature"},
		{"signature wrong", func(e *attestEnvelope) { e.Signature.Signature = "3006020101020101" }, "does not match its signature"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, _, err := verifyAttestation(mutatedEnvelope(t, c.edit))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error containing %q", err, c.want)
			}
		})
	}
	// verifyAttestation does not validate key_mode: it only reports it, so the
	// caller (policy attest) shows it. An odd value must pass through unchanged.
	_, _, mode, err := verifyAttestation(mutatedEnvelope(t, func(e *attestEnvelope) { e.Signature.KeyMode = "weird" }))
	if err != nil || mode != "weird" {
		t.Fatalf("key_mode is informational: mode=%q err=%v", mode, err)
	}
	// Surrounding whitespace is tolerated.
	env, _ := newTestApp(t).buildAttestation()
	if _, _, _, err := verifyAttestation(append([]byte("\n  "), append(env, " \n"...)...)); err != nil {
		t.Errorf("whitespace around a valid envelope: %v", err)
	}
}

func TestWriteAttestFileErrors(t *testing.T) {
	app := newTestApp(t)
	// CreateTemp fails: the directory does not exist.
	app.att.out = filepath.Join(t.TempDir(), "missing", "att.json")
	if err := app.writeAttestFile(); err == nil {
		t.Error("an unwritable directory must be reported")
	}
	// Rename fails: the target is an existing directory.
	if runtime.GOOS != "windows" {
		dir := t.TempDir()
		target := filepath.Join(dir, "att.json")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		app.att.out = target
		if err := app.writeAttestFile(); err == nil {
			t.Error("renaming over a directory must fail")
		}
		if left, _ := filepath.Glob(filepath.Join(dir, ".nullwire-attest-*")); len(left) != 0 {
			t.Errorf("the temp file must be removed after a failed rename: %v", left)
		}
	}
	// buildAttestation fails before any file is touched.
	bad := newTestApp(t)
	bad.att.out = filepath.Join(t.TempDir(), "att.json")
	bad.att.once.Do(func() { bad.att.ephErr = errors.New("no entropy") })
	if err := bad.writeAttestFile(); err == nil || !strings.Contains(err.Error(), "no entropy") {
		t.Errorf("signer failure: %v", err)
	}
	if _, err := os.Stat(bad.att.out); !os.IsNotExist(err) {
		t.Errorf("no file may be written when signing fails: %v", err)
	}
}

func TestToolAttestationSignerError(t *testing.T) {
	app := newTestApp(t)
	app.att.once.Do(func() { app.att.ephErr = errors.New("no entropy") })
	res := app.toolAttestation()
	if res["isError"] != true {
		t.Fatalf("expected an error result: %v", res)
	}
	if txt := attestText(t, res); !strings.Contains(txt, "cannot build the attestation") || !strings.Contains(txt, "no entropy") {
		t.Errorf("error text: %q", txt)
	}
}

func TestMarshalCompactError(t *testing.T) {
	if _, err := marshalCompact(make(chan int)); err == nil {
		t.Error("a value JSON cannot encode must be reported")
	}
}

func TestUtcStampAndListenerKind(t *testing.T) {
	if got := utcStamp(time.Time{}); got != "" {
		t.Errorf("zero time = %q, want empty", got)
	}
	if got := utcStamp(time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("x", 3600))); got != "2026-01-02T02:04:05Z" {
		t.Errorf("utcStamp = %q", got)
	}
	app := newTestApp(t)
	if got := app.listenerKind(); got != "tcp-loopback" {
		t.Errorf("default listener = %q", got)
	}
	app.listener = "unix"
	if got := app.listenerKind(); got != "unix" {
		t.Errorf("unix listener = %q", got)
	}
}

func TestAttestReportDisabledToolsSorted(t *testing.T) {
	app := newTestApp(t)
	app.listener = "unix"
	app.disabledTools = map[string]bool{"b_tool": true, "a_tool": true, "c_tool": false}
	r := app.attestReport(time.Now())
	if got := strings.Join(r.Controls.DisabledTools, ","); got != "a_tool,b_tool" {
		t.Errorf("disabled tools = %q, want only the disabled ones, sorted", got)
	}
	if r.Controls.Listener != "unix" {
		t.Errorf("listener = %q", r.Controls.Listener)
	}
	if r.StartedAt != "" {
		t.Errorf("an unset start time must be empty: %q", r.StartedAt)
	}
}
