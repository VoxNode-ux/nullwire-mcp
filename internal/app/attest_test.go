package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func attestText(t *testing.T, res map[string]any) string {
	t.Helper()
	content, _ := res["content"].([]any)
	if len(content) != 1 {
		t.Fatalf("bad tool result: %v", res)
	}
	return content[0].(map[string]any)["text"].(string)
}

func TestAttestationEphemeral(t *testing.T) {
	app := newTestApp(t)
	app.att.policySHA = strings.Repeat("ab", 32)
	app.att.presets = []string{"pci-dss"}
	app.ring.Push(FlowEntry{})
	app.ring.Push(FlowEntry{})
	app.ring.Clear() // the lifetime count survives a wipe

	env := attestText(t, app.toolAttestation())
	report, signer, mode, err := verifyAttestation([]byte(env))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if mode != "ephemeral" || signer == "" {
		t.Errorf("mode=%q signer=%q", mode, signer)
	}
	var r attestReport
	if err := json.Unmarshal(report, &r); err != nil {
		t.Fatal(err)
	}
	if r.Version != attestVersion || r.Counts.FlowsCaptured != 2 || r.Counts.RingEntries != 0 {
		t.Errorf("counts: %+v", r)
	}
	if r.Policy.ConfigSHA256 != app.att.policySHA || len(r.Policy.Presets) != 1 || r.Controls.Listener != "tcp-loopback" {
		t.Errorf("policy/controls: %+v", r)
	}
	if strings.Contains(string(report), "http") {
		t.Errorf("a report must hold no URLs: %s", report)
	}
	// The same ephemeral key signs every report of one run.
	_, signer2, _, err := verifyAttestation([]byte(attestText(t, app.toolAttestation())))
	if err != nil || signer2 != signer {
		t.Errorf("ephemeral key changed within a run: %v", err)
	}
}

func TestAttestationTamperDetected(t *testing.T) {
	app := newTestApp(t)
	env, err := app.buildAttestation()
	if err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(string(env), `"flows_captured":0`, `"flows_captured":9`, 1)
	if bad == string(env) {
		t.Fatal("test did not change the report")
	}
	if _, _, _, err := verifyAttestation([]byte(bad)); err == nil {
		t.Error("an altered report must fail verification")
	}
	if _, _, _, err := verifyAttestation([]byte("not json")); err == nil {
		t.Error("garbage must fail verification")
	}
}

func TestAttestationProvidedKey(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "org")
	if code, _, _ := runPolicyCmd(t, "keygen", "-out", prefix); code != 0 {
		t.Fatal("keygen")
	}
	key, err := loadP256PrivateKeyFile(prefix + ".key")
	if err != nil {
		t.Fatal(err)
	}
	app := newTestApp(t)
	app.att.key = key
	env, err := app.buildAttestation()
	if err != nil {
		t.Fatal(err)
	}
	_, signer, mode, err := verifyAttestation(env)
	if err != nil || mode != "provided" || signer != pubKeyHex(&key.PublicKey) {
		t.Fatalf("provided key: %v mode=%q", err, mode)
	}
	// The CLI pins the signer with -pubkey.
	file := filepath.Join(dir, "report.json")
	if err := os.WriteFile(file, env, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := runPolicyCmd(t, "attest", "-pubkey", prefix+".pub", file); code != 0 || !strings.Contains(out, "expected key") {
		t.Errorf("attest with the right key: %d %q", code, out)
	}
	other := filepath.Join(dir, "other")
	if code, _, _ := runPolicyCmd(t, "keygen", "-out", other); code != 0 {
		t.Fatal("keygen other")
	}
	if code, _, _ := runPolicyCmd(t, "attest", "-pubkey", other+".pub", file); code != 1 {
		t.Error("attest must fail for a different pinned key")
	}
	if code, out, _ := runPolicyCmd(t, "attest", file); code != 0 || !strings.Contains(out, "not checked") {
		t.Errorf("attest without a pinned key: %d %q", code, out)
	}
}

func TestWriteAttestFile(t *testing.T) {
	app := newTestApp(t)
	if err := app.writeAttestFile(); err != nil {
		t.Fatalf("no -attest-out must be a no-op: %v", err)
	}
	app.att.out = filepath.Join(t.TempDir(), "att.json")
	if err := app.writeAttestFile(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(app.att.out)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := verifyAttestation(b); err != nil {
		t.Errorf("written report does not verify: %v", err)
	}
}

func TestAttestationToolCanBeDisabled(t *testing.T) {
	d, err := disabledToolSet("export_attestation")
	if err != nil || !d["export_attestation"] {
		t.Fatalf("export_attestation must be a known tool: %v", err)
	}
}
