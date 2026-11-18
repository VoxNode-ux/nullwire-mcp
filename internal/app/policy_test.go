package app

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testPolicyJSON = `{"presets":["pci-dss"]}`

func runPolicyCmd(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := RunPolicy(args, &out, &errb)
	return code, out.String(), errb.String()
}

// signedPack makes a key pair and a signed policy file in a temp dir.
func signedPack(t *testing.T) (dir, policy, pubFile string) {
	t.Helper()
	dir = t.TempDir()
	prefix := filepath.Join(dir, "k")
	if code, _, e := runPolicyCmd(t, "keygen", "-out", prefix); code != 0 {
		t.Fatalf("keygen: %d %s", code, e)
	}
	policy = filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policy, []byte(testPolicyJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, e := runPolicyCmd(t, "sign", "-key", prefix+".key", policy); code != 0 {
		t.Fatalf("sign: %d %s", code, e)
	}
	return dir, policy, prefix + ".pub"
}

func TestPolicyKeygenSignVerify(t *testing.T) {
	_, policy, pub := signedPack(t)
	if code, out, e := runPolicyCmd(t, "verify", "-pubkey", pub, policy); code != 0 || !strings.Contains(out, "signature OK") {
		t.Fatalf("verify: %d %q %q", code, out, e)
	}
	if err := os.WriteFile(policy, []byte(`{"presets":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runPolicyCmd(t, "verify", "-pubkey", pub, policy); code != 1 {
		t.Fatalf("a changed policy must fail verification, got %d", code)
	}
	if code, _, _ := runPolicyCmd(t); code != 2 {
		t.Fatalf("no subcommand = %d, want 2", code)
	}
}

func TestPolicyKeygenRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "k")
	if code, _, _ := runPolicyCmd(t, "keygen", "-out", prefix); code != 0 {
		t.Fatal("first keygen failed")
	}
	if code, _, _ := runPolicyCmd(t, "keygen", "-out", prefix); code != 1 {
		t.Fatal("keygen must not overwrite an existing key")
	}
	fi, err := os.Stat(prefix + ".key")
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("private key mode %o, want 600", fi.Mode().Perm())
	}
}

func TestLoadPolicy(t *testing.T) {
	_, policy, pub := signedPack(t)

	cfg, sha, signed, err := loadPolicy(policy, pub)
	if err != nil || !signed || len(sha) != 64 || len(cfg.Presets) != 1 {
		t.Fatalf("signed load: %v signed=%v sha=%q cfg=%+v", err, signed, sha, cfg)
	}
	// Unsigned use is unchanged: no key, no signature needed.
	if _, sha2, signed2, err := loadPolicy(policy, ""); err != nil || signed2 || sha2 != sha {
		t.Fatalf("unsigned load: %v signed=%v", err, signed2)
	}
	// No -secrets-config at all.
	if cfg, sha, signed, err := loadPolicy("", ""); err != nil || cfg == nil || sha != "" || signed {
		t.Fatalf("empty load: %v", err)
	}
	if _, _, _, err := loadPolicy("", pub); err == nil {
		t.Error("-policy-pubkey without -secrets-config must fail")
	}
	// Tampered bytes are refused before they are parsed.
	if err := os.WriteFile(policy, []byte(`{"presets":["hipaa"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := loadPolicy(policy, pub); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Errorf("tampered policy: %v", err)
	}
	// A missing signature is refused when a key is set.
	if err := os.Remove(policy + policySigSuffix); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := loadPolicy(policy, pub); err == nil {
		t.Error("missing .sig must fail when -policy-pubkey is set")
	}
	// A signature by another key is refused.
	otherDir := t.TempDir()
	if code, _, _ := runPolicyCmd(t, "keygen", "-out", filepath.Join(otherDir, "o")); code != 0 {
		t.Fatal("keygen other")
	}
	if code, _, _ := runPolicyCmd(t, "sign", "-key", filepath.Join(otherDir, "o.key"), policy); code != 0 {
		t.Fatal("sign other")
	}
	if _, _, _, err := loadPolicy(policy, pub); err == nil {
		t.Error("a signature from a different key must fail")
	}
}

func TestPolicyPubKeyForms(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// hex of the DER key
	if _, err := parsePolicyPubKey(pubKeyHex(&key.PublicKey)); err != nil {
		t.Errorf("DER hex: %v", err)
	}
	// hex of the raw uncompressed point
	raw, err := key.PublicKey.Bytes() // uncompressed point, 04||X||Y
	if err != nil {
		t.Fatal(err)
	}
	got, err := parsePolicyPubKey(hex.EncodeToString(raw))
	if err != nil || pubKeyHex(got) != pubKeyHex(&key.PublicKey) {
		t.Errorf("raw point hex: %v", err)
	}
	for _, bad := range []string{"", "zz", "00ff", "not a key"} {
		if _, err := parsePolicyPubKey(bad); err == nil {
			t.Errorf("parsePolicyPubKey(%q) must fail", bad)
		}
	}
}

func TestPolicyLockError(t *testing.T) {
	if err := policyLockError(true, true); err == nil {
		t.Error("-allow-uninspectable with -policy-pubkey must be refused")
	}
	for _, c := range [][2]bool{{false, false}, {false, true}, {true, false}} {
		if err := policyLockError(c[0], c[1]); err != nil {
			t.Errorf("policyLockError(%v,%v) = %v, want nil", c[0], c[1], err)
		}
	}
}
