package app

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyUsageAndBadFlags(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "p.json")
	if err := os.WriteFile(f, []byte(testPolicyJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"nosuchcommand"},
		{"keygen", "-bogus"},
		{"keygen", "extra"},
		{"sign"},
		{"sign", "-key", "k"},
		{"sign", "-bogus", f},
		{"verify", f},
		{"verify", "-bogus", f},
		{"verify", "-pubkey", "x"},
		{"attest"},
		{"attest", "-bogus", f},
		{"attest", "a", "b"},
	} {
		code, _, errOut := runPolicyCmd(t, args...)
		if code != 2 || !strings.Contains(errOut, "usage: nullwire-mcp policy") {
			t.Errorf("policy %v = %d, want usage exit 2 (stderr %q)", args, code, errOut)
		}
	}
}

func TestPolicyCommandFailures(t *testing.T) {
	dir, policy, pub := signedPack(t)
	missing := filepath.Join(dir, "missing")
	garbage := filepath.Join(dir, "garbage.json")
	if err := os.WriteFile(garbage, []byte("not an envelope"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"sign", "-key", missing, policy},
		{"sign", "-key", pub, policy},
		{"sign", "-key", filepath.Join(dir, "k.key"), missing},
		{"verify", "-pubkey", "zz-not-a-key", policy},
		{"verify", "-pubkey", pub, missing},
		{"verify", "-pubkey", pub, garbage},
		{"attest", missing},
		{"attest", garbage},
		{"attest", "-pubkey", "zz-not-a-key", policy},
	} {
		if code, _, errOut := runPolicyCmd(t, args...); code != 1 || !strings.Contains(errOut, "nullwire-mcp policy "+args[0]+":") {
			t.Errorf("policy %v = %d %q, want exit 1 with a prefixed error", args, code, errOut)
		}
	}
	// A valid report with an unparseable pinned key fails after verification.
	app := newTestApp(t)
	env, err := app.buildAttestation()
	if err != nil {
		t.Fatal(err)
	}
	rep := filepath.Join(dir, "rep.json")
	if err := os.WriteFile(rep, env, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runPolicyCmd(t, "attest", "-pubkey", "zz-not-a-key", rep); code != 1 {
		t.Errorf("attest with a bad -pubkey = %d, want 1", code)
	}
	if code, out, _ := runPolicyCmd(t, "attest", rep); code != 0 || !strings.Contains(out, "ephemeral") {
		t.Errorf("attest of an ephemeral report = %d %q", code, out)
	}
	// keygen into a directory that does not exist.
	if code, _, _ := runPolicyCmd(t, "keygen", "-out", filepath.Join(dir, "no", "such", "dir", "k")); code != 1 {
		t.Errorf("keygen into a missing directory = %d, want 1", code)
	}
}

func TestParseP256PrivateKeyForms(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseP256PrivateKey(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}))
	if err != nil || !got.Equal(key) {
		t.Fatalf("SEC1 key: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := parseP256PrivateKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})); err != nil || !got.Equal(key) {
		t.Fatalf("PKCS#8 key: %v", err)
	}

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384sec1, _ := x509.MarshalECPrivateKey(p384)
	p384pkcs8, _ := x509.MarshalPKCS8PrivateKey(p384)
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPKCS8, _ := x509.MarshalPKCS8PrivateKey(edPriv)
	for _, c := range []struct {
		name string
		in   []byte
		want string
	}{
		{"not PEM", []byte("hello"), "no PEM block"},
		{"wrong PEM type", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}), "unsupported PEM type"},
		{"bad SEC1 bytes", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1, 2, 3}}), "private key:"},
		{"bad PKCS8 bytes", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}), "private key:"},
		{"P-384 SEC1", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: p384sec1}), "must be ECDSA P-256"},
		{"P-384 PKCS8", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p384pkcs8}), "must be ECDSA P-256"},
		{"Ed25519 PKCS8", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: edPKCS8}), "must be ECDSA P-256"},
	} {
		if _, err := parseP256PrivateKey(c.in); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error containing %q", c.name, err, c.want)
		}
	}
	if _, err := loadP256PrivateKeyFile(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("a missing key file must fail")
	}
}

func TestDecodeP256PublicKeyForms(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdhPub, err := key.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	raw := ecdhPub.Bytes() // 65-byte uncompressed point
	if len(raw) != 65 || raw[0] != 4 {
		t.Fatalf("unexpected raw point: %d bytes", len(raw))
	}
	got, err := decodeP256PublicKey([]byte("  " + hex.EncodeToString(raw) + "\n"))
	if err != nil || !got.Equal(&key.PublicKey) {
		t.Fatalf("raw 65-byte hex: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := decodeP256PublicKey([]byte(hex.EncodeToString(der))); err != nil || !got.Equal(&key.PublicKey) {
		t.Fatalf("DER hex: %v", err)
	}
	if got, err := decodeP256PublicKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})); err != nil || !got.Equal(&key.PublicKey) {
		t.Fatalf("PEM: %v", err)
	}

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384DER, err := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edDER, err := x509.MarshalPKIXPublicKey(edPub)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		in   []byte
		want string
	}{
		{"neither PEM nor hex", []byte("not hex at all"), "neither PEM nor hex"},
		{"hex but not a key", []byte("00ff"), "public key:"},
		{"raw point, off curve", []byte("04" + strings.Repeat("11", 64)), "public key:"},
		{"P-384 DER hex", []byte(hex.EncodeToString(p384DER)), "must be ECDSA P-256"},
		{"P-384 PEM", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: p384DER}), "must be ECDSA P-256"},
		{"Ed25519 PEM", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: edDER}), "must be ECDSA P-256"},
	} {
		if _, err := decodeP256PublicKey(c.in); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error containing %q", c.name, err, c.want)
		}
	}
}

func TestVerifyBytesHexEdges(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("policy bytes")
	sig, err := signBytesHex(key, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyBytesHex(&key.PublicKey, data, "  "+sig+"\n"); err != nil {
		t.Fatalf("whitespace around a valid signature: %v", err)
	}
	for _, c := range []struct {
		name, sig string
		data      []byte
		want      string
	}{
		{"not hex", "zz", data, "not hex"},
		{"odd length hex", "abc", data, "not hex"},
		{"truncated signature", sig[:len(sig)-8], data, "does not match"},
		{"empty signature", "", data, "does not match"},
		{"other data", sig, []byte("other bytes"), "does not match"},
	} {
		if err := verifyBytesHex(&key.PublicKey, c.data, c.sig); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error containing %q", c.name, err, c.want)
		}
	}
}

func TestLoadPolicyMoreErrors(t *testing.T) {
	dir, policy, pub := signedPack(t)
	if _, _, _, err := loadPolicy(filepath.Join(dir, "none.json"), pub); err == nil || !strings.Contains(err.Error(), "-secrets-config") {
		t.Errorf("missing policy file: %v", err)
	}
	if _, _, _, err := loadPolicy(policy, "zz-not-a-key"); err == nil || !strings.Contains(err.Error(), "-policy-pubkey:") {
		t.Errorf("unparseable -policy-pubkey: %v", err)
	}
	// A correctly signed file that is not valid JSON is still refused.
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, e := runPolicyCmd(t, "sign", "-key", filepath.Join(dir, "k.key"), bad); code != 0 {
		t.Fatalf("sign: %d %s", code, e)
	}
	if _, _, _, err := loadPolicy(bad, pub); err == nil || !strings.Contains(err.Error(), "invalid JSON") {
		t.Errorf("signed but invalid JSON: %v", err)
	}
}

func TestParsePolicyPubKeyFileForms(t *testing.T) {
	dir, _, pubPEM := signedPack(t)
	want, err := parsePolicyPubKey(pubPEM)
	if err != nil {
		t.Fatalf("PEM file: %v", err)
	}
	b, err := os.ReadFile(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	hexFile := filepath.Join(dir, "k.hex")
	if err := os.WriteFile(hexFile, []byte(hex.EncodeToString(block.Bytes)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := parsePolicyPubKey(hexFile)
	if err != nil || !got.Equal(want) {
		t.Errorf("hex file: %v", err)
	}
	// A directory is not a key file; it is read as hex text and fails.
	if _, err := parsePolicyPubKey(dir); err == nil {
		t.Error("a directory must not be accepted as a public key")
	}
}

func TestWriteNewFileEdges(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := writeNewFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeNewFile(p, []byte("y"), 0o600); err == nil {
		t.Error("an existing file must not be overwritten")
	}
	if b, _ := os.ReadFile(p); string(b) != "x" {
		t.Errorf("existing file changed: %q", b)
	}
	if err := writeNewFile(filepath.Join(t.TempDir(), "no", "dir", "f"), []byte("x"), 0o600); err == nil {
		t.Error("a missing directory must fail")
	}
}

func TestPolicyVerifyAndSignSignatureFileEdges(t *testing.T) {
	dir, policy, pub := signedPack(t)
	sigPath := policy + policySigSuffix
	if err := os.WriteFile(sigPath, []byte("zz\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, e := runPolicyCmd(t, "verify", "-pubkey", pub, policy); code != 1 || !strings.Contains(e, "not hex") {
		t.Errorf("a .sig that is not hex = %d %q", code, e)
	}
	if err := os.Remove(sigPath); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runPolicyCmd(t, "verify", "-pubkey", pub, policy); code != 1 {
		t.Errorf("a missing .sig = %d, want 1", code)
	}
	// The signature cannot be written when its path is already a directory.
	if err := os.Mkdir(sigPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runPolicyCmd(t, "sign", "-key", filepath.Join(dir, "k.key"), policy); code != 1 {
		t.Errorf("sign with an unwritable .sig path = %d, want 1", code)
	}
}

func TestPolicyAttestPinnedKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	app := newTestApp(t)
	app.att.key = key
	env, err := app.buildAttestation()
	if err != nil {
		t.Fatal(err)
	}
	rep := filepath.Join(t.TempDir(), "rep.json")
	if err := os.WriteFile(rep, env, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, e := runPolicyCmd(t, "attest", "-pubkey", pubKeyHex(&key.PublicKey), rep); code != 0 || !strings.Contains(out, "expected key") {
		t.Errorf("pinned to the signer = %d %q %q", code, out, e)
	}
	if code, _, e := runPolicyCmd(t, "attest", "-pubkey", pubKeyHex(&other.PublicKey), rep); code != 1 || !strings.Contains(e, "different key") {
		t.Errorf("pinned to another key = %d %q", code, e)
	}
	if code, out, _ := runPolicyCmd(t, "attest", rep); code != 0 || !strings.Contains(out, "provided") {
		t.Errorf("unpinned report from a provided key = %d %q", code, out)
	}
}
