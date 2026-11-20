package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
)

// valExtraKeys returns standard-base64 DER bodies of freshly generated
// private keys, one per format derKeyParses accepts.
func valExtraKeys(t *testing.T) (pkcs8, pkcs1, ec string) {
	t.Helper()
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	d8, err := x509.MarshalPKCS8PrivateKey(rk)
	if err != nil {
		t.Fatal(err)
	}
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := x509.MarshalECPrivateKey(ek)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.StdEncoding.EncodeToString
	return enc(d8), enc(x509.MarshalPKCS1PrivateKey(rk)), enc(dec)
}

func TestDerKeyParsesFormats(t *testing.T) {
	pkcs8, pkcs1, ec := valExtraKeys(t)
	for name, b64 := range map[string]string{"pkcs8": pkcs8, "pkcs1": pkcs1, "ec": ec} {
		if !derKeyParses(b64) {
			t.Errorf("%s private key should parse", name)
		}
	}
}

func TestDerKeyParsesRejects(t *testing.T) {
	pkcs8, _, _ := valExtraKeys(t)
	notKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("not a private key ", 8)))
	cases := map[string]string{
		"empty":       "",
		"short":       "MIIBVQIBADANBgkqhkiG9w0B", // under 64 chars
		"too long":    strings.Repeat("A", 16<<10+1),
		"bad base64":  strings.Repeat("!", 80),
		"truncated":   pkcs8[:len(pkcs8)/2],
		"valid b64 but not a key": notKey,
	}
	for name, in := range cases {
		if derKeyParses(in) {
			t.Errorf("%s: must not parse", name)
		}
	}
}

func TestGithubPATShape(t *testing.T) {
	first := strings.Repeat("aB3", 7) + "z"  // 22 chars
	second := strings.Repeat("Zy9", 19) + "q" // 58 chars
	second += "r"                               // 59 chars
	good := "github_pat_" + first + "_" + second
	if len(first) != 22 || len(second) != 59 {
		t.Fatalf("test setup: %d/%d", len(first), len(second))
	}
	if !githubPATShape(good) || !validatedSecret(good) {
		t.Fatal("valid fine-grained token rejected")
	}
	bad := map[string]string{
		"wrong prefix":       "github_pax_" + first + "_" + second,
		"too short":          good[:len(good)-1],
		"too long":           good + "a",
		"no underscore":      "github_pat_" + first + "A" + second,
		"dash in first part": "github_pat_" + first[:5] + "-" + first[6:] + "_" + second,
		"dash in second":     "github_pat_" + first + "_" + second[:10] + "-" + second[11:],
		"empty":              "",
	}
	for name, in := range bad {
		if githubPATShape(in) {
			t.Errorf("%s: must be rejected", name)
		}
	}
}

func TestGithubClassicCRCBranches(t *testing.T) {
	good := makeGHP("abcdefghijklmnopqrstuvwxyz0123")
	for _, p := range []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"} {
		if !githubClassicCRC(p + good[4:]) {
			t.Errorf("%s with a valid checksum rejected", p)
		}
	}
	if githubClassicCRC(good[:39]) || githubClassicCRC(good + "a") {
		t.Error("wrong length accepted")
	}
	if githubClassicCRC("ghx_" + good[4:]) {
		t.Error("unknown prefix accepted")
	}
}

func TestJWTJOSEBranches(t *testing.T) {
	enc := base64.RawURLEncoding.EncodeToString
	hdr := enc([]byte(`{"alg":"HS256"}`))
	body := enc([]byte(`{"sub":"1"}`))
	if !jwtJOSEValid(hdr + "." + body + ".sig") {
		t.Fatal("valid token rejected")
	}
	if !jwtJOSEValid(hdr + "=." + body + "=.sig") {
		t.Fatal("padded parts should be accepted")
	}
	bad := map[string]string{
		"no eyJ prefix":   "abc." + body + ".sig",
		"two parts":       hdr + "." + body,
		"four parts":      hdr + "." + body + ".a.b",
		"header not b64":  "eyJ!!!." + body + ".sig",
		"no alg":          enc([]byte(`{"typ":"JWT"}`)) + "." + body + ".sig",
		"empty alg":       enc([]byte(`{"alg":""}`)) + "." + body + ".sig",
		"payload not b64": hdr + ".!!!.sig",
	}
	for name, in := range bad {
		if jwtJOSEValid(in) {
			t.Errorf("%s: must be rejected", name)
		}
	}
}

func TestAWSKeyIDBranches(t *testing.T) {
	if !awsKeyIDValid("ASIAIOSFODNN7EXAMPLE") {
		t.Error("ASIA key rejected")
	}
	for name, in := range map[string]string{
		"too short":    "AKIAIOSFODNN7EXAMPL",
		"too long":     "AKIAIOSFODNN7EXAMPLES",
		"wrong prefix": "AKIBIOSFODNN7EXAMPLE",
		"not base32":   "ASIAIOSFODNN7EXAMPL8",
		"lowercase":    "AKIAiosfodnn7example",
	} {
		if awsKeyIDValid(in) {
			t.Errorf("%s: must be rejected", name)
		}
	}
}

func TestValidatedSecretDispatch(t *testing.T) {
	enc := base64.RawURLEncoding.EncodeToString
	jwt := enc([]byte(`{"alg":"HS256"}`)) + "." + enc([]byte(`{"sub":"1"}`)) + ".sig"
	ghp := makeGHP("abcdefghijklmnopqrstuvwxyz0123")
	pat := "github_pat_" + strings.Repeat("a", 22) + "_" + strings.Repeat("b", 59)
	yes := map[string]string{"classic": ghp, "fine-grained": pat, "jwt": jwt, "akia": "AKIAIOSFODNN7EXAMPLE", "asia": "ASIAIOSFODNN7EXAMPLE"}
	for name, s := range yes {
		if !validatedSecret(s) {
			t.Errorf("%s should be validated", name)
		}
	}
	no := map[string]string{
		"gh bad checksum": ghp[:39] + "!",
		"gh other":        "ghost_story",
		"jwt bad header":  "eyJub3Rqc29u.e30.x",
		"akia bad":        "AKIAIOSFODNN7EXAMPL1",
		"asia bad":        "ASIAIOSFODNN7EXAMPL1",
		"sk prefix":       "sk-abcdefghijklmnop",
		"plain":           "hello world",
		"empty":           "",
	}
	for name, s := range no {
		if validatedSecret(s) {
			t.Errorf("%s: no validator should affirm it", name)
		}
	}
}

func TestHasStructuredPrefix(t *testing.T) {
	for _, s := range []string{"ghp_x", "github_pat_x", "eyJx", "AKIAx", "-----BEGIN X", "v4.local.x", "sk-x", "xoxb-x", "AIzaX"} {
		if !hasStructuredPrefix(s) {
			t.Errorf("%q should have a structured prefix", s)
		}
	}
	for _, s := range []string{"", "changeme", "password", "Zx9Qw3"} {
		if hasStructuredPrefix(s) {
			t.Errorf("%q must not have a structured prefix", s)
		}
	}
}

func TestStage3PlaceholderLengthBounds(t *testing.T) {
	if stage3Placeholder("a_b") {
		t.Error("shorter than 5 chars must be false")
	}
	if stage3Placeholder(strings.Repeat("your_", 13)) { // 65 chars
		t.Error("longer than 64 chars must be false")
	}
	if stage3Placeholder("your__") { // one word only
		t.Error("a single word must be false")
	}
}

func TestDSNPasswordIsPlaceholderBranches(t *testing.T) {
	yes := []string{
		"postgres://app:changeme@db/x",
		"postgres://app:xxxx@db/x",
		"postgres://app:your_password@db/x",
		"postgres://app:%3Cpassword%3E@db/x", // <password>
		"postgres://app:$%7BDB_PASS%7D@db/x", // ${DB_PASS}
	}
	for _, d := range yes {
		if !dsnPasswordIsPlaceholder(d) {
			t.Errorf("%q should be a placeholder", d)
		}
	}
	no := map[string]string{
		"bad url":       "://x",
		"bad port":      "postgres://app:pw@db:notaport/x",
		"no user":       "postgres://db/x",
		"no password":   "postgres://app@db/x",
		"empty pw":      "postgres://app:@db/x",
		"real password": "postgres://app:Zx9Qw3Lp7Mn2@db/x",
	}
	for name, d := range no {
		if dsnPasswordIsPlaceholder(d) {
			t.Errorf("%s: must not be a placeholder", name)
		}
	}
}

func TestDSNMatchIsTemplateBranches(t *testing.T) {
	for _, m := range []string{
		"postgres://app:your_password@db/x",
		"postgres://app:changeme@db/x",
		"postgres://app:%3Cpassword%3E@db/x",
	} {
		if !dsnMatchIsTemplate(m) {
			t.Errorf("%q should be a template", m)
		}
	}
	no := map[string]string{
		"bad url":             "://x",
		"no user":             "postgres://db/x",
		"no password":         "postgres://app@db/x",
		"empty password":      "postgres://app:@db/x",
		"real password":       "postgres://app:Zx9Qw3Lp7Mn2@db/x",
		"prefixed github tok": "postgres://app:" + makeGHP("abcdefghijklmnopqrstuvwxyz0123") + "@db/x",
		"prefixed aws key":    "postgres://app:AKIAIOSFODNN7EXAMPLE@db/x",
	}
	for name, m := range no {
		if dsnMatchIsTemplate(m) {
			t.Errorf("%s: must not be a template", name)
		}
	}
}
