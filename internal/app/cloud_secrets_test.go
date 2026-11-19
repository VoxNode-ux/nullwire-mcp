package app

import (
	"net/http"
	"strings"
	"testing"
)

// AWS's documentation example key, split so it is not one literal in the source.
const awsExampleSecret = "wJalrXUtnFEMI/K7MDENG/bPx" + "RfiCYEXAMPLEKEY"

func newCloudScrubber(t *testing.T) *Scrubber {
	t.Helper()
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCloudAWSSecretKeyByName(t *testing.T) {
	s := newCloudScrubber(t)
	for _, in := range []string{
		`{"AccessKeyId":"` + "AKIA" + `IOSFODNN7EXAMPLE","SecretAccessKey":"` + awsExampleSecret + `"}`,
		"aws_secret_access_key = " + awsExampleSecret + "\n",
		"AWS_SECRET_ACCESS_KEY=" + awsExampleSecret,
	} {
		out, n := s.ScrubText(in)
		if n < 1 || strings.Contains(out, awsExampleSecret) || strings.Contains(out, "K7MDENG") {
			t.Errorf("AWS secret key not redacted in %q -> %q (%d)", in, out, n)
		}
	}
}

func TestCloudAWSSecretKeyWithoutAName(t *testing.T) {
	s := newCloudScrubber(t)
	out, n := s.ScrubText("the value is " + awsExampleSecret + " so keep it safe")
	if n < 1 || strings.Contains(out, "K7MDENG") {
		t.Errorf("standalone AWS secret key not redacted: %q (%d)", out, n)
	}
}

func TestLooksLikeAWSSecretKey(t *testing.T) {
	if !looksLikeAWSSecretKey(awsExampleSecret) {
		t.Error("the AWS example secret key should match")
	}
	for name, c := range map[string]string{
		"git hash":   "da39a3ee5e6b4b0d3255bfef95601890afd80709",
		"file path":  "Documents/Projects/App1/src/Models/Users",
		"repeating":  "Zx9YwZx9YwZx9YwZx9YwZx9YwZx9YwZx9Yw+Zx9Y",
		"too short":  "wJalrXUtnFEMI/K7MDENG",
		"no symbols": "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY12",
	} {
		if looksLikeAWSSecretKey(c) {
			t.Errorf("%s must not look like an AWS secret key: %q", name, c)
		}
	}
}

func TestCloudAzureStorageConnectionString(t *testing.T) {
	s := newCloudScrubber(t)
	key := strings.Repeat("Qm9v/Kz3", 11) // 88 characters, like a storage account key
	in := "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=" + key + ";EndpointSuffix=core.windows.net"
	out, n := s.ScrubText(in)
	if n < 1 || strings.Contains(out, "Qm9v/Kz3") {
		t.Fatalf("AccountKey not redacted: %q (%d)", out, n)
	}
	for _, keep := range []string{"AccountName=acct", "EndpointSuffix=core.windows.net"} {
		if !strings.Contains(out, keep) {
			t.Errorf("the rest of the connection string should survive, lost %q in %q", keep, out)
		}
	}
}

func TestCloudSQLConnectionStringPassword(t *testing.T) {
	s := newCloudScrubber(t)
	out, n := s.ScrubText("Server=tcp:db.example.com,1433;User ID=sa;Password=hunter2;Encrypt=true")
	if n < 1 || strings.Contains(out, "hunter2") {
		t.Fatalf("password not redacted: %q (%d)", out, n)
	}
	if !strings.Contains(out, "Encrypt=true") {
		t.Errorf("the rest of the string should survive: %q", out)
	}
}

func TestCloudAzureADClientSecret(t *testing.T) {
	s := newCloudScrubber(t)
	secret := "abc" + "8Q~" + strings.Repeat("Zx9Yw", 7)
	out, n := s.ScrubText("found " + secret + " in the logs")
	if n < 1 || strings.Contains(out, "Zx9YwZx9Yw") {
		t.Errorf("Azure AD client secret not redacted: %q (%d)", out, n)
	}
}

func TestCloudHeadersAreRedacted(t *testing.T) {
	s := newCloudScrubber(t)
	h := http.Header{}
	for _, name := range cloudSensitiveHeaders {
		h.Set(name, "value-that-must-not-leak-1234")
	}
	h.Set("Content-Type", "application/json")
	m, _ := s.ScrubHeaders(h)
	for _, name := range cloudSensitiveHeaders {
		v := m[http.CanonicalHeaderKey(name)]
		if strings.Contains(v, "must-not-leak") || !strings.HasPrefix(v, "[REDACTED_") {
			t.Errorf("header %s was not redacted: %q", name, v)
		}
	}
	if m["Content-Type"] != "application/json" {
		t.Errorf("Content-Type should be untouched, got %q", m["Content-Type"])
	}
}

func TestAWSSecretAfterEqualsIsCaught(t *testing.T) {
	if len(awsSecretKeySpans("MYVAR="+awsExampleSecret)) != 1 {
		t.Errorf("KEY=<aws secret> assignment not matched")
	}
	if len(awsSecretKeySpans("MYVAR_"+awsExampleSecret)) != 0 {
		t.Errorf("a run glued to an identifier with _ must still be rejected")
	}
}

func TestCloudflareOriginCAKeyHexValidated(t *testing.T) {
	s := newCloudScrubber(t)
	key := "v1.0-" + strings.Repeat("a1b2c3d4", 3) + "-" + strings.Repeat("0f1e2d3c", 8)
	out, n := s.ScrubText("origin ca key " + key + " here")
	if n < 1 || strings.Contains(out, key) {
		t.Errorf("Origin CA key not redacted: %q (%d)", out, n)
	}
	badHex := "v1.0-" + strings.Repeat("a1b2c3d4", 3) + "-short"
	if reCloudflareOriginCA.MatchString(badHex) {
		t.Errorf("reCloudflareOriginCA must reject non-hex tail %q", badHex)
	}
	for _, in := range []string{
		"download v1.0-linux-amd64-musl today",
		"tag v1.0-release-candidate-2 is out",
		"v1.0-deadbeefdeadbeef-release",
	} {
		if out, n := s.ScrubText(in); n != 0 || out != in {
			t.Errorf("release tag %q was changed: %q (%d)", in, out, n)
		}
	}
}

func TestStrictSlashDotMixedCasePaths(t *testing.T) {
	for _, v := range []string{"Users/Alice/Desktop/file1.txt", "Config/Prod2/App.json", "src/Main/util.go"} {
		if strictSlashDotOK(v) {
			t.Errorf("path %q should not count as a secret candidate", v)
		}
	}
	for _, v := range []string{
		"Zq8Xv3LmP0aTr9Yk/B2nWd6HsJ4cFe7Gu",
		"Zq8Xv3LmP0aTr9Yk/B2nWd6HsJ4cFe7Gu+x==",
		"9fK2xQ7vLm3Zt8Yb1nPd/5RcJ0wHs4Ae6Qw",
	} {
		if !strictSlashDotOK(v) {
			t.Errorf("key-like value %q should stay a secret candidate", v)
		}
	}
}

func TestLooksLikeAWSSecretKeyShapes(t *testing.T) {
	for name, c := range map[string]string{
		"hyphen":        "wJalrXUtnFEMI-K7MDENG/bPxRfiCYEXAMPLEKEY",
		"underscore":    "wJalrXUtnFEMI_K7MDENG/bPxRfiCYEXAMPLEKEY",
		"no upper":      "wjalrxutnfemi/k7mdeng/bpxrficyexamplekey",
		"no lower":      "WJALRXUTNFEMI/K7MDENG/BPXRFICYEXAMPLEKEY",
		"no digit":      "wJalrXUtnFEMI/KxMDENG/bPxRfiCYEXAMPLEKEY",
		"too many /":    "wJalr/Utn/EMI/K7M/ENG/bPxRfiCYEXAMPLEKEY",
		"low entropy":   strings.Repeat("aA1+", 10),
		"39 characters": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKE",
		"41 characters": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEYY",
		"empty":         "",
	} {
		if looksLikeAWSSecretKey(c) {
			t.Errorf("%s must not look like an AWS secret key: %q", name, c)
		}
	}
}

func TestAWSSecretKeySpansBoundaries(t *testing.T) {
	k := awsExampleSecret
	for name, in := range map[string]string{
		"too short for a key":       "short/text+here",
		"no slash or plus":          strings.Repeat("a1B2", 12),
		"longer run":                k + "Q",
		"preceded by underscore":    "_" + k,
		"preceded by hyphen":        "-" + k,
		"preceded by dot":           "." + k,
		"followed by padding":       k + "=",
		"followed by underscore":    k + "_x",
		"followed by hyphen":        k + "-x",
		"followed by dot":           k + ".x",
	} {
		if got := awsSecretKeySpans(in); len(got) != 0 {
			t.Errorf("%s: found %v in %q", name, got, in)
		}
	}
	for name, in := range map[string]string{
		"alone":              k,
		"after an equals":    "SECRET=" + k,
		"in quotes":          `"` + k + `"`,
		"after a space":      "key " + k + " end",
		"at the end of line": "x\n" + k,
	} {
		got := awsSecretKeySpans(in)
		if len(got) != 1 || in[got[0].start:got[0].end] != k {
			t.Errorf("%s: spans %v in %q", name, got, in)
		}
	}
	if got := awsSecretKeySpans(k + " " + k); len(got) != 2 {
		t.Errorf("two keys: %v", got)
	}
	s := newCloudScrubber(t)
	if out, n := s.scrubAWSSecretKeys("nothing to see"); out != "nothing to see" || n != 0 {
		t.Errorf("no key: %q, %d", out, n)
	}
	out, n := s.scrubAWSSecretKeys("a " + k + " b " + k + " c")
	if n != 2 || strings.Contains(out, k) || !strings.HasPrefix(out, "a ") || !strings.HasSuffix(out, " c") {
		t.Errorf("two keys: %q, %d", out, n)
	}
}
