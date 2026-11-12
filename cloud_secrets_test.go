package main

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