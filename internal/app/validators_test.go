package app

import (
	"hash/crc32"
	"strings"
	"testing"
)

func makeGHP(payload string) string {
	sum := crc32.ChecksumIEEE([]byte(payload))
	var enc [6]byte
	for i := 5; i >= 0; i-- {
		enc[i] = base62Alphabet[sum%62]
		sum /= 62
	}
	return "ghp_" + payload + string(enc[:])
}

func TestGitHubCRC(t *testing.T) {
	good := makeGHP("abcdefghijklmnopqrstuvwxyz0123")
	if !githubClassicCRC(good) || !validatedSecret(good) {
		t.Fatalf("valid checksum rejected: %s", good)
	}
	bad := good[:39] + "!"
	if githubClassicCRC(bad) {
		t.Fatal("bad checksum accepted")
	}
	// Synthetic token: validator says no, but it must still be redacted.
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	syn := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	out, n := s.ScrubText("token " + syn + " end")
	if n == 0 || strings.Contains(out, syn) {
		t.Fatalf("synthetic token leaked: %q", out)
	}
}

func TestJWTAndAWS(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.c2ln"
	if !jwtJOSEValid(jwt) || !validatedSecret(jwt) {
		t.Fatal("valid JWT rejected")
	}
	if jwtJOSEValid("eyJub3Rqc29u.e30.x") {
		t.Fatal("non-JSON header accepted")
	}
	if !awsKeyIDValid("AKIAIOSFODNN7EXAMPLE") || awsKeyIDValid("AKIAIOSFODNN7EXAMPL1") {
		t.Fatal("aws validator wrong")
	}
}

func TestPlaceholderHelpers(t *testing.T) {
	for _, v := range []string{"YOUR_API_KEY_HERE", "replace-me-token", "your_secret_key"} {
		if !stage3Placeholder(v) {
			t.Errorf("%q should be a placeholder", v)
		}
	}
	for _, v := range []string{"wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY", "Zx9_Qw3_Lp7_Mn2", "token"} {
		if stage3Placeholder(v) {
			t.Errorf("%q must not be a placeholder", v)
		}
	}
	if !dsnPasswordIsPlaceholder("postgres://app:changeme@db/x") || dsnPasswordIsPlaceholder("postgres://app:Zx9Qw3Lp7Mn2@db/x") {
		t.Fatal("dsn placeholder check wrong")
	}
	// Prefixed candidates are never suppressed.
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	if out, n := s.ScrubText("auth AKIA" + "IOSFODNN7EXAMPLE ok"); n == 0 || strings.Contains(out, "IOSFODNN7") {
		t.Fatalf("prefixed key leaked: %q", out)
	}
}
