package app

import (
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"hash/crc32"
	"net/url"
	"strings"
)

// Stdlib-only validators for well-known secret formats.
//
// The safety rule that governs every use of them: a validator may only
// PROMOTE a candidate (confirm that it is a real secret, so the entropy and
// bigram penalties do not drop it) or help suppress a Stage-3 heuristic-only
// candidate that carries no structured prefix. A validator failing never
// removes a redaction for text that starts with an explicit prefix (ghp_,
// eyJ, AKIA, -----BEGIN, v4.local. ...), so synthetic test tokens and
// truncated bodies are still redacted.

// structuredPrefixes are the explicit shapes that are never dropped because a
// validator, or a placeholder test, says no.
var structuredPrefixes = []string{
	"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
	"eyJ", "AKIA", "ASIA", "-----BEGIN", "v4.local.", "v4.public.",
	"sk-", "xox", "AIza",
}

// hasStructuredPrefix reports whether s starts with an explicit secret prefix.
func hasStructuredPrefix(s string) bool {
	for _, p := range structuredPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// githubClassicCRC checks the checksum of a classic GitHub token: ghp_, gho_,
// ghu_, ghs_ or ghr_, then 30 random characters, then the CRC-32 (IEEE) of
// those 30 characters written as 6 base-62 digits.
func githubClassicCRC(tok string) bool {
	if len(tok) != 40 {
		return false
	}
	switch tok[:4] {
	case "ghp_", "gho_", "ghu_", "ghs_", "ghr_":
	default:
		return false
	}
	sum := crc32.ChecksumIEEE([]byte(tok[4:34]))
	var enc [6]byte
	for i := 5; i >= 0; i-- {
		enc[i] = base62Alphabet[sum%62]
		sum /= 62
	}
	return string(enc[:]) == tok[34:]
}

func isBase62Run(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return len(s) > 0
}

// githubPATShape checks the shape of a fine-grained token:
// github_pat_ + 22 characters + "_" + 59 characters. No checksum is claimed.
func githubPATShape(tok string) bool {
	rest, ok := strings.CutPrefix(tok, "github_pat_")
	if !ok || len(rest) != 22+1+59 || rest[22] != '_' {
		return false
	}
	return isBase62Run(rest[:22]) && isBase62Run(rest[23:])
}

// jwtJOSEValid checks that tok is three base64url parts whose first part
// decodes to a JSON object with a string "alg".
func jwtJOSEValid(tok string) bool {
	if !strings.HasPrefix(tok, "eyJ") {
		return false
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[0], "="))
	if err != nil {
		return false
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(raw, &h) != nil || h.Alg == "" {
		return false
	}
	_, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	return err == nil
}

// awsKeyIDValid checks an access key ID: AKIA or ASIA plus 16 base-32 characters.
func awsKeyIDValid(tok string) bool {
	if len(tok) != 20 || (!strings.HasPrefix(tok, "AKIA") && !strings.HasPrefix(tok, "ASIA")) {
		return false
	}
	_, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(tok[4:])
	return err == nil
}

// pemKeyParses reports whether block holds a private key that crypto/x509
// can parse (PKCS#1, PKCS#8 or SEC 1). A truncated or damaged block returns
// false; callers must not use that to skip a redaction.
func pemKeyParses(block string) bool {
	b, _ := pem.Decode([]byte(block))
	if b == nil {
		return false
	}
	var err error
	switch b.Type {
	case "RSA PRIVATE KEY":
		_, err = x509.ParsePKCS1PrivateKey(b.Bytes)
	case "PRIVATE KEY":
		_, err = x509.ParsePKCS8PrivateKey(b.Bytes)
	case "EC PRIVATE KEY":
		_, err = x509.ParseECPrivateKey(b.Bytes)
	default:
		return false
	}
	return err == nil
}

// derKeyParses reports whether b64 is standard base64 of a private key that
// crypto/x509 parses (the body of a PEM block without its header lines). It
// is a CONFIRMATION only: true promotes a value past the weak-key filters,
// false never clears one.
func derKeyParses(b64 string) bool {
	if len(b64) < 64 || len(b64) > 16<<10 {
		return false
	}
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return false
	}
	if _, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return true
	}
	if _, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return true
	}
	_, err = x509.ParseECPrivateKey(der)
	return err == nil
}

// dsnPasswordIsPlaceholder reports whether dsn is a URL whose password is an
// obvious template value (changeme, <password>, ${DB_PASS}, xxxx ...).
func dsnPasswordIsPlaceholder(dsn string) bool {
	u, err := url.Parse(dsn)
	if err != nil || u.User == nil {
		return false
	}
	pw, ok := u.User.Password()
	if !ok || pw == "" {
		return false
	}
	t := strings.ToLower(pw)
	if isPlaceholderValue(pw) || (strings.HasPrefix(t, "<") && strings.HasSuffix(t, ">")) {
		return true
	}
	return stage3Placeholder(pw)
}

// validatedSecret is true only when a format validator AFFIRMS s. It is used
// to promote a candidate past the entropy and bigram penalties; false means
// "no opinion", never "not a secret".
func validatedSecret(s string) bool {
	switch {
	case strings.HasPrefix(s, "gh"):
		return githubClassicCRC(s) || githubPATShape(s)
	case strings.HasPrefix(s, "eyJ"):
		return jwtJOSEValid(s)
	case strings.HasPrefix(s, "AKIA"), strings.HasPrefix(s, "ASIA"):
		return awsKeyIDValid(s)
	}
	return false
}

var placeholderWords = map[string]struct{}{
	"your": {}, "my": {}, "replace": {}, "me": {}, "insert": {}, "enter": {}, "here": {},
	"placeholder": {}, "example": {}, "sample": {}, "dummy": {}, "fake": {}, "change": {},
	"api": {}, "key": {}, "token": {}, "secret": {}, "password": {}, "test": {}, "xxx": {}, "xxxx": {},
}

// stage3Placeholder reports whether s is nothing but template words joined by
// '_' or '-' (YOUR_API_KEY_HERE, replace-me-token). It is only a reason to
// skip a heuristic-only Stage-3 candidate, and callers must check
// hasStructuredPrefix first. At least two words are needed.
func stage3Placeholder(s string) bool {
	if len(s) < 5 || len(s) > 64 {
		return false
	}
	words := 0
	start := 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] != '_' && s[i] != '-' {
			continue
		}
		if i > start {
			if _, ok := placeholderWords[strings.ToLower(s[start:i])]; !ok {
				return false
			}
			words++
		}
		start = i + 1
	}
	return words >= 2
}
