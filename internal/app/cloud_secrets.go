package main

import (
	"regexp"
	"strings"
)

// Cloud credentials (AWS, Azure, Cloudflare and similar) often have no prefix
// at all, so the vendor-prefix rules cannot see them. These rules find them by
// the name they are stored under, by a few distinctive shapes, and by the
// header they travel in.

// cloudSensitiveHeaders are always redacted in addition to the built-in list
// and the user's own. A name in the user's ignore_headers still wins.
var cloudSensitiveHeaders = []string{
	// Cloudflare
	"x-auth-key", "cf-access-client-secret", "cf-access-jwt-assertion",
	// AWS and Google
	"x-amz-security-token", "x-goog-api-key", "x-goog-iam-authorization-token",
	// Azure
	"ocp-apim-subscription-key", "x-functions-key",
	// Source hosting, secrets managers and developer tools
	"private-token", "job-token", "x-gitlab-token", "x-vault-token", "x-consul-token",
	"x-access-token", "x-api-token", "x-rapidapi-key", "x-shopify-access-token",
	"x-figma-token", "dd-api-key", "dd-application-key", "x-ibm-client-secret",
	"apikey", "x-csrf-token", "x-xsrf-token",
}

// cloudGate is the cheap lower-case check that decides whether the name-based
// rules below are worth running on a piece of text.
var cloudGate = []string{
	"secret", "accountkey", "account_key", "account-key", "sharedaccess",
	"shared_access", "shared-access", "sas_token", "sas-token", "session",
	"security", "password", "pwd",
}

var (
	// A secret stored under a telling name. Unlike the generic field rule, the
	// value may contain "/", "+", "=", "." and "~", which is what AWS secret
	// keys and Azure account keys are made of. It stops at ";", quotes and
	// spaces, so connection strings keep their other parts. A value that is
	// already a [REDACTED_...] tag cannot match (it starts with "[").
	reCloudNamedSecret = regexp.MustCompile(`(?i)((?:aws[_-]?secret[_-]?(?:access[_-]?)?key|secret[_-]?access[_-]?key|account[_-]?key|shared[_-]?access[_-]?key|shared[_-]?access[_-]?signature|sas[_-]?token|client[_-]?secret|session[_-]?token|security[_-]?token)["']?\s*[:=]\s*["']?)([A-Za-z0-9/+=_.~-]{16,})`)

	// A password inside a connection string ("...;Password=hunter2;...").
	// Passwords can be short, so no minimum length beyond one character.
	reCloudConnPassword = regexp.MustCompile(`(?i)((?:^|[;\s"'])(?:password|pwd)\s*=\s*)([^;&"'\s]+)`)

	// Azure AD (Entra ID) client secrets: 3 characters, "8Q~", then 30+ more.
	reAzureADSecret = regexp.MustCompile(`[A-Za-z0-9_.~-]{3}8Q~[A-Za-z0-9_.~-]{30,}`)
)

// scrubCloudSecrets runs the cloud rules. lower is the lower-cased text, passed
// in so it is not computed twice.
func (s *Scrubber) scrubCloudSecrets(in, lower string) (string, int) {
	out := in
	count := 0

	if containsAny(lower, cloudGate) {
		out = reCloudNamedSecret.ReplaceAllStringFunc(out, func(m string) string {
			g := reCloudNamedSecret.FindStringSubmatch(m)
			if g == nil {
				return m
			}
			count++
			s.Tokens.Add(1)
			return g[1] + s.tag("KEY", g[2])
		})
		if strings.Contains(lower, "pass") || strings.Contains(lower, "pwd") {
			out = reCloudConnPassword.ReplaceAllStringFunc(out, func(m string) string {
				g := reCloudConnPassword.FindStringSubmatch(m)
				if g == nil || strings.HasPrefix(g[2], "[REDACTED_") {
					return m
				}
				count++
				s.Tokens.Add(1)
				return g[1] + s.tag("TOKEN", g[2])
			})
		}
	}

	if strings.Contains(out, "8Q~") {
		out = reAzureADSecret.ReplaceAllStringFunc(out, func(m string) string {
			count++
			s.Tokens.Add(1)
			return s.tag("KEY", m)
		})
	}

	var n int
	out, n = s.scrubAWSSecretKeys(out)
	count += n
	return out, count
}

func isAWSSecretByte(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '/' || c == '+'
}

// looksLikeAWSSecretKey reports whether c has the shape of an AWS secret access
// key: exactly 40 base64 characters, random-looking, with upper case, lower
// case, a digit and at least one "/" or "+". Git hashes (hex), file paths (low
// entropy, many slashes) and ordinary words do not fit.
func looksLikeAWSSecretKey(c string) bool {
	if len(c) != 40 {
		return false
	}
	var upper, lower, digit, symbol, slash int
	for i := 0; i < len(c); i++ {
		switch ch := c[i]; {
		case ch >= 'A' && ch <= 'Z':
			upper++
		case ch >= 'a' && ch <= 'z':
			lower++
		case ch >= '0' && ch <= '9':
			digit++
		case ch == '/':
			slash++
			symbol++
		case ch == '+':
			symbol++
		default:
			return false
		}
	}
	if upper == 0 || lower == 0 || digit == 0 || symbol == 0 || slash > 4 {
		return false
	}
	return shannonEntropyBits(c) >= 4.5
}

// scrubAWSSecretKeys redacts a standalone AWS-style secret access key found
// anywhere in text, even with no field name next to it.
func (s *Scrubber) scrubAWSSecretKeys(in string) (string, int) {
	if len(in) < 40 || !strings.ContainsAny(in, "/+") {
		return in, 0
	}
	var b strings.Builder
	count, last := 0, 0
	for i := 0; i < len(in); {
		if !isAWSSecretByte(in[i]) {
			i++
			continue
		}
		j := i
		for j < len(in) && isAWSSecretByte(in[j]) {
			j++
		}
		if j-i == 40 && awsKeyBoundaryOK(in, i, j) && looksLikeAWSSecretKey(in[i:j]) {
			b.WriteString(in[last:i])
			b.WriteString(s.tag("KEY", in[i:j]))
			s.Tokens.Add(1)
			count++
			last = j
		}
		i = j
	}
	if count == 0 {
		return in, 0
	}
	b.WriteString(in[last:])
	return b.String(), count
}

// awsKeyBoundaryOK rejects a 40-character run that is only a piece of a longer
// token or identifier (neighbouring "=", "_", "-" or ".").
func awsKeyBoundaryOK(in string, i, j int) bool {
	if i > 0 && strings.IndexByte("=_-.", in[i-1]) >= 0 {
		return false
	}
	if j < len(in) && strings.IndexByte("=_-.", in[j]) >= 0 {
		return false
	}
	return true
}
