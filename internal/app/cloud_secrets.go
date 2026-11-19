package app

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
	// AI, search, backend and webhook signing
	"xi-api-key", "x-client-secret", "x-secret-key", "x-webhook-secret", "x-hasura-admin-secret",
	"x-supabase-api-key", "x-algolia-api-key", "x-meilisearch-api-key", "x-typesense-api-key",
	"x-hub-signature", "x-hub-signature-256", "x-slack-signature", "stripe-signature",
}

// cloudGate is the cheap lower-case check that decides whether the name-based
// rules below are worth running on a piece of text.
var cloudGate = []string{
	"secret", "accountkey", "account_key", "account-key", "sharedaccess",
	"shared_access", "shared-access", "sas_token", "sas-token", "sastoken", "session",
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

	// Cloudflare Origin CA key: "v1.0-", hex, "-", more hex. A bare "v1.0-"
	// vendor prefix would also match release tags like v1.0-linux-amd64-musl.
	reCloudflareOriginCA = regexp.MustCompile(`\bv1\.0-[0-9a-fA-F]{16,}-[0-9a-fA-F]{32,}\b`)
)

// scrubCloudSecrets runs the cloud rules. gm is the scrubGate result for the
// text, computed once by the caller.
func (s *Scrubber) scrubCloudSecrets(in string, gm uint32) (string, int) {
	out := in
	count := 0

	if gm&gateCloud != 0 {
		out = reCloudNamedSecret.ReplaceAllStringFunc(out, func(m string) string {
			g := reCloudNamedSecret.FindStringSubmatch(m)
			if g == nil || strings.HasPrefix(g[2], "[REDACTED_") || isAllowMarkOnly(g[2]) || isPlaceholderValue(g[2]) {
				return m
			}
			count++
			s.Tokens.Add(1)
			return g[1] + s.tag("KEY", g[2])
		})
		if gm&gateCloudPass != 0 {
			out = reCloudConnPassword.ReplaceAllStringFunc(out, func(m string) string {
				g := reCloudConnPassword.FindStringSubmatch(m)
				if g == nil || strings.HasPrefix(g[2], "[REDACTED_") || isAllowMarkOnly(g[2]) || isPlaceholderValue(g[2]) {
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

	if strings.Contains(out, "v1.0-") {
		out = reCloudflareOriginCA.ReplaceAllStringFunc(out, func(m string) string {
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
	spans := awsSecretKeySpans(in)
	if len(spans) == 0 {
		return in, 0
	}
	var b strings.Builder
	last := 0
	for _, sp := range spans {
		b.WriteString(in[last:sp.start])
		b.WriteString(s.tag("KEY", in[sp.start:sp.end]))
		s.Tokens.Add(1)
		last = sp.end
	}
	b.WriteString(in[last:])
	return b.String(), len(spans)
}

// awsSecretKeySpans returns where standalone AWS-style secret access keys sit
// in in. It allocates only when it finds one.
func awsSecretKeySpans(in string) []secretSpan {
	if len(in) < 40 || !strings.ContainsAny(in, "/+") {
		return nil
	}
	var spans []secretSpan
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
			spans = append(spans, secretSpan{start: i, end: j})
		}
		i = j
	}
	return spans
}

// awsKeyBoundaryOK rejects a 40-character run that is only a piece of a longer
// token or identifier (neighbouring "_", "-" or "."). A "=" in front is allowed,
// so KEY=<secret> assignments are caught; one after the run still rejects it
// (base64 padding means the run is part of something longer).
func awsKeyBoundaryOK(in string, i, j int) bool {
	if i > 0 && strings.IndexByte("_-.", in[i-1]) >= 0 {
		return false
	}
	if j < len(in) && strings.IndexByte("=_-.", in[j]) >= 0 {
		return false
	}
	return true
}
