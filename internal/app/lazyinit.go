package app

import (
	"regexp"
	"sync"

	"github.com/VoxNode-ux/nullwire-mcp/internal/vendors"
)

// Everything in this file exists so that the process pays for a DLP rule only
// when text first reaches it. Compiling the regular expressions, building the
// Aho-Corasick tables and filling the bigram matrix used to run in package
// init() and in NewScrubberWithConfig, ahead of "-version", the MCP
// "initialize" / "tools/list" replies and every one-shot command. Now each of
// them is built once, on first use, behind a sync.Once. The wrappers expose the
// same method names as the types they replace, so no call site (or test)
// changes, and no rule is skipped: the first call simply builds it.

// lazyRegexp is a regexp.Regexp compiled on first use. All of the patterns that
// use it are constants, so MustCompile cannot fail on a user's input.
type lazyRegexp struct {
	once sync.Once
	expr string
	re   *regexp.Regexp
}

func lazyRe(expr string) *lazyRegexp { return &lazyRegexp{expr: expr} }

func (l *lazyRegexp) get() *regexp.Regexp {
	l.once.Do(func() { l.re = regexp.MustCompile(l.expr) })
	return l.re
}

func (l *lazyRegexp) MatchString(s string) bool { return l.get().MatchString(s) }
func (l *lazyRegexp) FindString(s string) string { return l.get().FindString(s) }
func (l *lazyRegexp) FindStringIndex(s string) []int {
	return l.get().FindStringIndex(s)
}
func (l *lazyRegexp) FindStringSubmatch(s string) []string {
	return l.get().FindStringSubmatch(s)
}
func (l *lazyRegexp) FindAllStringIndex(s string, n int) [][]int {
	return l.get().FindAllStringIndex(s, n)
}
func (l *lazyRegexp) FindAllStringSubmatch(s string, n int) [][]string {
	return l.get().FindAllStringSubmatch(s, n)
}
func (l *lazyRegexp) FindAllStringSubmatchIndex(s string, n int) [][]int {
	return l.get().FindAllStringSubmatchIndex(s, n)
}
func (l *lazyRegexp) ReplaceAllString(src, repl string) string {
	return l.get().ReplaceAllString(src, repl)
}
func (l *lazyRegexp) ReplaceAllStringFunc(src string, repl func(string) string) string {
	return l.get().ReplaceAllStringFunc(src, repl)
}

// The regular expressions every Scrubber uses. They are the same for every
// Scrubber, and a compiled *regexp.Regexp is safe for concurrent use, so they
// are shared, built once per process, and only when first matched.
var (
	reBearerShared          = lazyRe(`(?i)(Bearer|Basic|Token)\s+([A-Za-z0-9._~+/=-]{8,})`)
	reSensitiveHeaderShared = lazyRe(`(?i)^(authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token|proxy-authorization)$`)
	reJWTShared             = lazyRe(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)
	reAPIKeyShared          = lazyRe(`(?i)\b((?-i:sk-[A-Za-z0-9]{20,})|ghp_[a-zA-Z0-9]{30,}|github_pat_[a-zA-Z0-9_]{30,}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[0-9a-zA-Z-]+|AKIA[0-9A-Z]{16})\b`)
	reJSONSecretShared      = lazyRe(`(?i)("(?:access_token|refresh_token|id_token|api_key|apikey|secret|client_secret|password|passwd|session_id|auth_token|key)"\s*:\s*")((?:[^"\\]|\\.)+)(")`)
	reQuerySecretShared     = lazyRe(`(?i)((?:^|[?&])(?:api_key|apikey|token|access_token|refresh_token|id_token|secret|client_secret|password|passwd|key)=)([^&\s#]+)`)
	reUserInfoShared        = lazyRe(`(://[^/\s:@]+:)([^@/\s]+)(@)`)
	reIPv4Shared            = lazyRe(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	// A private key block, from BEGIN to END; a block cut off by the capture limit is redacted to the end of the text.
	rePEMShared = lazyRe(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----(?:.*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|.*)`)
	// The text of an XML element whose name suggests a secret. Only the opening "</" is part of the match, so the rest of the closing tag is
	// left in place; a body cut off before the closing tag is redacted to the end of the text. RE2 has no backreferences, so the closing
	// tag name is not compared with the opening one.
	reXMLShared = lazyRe(`(?is)(<(?:[A-Za-z0-9_.-]+:)?[A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|apikey|api_key|api-key|authorization|credential|privatekey|private_key|accesskey|access_key|sessionid|session_id)[A-Za-z0-9_.-]*(?:\s(?:[^<>]*[^/<>])?)?>)(<!\[CDATA\[.*?\]\]>|[^<]+)(</|\z)`)
	// "password": ["a", "b"]
	reJSONSecretArrShared = lazyRe(`(?i)("(?:access_token|refresh_token|id_token|api_key|apikey|secret|client_secret|password|passwd|session_id|auth_token|key)"\s*:\s*\[)((?:\s*"(?:[^"\\]|\\.)*"\s*,?)+)(\s*\])`)
)

// lazyMaskGate builds a maskGate on first use.
type lazyMaskGate struct {
	once   sync.Once
	groups []maskGroup
	g      *maskGate
}

func lazyGate(groups ...maskGroup) *lazyMaskGate { return &lazyMaskGate{groups: groups} }

// Match is maskGate.Match. After the first call it adds one atomic load and
// allocates nothing.
func (l *lazyMaskGate) Match(text string) uint32 {
	l.once.Do(func() { l.g = newMaskGate(l.groups...) })
	return l.g.Match(text)
}

// lazyVendorGate builds the vendor-prefix Aho-Corasick gate on first use. The
// literals are already lower-cased and de-duplicated by the caller.
type lazyVendorGate struct {
	once sync.Once
	lits []string
	g    *vendors.Gate
}

func lazyVendors(lits []string) *lazyVendorGate { return &lazyVendorGate{lits: lits} }

func (l *lazyVendorGate) Match(text string) bool {
	if l == nil {
		return false
	}
	l.once.Do(func() { l.g = vendors.NewGate(l.lits) })
	return l.g.Match(text)
}

// tokenScoreOnce guards the bigram matrix and the entropy table (see
// tokenscore.go). Anything that reads them calls ensureTokenScore first.
var tokenScoreOnce sync.Once

func ensureTokenScore() { tokenScoreOnce.Do(initTokenScore) }
