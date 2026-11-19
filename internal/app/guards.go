package app

import (
	"net/netip"
	"strings"
)

// proseAfterScheme reports whether "Basic <word>" or "Token <word>" is ordinary
// English ("invalid token provided") rather than a credential. Bearer is always
// treated as a credential. Real tokens have digits, capitals or symbols.
func proseAfterScheme(scheme, tok string, ctx ScrubContext) bool {
	// In a header, query or path the value after the scheme is a credential,
	// however short or lowercase; only free text can be prose.
	if ctx != ContextBody || strings.EqualFold(scheme, "bearer") {
		return false
	}
	for i := 0; i < len(tok); i++ {
		if c := tok[i]; c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

// benignBareKey reports whether a field named exactly "key" holds a short word,
// a path, an id with a colon, or text with spaces: S3 object keys, i18n keys,
// cache keys. Longer opaque values under "key" are still redacted. prefix is
// the matched text up to the value (the field name, quote and separator).
func benignBareKey(prefix, val string) bool {
	end := len(prefix)
	for end > 0 && strings.IndexByte(" \t\"'=:[", prefix[end-1]) >= 0 {
		end--
	}
	start := end
	for start > 0 && isKeyByte(prefix[start-1]) {
		start--
	}
	if !strings.EqualFold(prefix[start:end], "key") {
		return false
	}
	return len(val) < 12 || strings.ContainsAny(val, "/\\: ")
}

var resourceIDPrefixes = []string{
	"req_", "msg_", "resp_", "ch_", "cus_", "in_", "sub_", "pi_", "pm_", "evt_", "cs_",
	"i-0", "vpc-0", "ami-0", "subnet-0", "sg-0",
	"sha256-", "sha384-", "sha512-",
}

// benignResourceID reports whether s is a provider resource id (Stripe, OpenAI,
// AWS), a subresource-integrity hash or a ULID: random-looking but not secret.
// A Stripe client secret ("pi_..._secret_...") is still a secret.
func benignResourceID(s string) bool {
	if strings.Contains(s, "_secret_") {
		return false
	}
	for _, p := range resourceIDPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return isULID(s)
}

// ULID timestamp window, in milliseconds since the Unix epoch: 2015-01-01 to
// 2040-01-01 (UTC). A random 26-character Crockford string is only a ULID
// here when its 48-bit time prefix lands in this range.
const (
	ulidMinMs uint64 = 1420070400000
	ulidMaxMs uint64 = 2208988800000
)

// crockfordVal returns the value of one upper-case Crockford base32 digit
// (0-9 and A-Z without I, L, O, U), or -1. Lower case is not accepted: a
// lower-case 26-character run is far more likely to be something else.
func crockfordVal(c byte) int {
	if c >= '0' && c <= '9' {
		return int(c - '0')
	}
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	if c >= 'A' && c <= 'Z' {
		if i := strings.IndexByte(alphabet, c); i >= 0 {
			return i
		}
	}
	return -1
}

// isULID reports a 26-character upper-case Crockford base32 ULID (no I L O U) whose 10-character timestamp prefix decodes to a date between 2015 and
// 2040. It allocates nothing.
func isULID(s string) bool {
	if len(s) != 26 {
		return false
	}
	var ms uint64
	for i := 0; i < len(s); i++ {
		v := crockfordVal(s[i])
		if v < 0 {
			return false
		}
		if i < 10 {
			ms = ms<<5 | uint64(v)
		}
	}
	return ms >= ulidMinMs && ms <= ulidMaxMs
}

// replaceIPv4 redacts IPv4 addresses, leaving version numbers that follow a
// slash inside a word ("Chrome/120.0.6099.109") alone.
func replaceIPv4(s *Scrubber, in string, count *int) string {
	idx := s.reIPv4.FindAllStringIndex(in, -1)
	if len(idx) == 0 {
		return in
	}
	var b strings.Builder
	last := 0
	changed := false
	for _, m := range idx {
		start, end := m[0], m[1]
		if start >= 2 && in[start-1] == '/' && isWordByte(in[start-2]) {
			// Skip a version number after "Product/" but not an address in a
			// URL path: walk back over the word before the slash and skip only
			// if that word is not itself preceded by a slash.
			w := start - 2
			for w > 0 && isWordByte(in[w-1]) {
				w--
			}
			if w == 0 || in[w-1] != '/' {
				continue
			}
		}
		addr, err := netip.ParseAddr(in[start:end])
		if err != nil || !addr.Is4() {
			continue
		}
		canon := addr.String()
		if canon == "127.0.0.1" || canon == "0.0.0.0" {
			continue
		}
		b.WriteString(in[last:start])
		b.WriteString(s.tag("IP", canon))
		s.IPs.Add(1)
		*count++
		last = end
		changed = true
	}
	if !changed {
		return in
	}
	b.WriteString(in[last:])
	return b.String()
}
