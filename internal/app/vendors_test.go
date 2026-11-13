package app

import (
	"strings"
	"testing"

	"github.com/VoxNode-ux/nullwire-mcp/internal/vendors"
)

const vendorTestBody = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"

func vendorLists() map[string][]string {
	return map[string][]string{
		"strong": vendors.DefaultVendorPrefixes,
		"weak":   vendors.DefaultWeakVendorPrefixes,
		"dsn":    vendors.DefaultDSNPrefixes,
	}
}

// Every prefix must be usable: non-empty, printable ASCII, starting with a
// letter or digit (matching starts at a word boundary), and listed only once.
func TestVendorPrefixListsAreSane(t *testing.T) {
	seen := map[string]string{}
	for name, list := range vendorLists() {
		for _, p := range list {
			if p == "" {
				t.Errorf("%s list has an empty prefix", name)
				continue
			}
			c := p[0]
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
				t.Errorf("%s prefix %q must start with a letter or digit", name, p)
			}
			for i := 0; i < len(p); i++ {
				if p[i] < 0x20 || p[i] > 0x7e {
					t.Errorf("%s prefix %q has a non-printable or non-ASCII byte", name, p)
					break
				}
			}
			if other, dup := seen[p]; dup {
				t.Errorf("prefix %q is listed in both %s and %s", p, other, name)
			}
			seen[p] = name
		}
	}
	if len(seen) < 150 {
		t.Errorf("only %d vendor prefixes are listed; was a list truncated?", len(seen))
	}
}

// Builds a fake key for every listed prefix at run time (so no real-looking
// secret sits in the source) and checks that it is redacted completely.
func TestEveryVendorPrefixRedactsItsKey(t *testing.T) {
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range vendors.DefaultVendorPrefixes {
		checkVendorRedacted(t, s, "strong", p, p+vendorTestBody, vendorTestBody[8:])
	}
	for _, p := range vendors.DefaultWeakVendorPrefixes {
		checkVendorRedacted(t, s, "weak", p, p+vendorTestBody, vendorTestBody[8:])
	}
	for _, p := range vendors.DefaultDSNPrefixes {
		checkVendorRedacted(t, s, "dsn", p, p+"user:pa55w0rd@db.example.com:5432/app", "pa55w0rd")
	}
}

func checkVendorRedacted(t *testing.T, s *Scrubber, kind, prefix, key, secret string) {
	t.Helper()
	out, n := s.ScrubText("found " + key + " in the response")
	if n < 1 {
		t.Errorf("%s prefix %q: nothing was redacted in %q", kind, prefix, key)
		return
	}
	if strings.Contains(out, secret) {
		t.Errorf("%s prefix %q: the secret is still visible: %q", kind, prefix, out)
	}
}

// Ordinary text that merely resembles a prefix must be left alone.
func TestVendorPrefixesIgnoreOrdinaryText(t *testing.T) {
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{
		"hvs.example.com is the host name",
		"the glc_ prefix is documented",
		"ntn_rate limits apply",
		"released as version v1.0-beta today",
		"sk_live_short",
		"npm_package_version",
		"AKIA",
		"see https://hooks.slack.com/services/ for the docs",
		"The deployment finished in us-east-1 without errors.",
	} {
		if out, n := s.ScrubText(in); n != 0 || out != in {
			t.Errorf("ordinary text was changed: %q -> %q (%d)", in, out, n)
		}
	}
}
