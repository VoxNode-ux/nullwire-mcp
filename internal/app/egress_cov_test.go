package app

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestParseHostRuleErrors(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string
	}{
		{"", "empty host rule"},
		{"   ", "empty host rule"},
		// wildcards
		{"*.", "invalid wildcard host"},
		{"*..example.com", "invalid wildcard host"},
		{"*.a..b", "invalid wildcard host"},
		{"*.*.com", "invalid wildcard host"},
		{"*.exa mple.com", "invalid wildcard host"},
		{"*.exa!mple.com", "invalid wildcard host"},
		{"*." + strings.Repeat("a", 254), "invalid wildcard host"},
		// host names
		{"*", "invalid host"},
		{"ex ample.com", "invalid host"},
		{"exa!mple.com", "invalid host"},
		{".leading.com", "invalid host"},
		{"a..b", "invalid host"},
		{"a.*.com", "invalid host"},
		{"http:x", "invalid host"},
		{"ünicode.com", "invalid host"},
		{strings.Repeat("a", 254), "invalid host"},
		{".", "invalid host"},
		// CIDRs
		{"10.0.0.0/33", "invalid CIDR"},
		{"10.0.0.0/", "invalid CIDR"},
		{"10.0.0.0/-1", "invalid CIDR"},
		{"2001:db8::/129", "invalid CIDR"},
		{"1.2.3/8", "invalid CIDR"},
		{"exa/mple", "invalid CIDR"},
		{"http://x.com", "invalid CIDR"},
	} {
		_, err := parseHostRule(c.in)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("parseHostRule(%q) = %v, want an error containing %q", c.in, err, c.want)
		}
	}
	// The message quotes the rule as the admin wrote it, not lower-cased.
	if _, err := parseHostRule("Ex Ample.com"); err == nil || !strings.Contains(err.Error(), `"Ex Ample.com"`) {
		t.Errorf("the error should quote the original text: %v", err)
	}
}

func TestParseHostRuleForms(t *testing.T) {
	r, err := parseHostRule("10.1.2.3/8")
	if err != nil || !r.isPrefix || r.prefix != netip.MustParsePrefix("10.0.0.0/8") || r.raw != "10.1.2.3/8" {
		t.Errorf("CIDR must be masked and keep its raw text: %+v %v", r, err)
	}
	r, err = parseHostRule("[::1]")
	if err != nil || !r.isPrefix || r.prefix != netip.MustParsePrefix("::1/128") {
		t.Errorf("bracketed IPv6: %+v %v", r, err)
	}
	r, err = parseHostRule("::ffff:10.0.0.1")
	if err != nil || !r.isPrefix || r.prefix != netip.MustParsePrefix("10.0.0.1/32") {
		t.Errorf("an IPv4-mapped address is the plain IPv4 rule: %+v %v", r, err)
	}
	r, err = parseHostRule("fe80::1%eth0")
	if err != nil || !r.isPrefix || r.prefix != netip.MustParsePrefix("fe80::1/128") {
		t.Errorf("a zone is dropped: %+v %v", r, err)
	}
	r, err = parseHostRule(" *.EXAMPLE.com. ")
	if err != nil || r.isPrefix || r.suffix != ".example.com" || r.exact != "" {
		t.Errorf("wildcard: %+v %v", r, err)
	}
	r, err = parseHostRule("Example.COM.")
	if err != nil || r.isPrefix || r.exact != "example.com" || r.suffix != "" {
		t.Errorf("exact name: %+v %v", r, err)
	}
	r, err = parseHostRule("my_host-1.internal")
	if err != nil || r.exact != "my_host-1.internal" {
		t.Errorf("underscore and hyphen are allowed: %+v %v", r, err)
	}
}

func TestEgressRuleErrorsNameTheListAndIndex(t *testing.T) {
	if _, err := newEgressPolicy([]string{"ok.example.com", "bad host"}, nil); err == nil || !strings.Contains(err.Error(), "allowed_upstream_hosts[1]:") {
		t.Errorf("allowed list error: %v", err)
	}
	if _, err := newEgressPolicy([]string{"ok.example.com"}, []string{"10.0.0.0/33"}); err == nil || !strings.Contains(err.Error(), "blocked_upstream_hosts[0]:") {
		t.Errorf("blocked list error: %v", err)
	}
}

func TestEgressControlAddressForms(t *testing.T) {
	p := mustPolicy(t, nil, []string{"10.0.0.0/8"})

	// A normal ip:port.
	if err := p.control("tcp", "10.1.2.3:80", nil); !errors.Is(err, errEgressDenied) {
		t.Errorf("blocked ip:port: %v", err)
	}
	if err := p.control("tcp", "8.8.8.8:80", nil); err != nil {
		t.Errorf("allowed ip:port: %v", err)
	}
	if err := p.control("tcp6", "[::1]:80", nil); err != nil {
		t.Errorf("allowed IPv6: %v", err)
	}
	// netip.ParseAddrPort rejects these ports, so the SplitHostPort fallback decides.
	for _, addr := range []string{"10.1.2.3:http", "10.1.2.3:99999"} {
		if err := p.control("tcp", addr, nil); !errors.Is(err, errEgressDenied) || !strings.Contains(err.Error(), "blocked_upstream_hosts") {
			t.Errorf("fallback must still enforce the block for %q: %v", addr, err)
		}
	}
	for _, addr := range []string{"8.8.8.8:http", "8.8.8.8:99999"} {
		if err := p.control("tcp", addr, nil); err != nil {
			t.Errorf("fallback must admit %q: %v", addr, err)
		}
	}
	// Anything that is not an address fails closed.
	for _, addr := range []string{"", "no-port", "10.1.2.3", "example.com:80", "[::1", "::1::1:80"} {
		err := p.control("tcp", addr, nil)
		if !errors.Is(err, errEgressDenied) || !strings.Contains(err.Error(), "cannot parse upstream address") {
			t.Errorf("control(%q) = %v, want a fail-closed parse error", addr, err)
		}
	}
	// A nil policy still refuses what it cannot read but admits real addresses.
	var none *egressPolicy
	if err := none.control("tcp", "10.1.2.3:80", nil); err != nil {
		t.Errorf("nil policy: %v", err)
	}
	if err := none.control("tcp", "not an address", nil); !errors.Is(err, errEgressDenied) {
		t.Errorf("nil policy with garbage: %v", err)
	}
	// A CIDR-only allowlist is enforced through the same hook, also in the fallback.
	allow := mustPolicy(t, []string{"192.0.2.0/24"}, nil)
	if err := allow.control("tcp", "192.0.2.9:http", nil); err != nil {
		t.Errorf("inside the allowed CIDR: %v", err)
	}
	if err := allow.control("tcp", "198.51.100.1:http", nil); !errors.Is(err, errEgressDenied) {
		t.Errorf("outside the allowed CIDR: %v", err)
	}
}

func TestDisabledToolSetEmptySegments(t *testing.T) {
	for _, spec := range []string{",", ",,", " , ,", "\t,\n"} {
		if set, err := disabledToolSet(spec); err != nil || len(set) != 0 {
			t.Errorf("disabledToolSet(%q) = %v, %v; want empty", spec, set, err)
		}
	}
	set, err := disabledToolSet(",, export_har ,, export_sanitized_curl, ,export_har,")
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 2 || !set["export_har"] || !set["export_sanitized_curl"] {
		t.Errorf("empty segments are skipped and duplicates collapse: %v", set)
	}
	if _, err := disabledToolSet("export_har,,nope,"); err == nil || !strings.Contains(err.Error(), `"nope"`) {
		t.Errorf("an unknown name between empty segments must still fail: %v", err)
	}
	if _, err := disabledToolSet("Export_Har"); err == nil {
		t.Error("tool names are case-sensitive")
	}
}
