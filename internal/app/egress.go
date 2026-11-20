package app

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"syscall"
)

// Host egress controls: allowed_upstream_hosts / blocked_upstream_hosts.
//
// A rule is one of:
//   - an exact host name         api.example.com
//   - a wildcard                 *.example.com   (subdomains only, not example.com itself)
//   - an IP address or CIDR      203.0.113.7, 10.0.0.0/8, 2001:db8::/32
//
// blocked always beats allowed. When allowed is non-empty, a host that no
// allowed rule admits is denied. Name rules are checked on the host the client
// asked for; IP/CIDR rules are checked on IP literals up front and, so that DNS
// rebinding cannot slip past them, on every address the dialer actually
// connects to.
//
// Allowed CIDRs admit by address. When allowed_upstream_hosts holds only
// IP/CIDR rules, a host name is let through the name check and the dialer then
// requires its resolved address to sit inside an allowed CIDR. When it holds
// at least one name rule, host names must match a name rule and the resolved
// address is only tested against the blocked CIDRs.

// errEgressDenied marks a connection refused by the egress policy.
var errEgressDenied = errors.New("blocked by egress policy")

type hostRule struct {
	raw      string
	exact    string       // exact host name
	suffix   string       // ".example.com" for *.example.com
	prefix   netip.Prefix // IP or CIDR rule
	isPrefix bool
}

type egressPolicy struct {
	allowed, blocked []hostRule
	allowNames       bool // allowed holds at least one name rule
	allowCIDRs       bool // allowed holds at least one IP/CIDR rule
	blockCIDRs       bool // blocked holds at least one IP/CIDR rule
}

func validHostName(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if c != '.' && c != '-' && c != '_' && (c < '0' || c > '9') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return h[0] != '.' && !strings.Contains(h, "..")
}

func parseHostRule(s string) (hostRule, error) {
	raw := s
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return hostRule{}, fmt.Errorf("empty host rule")
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return hostRule{}, fmt.Errorf("invalid CIDR %q: %v", raw, err)
		}
		return hostRule{raw: raw, prefix: p.Masked(), isPrefix: true}, nil
	}
	ip := strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	if a, err := netip.ParseAddr(ip); err == nil {
		a = a.Unmap().WithZone("")
		return hostRule{raw: raw, prefix: netip.PrefixFrom(a, a.BitLen()), isPrefix: true}, nil
	}
	if strings.HasPrefix(s, "*.") {
		d := strings.TrimSuffix(s[2:], ".")
		if !validHostName(d) {
			return hostRule{}, fmt.Errorf("invalid wildcard host %q", raw)
		}
		return hostRule{raw: raw, suffix: "." + d}, nil
	}
	s = strings.TrimSuffix(s, ".")
	if !validHostName(s) {
		return hostRule{}, fmt.Errorf("invalid host %q (use a host name, *.domain, an IP or a CIDR)", raw)
	}
	return hostRule{raw: raw, exact: s}, nil
}

func parseHostRules(field string, in []string) ([]hostRule, error) {
	out := make([]hostRule, 0, len(in))
	for i, s := range in {
		r, err := parseHostRule(s)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %v", field, i, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// newEgressPolicy validates and compiles both lists. It returns nil when both
// are empty (no policy).
func newEgressPolicy(allowed, blocked []string) (*egressPolicy, error) {
	if len(allowed) == 0 && len(blocked) == 0 {
		return nil, nil
	}
	a, err := parseHostRules("allowed_upstream_hosts", allowed)
	if err != nil {
		return nil, err
	}
	b, err := parseHostRules("blocked_upstream_hosts", blocked)
	if err != nil {
		return nil, err
	}
	p := &egressPolicy{allowed: a, blocked: b}
	for _, r := range a {
		if r.isPrefix {
			p.allowCIDRs = true
		} else {
			p.allowNames = true
		}
	}
	for _, r := range b {
		if r.isPrefix {
			p.blockCIDRs = true
		}
	}
	return p, nil
}

func (r hostRule) matchName(host string) bool {
	if r.isPrefix {
		return false
	}
	if r.exact != "" {
		return host == r.exact
	}
	return strings.HasSuffix(host, r.suffix) && len(host) > len(r.suffix)
}

func (r hostRule) matchIP(a netip.Addr) bool {
	return r.isPrefix && r.prefix.Contains(a)
}

// normalizeHost lower-cases a host, drops brackets, a zone and a trailing dot.
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	if i := strings.IndexByte(h, '%'); i >= 0 {
		h = h[:i]
	}
	return strings.TrimSuffix(h, ".")
}

func matchesAny(rules []hostRule, host string, ip netip.Addr, isIP bool) bool {
	for _, r := range rules {
		if isIP {
			if r.matchIP(ip) {
				return true
			}
		} else if r.matchName(host) {
			return true
		}
	}
	return false
}

// checkHost applies the policy to the host (no port) the client asked for.
// A nil policy allows everything.
func (p *egressPolicy) checkHost(host string) error {
	if p == nil {
		return nil
	}
	h := normalizeHost(host)
	ip, err := netip.ParseAddr(h)
	isIP := err == nil
	if isIP {
		ip = ip.Unmap()
	}
	if matchesAny(p.blocked, h, ip, isIP) {
		return fmt.Errorf("upstream host %q is in blocked_upstream_hosts", h)
	}
	if len(p.allowed) == 0 {
		return nil
	}
	if matchesAny(p.allowed, h, ip, isIP) {
		return nil
	}
	if !isIP && !p.allowNames && p.allowCIDRs {
		return nil // CIDR-only allowlist: the dialer checks the resolved address
	}
	return fmt.Errorf("upstream host %q is not in allowed_upstream_hosts", h)
}

// checkIP applies the IP/CIDR rules to a resolved address; the dialer calls it
// for every connection attempt.
func (p *egressPolicy) checkIP(a netip.Addr) error {
	if p == nil {
		return nil
	}
	a = a.Unmap().WithZone("")
	if p.blockCIDRs && matchesAny(p.blocked, "", a, true) {
		return fmt.Errorf("upstream address %s is in blocked_upstream_hosts: %w", a, errEgressDenied)
	}
	if len(p.allowed) > 0 && !p.allowNames && p.allowCIDRs && !matchesAny(p.allowed, "", a, true) {
		return fmt.Errorf("upstream address %s is not in allowed_upstream_hosts: %w", a, errEgressDenied)
	}
	return nil
}

// Built-in upstream address blocks, checked on the resolved address of every
// new connection (Dialer.Control runs per dial, so HTTP keep-alive pays once
// per connection, not per request).
//
//   - Cloud metadata (169.254.0.0/16, fd00:ec2::254) is blocked by default,
//     because an SSRF into it hands out instance credentials. The secrets
//     config key allow_metadata_upstream turns the block off.
//   - CGNAT (100.64.0.0/10: Tailscale, carrier NAT) and IPv6 link-local
//     (fe80::/10) are opt-in (block_cgnat_upstream, block_link_local_upstream),
//     so tailnets and local networks work out of the box. Note that Alibaba
//     Cloud's metadata address (100.100.100.200) sits inside the CGNAT range.
var (
	metadataV4  = netip.MustParsePrefix("169.254.0.0/16")
	metadataV6  = netip.MustParseAddr("fd00:ec2::254")
	cgnatNet    = netip.MustParsePrefix("100.64.0.0/10")
	linkLocalV6 = netip.MustParsePrefix("fe80::/10")
)

// upstreamBlocks selects the built-in blocks above.
type upstreamBlocks struct {
	allowMetadata bool // turn the default metadata block off
	blockCGNAT    bool // opt in
	blockLinkV6   bool // opt in
}

// check refuses an address that one of the enabled built-in blocks covers.
func (b upstreamBlocks) check(a netip.Addr) error {
	a = a.Unmap().WithZone("")
	switch {
	case !b.allowMetadata && (metadataV4.Contains(a) || a == metadataV6):
		return fmt.Errorf("upstream address %s is a cloud metadata address (allow_metadata_upstream in -secrets-config turns this off): %w", a, errEgressDenied)
	case b.blockCGNAT && cgnatNet.Contains(a):
		return fmt.Errorf("upstream address %s is in the CGNAT range 100.64.0.0/10 (block_cgnat_upstream): %w", a, errEgressDenied)
	case b.blockLinkV6 && linkLocalV6.Contains(a):
		return fmt.Errorf("upstream address %s is IPv6 link-local fe80::/10 (block_link_local_upstream): %w", a, errEgressDenied)
	}
	return nil
}

// parseDialAddr extracts the IP from the "ip:port" string Dialer.Control gets.
func parseDialAddr(address string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(address); err == nil {
		return ap.Addr(), true
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(host)
	return a, err == nil
}

// upstreamControl is the Dialer.Control hook: the built-in blocks first, then
// the user's allowed/blocked CIDR rules. It fails closed on an address it
// cannot parse. egress may be nil.
func upstreamControl(egress *egressPolicy, b upstreamBlocks) func(string, string, syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		a, ok := parseDialAddr(address)
		if !ok {
			return fmt.Errorf("cannot parse upstream address %q: %w", address, errEgressDenied)
		}
		if err := b.check(a); err != nil {
			return err
		}
		return egress.checkIP(a)
	}
}

// needsDialControl reports whether the dialer has anything to enforce.
func (p *egressPolicy) needsDialControl() bool {
	return p != nil && (p.blockCIDRs || (!p.allowNames && p.allowCIDRs))
}

// control is a net.Dialer.Control hook. address is the resolved ip:port the
// dialer is about to connect to, so a host name that resolves (or later
// rebinds) into a blocked range is refused here. It fails closed.
func (p *egressPolicy) control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		host, _, serr := net.SplitHostPort(address)
		if serr != nil {
			return fmt.Errorf("cannot parse upstream address %q: %w", address, errEgressDenied)
		}
		a, aerr := netip.ParseAddr(host)
		if aerr != nil {
			return fmt.Errorf("cannot parse upstream address %q: %w", address, errEgressDenied)
		}
		return p.checkIP(a)
	}
	return p.checkIP(ap.Addr())
}

// disabledToolSet parses -disable-tools. Unknown names are an error.
func disabledToolSet(spec string) (map[string]bool, error) {
	known := map[string]bool{}
	for _, n := range toolNames() {
		known[n] = true
	}
	out := map[string]bool{}
	for _, n := range strings.Split(spec, ",") {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if !known[n] {
			return nil, fmt.Errorf("-disable-tools: unknown tool %q (known: %s)", n, strings.Join(toolNames(), ", "))
		}
		out[n] = true
	}
	return out, nil
}

// toolNames lists every tool toolDefinitions offers, sorted.
func toolNames() []string {
	var names []string
	for _, d := range toolDefinitions() {
		if m, ok := d.(map[string]any); ok {
			if n, ok := m["name"].(string); ok {
				names = append(names, n)
			}
		}
	}
	sort.Strings(names)
	return names
}

// toolDefs is toolDefinitions without the tools turned off by -disable-tools.
func (a *App) toolDefs() []any {
	defs := toolDefinitions()
	if len(a.disabledTools) == 0 {
		return defs
	}
	out := make([]any, 0, len(defs))
	for _, d := range defs {
		if m, ok := d.(map[string]any); ok {
			if n, _ := m["name"].(string); a.disabledTools[n] {
				continue
			}
		}
		out = append(out, d)
	}
	return out
}
