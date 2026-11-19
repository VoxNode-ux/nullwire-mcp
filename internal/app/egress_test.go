package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func mustPolicy(t *testing.T, allowed, blocked []string) *egressPolicy {
	t.Helper()
	p, err := newEgressPolicy(allowed, blocked)
	if err != nil {
		t.Fatalf("newEgressPolicy: %v", err)
	}
	return p
}

func TestEgressRuleSyntax(t *testing.T) {
	for _, bad := range []string{"", "  ", "ex ample.com", "*.", "*", "a.*.com", "10.0.0.0/33", "10.0.0.0/", "http://x.com", "exa/mple", "-bad host"} {
		if _, err := newEgressPolicy([]string{bad}, nil); err == nil {
			t.Errorf("allowed rule %q should be rejected", bad)
		}
		if _, err := newEgressPolicy(nil, []string{bad}); err == nil {
			t.Errorf("blocked rule %q should be rejected", bad)
		}
	}
	for _, good := range []string{"api.example.com", "*.example.com", "10.0.0.0/8", "203.0.113.7", "2001:db8::/32", "::1", "[::1]", "Example.COM."} {
		if _, err := newEgressPolicy([]string{good}, nil); err != nil {
			t.Errorf("rule %q should be accepted: %v", good, err)
		}
	}
	if p, err := newEgressPolicy(nil, nil); p != nil || err != nil {
		t.Errorf("empty lists give no policy, got %v %v", p, err)
	}
}

func TestEgressPrecedenceAndMatching(t *testing.T) {
	p := mustPolicy(t,
		[]string{"api.example.com", "*.corp.test", "203.0.113.0/24"},
		[]string{"evil.corp.test", "203.0.113.66"})
	cases := []struct {
		host string
		ok   bool
	}{
		{"api.example.com", true},
		{"API.Example.com.", true},
		{"a.corp.test", true},
		{"a.b.corp.test", true},
		{"corp.test", false}, // wildcard is subdomains only
		{"evil.corp.test", false},
		{"other.example.com", false},
		{"203.0.113.5", true},
		{"203.0.113.66", false}, // blocked beats allowed
		{"198.51.100.1", false},
		{"::ffff:203.0.113.5", true},
		{"::ffff:203.0.113.66", false},
	}
	for _, c := range cases {
		if err := p.checkHost(c.host); (err == nil) != c.ok {
			t.Errorf("checkHost(%q) = %v, want ok=%v", c.host, err, c.ok)
		}
	}
	var nilPolicy *egressPolicy
	if err := nilPolicy.checkHost("anything"); err != nil {
		t.Errorf("nil policy must allow: %v", err)
	}
	// blocked only: everything else passes
	b := mustPolicy(t, nil, []string{"*.bad.test", "10.0.0.0/8"})
	if b.checkHost("x.bad.test") == nil || b.checkHost("10.1.2.3") == nil {
		t.Error("blocked hosts must be denied")
	}
	if b.checkHost("good.test") != nil || b.checkHost("8.8.8.8") != nil {
		t.Error("unlisted hosts pass when there is no allowlist")
	}
}

func TestEgressCIDROnlyAllowlistAdmitsNamesForDialer(t *testing.T) {
	p := mustPolicy(t, []string{"10.0.0.0/8"}, nil)
	if err := p.checkHost("example.com"); err != nil {
		t.Errorf("host name passes the name check in a CIDR-only allowlist: %v", err)
	}
	if err := p.checkHost("192.0.2.1"); err == nil {
		t.Error("IP literal outside the allowed CIDR must be denied")
	}
	if !p.needsDialControl() {
		t.Error("dialer must enforce a CIDR-only allowlist")
	}
}

func TestResolveUpstreamEnforcesEgress(t *testing.T) {
	app := newTestApp(t)
	app.egress = mustPolicy(t, nil, []string{"blocked.example.com", "10.0.0.0/8"})

	r := httptest.NewRequest(http.MethodGet, "http://blocked.example.com/x", nil)
	if _, _, status, err := app.resolveUpstream(r); err == nil || status != http.StatusForbidden {
		t.Errorf("blocked forward host: status %d err %v", status, err)
	}
	r = httptest.NewRequest(http.MethodGet, "http://10.1.2.3/x", nil)
	if _, _, status, err := app.resolveUpstream(r); err == nil || status != http.StatusForbidden {
		t.Errorf("blocked forward IP: status %d err %v", status, err)
	}
	r = httptest.NewRequest(http.MethodGet, "http://fine.example.com/x", nil)
	if u, _, _, err := app.resolveUpstream(r); err != nil || u.Host != "fine.example.com" {
		t.Errorf("allowed host: %v %v", u, err)
	}

	// reverse mode through X-Target-URL
	r = httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Host = "127.0.0.1:8080"
	r.Header.Set("X-Target-URL", "https://blocked.example.com")
	if _, _, status, err := app.resolveUpstream(r); err == nil || status != http.StatusForbidden {
		t.Errorf("blocked X-Target-URL: status %d err %v", status, err)
	}

	// allowlist
	app.egress = mustPolicy(t, []string{"only.example.com"}, nil)
	r = httptest.NewRequest(http.MethodGet, "http://other.example.com/x", nil)
	if _, _, status, err := app.resolveUpstream(r); err == nil || status != http.StatusForbidden {
		t.Errorf("unlisted host with allowlist: status %d err %v", status, err)
	}
}

func TestHandleConnectEgress403(t *testing.T) {
	app := newTestApp(t)
	app.egress = mustPolicy(t, nil, []string{"*.blocked.test"})
	r := httptest.NewRequest(http.MethodConnect, "http://x.blocked.test:443", nil)
	r.Host = "x.blocked.test:443"
	w := httptest.NewRecorder()
	app.handleConnect(w, r, time.Now())
	if w.Code != http.StatusForbidden {
		t.Errorf("CONNECT to a blocked host: status %d, want 403", w.Code)
	}
}

func TestDialerBlocksResolvedAddress(t *testing.T) {
	// DNS-rebinding guard: "localhost" resolves into the blocked range, so the
	// dial itself must fail with the egress error, not just the name check.
	d := newDialer(nil, mustPolicy(t, nil, []string{"127.0.0.0/8", "::1/128"}))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, addr := range []string{"127.0.0.1:1", "localhost:1", "[::ffff:127.0.0.1]:1"} {
		if _, err := d.DialContext(ctx, "tcp", addr); !errors.Is(err, errEgressDenied) {
			t.Errorf("dial %s: %v, want egress denial", addr, err)
		}
	}
	// CIDR-only allowlist: an address outside it is refused.
	d = newDialer(nil, mustPolicy(t, []string{"10.0.0.0/8"}, nil))
	if _, err := d.DialContext(ctx, "tcp", "127.0.0.1:1"); !errors.Is(err, errEgressDenied) {
		t.Errorf("dial outside allowed CIDR: %v", err)
	}
	// No policy: no Control hook.
	if newDialer(nil, nil).Control != nil {
		t.Error("no policy must install no Control hook")
	}
}

func TestSecretsConfigRejectsBadEgressAndPresets(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"allow":  `{"allowed_upstream_hosts":["bad host"]}`,
		"block":  `{"blocked_upstream_hosts":["10.0.0.0/99"]}`,
		"preset": `{"presets":["nope"]}`,
	} {
		path := dir + "/" + name + ".json"
		if err := writeTestFile(path, body); err != nil {
			t.Fatal(err)
		}
		if _, err := loadSecretsConfig(path); err == nil {
			t.Errorf("%s: invalid config accepted", name)
		}
	}
}

func TestDisableTools(t *testing.T) {
	app := newTestApp(t)
	app.disabledTools, _ = disabledToolSet("export_sanitized_curl, export_har")

	resp := app.dispatchTo(rpcRequest{ID: json.RawMessage(`1`), Method: "tools/list"})
	res, _ := resp.Result.(map[string]any)
	var names []string
	for _, d := range res["tools"].([]any) {
		names = append(names, d.(map[string]any)["name"].(string))
	}
	joined := strings.Join(names, ",")
	if strings.Contains(joined, "export_har") || strings.Contains(joined, "export_sanitized_curl") || !strings.Contains(joined, "inspect_traffic") {
		t.Errorf("tools/list after disabling: %s", joined)
	}
	call := app.dispatchTo(rpcRequest{ID: json.RawMessage(`2`), Method: "tools/call", Params: json.RawMessage(`{"name":"export_har"}`)})
	if call.Error == nil || !strings.Contains(call.Error.Message, "disabled") {
		t.Errorf("disabled tool call: %+v", call)
	}
	ok := app.dispatchTo(rpcRequest{ID: json.RawMessage(`3`), Method: "tools/call", Params: json.RawMessage(`{"name":"clear_ram_buffer"}`)})
	if ok.Error != nil {
		t.Errorf("enabled tool must still work: %+v", ok.Error)
	}

	if _, err := disabledToolSet("export_har,not_a_tool"); err == nil || !strings.Contains(err.Error(), "not_a_tool") {
		t.Errorf("unknown tool name must fail startup, got %v", err)
	}
	if set, err := disabledToolSet(""); err != nil || len(set) != 0 {
		t.Errorf("empty spec: %v %v", set, err)
	}
	// default: everything listed
	if n := len(newTestApp(t).toolDefs()); n != len(toolDefinitions()) {
		t.Errorf("no disabled tools should list all %d tools, got %d", len(toolDefinitions()), n)
	}
}
