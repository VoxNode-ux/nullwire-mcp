package main

import (
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// vendor key shapes
// ---------------------------------------------------------------------------

const vendorBody = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"

func TestVendorKeyShapes(t *testing.T) {
	s, _ := NewScrubber()
	shapes := map[string]string{
		"stripe secret":     "sk_live_" + vendorBody,
		"stripe restricted": "rk_live_" + vendorBody,
		"openai project":    "sk-proj-" + vendorBody + "_-x",
		"google oauth":      "ya29.a0AfH6SMB" + vendorBody,
		"gitlab":            "glpat-" + vendorBody[:20],
		"gitlab routable":   "glpat-" + vendorBody[:24] + ".01.0abc12",
		"hugging face":      "hf_" + vendorBody,
		"npm":               "npm_" + vendorBody + "abcd",
		"sendgrid":          "SG." + vendorBody[:22] + "." + vendorBody + "Abcdefghij",
	}
	for name, key := range shapes {
		for _, in := range []string{
			"found " + key + " in the body",
			`{"note":"` + key + `"}`,
			"GET /x HTTP/1.1 key:" + key,
		} {
			out, n := s.ScrubText(in)
			if n != 1 {
				t.Errorf("%s: redaction count = %d, want 1 (input %q)", name, n, in)
			}
			if strings.Contains(out, key) || strings.Contains(out, key[len(key)-10:]) {
				t.Errorf("%s: key leaked: %q", name, out)
			}
			if !tokenTagRe.MatchString(out) {
				t.Errorf("%s: no TOKEN tag in %q", name, out)
			}
		}
	}
}

func TestVendorKeyLookalikesUntouched(t *testing.T) {
	s, _ := NewScrubber()
	for _, in := range []string{
		"sk_live_short",
		"npm_config_registry",
		"npm_package_version",
		"hf_dataset_name_here",
		"SG.short.x",
		"ya29.short",
		"glpat-short",
		// Glued to a longer word or identifier.
		"mysk_live_" + vendorBody,
		"task_live_" + vendorBody,
		"my_hf_" + vendorBody,
		// Prefixes are case-sensitive.
		"HF_" + vendorBody,
		// Test-mode keys are not live secrets.
		"sk_test_" + vendorBody,
	} {
		out, n := s.ScrubText(in)
		if out != in || n != 0 {
			t.Errorf("false positive: %q -> %q (%d)", in, out, n)
		}
	}
}

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

func TestIPv6Redaction(t *testing.T) {
	s, _ := NewScrubber()
	cases := []struct {
		in, leak string
		want     int
	}{
		{"peer 2001:db8::1 connected", "2001:db8", 1},
		{"2001:0db8:85a3:0000:0000:8a2e:0370:7334", "85a3", 1},
		{"fe80::1ff:fe23:4567:890a", "fe23", 1},
		{"from [2001:db8::1]:443/x", "2001:db8", 1},
		{"fe80::1%eth0", "eth0", 1},
		{"seen at fe80::abcd.", "abcd", 1},
		{"::ffff:192.0.2.1", "192.0.2.1", 1}, // one unit, not IPv6 plus IPv4
		{"2001:DB8::A", "DB8", 1},
		{`{"ip":"2001:db8::7"}`, "db8", 1},
		{"2001:db8::", "2001", 1},
		{"X-Forwarded-For: 2001:db8::1, 2001:db8::2", "2001:db8", 2},
	}
	for _, c := range cases {
		out, n := s.ScrubText(c.in)
		if n != c.want {
			t.Errorf("%q: count = %d, want %d (out %q)", c.in, n, c.want, out)
		}
		if strings.Contains(out, c.leak) {
			t.Errorf("%q: %q leaked: %q", c.in, c.leak, out)
		}
		if len(ipTagRe.FindAllString(out, -1)) != c.want {
			t.Errorf("%q: IP tags in %q, want %d", c.in, out, c.want)
		}
	}
	if s.IPs.Load() == 0 {
		t.Errorf("IPs counter never moved")
	}

	// Punctuation around an address survives.
	out, _ := s.ScrubText("from [2001:db8::1]:443/x")
	if !strings.HasPrefix(out, "from [[REDACTED_IP#") || !strings.HasSuffix(out, "]]:443/x") {
		t.Errorf("surrounding text damaged: %q", out)
	}
	out, _ = s.ScrubText("seen at fe80::abcd.")
	if !strings.HasSuffix(out, "].") {
		t.Errorf("sentence period lost: %q", out)
	}
}

func TestIPv6CorrelatesAcrossSpellings(t *testing.T) {
	s, _ := NewScrubber()
	a, _ := s.ScrubText("2001:db8::1")
	b, _ := s.ScrubText("2001:0DB8:0:0:0:0:0:1")
	if a != b || !ipTagRe.MatchString(a) {
		t.Errorf("same address, different tags: %q vs %q", a, b)
	}
	c, _ := s.ScrubText("2001:db8::2")
	if a == c {
		t.Errorf("different addresses share a tag: %q", a)
	}
}

// These are the strings an IPv6 rule must leave alone: hex, versions, clock
// times, MAC addresses, namespaces, loopback, ports.
func TestIPv6FalsePositives(t *testing.T) {
	s, _ := NewScrubber()
	for _, in := range []string{
		"v1.2.3", "0xdeadbeef", "deadbeefcafe",
		"sha256:3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
		"12:30:45", "09:16:49.123", "2026-10-29T09:16:49.123Z", "Mon Jan  2 15:04:05 2006",
		"aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55:66:77:88",
		"AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89",
		"std::vector<int>", "Foo::Bar::baz", "x_fe80::1", "::before", "::after", "::face",
		"a::b", "ab::cd", "dead::beef", "dead::beefx",
		"localhost:8080", "key: value", "10:20", "ratio 3:1:2", "a:b:c",
		"http://[::1]:8080/x", "::1", "::", "::ffff:127.0.0.1", "dial tcp [::1]:80: refused",
	} {
		out, n := s.scrubIPv6(in)
		if out != in || n != 0 {
			t.Errorf("false positive: %q -> %q (%d)", in, out, n)
		}
	}
}

func TestIPv6InHeaders(t *testing.T) {
	s, _ := NewScrubber()
	h := http.Header{}
	h.Set("X-Forwarded-For", "2001:db8::1")
	got, n := s.ScrubHeaders(h)
	if n != 1 || strings.Contains(got["X-Forwarded-For"], "2001") {
		t.Errorf("header not scrubbed: %q (%d)", got["X-Forwarded-For"], n)
	}
}

// ---------------------------------------------------------------------------
// named upstreams
// ---------------------------------------------------------------------------

func TestParseTargets(t *testing.T) {
	def, named, err := parseTargets("https://api.example.com")
	if err != nil || def == nil || def.Host != "api.example.com" || len(named) != 0 {
		t.Fatalf("single bare URL: %v %v %v", def, named, err)
	}

	def, named, err = parseTargets("openai=https://api.openai.com, Anthropic=https://api.anthropic.com")
	if err != nil || def != nil || len(named) != 2 {
		t.Fatalf("two named: %v %v %v", def, named, err)
	}
	if named["openai"].Host != "api.openai.com" || named["anthropic"].Host != "api.anthropic.com" {
		t.Errorf("wrong hosts: %v", named)
	}

	def, named, err = parseTargets("https://a.test,openai=https://api.openai.com")
	if err != nil || def == nil || def.Host != "a.test" || len(named) != 1 {
		t.Fatalf("default plus named: %v %v %v", def, named, err)
	}

	// An "=" inside a bare URL is not a name.
	def, named, err = parseTargets("https://a.test/x?y=z")
	if err != nil || def == nil || len(named) != 0 || def.RawQuery != "y=z" {
		t.Fatalf("query string: %v %v %v", def, named, err)
	}

	for _, bad := range []string{
		"", " , ",
		"openai=https://a.test,openai=https://b.test",
		"OpenAI=https://a.test,openai=https://b.test",
		"https://a.test,https://b.test",
		"openai=ftp://a.test",
		"openai=notaurl",
		"=https://a.test",
	} {
		if _, _, err := parseTargets(bad); err == nil {
			t.Errorf("parseTargets(%q) should fail", bad)
		}
	}
}

func TestNamedUpstreamRouting(t *testing.T) {
	app := newTestApp(t)
	seenA, seenB, seenD := &upstreamSeen{}, &upstreamSeen{}, &upstreamSeen{}
	upA, upB, upD := newUpstream(t, seenA), newUpstream(t, seenB), newUpstream(t, seenD)
	ua, _ := url.Parse(upA.URL)
	ub, _ := url.Parse(upB.URL + "/base")
	ud, _ := url.Parse(upD.URL)
	app.upstreams = map[string]*url.URL{"alpha": ua, "beta": ub}
	app.target = ud

	do := func(path string, hdr ...string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		req.Host = "127.0.0.1:8080"
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, req)
		return rec
	}
	pathOf := func(s *upstreamSeen) string {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.path
	}

	if rec := do("/alpha/v1/chat?x=1"); rec.Code != 200 || pathOf(seenA) != "/v1/chat?x=1" {
		t.Errorf("alpha: %d, upstream saw %q", rec.Code, pathOf(seenA))
	}
	if rec := do("/BETA/v1/models"); rec.Code != 200 || pathOf(seenB) != "/base/v1/models" {
		t.Errorf("beta (case-insensitive, base path): %d, upstream saw %q", rec.Code, pathOf(seenB))
	}
	if rec := do("/alpha"); rec.Code != 200 || pathOf(seenA) != "/" {
		t.Errorf("bare prefix: %d, upstream saw %q", rec.Code, pathOf(seenA))
	}
	// A prefix only matches a whole path segment.
	if rec := do("/alphabet/x"); rec.Code != 200 || pathOf(seenD) != "/alphabet/x" {
		t.Errorf("segment boundary: %d, default saw %q", rec.Code, pathOf(seenD))
	}
	if rec := do("/other"); rec.Code != 200 || pathOf(seenD) != "/other" {
		t.Errorf("default fallback: %d, default saw %q", rec.Code, pathOf(seenD))
	}
	// An explicit X-Target-URL beats the prefix and the path is left whole.
	if rec := do("/alpha/q", "X-Target-URL", upD.URL); rec.Code != 200 || pathOf(seenD) != "/alpha/q" {
		t.Errorf("X-Target-URL precedence: %d, default saw %q", rec.Code, pathOf(seenD))
	}
	// A percent-encoded prefix is refused, not guessed at.
	if rec := do("/%61lpha/x"); rec.Code != http.StatusBadRequest {
		t.Errorf("encoded prefix: status %d, want 400", rec.Code)
	}

	// No default: unknown prefixes get a 404 that lists the names (not URLs).
	app.target = nil
	for _, p := range []string{"/gamma/x", "/alphabet/x", "/"} {
		rec := do(p)
		body := rec.Body.String()
		if rec.Code != http.StatusNotFound || !strings.Contains(body, "/alpha/") || !strings.Contains(body, "/beta/") {
			t.Errorf("%s without default: %d %q", p, rec.Code, body)
		}
		if strings.Contains(body, "127.0.0.1:") && strings.Contains(body, "http") {
			t.Errorf("404 must not print upstream URLs: %q", body)
		}
	}
}

func TestNamedUpstreamForwardModeUnaffected(t *testing.T) {
	app := newTestApp(t)
	seen := &upstreamSeen{}
	up := newUpstream(t, seen)
	u, _ := url.Parse(up.URL)
	app.upstreams = map[string]*url.URL{"alpha": u}

	req := httptest.NewRequest("GET", up.URL+"/alpha/x", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	seen.mu.Lock()
	defer seen.mu.Unlock()
	if rec.Code != 200 || seen.path != "/alpha/x" {
		t.Errorf("forward mode must not strip prefixes: %d %q", rec.Code, seen.path)
	}
}

// ---------------------------------------------------------------------------
// TLS trust roots (the Termux "unknown authority" fix)
// ---------------------------------------------------------------------------

func newTLSUpstream(t *testing.T) (*httptest.Server, *url.URL) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "secure ok")
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return srv, u
}

func writeServerCert(t *testing.T, srv *httptest.Server, path string) {
	t.Helper()
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func getVia(app *App) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/ping", nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	return rec
}

func TestHTTPSUpstreamFailsWithoutTrustAndWorksWithCACert(t *testing.T) {
	srv, target := newTLSUpstream(t)

	// This is the Termux symptom: the certificate is not trusted.
	app := newTestApp(t)
	app.target = target
	rec := getVia(app)
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "unknown authority") {
		t.Fatalf("expected an unknown-authority failure, got %d %q", rec.Code, rec.Body.String())
	}

	// -cacert with a PEM file.
	dir := t.TempDir()
	file := filepath.Join(dir, "ca.pem")
	writeServerCert(t, srv, file)
	pool, src, err := buildRootCAs(file, false)
	if err != nil || pool == nil || src != file {
		t.Fatalf("buildRootCAs(file): %v %v %q", pool, err, src)
	}
	app2 := newTestApp(t)
	app2.target = target
	app2.transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if rec := getVia(app2); rec.Code != 200 || rec.Body.String() != "secure ok" {
		t.Errorf("with -cacert file: %d %q", rec.Code, rec.Body.String())
	}

	// -cacert with a directory of PEM files (Android's /system/etc/security/cacerts layout).
	certDir := t.TempDir()
	writeServerCert(t, srv, filepath.Join(certDir, "9a8b7c6d.0"))
	pool, _, err = buildRootCAs(certDir, false)
	if err != nil || pool == nil {
		t.Fatalf("buildRootCAs(dir): %v %v", pool, err)
	}
	app3 := newTestApp(t)
	app3.target = target
	app3.transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if rec := getVia(app3); rec.Code != 200 {
		t.Errorf("with -cacert dir: %d %q", rec.Code, rec.Body.String())
	}
}

func TestBuildRootCAsErrorsAndDefaults(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(empty, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := buildRootCAs(filepath.Join(dir, "missing.pem"), false); err == nil {
		t.Errorf("a missing -cacert path must be an error")
	}
	if _, _, err := buildRootCAs(empty, false); err == nil || !strings.Contains(err.Error(), "no PEM") {
		t.Errorf("a file without certificates must be an error, got %v", err)
	}

	// Off Termux with no flag: Go's default behaviour, nothing changed.
	t.Setenv("SSL_CERT_FILE", "")
	t.Setenv("SSL_CERT_DIR", "")
	if pool, src, err := buildRootCAs("", false); pool != nil || src != "" || err != nil {
		t.Errorf("default must be untouched: %v %q %v", pool, src, err)
	}
}

func TestBuildRootCAsFindsTermuxBundle(t *testing.T) {
	srv, _ := newTLSUpstream(t)
	prefix := t.TempDir()
	if err := os.MkdirAll(filepath.Join(prefix, "etc", "tls"), 0o755); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(prefix, "etc", "tls", "cert.pem")
	writeServerCert(t, srv, bundle)

	t.Setenv("PREFIX", prefix)
	t.Setenv("SSL_CERT_FILE", "")
	t.Setenv("SSL_CERT_DIR", "")
	pool, src, err := buildRootCAs("", true)
	if err != nil || pool == nil || src != bundle {
		t.Fatalf("Termux auto-detect: %v %q %v", pool, src, err)
	}

	// If the user already set SSL_CERT_FILE, Go's own handling is left alone.
	t.Setenv("SSL_CERT_FILE", bundle)
	if pool, _, err := buildRootCAs("", true); pool != nil || err != nil {
		t.Errorf("SSL_CERT_FILE must win: %v %v", pool, err)
	}
}
