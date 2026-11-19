package app

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
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
	} {
		out, n := s.ScrubText(in)
		if out != in || n != 0 {
			t.Errorf("false positive: %q -> %q (%d)", in, out, n)
		}
	}

	// Glued to a longer word, or the wrong case. These are long random-looking
	// strings, so the generic high-entropy layer (TestHighEntropyCatch) is
	// allowed to redact them. What must not happen is a vendor prefix rule
	// claiming them, so probe the rules directly.
	for _, in := range []string{
		"mysk_live_" + vendorBody,
		"task_live_" + vendorBody,
		"my_hf_" + vendorBody,
		"HF_" + vendorBody, // prefixes are case-sensitive
	} {
		for _, vr := range s.vendorRules {
			if m := vr.re.FindString(in); m != "" && (!vr.weak || weakVendorMatchOK(m, vr.prefixes)) {
				t.Errorf("vendor rule matched a lookalike: %q (matched %q)", in, m)
			}
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
		{"::ffff:192.0.2.1", "192.0.2.1", 1},
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

// ---------------------------------------------------------------------------
// coverage: TLS trust files, config loading and scrubber edge branches
// ---------------------------------------------------------------------------

func TestCovAddPEMPathBranches(t *testing.T) {
	srv, _ := newTLSUpstream(t)
	dir := t.TempDir()
	good := filepath.Join(dir, "good.pem")
	writeServerCert(t, srv, good)
	badPEM := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(badPEM, []byte("-----BEGIN CERTIFICATE-----\nnot base64 !!\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	garbage := filepath.Join(dir, "garbage.bin")
	if err := os.WriteFile(garbage, []byte("\x00\x01\x02 not pem at all"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A missing path is an error, not an empty result.
	if ok, err := addPEMPath(x509.NewCertPool(), filepath.Join(dir, "missing.pem")); ok || err == nil {
		t.Errorf("missing file: ok=%v err=%v, want an error", ok, err)
	}
	// A file that holds no certificate adds nothing and is not an error.
	for _, p := range []string{badPEM, garbage} {
		if ok, err := addPEMPath(x509.NewCertPool(), p); ok || err != nil {
			t.Errorf("%s: ok=%v err=%v, want false and no error", filepath.Base(p), ok, err)
		}
	}
	if ok, err := addPEMPath(x509.NewCertPool(), good); !ok || err != nil {
		t.Errorf("valid certificate file: ok=%v err=%v", ok, err)
	}

	// A folder: junk and sub-folders are skipped, one good file is enough.
	mixed := t.TempDir()
	if err := os.WriteFile(filepath.Join(mixed, "junk.txt"), []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(mixed, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeServerCert(t, srv, filepath.Join(mixed, "ok.pem"))
	if ok, err := addPEMPath(x509.NewCertPool(), mixed); !ok || err != nil {
		t.Errorf("folder with one good file: ok=%v err=%v", ok, err)
	}
	junkOnly := t.TempDir()
	if err := os.WriteFile(filepath.Join(junkOnly, "junk.txt"), []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, err := addPEMPath(x509.NewCertPool(), junkOnly); ok || err != nil {
		t.Errorf("folder with only junk: ok=%v err=%v, want false and no error", ok, err)
	}
	if ok, err := addPEMPath(x509.NewCertPool(), t.TempDir()); ok || err != nil {
		t.Errorf("empty folder: ok=%v err=%v, want false and no error", ok, err)
	}
}

func TestCovTermuxCAPaths(t *testing.T) {
	const termuxBundle = "/data/data/com.termux/files/usr/etc/tls/cert.pem"
	const androidStore = "/system/etc/security/cacerts"

	t.Setenv("PREFIX", "/opt/pfx")
	got := termuxCAPaths()
	want := []string{"/opt/pfx/etc/tls/cert.pem", "/opt/pfx/etc/ssl/certs/ca-certificates.crt", termuxBundle, androidStore}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("with PREFIX = %v, want %v", got, want)
	}

	t.Setenv("PREFIX", "")
	got = termuxCAPaths()
	want = []string{termuxBundle, androidStore}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("without PREFIX = %v, want %v", got, want)
	}
}

func covWriteConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCovLoadSecretsConfigErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.json")
	if cfg, err := loadSecretsConfig(missing); err == nil || cfg != nil || !strings.Contains(err.Error(), "-secrets-config") || !strings.Contains(err.Error(), missing) {
		t.Errorf("missing file: %v %v", cfg, err)
	}
	if cfg, err := loadSecretsConfig(t.TempDir()); err == nil || cfg != nil {
		t.Errorf("a folder is not a config file: %v %v", cfg, err)
	}

	cases := []struct{ name, body, want string }{
		{"truncated json", `{"sensitive_headers": [`, "invalid JSON"},
		{"not json", `this is not json`, "invalid JSON"},
		{"wrong type", `{"sensitive_headers": "X-Secret"}`, "invalid JSON"},
		{"empty extra pattern", `{"extra_regex_patterns":[{"name":"n","pattern":""}]}`, "extra_regex_patterns[0] has empty pattern"},
		{"invalid extra regex", `{"extra_regex_patterns":[{"name":"ok","pattern":"abc[0-9]+"},{"name":"broken","pattern":"(unclosed"}]}`, "extra_regex_patterns[1]"},
		{"invalid ignore pattern", `{"ignore_patterns":["(unclosed"]}`, "-secrets-config"},
		{"empty ignore field", `{"ignore_fields":[""]}`, "ignore_fields[0] is empty"},
		{"invalid vendor regex", `{"custom_vendors":[{"name":"acme","prefix":"ac_","pattern":"(bad"}]}`, "custom_vendors[0]"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := covWriteConfig(t, c.body)
			cfg, err := loadSecretsConfig(path)
			if err == nil || cfg != nil {
				t.Fatalf("want an error and no config, got %v / %v", cfg, err)
			}
			if !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), path) {
				t.Errorf("error = %q, want it to name the file and contain %q", err, c.want)
			}
		})
	}
}

func TestCovLoadSecretsConfigAccepts(t *testing.T) {
	if cfg, err := loadSecretsConfig(""); err != nil || cfg == nil {
		t.Errorf("no path means an empty config: %v %v", cfg, err)
	}
	if cfg, err := loadSecretsConfig(covWriteConfig(t, `{}`)); err != nil || cfg == nil || len(cfg.ExtraRegexPatterns) != 0 {
		t.Errorf("empty object: %v %v", cfg, err)
	}
	cfg, err := loadSecretsConfig(covWriteConfig(t, `{
		"sensitive_headers": ["X-Internal"],
		"ignore_url_substrings": ["/healthz"],
		"extra_regex_patterns": [{"name": "emp", "pattern": "EMP-[0-9]{6}"}],
		"custom_vendors": [{"name": "acme", "prefix": "ac_"}]
	}`))
	if err != nil || cfg == nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if len(cfg.SensitiveHeaders) != 1 || cfg.SensitiveHeaders[0] != "X-Internal" ||
		len(cfg.IgnoreURLSubstrings) != 1 || cfg.IgnoreURLSubstrings[0] != "/healthz" ||
		len(cfg.ExtraRegexPatterns) != 1 || cfg.ExtraRegexPatterns[0].Name != "emp" ||
		len(cfg.CustomVendors) != 1 || cfg.CustomVendors[0].Prefix != "ac_" {
		t.Errorf("config = %+v", cfg)
	}
}

func TestCovSignatureValueOK(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"AbCdEfGhIjKl%2FMnOp%3D", true},
		{"AbCdEfGhIjKl%2F", true},
		{"AbCdEfGhIjK/lMn", true},
		{"AbCd+EfGhIjKlMn", true},
		{"AbCdEfGh=IjKlMn", true},
		{"AbCdEfGhIjKlMnOpQrSt", false},
		{"short%2F", false},
		{"AbCdEfGhIjKl%2", false},
		{"AbCdEfGhIjKl%ZZ", false},
		{"AbCdEfGhIjKl!", false},
		{"Ab.CdEfGhIjKlMn", false},
		{"https://x.example.com/a", false},
		{"/abs/path/value1234", false},
	}
	for _, c := range cases {
		if got := signatureValueOK(c.in); got != c.want {
			t.Errorf("signatureValueOK(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestCovScrubStrictFieldsMax(t *testing.T) {
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}

	// Azure SAS signature, percent-encoded and plain base64 with "/".
	for _, c := range []struct{ name, in string }{
		{"percent-encoded", "sv=2022-11-02&sig=AbCdEfGhIjKlMnOp%2FQrStUv%3D&sp=r"},
		{"plain base64", "sv=2022-11-02&sig=Zm9vYmFyYmF6/quxQUJDREVGR0g=&sp=r"},
	} {
		name, in := c.name, c.in
		out, n := s.scrubStrictFieldsMax(in, 2048)
		if n != 1 || !tokenTagRe.MatchString(out) || !strings.HasPrefix(out, "sv=2022-11-02&sig=[REDACTED_TOKEN#") || !strings.HasSuffix(out, "]&sp=r") {
			t.Errorf("%s: %q (n=%d)", name, out, n)
		}
		if strings.Contains(out, "AbCdEf") || strings.Contains(out, "Zm9vYm") {
			t.Errorf("%s: the signature survived: %q", name, out)
		}
	}

	// A signature-named field whose value has dots and no base64 symbol is not a signature.
	if out, n := s.scrubStrictFieldsMax("x=1&sig=com.example.signature&y=2", 2048); n != 0 || out != "x=1&sig=com.example.signature&y=2" {
		t.Errorf("dotted lower-case value: %q (n=%d), want it untouched", out, n)
	}

	// JSON that is itself inside a JSON string, so every quote is escaped.
	esc := `{\"api_key\":\"Sup3rS3cretValue12345\"}`
	out, n := s.scrubStrictFieldsMax(esc, 256)
	if n != 1 || !tokenTagRe.MatchString(out) || strings.Contains(out, "Sup3rS3cret") ||
		!strings.HasPrefix(out, `{\"api_key\":\"[REDACTED_TOKEN#`) || !strings.HasSuffix(out, `]\"}`) {
		t.Errorf("escaped JSON: %q (n=%d)", out, n)
	}

	// The value-length limit: 256 for bodies, 2048 for headers and queries.
	long := "api_key=" + strings.Repeat("Ab3dEf7hIj", 30) // a 300-byte value
	if out, n := s.scrubStrictFieldsMax(long, 256); n != 0 || out != long {
		t.Errorf("a value over the limit must be left alone: n=%d", n)
	}
	if out, n := s.scrubStrictFieldsMax(long, 2048); n != 1 || !tokenTagRe.MatchString(out) {
		t.Errorf("the wider limit must redact it: %q (n=%d)", out, n)
	}

	// Inputs that must pass through unchanged.
	for _, in := range []string{
		"k=v",
		"api_key=[REDACTED_TOKEN#abc123]",
		"api_key=${SECRET_VALUE_HERE}",
	} {
		if out, n := s.scrubStrictFieldsMax(in, 256); n != 0 || out != in {
			t.Errorf("%q changed to %q (n=%d)", in, out, n)
		}
	}
}

func TestCovIPv6Redactable(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"2001:db8::1", true},
		{"fe80::", true},
		{"fe80::1%eth0", true},
		{"::ffff:8.8.8.8", true},
		{"::ffff:127.0.0.1", false},
		{"::ffff:7f00:1", false},
		{"::ffff:0.0.0.0", false},
		{"::1", false},
		{"::", false},
		{"a::b", false},
		{"dead::beef", false},
		{"::a", false},
		{"a:b::c", true},
		{"dead:beef::cafe", true},
	}
	for _, c := range cases {
		if got := ipv6Redactable(netip.MustParseAddr(c.addr)); got != c.want {
			t.Errorf("ipv6Redactable(%s) = %v, want %v", c.addr, got, c.want)
		}
	}
	if ipv6Redactable(netip.MustParseAddr("1.2.3.4")) {
		t.Errorf("an IPv4 address is not an IPv6 one")
	}
}

func TestCovScrubIPv6EdgeBranches(t *testing.T) {
	s, err := NewScrubber()
	if err != nil {
		t.Fatal(err)
	}

	// A zone id belongs to the address and goes with it.
	out, n := s.scrubIPv6("peer fe80::1%eth0 ok")
	if n != 1 || !ipTagRe.MatchString(out) || strings.Contains(out, "eth0") || strings.Contains(out, "fe80") ||
		!strings.HasPrefix(out, "peer ") || !strings.HasSuffix(out, " ok") {
		t.Errorf("zone: %q (n=%d)", out, n)
	}

	// An IPv4-mapped public address is redacted.
	if out, n = s.scrubIPv6("via ::ffff:8.8.8.8 ok"); n != 1 || strings.Contains(out, "8.8.8.8") || !ipTagRe.MatchString(out) {
		t.Errorf("mapped public: %q (n=%d)", out, n)
	}

	// Loopback, the unspecified address and a mapped loopback stay as they are.
	for _, in := range []string{"bind ::ffff:127.0.0.1 now", "listen on ::1 now", "wildcard :: now"} {
		if out, n = s.scrubIPv6(in); n != 0 || out != in {
			t.Errorf("%q changed to %q (n=%d)", in, out, n)
		}
	}

	// Letters only: fewer than 3 groups is text, 3 or more is an address.
	const twoGroups = "ids a::b here"
	if out, n = s.scrubIPv6(twoGroups); n != 0 || out != twoGroups {
		t.Errorf("%q changed to %q (n=%d)", twoGroups, out, n)
	}
	if out, n = s.scrubIPv6("x a:b::c y"); n != 1 || !ipTagRe.MatchString(out) {
		t.Errorf("three letter groups: %q (n=%d)", out, n)
	}

	// Things with colons that are not IPv6 at all.
	for _, in := range []string{"at 12:30:45 today", "ratio 12:30", "no colons here"} {
		if out, n = s.scrubIPv6(in); n != 0 || out != in {
			t.Errorf("%q changed to %q (n=%d)", in, out, n)
		}
	}
}
