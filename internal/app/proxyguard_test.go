package app

import (
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testToken = "0123456789abcdef0123456789abcdef"

func guardedApp(t *testing.T) *App {
	t.Helper()
	app := newTestApp(t)
	app.setProxyToken(testToken)
	return app
}

func proxyAuth(tok string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("nw:"+tok))
}

func TestAuthorizeProxyToken(t *testing.T) {
	app := guardedApp(t)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)
	req.Header.Set("Proxy-Authorization", proxyAuth(testToken))
	if !app.authorize(httptest.NewRecorder(), req) {
		t.Error("the right Proxy-Authorization password must pass")
	}
	if req.Header.Get("Proxy-Authorization") != "" {
		t.Error("the credentials must be removed from the request")
	}

	req = httptest.NewRequest(http.MethodGet, "/_gw/x/", nil)
	req.Header.Set(tokenHeader, testToken)
	if !app.authorize(httptest.NewRecorder(), req) {
		t.Error("the right X-Nullwire-Token must pass")
	}
	if req.Header.Get(tokenHeader) != "" {
		t.Error("the token header must be removed from the request")
	}

	rec := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)
	if app.authorize(rec, req) || rec.Code != http.StatusProxyAuthRequired || rec.Header().Get("Proxy-Authenticate") == "" {
		t.Errorf("a proxy request without a token: %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/_gw/x/", nil)
	req.Header.Set(tokenHeader, "wrong-wrong-wrong-wrong")
	if app.authorize(rec, req) || rec.Code != http.StatusUnauthorized {
		t.Errorf("a wrong token on a gateway request: %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
	req.Header.Set("Proxy-Authorization", proxyAuth("nope"))
	if app.authorize(rec, req) || rec.Code != http.StatusProxyAuthRequired {
		t.Errorf("CONNECT with a wrong token: %d", rec.Code)
	}
}

func TestAuthorizeOffByDefault(t *testing.T) {
	app := newTestApp(t)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)
	if !app.authorize(httptest.NewRecorder(), req) {
		t.Error("without -proxy-token every request must pass")
	}
}

func TestServeHTTPRefusesWithoutToken(t *testing.T) {
	app := guardedApp(t)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com/x", nil))
	if rec.Code != http.StatusProxyAuthRequired {
		t.Errorf("ServeHTTP without a token: %d, want 407", rec.Code)
	}
	if app.ring.Total() != 0 {
		t.Error("a refused request must not be captured")
	}
}

func TestValidProxyToken(t *testing.T) {
	if err := validProxyToken(testToken); err != nil {
		t.Errorf("good token: %v", err)
	}
	for _, bad := range []string{"", "short", strings.Repeat("a", 15), "0123456789abcdef@0123", "0123456789abcdef 0123", "0123456789abcdef/0123"} {
		if err := validProxyToken(bad); err == nil {
			t.Errorf("validProxyToken(%q) must fail", bad)
		}
	}
	tok, err := newProxyToken()
	if err != nil || len(tok) != 48 || validProxyToken(tok) != nil {
		t.Errorf("newProxyToken = %q, %v", tok, err)
	}
}

func TestParseListen(t *testing.T) {
	if p, err := parseListen("unix:///tmp/nw.sock"); err != nil || p != "/tmp/nw.sock" {
		t.Errorf("good spec: %q %v", p, err)
	}
	for _, bad := range []string{"", "tcp://127.0.0.1:1", "/tmp/nw.sock", "unix://relative.sock", "0.0.0.0:8080"} {
		if _, err := parseListen(bad); err == nil {
			t.Errorf("parseListen(%q) must fail", bad)
		}
	}
}

func TestListenUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets: Linux and macOS")
	}
	dir, err := os.MkdirTemp("", "nw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "p.sock")

	ln, err := listenUnix(path)
	if err != nil {
		t.Fatalf("listenUnix: %v", err)
	}
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket file: %v %v", fi, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("no temporary files may remain, got %d entries", len(entries))
	}
	// A live socket is refused.
	if _, err := listenUnix(path); err == nil {
		t.Error("a socket that is in use must be refused")
	}
	// A stale socket file is replaced.
	_ = ln.Close()
	ln2, err := listenUnix(path)
	if err != nil {
		t.Fatalf("stale socket: %v", err)
	}
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = c.Close()
	_ = ln2.Close()
	// Anything that is not a socket is refused.
	other := filepath.Join(dir, "file")
	if err := os.WriteFile(other, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenUnix(other); err == nil {
		t.Error("a regular file must be refused")
	}
}

func TestProxyTokenFromForms(t *testing.T) {
	basic := func(s string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte(s)) }
	for _, c := range []struct {
		name         string
		token, proxy string
		want         string
	}{
		{"nothing", "", "", ""},
		{"token header, trimmed", "  " + testToken + "  ", "", testToken},
		{"basic with any user", "", basic("anyone:" + testToken), testToken},
		{"token header wins over basic", "from-header", basic("nw:from-basic"), "from-header"},
		{"blank token header falls back to basic", "   ", basic("nw:" + testToken), testToken},
		{"bearer scheme is not read", "", "Bearer " + testToken, ""},
		{"basic with bad base64", "", "Basic !!!not-base64!!!", ""},
		{"basic without a colon", "", basic("nocolon"), ""},
		{"basic with an empty password", "", basic("nw:"), ""},
	} {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)
		if c.token != "" {
			req.Header.Set(tokenHeader, c.token)
		}
		if c.proxy != "" {
			req.Header.Set("Proxy-Authorization", c.proxy)
		}
		if got := proxyTokenFrom(req); got != c.want {
			t.Errorf("%s: proxyTokenFrom = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestAuthorizeRefusesEmptyAndAcceptsPaddedToken(t *testing.T) {
	app := guardedApp(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)
	req.Header.Set("Proxy-Authorization", proxyAuth("")) // "nw:" carries an empty password
	if app.authorize(rec, req) || rec.Code != http.StatusProxyAuthRequired {
		t.Errorf("an empty password: %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
	if app.authorize(rec, req) || rec.Code != http.StatusProxyAuthRequired || rec.Header().Get("Proxy-Authenticate") == "" {
		t.Errorf("CONNECT without credentials: %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/_gw/x/", nil)
	if app.authorize(rec, req) || rec.Code != http.StatusUnauthorized || rec.Header().Get("Proxy-Authenticate") != "" {
		t.Errorf("a gateway request without credentials must be 401 without Proxy-Authenticate: %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/_gw/x/", nil)
	req.Header.Set(tokenHeader, " "+testToken+" ")
	if !app.authorize(httptest.NewRecorder(), req) {
		t.Error("a token with surrounding spaces must pass")
	}
}

func edgeSockDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets: Linux and macOS")
	}
	// Short, so the socket path stays under the sun_path limit.
	dir, err := os.MkdirTemp("", "nw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0o700)
		_ = os.RemoveAll(dir)
	})
	return dir
}

// deadSocket leaves a socket file with nothing listening behind it.
func deadSocket(t *testing.T, path string) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	_ = ln.Close()
	if fi, err := os.Lstat(path); err != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("setup: expected a leftover socket file, got %v, %v", fi, err)
	}
}

func TestParseListenEdges(t *testing.T) {
	for _, c := range []struct{ spec, want string }{
		{"unix:///tmp/nw.sock", "/tmp/nw.sock"},
		{"  unix:///tmp/nw.sock \n", "/tmp/nw.sock"},
		{"unix:///tmp//a/../nw.sock", "/tmp/nw.sock"},
		{"unix:///run/user/1000/nullwire.sock", "/run/user/1000/nullwire.sock"},
	} {
		if p, err := parseListen(c.spec); err != nil || p != c.want {
			t.Errorf("parseListen(%q) = %q, %v; want %q", c.spec, p, err, c.want)
		}
	}
	// Anything but unix://: the error points at the right syntax.
	for _, spec := range []string{"", "   ", "/tmp/nw.sock", "unix:/tmp/nw.sock", "UNIX:///tmp/nw.sock", "tcp://127.0.0.1:1", "127.0.0.1:8080"} {
		p, err := parseListen(spec)
		if err == nil || p != "" || !strings.Contains(err.Error(), "unix:///") {
			t.Errorf("parseListen(%q) = %q, %v; want a unix:// usage error", spec, p, err)
		}
	}
	// unix:// with no path, or a relative one: an absolute path is required.
	for _, spec := range []string{"unix://", "unix://   ", "unix://nw.sock", "unix://./nw.sock", "unix://../nw.sock", "unix://run/nw.sock"} {
		p, err := parseListen(spec)
		if err == nil || p != "" || !strings.Contains(err.Error(), "absolute") {
			t.Errorf("parseListen(%q) = %q, %v; want an absolute-path error", spec, p, err)
		}
	}
}

func TestListenUnixRefusesNonSocket(t *testing.T) {
	dir := edgeSockDir(t)

	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "subdir")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	// A symlink is not a socket either, even when it points at one.
	sock := filepath.Join(dir, "sock.sock")
	deadSocket(t, sock)
	link := filepath.Join(dir, "link.sock")
	if err := os.Symlink(sock, link); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{file, sub, link} {
		ln, err := listenUnix(p)
		if err == nil || !strings.Contains(err.Error(), "not a socket") || !strings.Contains(err.Error(), p) {
			if ln != nil {
				_ = ln.Close()
			}
			t.Errorf("listenUnix(%s) = %v; want a \"not a socket\" refusal", p, err)
		}
	}
	// Nothing was removed or replaced.
	if b, err := os.ReadFile(file); err != nil || string(b) != "keep" {
		t.Errorf("regular file was touched: %q, %v", b, err)
	}
	if fi, err := os.Lstat(sub); err != nil || !fi.IsDir() {
		t.Errorf("directory was touched: %v, %v", fi, err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("symlink was touched: %v, %v", fi, err)
	}
	if fi, err := os.Lstat(sock); err != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Errorf("socket behind the symlink was touched: %v, %v", fi, err)
	}
}

func TestListenUnixRefusesLiveSocket(t *testing.T) {
	dir := edgeSockDir(t)
	path := filepath.Join(dir, "live.sock")

	live, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = live.Close() })

	ln, err := listenUnix(path)
	if err == nil || !strings.Contains(err.Error(), "already in use") || !strings.Contains(err.Error(), path) {
		if ln != nil {
			_ = ln.Close()
		}
		t.Fatalf("listenUnix on a live socket = %v; want \"already in use\"", err)
	}
	// The original listener is untouched and still reachable.
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("the live socket was disturbed: %v", err)
	}
	_ = c.Close()
	// No temporary directory was left behind.
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("expected only the live socket in %s, got %d entries", dir, len(entries))
	}
}

func TestListenUnixReplacesStaleSocket(t *testing.T) {
	dir := edgeSockDir(t)
	path := filepath.Join(dir, "stale.sock")
	deadSocket(t, path)

	ln, err := listenUnix(path)
	if err != nil {
		t.Fatalf("a dead socket must be cleaned up and reused: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("replacement socket: %v, %v", fi, err)
	}
	// It is the new listener that answers.
	accepted := make(chan struct{})
	go func() {
		if c, err := ln.Accept(); err == nil {
			_ = c.Close()
		}
		close(accepted)
	}()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial the replacement: %v", err)
	}
	_ = c.Close()
	<-accepted
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("temporary files remain: %d entries", len(entries))
	}
}

// A dead socket that cannot be removed is reported, not ignored.
func TestListenUnixStaleSocketNotRemovable(t *testing.T) {
	dir := edgeSockDir(t)
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(locked, "s.sock")
	deadSocket(t, path)
	if err := os.Chmod(locked, 0o500); err != nil { // no write: unlink is refused
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })

	ln, err := listenUnix(path)
	if err == nil || !strings.HasPrefix(err.Error(), "-listen:") {
		if ln != nil {
			_ = ln.Close()
		}
		t.Fatalf("listenUnix = %v; want a -listen error", err)
	}
	if fi, err := os.Lstat(path); err != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Errorf("the stale socket should still be there: %v, %v", fi, err)
	}
}
