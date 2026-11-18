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
