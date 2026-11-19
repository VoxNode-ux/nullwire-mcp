package app

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestListenUnixPathTooLong(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets: Linux and macOS")
	}
	base, err := os.MkdirTemp("", "nw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })

	// 1. The final socket path itself is over the limit.
	long := filepath.Join(base, strings.Repeat("a", maxSockPath+10)+".sock")
	if len(long) <= maxSockPath {
		t.Fatalf("test path is not long enough: %d", len(long))
	}
	if _, err := listenUnix(long); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Errorf("a path over %d bytes must be refused: %v", maxSockPath, err)
	}

	// 2. The final path fits but the temporary one (inside .nullwire-XXXX/) does not.
	pad := 90 - len(base) - 1
	if pad < 1 {
		t.Skipf("temp dir %q is too long for the second case", base)
	}
	deep := filepath.Join(base, strings.Repeat("d", pad))
	if err := os.Mkdir(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	short := filepath.Join(deep, "p.sock")
	if len(short) > maxSockPath {
		t.Fatalf("final path should fit: %d", len(short))
	}
	if _, err := listenUnix(short); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Errorf("a temporary path over the limit must be refused: %v", err)
	}
	// The failed attempts leave nothing behind.
	for _, d := range []string{base, deep} {
		entries, _ := os.ReadDir(d)
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".nullwire-") || strings.HasSuffix(e.Name(), ".sock") {
				t.Errorf("leftover %s in %s", e.Name(), d)
			}
		}
	}
}

func TestListenUnixMissingParentDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets: Linux and macOS")
	}
	base, err := os.MkdirTemp("", "nw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	path := filepath.Join(base, "missing", "p.sock")
	ln, err := listenUnix(path)
	if err == nil {
		_ = ln.Close()
		t.Fatal("a missing parent directory must be an error")
	}
	if !strings.HasPrefix(err.Error(), "-listen:") {
		t.Errorf("error should be prefixed with -listen: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(base, "missing")); !os.IsNotExist(statErr) {
		t.Errorf("the parent directory must not be created: %v", statErr)
	}
}

// headerUpstream records the headers and the number of requests it receives.
type headerUpstream struct {
	mu   sync.Mutex
	hits int
	hdr  http.Header
	*httptest.Server
}

func newHeaderUpstream(t *testing.T) *headerUpstream {
	t.Helper()
	u := &headerUpstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.hits++
		u.hdr = r.Header.Clone()
		u.mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(u.Close)
	return u
}

func (u *headerUpstream) snapshot() (int, http.Header) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hits, u.hdr.Clone()
}

// assertNoCredentials fails if a header map still carries the proxy token in
// any spelling.
func assertNoCredentials(t *testing.T, where string, h func(string) []string, names []string) {
	t.Helper()
	for _, n := range names {
		if v := h(n); len(v) != 0 {
			t.Errorf("%s still has %s: %q", where, n, v)
		}
	}
}

func TestServeHTTPStripsProxyCredentialsEndToEnd(t *testing.T) {
	creds := []string{"Proxy-Authorization", tokenHeader}

	t.Run("reverse gateway form", func(t *testing.T) {
		app := guardedApp(t)
		up := newHeaderUpstream(t)
		req := httptest.NewRequest(http.MethodGet, "/ping", nil)
		req.Host = "127.0.0.1:8080"
		req.Header.Set("X-Target-URL", up.URL)
		req.Header.Set(tokenHeader, testToken)
		req.Header.Set("Proxy-Authorization", proxyAuth(testToken))
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
			t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
		}
		hits, hdr := up.snapshot()
		if hits != 1 {
			t.Fatalf("upstream hits = %d", hits)
		}
		assertNoCredentials(t, "the upstream request", func(n string) []string { return hdr.Values(n) }, creds)
		assertNoCredentials(t, "the client request", func(n string) []string { return req.Header.Values(n) }, creds)
		assertCapturedWithoutToken(t, app)
	})

	t.Run("absolute proxy form", func(t *testing.T) {
		app := guardedApp(t)
		up := newHeaderUpstream(t)
		req := httptest.NewRequest(http.MethodGet, up.URL+"/abs", nil)
		req.Header.Set("Proxy-Authorization", proxyAuth(testToken))
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
		}
		hits, hdr := up.snapshot()
		if hits != 1 {
			t.Fatalf("upstream hits = %d", hits)
		}
		assertNoCredentials(t, "the upstream request", func(n string) []string { return hdr.Values(n) }, creds)
		assertCapturedWithoutToken(t, app)
	})

	t.Run("refused requests are stripped and never forwarded", func(t *testing.T) {
		app := guardedApp(t)
		up := newHeaderUpstream(t)
		req := httptest.NewRequest(http.MethodGet, up.URL+"/abs", nil)
		req.Header.Set("Proxy-Authorization", proxyAuth("wrong-wrong-wrong-wrong"))
		req.Header.Set(tokenHeader, "wrong-wrong-wrong-wrong")
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, req)
		if rec.Code != http.StatusProxyAuthRequired {
			t.Fatalf("status %d, want 407", rec.Code)
		}
		if hits, _ := up.snapshot(); hits != 0 {
			t.Errorf("a refused request reached upstream %d times", hits)
		}
		assertNoCredentials(t, "the refused request", func(n string) []string { return req.Header.Values(n) }, creds)
		if app.ring.Total() != 0 {
			t.Error("a refused request must not be captured")
		}
	})
}

func assertCapturedWithoutToken(t *testing.T, app *App) {
	t.Helper()
	waitForRing(t, app, 1)
	e := app.ring.ListRecent(1, "", "")
	if len(e) != 1 {
		t.Fatalf("captured %d flows", len(e))
	}
	for k, v := range e[0].RequestHeaders {
		lk := strings.ToLower(k)
		if lk == "proxy-authorization" || lk == strings.ToLower(tokenHeader) || strings.Contains(v, testToken) {
			t.Errorf("the captured flow holds the proxy credential: %s: %s", k, v)
		}
	}
}
