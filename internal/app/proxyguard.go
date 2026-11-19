package app

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Local isolation without a local CA.
//
// The proxy stays on 127.0.0.1 and does no TLS interception. To keep other
// local users and processes out, -proxy-token makes every request carry a
// shared secret: HTTP_PROXY=http://nw:<token>@127.0.0.1:<port> works in curl,
// Python, Node and most SDKs because they send it as Proxy-Authorization; a
// gateway client can send X-Nullwire-Token instead. -listen unix:///path
// (Linux and macOS, opt-in) adds a kernel-enforced 0600 socket.

const (
	tokenHeader    = "X-Nullwire-Token"
	tokenEnv       = "NULLWIRE_PROXY_TOKEN"
	minTokenLength = 16
	maxSockPath    = 100 // sun_path is 104 bytes on macOS, 108 on Linux
)

func validProxyToken(tok string) error {
	if len(tok) < minTokenLength {
		return fmt.Errorf("-proxy-token must be at least %d characters (use \"auto\" to make one)", minTokenLength)
	}
	for _, c := range tok {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~'
		if !ok {
			return errors.New("-proxy-token may only hold letters, digits and - . _ ~ so it is safe inside a proxy URL")
		}
	}
	return nil
}

// newProxyToken returns 24 random bytes as 48 hex characters.
func newProxyToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (a *App) setProxyToken(tok string) {
	a.tokenOn = tok != ""
	a.tokenSum = sha256.Sum256([]byte(tok))
}

// proxyTokenFrom takes the token from X-Nullwire-Token, or else from the
// password of Proxy-Authorization: Basic (any user name).
func proxyTokenFrom(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get(tokenHeader)); v != "" {
		return v
	}
	probe := http.Request{Header: http.Header{"Authorization": r.Header.Values("Proxy-Authorization")}}
	if _, pass, ok := probe.BasicAuth(); ok {
		return pass
	}
	return ""
}

// authorize returns true when no token is required or the request carries the
// right one. The credentials are removed from the request either way, so
// they are never forwarded upstream or stored in a captured flow.
func (a *App) authorize(w http.ResponseWriter, r *http.Request) bool {
	if !a.tokenOn {
		return true
	}
	got := proxyTokenFrom(r)
	r.Header.Del("Proxy-Authorization")
	r.Header.Del(tokenHeader)
	sum := sha256.Sum256([]byte(got))
	if got != "" && subtle.ConstantTimeCompare(sum[:], a.tokenSum[:]) == 1 {
		return true
	}
	a.Logf("refused a request without a valid proxy token")
	if r.Method == http.MethodConnect || (r.URL != nil && r.URL.IsAbs()) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="nullwire-mcp"`)
		http.Error(w, "nullwire-mcp: proxy token required (use http://nw:<token>@host:port as the proxy URL)", http.StatusProxyAuthRequired)
		return false
	}
	http.Error(w, "nullwire-mcp: proxy token required (send "+tokenHeader+")", http.StatusUnauthorized)
	return false
}

// parseListen accepts only unix:///absolute/path.sock.
func parseListen(spec string) (string, error) {
	path, ok := strings.CutPrefix(strings.TrimSpace(spec), "unix://")
	if !ok {
		return "", errors.New("-listen takes unix:///absolute/path.sock; the TCP listener is always 127.0.0.1 (see -port)")
	}
	if !filepath.IsAbs(path) {
		return "", errors.New("-listen unix:// needs an absolute path, as in unix:///run/user/1000/nullwire.sock")
	}
	return filepath.Clean(path), nil
}

// listenUnix opens the socket with mode 0600 and no window in which it is
// more open: it is made inside a fresh 0700 directory, chmodded, and only then
// moved to its final name. A stale socket file is replaced; a live one, or any
// other kind of file, is refused. The caller removes the file at exit.
func listenUnix(path string) (net.Listener, error) {
	if runtime.GOOS == "windows" {
		return nil, errors.New("-listen unix:// is for Linux and macOS")
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("-listen: %s exists and is not a socket", path)
		}
		if c, err := net.DialTimeout("unix", path, 500*time.Millisecond); err == nil {
			_ = c.Close()
			return nil, fmt.Errorf("-listen: %s is already in use", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("-listen: %v", err)
		}
	}
	dir, err := os.MkdirTemp(filepath.Dir(path), ".nullwire-") // 0700
	if err != nil {
		return nil, fmt.Errorf("-listen: %v", err)
	}
	defer func() { _ = os.Remove(dir) }()
	tmp := filepath.Join(dir, "s")
	if len(tmp) > maxSockPath || len(path) > maxSockPath {
		return nil, errors.New("-listen: the socket path is too long for this system")
	}
	ln, err := net.Listen("unix", tmp)
	if err != nil {
		return nil, fmt.Errorf("-listen: %v", err)
	}
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false) // the file is renamed below; the caller removes the final name
	}
	fail := func(err error) (net.Listener, error) {
		_ = ln.Close()
		_ = os.Remove(tmp)
		_ = os.Remove(path)
		return nil, fmt.Errorf("-listen: %v", err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return fail(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fail(err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return fail(err)
	}
	if fi.Mode().Perm() != 0o600 {
		return fail(fmt.Errorf("socket mode is %o, want 600", fi.Mode().Perm()))
	}
	return ln, nil
}
