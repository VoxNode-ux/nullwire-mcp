package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Network fault-injection ("chaos") tests. They check that hostile or broken
// peers can neither crash the proxy nor make it leak a secret, and that it keeps
// serving normal requests afterwards. Everything is local and uses fake secrets.

const chaosSecret = "tok_supersecretvalue_12345"

// chaosUpstream starts a raw TCP "server" whose behaviour is decided by handle.
// It returns a base URL usable as X-Target-URL.
func chaosUpstream(t *testing.T, handle func(c net.Conn, br *bufio.Reader)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				handle(c, bufio.NewReader(c))
			}(c)
		}
	}()
	return "http://" + ln.Addr().String()
}

// chaosGateway sends one GET through the reverse gateway and returns the recorder.
func chaosGateway(app *App, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/v1/data", nil)
	req.Host = "127.0.0.1:8080"
	req.Header.Set("X-Target-URL", target)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	return rec
}

// chaosNoLeak waits briefly for the asynchronous capture and then checks that
// no stored flow holds the secret. No flow at all also means nothing leaked.
func chaosNoLeak(t *testing.T, app *App) {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for app.ring.Len() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	for _, e := range app.ring.ListRecent(50, "", "") {
		blob := e.URL + e.RequestBody + e.ResponseBody + e.Note
		for _, v := range e.RequestHeaders {
			blob += v
		}
		for _, v := range e.ResponseHeaders {
			blob += v
		}
		if strings.Contains(blob, chaosSecret) {
			t.Errorf("secret leaked into a stored flow: %+v", e)
		}
	}
}

// chaosStillServes proves the proxy is healthy by completing a normal request.
func chaosStillServes(t *testing.T, app *App) {
	t.Helper()
	seen := &upstreamSeen{}
	up := newUpstream(t, seen)
	rec := chaosGateway(app, up.URL)
	if rec.Code != http.StatusOK {
		t.Fatalf("proxy no longer serves normal requests: status %d, body %q", rec.Code, rec.Body.String())
	}
}

func TestChaosSlowlorisHeaderTimeout(t *testing.T) {
	app := newTestApp(t)
	srv := httptest.NewUnstartedServer(app)
	// main() uses 10s; a short value keeps the test fast and checks the same mechanism.
	srv.Config.ReadHeaderTimeout = 300 * time.Millisecond
	srv.Start()
	t.Cleanup(srv.Close)

	var conns []net.Conn
	for i := 0; i < 8; i++ {
		c, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		// A header that never ends: the classic slowloris opening.
		fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Slow: ")
		conns = append(conns, c)
	}
	for i, c := range conns {
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, err := io.Copy(io.Discard, c)
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Errorf("stalled connection %d was not closed within 3s", i)
		}
		_ = c.Close()
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("proxy stopped answering after the slowloris burst: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest { // no target configured: the normal answer
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestChaosUpstreamClosesImmediately(t *testing.T) {
	app := newTestApp(t)
	up := chaosUpstream(t, func(c net.Conn, br *bufio.Reader) {}) // accept, then hang up
	rec := chaosGateway(app, up)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	chaosNoLeak(t, app)
	chaosStillServes(t, app)
}

func TestChaosUpstreamDropsMidBody(t *testing.T) {
	app := newTestApp(t)
	up := chaosUpstream(t, func(c net.Conn, br *bufio.Reader) {
		if _, err := http.ReadRequest(br); err != nil {
			return
		}
		// Promise 1000 bytes, send a few, then drop the TCP connection.
		fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{\"access_token\":%q,\"user\":", chaosSecret)
	})
	_ = chaosGateway(app, up) // must return, not hang or panic
	chaosNoLeak(t, app)
	chaosStillServes(t, app)
}

func TestChaosUpstreamSendsGarbage(t *testing.T) {
	app := newTestApp(t)
	up := chaosUpstream(t, func(c net.Conn, br *bufio.Reader) {
		_, _ = http.ReadRequest(br)
		_, _ = c.Write([]byte("\x00\x01\x02 this is not HTTP \xff\xfe\r\n\r\n"))
	})
	rec := chaosGateway(app, up)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	chaosNoLeak(t, app)
	chaosStillServes(t, app)
}

func TestChaosUpstreamBadChunkedStream(t *testing.T) {
	app := newTestApp(t)
	up := chaosUpstream(t, func(c net.Conn, br *bufio.Reader) {
		if _, err := http.ReadRequest(br); err != nil {
			return
		}
		// Chunk size is not hex, and the stream then just stops.
		fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\nZZZZ\r\n{\"access_token\":%q}\r\n", chaosSecret)
	})
	_ = chaosGateway(app, up)
	chaosNoLeak(t, app)
	chaosStillServes(t, app)
}

func TestChaosUpstreamBrokenGzip(t *testing.T) {
	app := newTestApp(t)
	up := chaosUpstream(t, func(c net.Conn, br *bufio.Reader) {
		if _, err := http.ReadRequest(br); err != nil {
			return
		}
		body := "this is not gzip data, but it claims to be: " + chaosSecret
		fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	})
	_ = chaosGateway(app, up)
	chaosNoLeak(t, app)
	chaosStillServes(t, app)
}

func TestChaosUpstreamNeverAnswers(t *testing.T) {
	app := newTestApp(t)
	app.transport.ResponseHeaderTimeout = 300 * time.Millisecond
	up := chaosUpstream(t, func(c net.Conn, br *bufio.Reader) {
		_, _ = http.ReadRequest(br)
		time.Sleep(2 * time.Second) // read the request, then say nothing
	})
	start := time.Now()
	rec := chaosGateway(app, up)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("a silent upstream held the request for %v", time.Since(start))
	}
	chaosStillServes(t, app)
}

func TestChaosMalformedClientStreams(t *testing.T) {
	app := newTestApp(t)
	srv := httptest.NewServer(app)
	t.Cleanup(srv.Close)

	payloads := map[string]string{
		"binary garbage":         "\x00\x01\x02\xff\xfe garbage \r\n\r\n",
		"bad request line":       "NOT A REQUEST\r\n\r\n",
		"huge header value":      "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Big: " + strings.Repeat("A", 1<<20) + "\r\n\r\n",
		"bad content length":     "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: -5\r\n\r\n",
		"invalid chunk size":     "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\nabc\r\n",
		"truncated body":         "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 100\r\n\r\nshort",
		"connect without target": "CONNECT \r\n\r\n",
	}
	for name, raw := range payloads {
		c, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatalf("%s: dial: %v", name, err)
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = c.Write([]byte(raw))
		if tc, ok := c.(*net.TCPConn); ok && name == "truncated body" {
			_ = tc.CloseWrite() // the client gives up halfway
		}
		_, _ = io.Copy(io.Discard, c) // read whatever comes back, until the server closes
		_ = c.Close()
	}
	chaosStillServes(t, app)

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("proxy stopped answering after malformed streams: %v", err)
	}
	_ = resp.Body.Close()
}

func TestChaosClientDropsMidRequest(t *testing.T) {
	app := newTestApp(t)
	seen := &upstreamSeen{}
	up := newUpstream(t, seen)
	srv := httptest.NewServer(app)
	t.Cleanup(srv.Close)

	for i := 0; i < 5; i++ {
		c, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(c, "POST /v1/login HTTP/1.1\r\nHost: %s\r\nX-Target-URL: %s\r\nContent-Length: 5000\r\n\r\n{\"password\":\"hunter2", srv.Listener.Addr().String(), up.URL)
		_ = c.Close() // vanish halfway through the body
	}
	time.Sleep(200 * time.Millisecond)
	chaosNoLeak(t, app)
	chaosStillServes(t, app)
}