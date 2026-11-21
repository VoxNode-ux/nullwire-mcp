package app

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// h2cTransport speaks plain-text HTTP/2 with prior knowledge, the way gRPC
// clients do when they are pointed at an address without TLS.
func h2cTransport() *http.Transport {
	var p http.Protocols
	p.SetUnencryptedHTTP2(true)
	return &http.Transport{Protocols: &p}
}

// startH2CProxy serves app with the same protocols as the real listener.
func startH2CProxy(t *testing.T, app *App) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(app)
	srv.Config.Protocols = serverProtocols()
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// An event stream must reach the client as it is produced. The upstream holds
// the stream open after the first event until the client has seen it, so a
// proxy that buffers would make this test time out.
func TestServerSentEventsStreamLive(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	open := func() { once.Do(func() { close(release) }) }

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl, _ := w.(http.Flusher)
		fmt.Fprint(w, "data: one\n\n")
		fl.Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		case <-time.After(10 * time.Second):
			return
		}
		fmt.Fprint(w, "data: two\n\n")
		fl.Flush()
	}))
	t.Cleanup(upstream.Close)

	app := newTestApp(t)
	proxy := httptest.NewServer(app)
	t.Cleanup(proxy.Close)
	t.Cleanup(open) // runs before the servers close, so a failure cannot hang them

	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	t.Cleanup(client.CloseIdleConnections)

	type result struct {
		resp *http.Response
		err  error
	}
	got := make(chan result, 1)
	go func() {
		resp, err := client.Get(upstream.URL)
		got <- result{resp, err}
	}()
	var resp *http.Response
	select {
	case r := <-got:
		if r.err != nil {
			t.Fatal(r.err)
		}
		resp = r.resp
	case <-time.After(5 * time.Second):
		t.Fatal("no response while the stream was still open: the proxy is buffering")
	}
	defer resp.Body.Close()

	lines := make(chan string, 16)
	go func() {
		defer close(lines)
		br := bufio.NewReader(resp.Body)
		for {
			line, err := br.ReadString('\n')
			if strings.TrimSpace(line) != "" {
				lines <- strings.TrimSpace(line)
			}
			if err != nil {
				return
			}
		}
	}()
	next := func(want string) {
		t.Helper()
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatalf("the stream ended before %q", want)
			}
			if line != want {
				t.Fatalf("got %q, want %q", line, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%q did not arrive while the upstream held the stream open: the proxy is buffering", want)
		}
	}
	next("data: one")
	open()
	next("data: two")
}

// A gRPC-style call: plain HTTP/2 from the client, TLS HTTP/2 to the upstream,
// "TE: trailers" forwarded, the status trailer returned, the status noted.
func TestGRPCStyleCallOverHTTP2KeepsTrailers(t *testing.T) {
	var mu sync.Mutex
	var sawProto int
	var sawTE, sawBody string

	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		sawProto, sawTE, sawBody = r.ProtoMajor, r.Header.Get("Te"), string(body)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{0, 0, 0, 0, 2, 'o', 'k'})
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
		w.Header().Set(http.TrailerPrefix+"Grpc-Message", "all good")
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	t.Cleanup(upstream.Close)

	app := newTestApp(t)
	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())
	app.transport = &http.Transport{
		Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}
	t.Cleanup(app.transport.CloseIdleConnections)
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	app.target = target
	proxy := startH2CProxy(t, app)

	client := &http.Client{Transport: h2cTransport()}
	t.Cleanup(client.CloseIdleConnections)
	frame := []byte{0, 0, 0, 0, 5, 'h', 'e', 'l', 'l', 'o'}
	req, err := http.NewRequest(http.MethodPost, proxy.URL+"/pkg.Service/Method", bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.ProtoMajor != 2 {
		t.Errorf("client protocol = HTTP/%d, want HTTP/2", resp.ProtoMajor)
	}
	if !bytes.Equal(body, []byte{0, 0, 0, 0, 2, 'o', 'k'}) {
		t.Errorf("response body = %v", body)
	}
	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Errorf("Grpc-Status trailer = %q, want 0 (trailers were not forwarded)", got)
	}
	mu.Lock()
	if sawProto != 2 || sawTE != "trailers" || sawBody != string(frame) {
		t.Errorf("upstream saw HTTP/%d, TE %q, body %v; want HTTP/2, trailers, the request frame", sawProto, sawTE, []byte(sawBody))
	}
	mu.Unlock()

	waitForRing(t, app, 1)
	e := app.ring.ListRecent(1, "POST", "")[0]
	if !strings.Contains(e.Note, "gRPC status 0") || !strings.Contains(e.Note, "all good") {
		t.Errorf("note = %q, want the gRPC status", e.Note)
	}
	if !strings.Contains(e.ResponseBody, "protobuf/gRPC body not captured") {
		t.Errorf("response body = %q, want the not-captured placeholder", e.ResponseBody)
	}
}

// A client that speaks plain HTTP/2 gets plain HTTP/2 to a plain upstream; an
// HTTP/1.1 client keeps getting HTTP/1.1.
func TestPlainHTTP2UpstreamFollowsTheClient(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "proto=%d", r.ProtoMajor)
	}))
	upstream.Config.Protocols = serverProtocols()
	upstream.Start()
	t.Cleanup(upstream.Close)

	app := newTestApp(t)
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	app.target = target
	proxy := startH2CProxy(t, app)

	h2 := &http.Client{Transport: h2cTransport()}
	t.Cleanup(h2.CloseIdleConnections)
	h1 := &http.Client{Transport: &http.Transport{}}
	t.Cleanup(h1.CloseIdleConnections)

	for _, tc := range []struct {
		name   string
		client *http.Client
		want   string
	}{
		{"HTTP/2 client", h2, "proto=2"},
		{"HTTP/1.1 client", h1, "proto=1"},
	} {
		resp, err := tc.client.Get(proxy.URL + "/ping")
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(body) != tc.want {
			t.Errorf("%s: upstream answered %q, want %q", tc.name, body, tc.want)
		}
	}
}

// CONNECT stays a blind tunnel: the TLS handshake must reach the real
// upstream, whose certificate the client checks against the real upstream's
// only. A proxy that opened the tunnel with its own certificate would fail it.
func TestConnectNeverInterceptsTLS(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello from upstream")
	}))
	t.Cleanup(upstream.Close)

	app := newTestApp(t)
	proxy := httptest.NewServer(app)
	t.Cleanup(proxy.Close)

	host := upstream.Listener.Addr().String()
	c, br := rawProxyConn(t, proxy)
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}

	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())
	tc := tls.Client(c, &tls.Config{RootCAs: pool, ServerName: "example.com", MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("TLS handshake through the tunnel failed, so the proxy is not a blind tunnel: %v", err)
	}
	peers := tc.ConnectionState().PeerCertificates
	if len(peers) == 0 || !bytes.Equal(peers[0].Raw, upstream.Certificate().Raw) {
		t.Fatal("the tunnel presented a certificate that is not the upstream's")
	}

	fmt.Fprint(tc, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	r2, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatalf("read the HTTPS response through the tunnel: %v", err)
	}
	body, _ := io.ReadAll(r2.Body)
	_ = r2.Body.Close()
	if string(body) != "hello from upstream" {
		t.Errorf("body through the tunnel = %q", body)
	}
	_ = tc.Close()

	waitForRing(t, app, 1)
	e := app.ring.ListRecent(1, "CONNECT", "")[0]
	if !strings.Contains(e.Note, "payload not inspected") {
		t.Errorf("note = %q, want the blind-tunnel note", e.Note)
	}
	if strings.Contains(e.ResponseBody, "hello from upstream") || strings.Contains(e.RequestBody, "GET /") {
		t.Errorf("the tunnel's payload leaked into the ring: %q / %q", e.RequestBody, e.ResponseBody)
	}
}

func TestGRPCStatusSources(t *testing.T) {
	h := func(kv ...string) http.Header {
		out := http.Header{}
		for i := 0; i+1 < len(kv); i += 2 {
			out.Set(kv[i], kv[i+1])
		}
		return out
	}
	cases := []struct {
		name         string
		f            rawFlow
		status, mess string
	}{
		{"trailers win", rawFlow{respTrailers: h("Grpc-Status", "5", "Grpc-Message", "not found"), respHeaders: h("Grpc-Status", "0")}, "5", "not found"},
		{"headers when there are no trailers", rawFlow{respHeaders: h("Grpc-Status", " 14 ", "Grpc-Message", "down")}, "14", "down"},
		{"blank trailer falls through to headers", rawFlow{respTrailers: h("Grpc-Status", "  "), respHeaders: h("Grpc-Status", "3")}, "3", ""},
		{"non-numeric status", rawFlow{respTrailers: h("Grpc-Status", "oops", "Grpc-Message", "x")}, "", ""},
		{"non-numeric trailer hides a good header", rawFlow{respTrailers: h("Grpc-Status", "x"), respHeaders: h("Grpc-Status", "0")}, "", ""},
		{"nothing", rawFlow{}, "", ""},
	}
	for _, c := range cases {
		if st, msg := grpcStatus(c.f); st != c.status || msg != c.mess {
			t.Errorf("%s: got (%q, %q), want (%q, %q)", c.name, st, msg, c.status, c.mess)
		}
	}
}

func TestAcceptsTrailersAndProtocols(t *testing.T) {
	for name, vals := range map[string][]string{
		"trailers":        {"trailers"},
		"mixed case":      {"Trailers"},
		"in a list":       {"gzip, Trailers"},
		"second header":   {"gzip", "trailers"},
		"spaces":          {"  trailers  "},
	} {
		h := http.Header{}
		for _, v := range vals {
			h.Add("Te", v)
		}
		if !acceptsTrailers(h) {
			t.Errorf("%s: TE %v must accept trailers", name, vals)
		}
	}
	for name, vals := range map[string][]string{"none": nil, "gzip only": {"gzip"}, "empty": {""}, "lookalike": {"trailersx"}} {
		h := http.Header{}
		for _, v := range vals {
			h.Add("Te", v)
		}
		if acceptsTrailers(h) {
			t.Errorf("%s: TE %v must not accept trailers", name, vals)
		}
	}
	if p := serverProtocols(); !p.HTTP1() || !p.UnencryptedHTTP2() || p.HTTP2() {
		t.Errorf("serverProtocols = http1:%v h2c:%v h2:%v", p.HTTP1(), p.UnencryptedHTTP2(), p.HTTP2())
	}
}

func TestRoundTripperForPicksByProtocol(t *testing.T) {
	app := fxApp(t)
	plain, err := url.Parse("http://upstream.test/")
	if err != nil {
		t.Fatal(err)
	}
	secure, err := url.Parse("https://upstream.test/")
	if err != nil {
		t.Fatal(err)
	}
	h1 := &http.Request{ProtoMajor: 1}
	h2 := &http.Request{ProtoMajor: 2}

	if rt := app.roundTripperFor(h1, plain); rt != http.RoundTripper(app.transport) {
		t.Error("an HTTP/1 client uses the shared transport")
	}
	if rt := app.roundTripperFor(h2, secure); rt != http.RoundTripper(app.transport) {
		t.Error("an HTTPS upstream negotiates HTTP/2 on its own, with the shared transport")
	}
	first := app.roundTripperFor(h2, plain)
	if first == http.RoundTripper(app.transport) || app.h2c == nil || first != http.RoundTripper(app.h2c) {
		t.Fatalf("an h2c client with a plain upstream needs the h2c transport: %v", first)
	}
	if again := app.roundTripperFor(h2, plain); again != first {
		t.Error("the h2c transport is created once")
	}
	if !app.h2c.Protocols.UnencryptedHTTP2() {
		t.Error("the h2c transport must speak unencrypted HTTP/2")
	}
}
