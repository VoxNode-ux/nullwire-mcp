package app

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// gRPC percent-encodes Grpc-Message, so an error message can carry a secret in
// encoded form. It must not reach the recorded note, encoded or not.
func TestGRPCMessageSecretIsScrubbed(t *testing.T) {
	const keyBody = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
	encoded := "%73k_live_" + keyBody // "sk_live_..." with the first letter percent-encoded

	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{0, 0, 0, 0, 2, 'o', 'k'})
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "3")
		w.Header().Set(http.TrailerPrefix+"Grpc-Message", "bad key "+encoded+" rejected")
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
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	waitForRing(t, app, 1)
	e := app.ring.ListRecent(1, "POST", "")[0]
	if !strings.Contains(e.Note, "gRPC status 3") {
		t.Errorf("note = %q, want the gRPC status", e.Note)
	}
	if strings.Contains(e.Note, keyBody[8:]) {
		t.Errorf("the secret reached the note: %q", e.Note)
	}
	if !strings.Contains(e.Note, "[REDACTED_") {
		t.Errorf("note = %q, want a redaction tag", e.Note)
	}
}

// An upgrade is HTTP/1.1 only. A server that also offers HTTP/2 must still be
// reached over HTTP/1.1 for an upgrade request, or the upgrade fails.
func TestUpgradeUsesHTTP1ToAnHTTP2CapableUpstream(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 {
			http.Error(w, "an upgrade needs HTTP/1.1", http.StatusHTTPVersionNotSupported)
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: x-nullwire-test\r\n\r\npong")
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
	proxy := httptest.NewServer(app)
	t.Cleanup(proxy.Close)

	c, br := rawProxyConn(t, proxy)
	fmt.Fprintf(c, "GET /up HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: x-nullwire-test\r\n\r\n", proxy.Listener.Addr().String())
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read the upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101 (the upgrade must go over HTTP/1.1)", resp.StatusCode)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "pong" {
		t.Errorf("data after the upgrade = %q, %v; want pong", buf, err)
	}
}

// A flow whose request body was a protobuf or gRPC placeholder has nothing to
// replay, so the exported curl command must not carry the placeholder as data.
func TestBuildCurlSkipsTheProtobufPlaceholder(t *testing.T) {
	e := FlowEntry{
		ID: 1, Method: "POST", URL: "http://127.0.0.1:1/pkg.Service/Method",
		RequestHeaders: map[string]string{"Content-Type": "application/grpc"},
		RequestBody:    "[protobuf/gRPC body not captured: 10 bytes]",
	}
	out := buildCurl(e)
	if strings.Contains(out, "--data-raw") || strings.Contains(out, "protobuf/gRPC body") {
		t.Errorf("the placeholder leaked into the curl command:\n%s", out)
	}
}
