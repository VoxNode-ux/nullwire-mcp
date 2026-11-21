package app

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRingBufferClearZeroesSlots(t *testing.T) {
	r := NewRingBuffer()
	r.Push(FlowEntry{URL: "https://example.test/secret"})
	r.Clear()
	if r.Len() != 0 {
		t.Fatalf("Len = %d after Clear", r.Len())
	}
	for i := range r.slots {
		if r.slots[i].URL != "" {
			t.Fatalf("slot %d not zeroed", i)
		}
	}
}

func TestTaintRingClearZeroesState(t *testing.T) {
	nonce := bytes.Repeat([]byte{7}, 32)
	tr := newTaintRing(nonce)
	tr.add("sk_live_abcdefghijklmnop1234567890")
	tr.clear()
	for i, h := range tr.ring {
		if h != 0 {
			t.Fatalf("ring[%d] = %d", i, h)
		}
	}
	if tr.k0 != 0 || tr.k1 != 0 || tr.size.Load() != 0 || len(tr.set) != 0 {
		t.Fatal("taint state not cleared")
	}
	var nilRing *taintRing
	nilRing.clear() // must not panic
}

func TestRawFlowWipe(t *testing.T) {
	f := rawFlow{reqBody: []byte("abc"), respBody: []byte("def")}
	rq, rs := f.reqBody, f.respBody
	f.wipe()
	if !bytes.Equal(rq, make([]byte, 3)) || !bytes.Equal(rs, make([]byte, 3)) {
		t.Fatal("bodies not zeroed")
	}
	(&rawFlow{}).wipe() // empty bodies are fine
}

func TestCaptureWipesBodiesAfterStoring(t *testing.T) {
	app := newTestApp(t)
	body := []byte(`{"a":1}`)
	f := rawFlow{started: time.Now(), method: "POST", url: "http://x.test/", reqBody: body,
		reqHeaders: http.Header{"Content-Type": {"application/json"}}, respHeaders: http.Header{}}
	app.capture(f)
	if app.ring.Len() != 1 {
		t.Fatalf("ring Len = %d", app.ring.Len())
	}
	if !bytes.Equal(body, make([]byte, len(body))) {
		t.Fatal("request body not wiped")
	}
}

func TestDecodeBodyMaxCutStillDecodes(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte("hello world"))
	_ = zw.Close()
	text, cut, ok := decodeBodyMaxCut("gzip", buf.Bytes(), 5)
	if !ok || !cut || text != "hello" {
		t.Fatalf("got %q cut=%v ok=%v", text, cut, ok)
	}
	if _, _, ok := decodeBodyMaxCut("gzip", []byte("junk"), 5); ok {
		t.Fatal("bad gzip accepted")
	}
}

// ---- mTLS ----

type testPKI struct {
	pool     *x509.CertPool
	certFile string
	keyFile  string
}

func newTestPKI(t *testing.T, name string) testPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name + " CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name + " client"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := testPKI{pool: x509.NewCertPool(), certFile: filepath.Join(dir, "c.pem"), keyFile: filepath.Join(dir, "k.pem")}
	p.pool.AddCert(caCert)
	if err := os.WriteFile(p.certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func newMTLSServer(t *testing.T, clientCAs *x509.CertPool) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func serverRoots(srv *httptest.Server) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(srv.Certificate())
	return p
}

func TestBuildClientCert(t *testing.T) {
	pki := newTestPKI(t, "a")
	if c, err := buildClientCert("", ""); c != nil || err != nil {
		t.Fatalf("empty: %v %v", c, err)
	}
	if _, err := buildClientCert(pki.certFile, ""); err == nil {
		t.Fatal("cert without key accepted")
	}
	if _, err := buildClientCert("", pki.keyFile); err == nil {
		t.Fatal("key without cert accepted")
	}
	if _, err := buildClientCert(pki.certFile, filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing key accepted")
	}
	other := newTestPKI(t, "b")
	if _, err := buildClientCert(pki.certFile, other.keyFile); err == nil {
		t.Fatal("mismatched pair accepted")
	}
	c, err := buildClientCert(pki.certFile, pki.keyFile)
	if err != nil || c == nil {
		t.Fatalf("valid pair: %v", err)
	}
}

func TestBuildTLSConfig(t *testing.T) {
	if buildTLSConfig(nil, nil) != nil {
		t.Fatal("expected nil config")
	}
	pki := newTestPKI(t, "a")
	c, _ := buildClientCert(pki.certFile, pki.keyFile)
	cfg := buildTLSConfig(nil, c) // no rootCAs: still built
	if cfg == nil || cfg.MinVersion != tls.VersionTLS12 || len(cfg.Certificates) != 1 || cfg.RootCAs != nil {
		t.Fatalf("bad config: %+v", cfg)
	}
	if cfg := buildTLSConfig(pki.pool, nil); cfg == nil || len(cfg.Certificates) != 0 || cfg.RootCAs == nil {
		t.Fatalf("roots-only config wrong: %+v", cfg)
	}
}

func TestUpstreamMTLSHandshake(t *testing.T) {
	good := newTestPKI(t, "good")
	bad := newTestPKI(t, "bad")
	srv := newMTLSServer(t, good.pool)
	goodCert, _ := buildClientCert(good.certFile, good.keyFile)
	badCert, _ := buildClientCert(bad.certFile, bad.keyFile)

	try := func(cert *tls.Certificate, upgrade bool) error {
		app := newTestApp(t)
		cfg := buildTLSConfig(serverRoots(srv), cert)
		app.transport = &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true}
		t.Cleanup(app.transport.CloseIdleConnections)
		rt := http.RoundTripper(app.transport)
		if upgrade {
			rt = app.upgradeTransport()
		}
		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		resp, err := rt.RoundTrip(req)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		return nil
	}
	for _, up := range []bool{false, true} {
		if err := try(goodCert, up); err != nil {
			t.Fatalf("upgrade=%v: valid client cert rejected: %v", up, err)
		}
		if err := try(nil, up); err == nil {
			t.Fatalf("upgrade=%v: missing client cert accepted", up)
		}
		if err := try(badCert, up); err == nil {
			t.Fatalf("upgrade=%v: mismatched client cert accepted", up)
		}
	}
}
