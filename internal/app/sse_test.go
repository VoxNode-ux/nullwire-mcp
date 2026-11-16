package app

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// sseUpstream starts a test server whose handler runs fn after the
// event-stream headers are written, and makes sure it can always be closed.
func sseUpstream(t *testing.T, headers map[string]string, fn func(w http.ResponseWriter, fl http.Flusher, r *http.Request)) *httptest.Server {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(http.StatusOK)
		fl, _ := w.(http.Flusher)
		fn(w, fl, r)
	}))
	t.Cleanup(func() { up.CloseClientConnections(); up.Close() })
	return up
}

// sseWaitClosed waits for the final capture of the /stream flow. The flow is
// already in the ring while the stream is open, so waiting for the ring to
// have an entry is not enough.
func sseWaitClosed(t *testing.T, app *App) FlowEntry {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if es := app.ring.ListRecent(1, "GET", "/stream"); len(es) == 1 && strings.Contains(es[0].Note, "stream closed") {
			return es[0]
		}
	}
	t.Fatal("the final capture of the stream never arrived")
	return FlowEntry{}
}

func sseGet(app *App, up *httptest.Server) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, httptest.NewRequest("GET", up.URL+"/stream", nil))
	return rec
}

// A secret that arrives in two network chunks is found, because the captured
// text is scrubbed as a whole. The client still gets the raw bytes.
func TestSSESecretSplitAcrossChunks(t *testing.T) {
	app := fxApp(t)
	secret := "sk-" + strings.Repeat("A", 28)
	up := sseUpstream(t, nil, func(w http.ResponseWriter, fl http.Flusher, _ *http.Request) {
		_, _ = w.Write([]byte("data: " + secret[:12]))
		fl.Flush()
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte(secret[12:] + "\n\n"))
		fl.Flush()
	})

	rec := sseGet(app, up)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), secret) {
		t.Errorf("the client must get the raw stream: %d %q", rec.Code, rec.Body.String())
	}
	e := sseWaitClosed(t, app)
	if app.ring.Len() != 1 {
		t.Errorf("one stream must be one flow, got %d", app.ring.Len())
	}
	if strings.Contains(e.ResponseBody, secret) || !strings.Contains(e.ResponseBody, "[REDACTED_TOKEN#") {
		t.Errorf("stored text: %q", e.ResponseBody)
	}
}

func TestSSEGzipIsDecodedAndScrubbed(t *testing.T) {
	app := fxApp(t)
	secret := "sk-" + strings.Repeat("B", 28)
	up := sseUpstream(t, map[string]string{"Content-Encoding": "gzip"}, func(w http.ResponseWriter, fl http.Flusher, _ *http.Request) {
		gz := gzip.NewWriter(w)
		_, _ = gz.Write([]byte("data: " + secret + "\n\n"))
		_ = gz.Flush()
		fl.Flush()
		_ = gz.Close()
	})

	rec := sseGet(app, up)
	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("the client must get the gzip bytes unchanged: %v", err)
	}
	if b, _ := io.ReadAll(zr); !strings.Contains(string(b), secret) {
		t.Errorf("client text: %q", b)
	}
	e := sseWaitClosed(t, app)
	if strings.Contains(e.ResponseBody, secret) || !strings.Contains(e.ResponseBody, "[REDACTED_TOKEN#") {
		t.Errorf("gzip stream was not decoded and scrubbed: %q", e.ResponseBody)
	}
}

// An encoding that cannot be decoded is forwarded but not stored: compressed
// bytes must not be shown as text.
func TestSSEUnsupportedEncodingIsNotCaptured(t *testing.T) {
	app := fxApp(t)
	payload := "\x1b\x03opaque-bytes-" + strings.Repeat("sk-"+strings.Repeat("C", 28), 1)
	up := sseUpstream(t, map[string]string{"Content-Encoding": "br"}, func(w http.ResponseWriter, fl http.Flusher, _ *http.Request) {
		_, _ = w.Write([]byte(payload))
		fl.Flush()
	})

	if rec := sseGet(app, up); rec.Body.String() != payload {
		t.Errorf("the client must get the bytes unchanged: %q", rec.Body.String())
	}
	e := sseWaitClosed(t, app)
	if e.ResponseBody != "" || !strings.Contains(e.Note, "cannot be decoded") {
		t.Errorf("body %q, note %q", e.ResponseBody, e.Note)
	}
}

// The flow shows scrubbed text while the stream is still open.
func TestSSELiveRefreshWhileOpen(t *testing.T) {
	app := fxApp(t)
	secret := "sk-" + strings.Repeat("D", 28)
	release := make(chan struct{})
	up := sseUpstream(t, nil, func(w http.ResponseWriter, fl http.Flusher, r *http.Request) {
		_, _ = w.Write([]byte("data: " + secret + "\n\n"))
		fl.Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})

	done := make(chan struct{})
	go func() {
		sseGet(app, up)
		close(done)
	}()
	var live FlowEntry
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if es := app.ring.ListRecent(1, "GET", "/stream"); len(es) == 1 && strings.Contains(es[0].ResponseBody, "[REDACTED_TOKEN#") {
			live = es[0]
			break
		}
	}
	if !strings.Contains(live.Note, "still open") || strings.Contains(live.ResponseBody, secret) {
		t.Errorf("no scrubbed live text while open: note %q body %q", live.Note, live.ResponseBody)
	}
	close(release)
	<-done
	e := sseWaitClosed(t, app)
	if app.ring.Len() != 1 || strings.Contains(e.ResponseBody, secret) {
		t.Errorf("final: len %d body %q", app.ring.Len(), e.ResponseBody)
	}
}

// When the client goes away the proxy stops reading the stream instead of
// holding the upstream connection open.
func TestSSEEndsWhenTheRequestIsCancelled(t *testing.T) {
	app := fxApp(t)
	up := sseUpstream(t, nil, func(w http.ResponseWriter, fl http.Flusher, r *http.Request) {
		_, _ = w.Write([]byte("data: hello\n\n"))
		fl.Flush()
		<-r.Context().Done()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		app.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", up.URL+"/stream", nil).WithContext(ctx))
		close(done)
	}()
	fxWaitRing(t, app, 1)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ServeHTTP kept streaming after the request was cancelled")
	}
	sseWaitClosed(t, app)
}

func TestSSEDecoder(t *testing.T) {
	const text = "data: hello sse\n\n"
	cases := []struct {
		header string
		mk     func(w io.Writer) io.WriteCloser
	}{
		{"gzip", func(w io.Writer) io.WriteCloser { return gzip.NewWriter(w) }},
		{"x-gzip", func(w io.Writer) io.WriteCloser { return gzip.NewWriter(w) }},
		{" Deflate ", func(w io.Writer) io.WriteCloser { return zlib.NewWriter(w) }}, // the standard form
		{"deflate", func(w io.Writer) io.WriteCloser { // raw deflate, as some servers send it
			fw, _ := flate.NewWriter(w, flate.DefaultCompression)
			return fw
		}},
	}
	for _, c := range cases {
		name, mk := c.header, c.mk
		var packed bytes.Buffer
		zw := mk(&packed)
		_, _ = zw.Write([]byte(text))
		_ = zw.Close()

		col := newSSECollector(1 << 10)
		d := newSSEDecoder(name, col)
		if d == nil {
			t.Fatalf("%q: no decoder", name)
		}
		// Feed it in small pieces, as a stream arrives.
		for b := packed.Bytes(); len(b) > 0; {
			n := min(3, len(b))
			_, _ = d.Write(b[:n])
			b = b[n:]
		}
		_ = d.Close()
		if string(col.Bytes()) != text {
			t.Errorf("%q: decoded %q", name, col.Bytes())
		}
	}
	for _, name := range []string{"br", "zstd", "gzip, br", "compress", ""} {
		if newSSEDecoder(name, newSSECollector(8)) != nil {
			t.Errorf("%q must not get a decoder", name)
		}
	}
}

func TestSSEDecoderCapsCompressionBombs(t *testing.T) {
	var packed bytes.Buffer
	zw := gzip.NewWriter(&packed)
	_, _ = zw.Write(bytes.Repeat([]byte("a"), 8<<20))
	_ = zw.Close()
	if packed.Len() > 64<<10 {
		t.Fatalf("test bomb is not small: %d bytes", packed.Len())
	}
	col := newSSECollector(1024)
	d := newSSEDecoder("gzip", col)
	finished := make(chan struct{})
	go func() {
		_, _ = d.Write(packed.Bytes()) // returns an error once the decoder stops; that is ignored
		_ = d.Close()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("the decoder did not stop at its limit")
	}
	if got := len(col.Bytes()); got != 1024 {
		t.Errorf("kept %d bytes, want 1024", got)
	}
}

func TestSSECollector(t *testing.T) {
	c := newSSECollector(5)
	if n, err := c.Write([]byte("abc")); n != 3 || err != nil {
		t.Fatalf("Write = %d, %v", n, err)
	}
	v := c.Version()
	if n, err := c.Write([]byte("defgh")); n != 5 || err != nil {
		t.Fatalf("Write past the limit must report all bytes taken: %d, %v", n, err)
	}
	if string(c.Bytes()) != "abcde" || c.Version() == v {
		t.Errorf("bytes %q, version unchanged: %v", c.Bytes(), c.Version() == v)
	}
	v = c.Version()
	_, _ = c.Write([]byte("more"))
	if c.Version() != v {
		t.Error("a full collector must not report a change")
	}
	if !isEventStream(http.Header{"Content-Type": {"Text/Event-Stream; charset=utf-8"}}) || isEventStream(http.Header{"Content-Type": {"text/plain"}}) {
		t.Error("isEventStream")
	}
}
