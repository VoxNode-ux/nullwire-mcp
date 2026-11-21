package app

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
)

type zeroReader struct{ left int64 }

func (z *zeroReader) Read(p []byte) (int, error) {
	if z.left <= 0 {
		return 0, io.EOF
	}
	n := int64(len(p))
	if n > z.left {
		n = z.left
	}
	for i := int64(0); i < n; i++ {
		p[i] = 'a'
	}
	z.left -= n
	return int(n), nil
}

// A 100 MiB stream must be forwarded whole while the capture stops at its cap
// and memory stays flat. No ReadTimeout/WriteTimeout is involved: SSE/WS stay open.
func TestCapBufferSoak100MiB(t *testing.T) {
	const capN = 32 << 10
	const size = 100 << 20
	cb := newSoloCapBuffer(capN)
	defer cb.release()
	var ms0, ms1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms0)
	var sink countWriter
	copyBuffered(&sink, &zeroReader{left: size}, cb, nil)
	runtime.GC()
	runtime.ReadMemStats(&ms1)
	if sink.n != size {
		t.Fatalf("forwarded %d bytes, want %d", sink.n, size)
	}
	got := cb.Bytes()
	if len(got) != capN {
		t.Fatalf("captured %d bytes, want %d", len(got), capN)
	}
	if !cb.Truncated() {
		t.Fatal("capture should be marked truncated")
	}
	if !bytes.HasPrefix(got, []byte("aaaa")) {
		t.Fatal("capture content wrong")
	}
	if grew := int64(ms1.HeapAlloc) - int64(ms0.HeapAlloc); grew > 4<<20 {
		t.Fatalf("heap grew %d bytes over a 100 MiB stream", grew)
	}
}

type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

// BenchmarkProxyBigBody sends the CI bigbody payload (32 KiB prefix with a
// secret at the capture edge + 1 MiB tail, application/octet-stream) through
// the gateway. Run with -cpuprofile to split loopback io.Copy, scrubber CPU
// and mutex time. Test-only: it changes nothing in production, and the
// octet-stream body is still scanned.
func BenchmarkProxyBigBody(b *testing.B) {
	s := benchScrubber(b)
	app := &App{
		ring:      NewRingBuffer(),
		scrub:     s,
		port:      1,
		transport: &http.Transport{Proxy: nil, DisableCompression: true},
	}
	defer app.transport.CloseIdleConnections()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer up.Close()

	body := append(bytes.Repeat([]byte("A"), 32768-20), []byte("ghp_abcdefghijklmnopqrstuvwxyz0123456789")...)
	body = append(body, bytes.Repeat([]byte("B"), 1<<20)...)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
		req.Host = "127.0.0.1:8080"
		req.Header.Set("X-Target-URL", up.URL)
		req.Header.Set("Content-Type", "application/octet-stream")
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("status = %d", rec.Code)
		}
	}
}
