package app

import (
	"bytes"
	"io"
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
	if got := len(cb.Bytes()); got != capN {
		t.Fatalf("captured %d bytes, want %d", got, capN)
	}
	if !cb.Truncated() {
		t.Fatal("capture should be marked truncated")
	}
	if !bytes.Equal(cb.Bytes()[:4], []byte("aaaa")) {
		t.Fatal("capture content wrong")
	}
	if grew := int64(ms1.HeapAlloc) - int64(ms0.HeapAlloc); grew > 4<<20 {
		t.Fatalf("heap grew %d bytes over a 100 MiB stream", grew)
	}
}

type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }
