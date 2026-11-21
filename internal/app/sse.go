package app

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Server-Sent Events (text/event-stream) are captured while they stream. The
// client gets every byte at once and unchanged; a copy goes to a collector,
// the flow is in the ring from the first byte, and it is refreshed about
// every sseLiveEvery while it is dirty (slower on very busy streams) and
// finalized when the stream ends. The text is scrubbed as a whole, so a secret
// that was split across two network chunks is found. A secret split across
// two SSE events, with the event framing in between, is not joined.

const sseLiveEvery = 500 * time.Millisecond

func isEventStream(h http.Header) bool {
	return mediaType(h.Get("Content-Type")) == "text/event-stream"
}

// sseCollector keeps the first max bytes written to it. Write never fails and
// never blocks, so it cannot slow the stream down.
type sseCollector struct {
	mu      sync.Mutex
	buf     []byte
	max     int
	version uint64
	cut     bool // bytes were dropped because the collector was full
}

func newSSECollector(limit int) *sseCollector { return &sseCollector{max: limit} }

func (c *sseCollector) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	room := c.max - len(c.buf)
	if room > 0 {
		c.buf = append(c.buf, p[:min(room, len(p))]...)
		c.version++
	}
	if len(p) > max(room, 0) {
		c.cut = true
	}
	return len(p), nil
}

// Truncated reports that the stream was longer than the collector holds.
func (c *sseCollector) Truncated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cut
}

func (c *sseCollector) Close() error { return nil }

func (c *sseCollector) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf...)
}

// Version changes whenever bytes were added.
func (c *sseCollector) Version() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.version
}

func sseLiveNote() string {
	return fmt.Sprintf("Server-Sent Events stream still open; text is scrubbed and refreshed about every %d ms; frames are forwarded unmodified", sseLiveEvery.Milliseconds())
}

// sseLiveLoop refreshes the entry of an open stream while the collector
// changes. Like wsLiveLoop it pauses at least ten times as long as a refresh
// took, and it stops when stop is closed or the entry was evicted. It closes
// done when it returns.
func (a *App) sseLiveLoop(id uint64, base rawFlow, col *sseCollector, stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	defer func() { _ = recover() }()
	pause := sseLiveEvery
	sc := a.scrub.detached() // refreshes do not raise the global counters; the final capture does
	var seen uint64
	for {
		timer := time.NewTimer(pause)
		select {
		case <-stop:
			timer.Stop()
			return
		case <-timer.C:
		}
		v := col.Version()
		if v == seen {
			pause = sseLiveEvery
			continue
		}
		seen = v
		began := time.Now()
		f := base
		f.respBody = col.Bytes()
		f.respCut = col.Truncated()
		f.latencyMs = time.Since(f.started).Milliseconds()
		f.note = sseLiveNote()
		e, ok := a.buildEntryWith(sc, f)
		if !ok {
			return
		}
		if !a.ring.Update(id, func(cur *FlowEntry) { *cur = e }) {
			return // evicted: nothing to refresh
		}
		a.Bar()
		pause = max(sseLiveEvery, 10*time.Since(began))
	}
}

// sseDecoder decodes a compressed stream into a collector. Close ends the
// input and waits until everything written so far has been decoded.
type sseDecoder struct {
	pw *io.PipeWriter
	wg sync.WaitGroup
}

func (d *sseDecoder) Write(p []byte) (int, error) { return d.pw.Write(p) }

func (d *sseDecoder) Close() error {
	err := d.pw.Close()
	d.wg.Wait()
	return err
}

// newSSEDecoder returns a writer that decodes gzip or deflate data into col,
// or nil for any other Content-Encoding (br, zstd, a stack of encodings),
// which cannot be read here. At most col.max bytes are decoded, so a
// compression bomb costs a bounded amount. Once the decoder has stopped, for
// that reason or on bad data, Write returns an error; the caller ignores it.
func newSSEDecoder(enc string, col *sseCollector) io.WriteCloser {
	enc = strings.ToLower(strings.TrimSpace(enc))
	if enc != "gzip" && enc != "x-gzip" && enc != "deflate" {
		return nil
	}
	pr, pw := io.Pipe()
	d := &sseDecoder{pw: pw}
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		defer pr.Close()
		br := bufio.NewReader(pr)
		var rd io.Reader
		if enc == "deflate" {
			// "deflate" is zlib-wrapped by the standard, but some servers
			// send raw deflate; the zlib header tells them apart.
			if h, _ := br.Peek(2); len(h) == 2 && h[0]&0x0f == 8 && (uint(h[0])<<8|uint(h[1]))%31 == 0 {
				zr, err := zlib.NewReader(br)
				if err != nil {
					return
				}
				defer zr.Close()
				rd = zr
			} else {
				fr := flate.NewReader(br)
				defer fr.Close()
				rd = fr
			}
		} else {
			zr, err := gzip.NewReader(br)
			if err != nil {
				return
			}
			defer zr.Close()
			rd = zr
		}
		_, _ = io.Copy(col, io.LimitReader(rd, int64(col.max)+1)) // a truncated stream is fine
	}()
	return d
}

// sseChunkSize is the read size for one event-stream chunk.
const sseChunkSize = 4 << 10

// sseChunkPool recycles the chunk buffer. Every buffer in it is all zero.
var sseChunkPool = sync.Pool{New: func() any { b := make([]byte, sseChunkSize); return &b }}

// streamSSE forwards an event stream to the client and captures it. The
// caller has not written anything to w yet.
func (a *App) streamSSE(w http.ResponseWriter, r *http.Request, resp *http.Response, flow rawFlow, reqCap *capBuffer, start time.Time) {
	copyHeadersInto(w.Header(), resp.Header) // static hop-by-hop set, no per-stream map
	w.WriteHeader(resp.StatusCode)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush() // the client sees the headers now
	}

	col := newSSECollector(a.limits().respBody + scrubWindow)
	var tap io.WriteCloser // nil: the body is not captured
	hdr := resp.Header.Clone()
	skipped := ""
	if enc := effectiveContentEncoding(joinedContentEncoding(resp.Header)); enc == "" {
		tap = col
	} else if dec := newSSEDecoder(enc, col); dec != nil {
		tap = dec
		hdr.Del("Content-Encoding") // the stored text is already decoded
	} else {
		skipped = "; body not captured because Content-Encoding " + enc + " cannot be decoded"
	}

	open := flow
	open.status = resp.StatusCode
	open.respHeaders = hdr
	open.reqBody = reqCap.Bytes()
	open.note = sseLiveNote() + skipped
	liveID, live := a.pushLive(open)
	var stop chan struct{}
	var done chan struct{}
	if live && tap != nil {
		stop, done = make(chan struct{}), make(chan struct{})
		go a.sseLiveLoop(liveID, open, col, stop, done)
	}

	clientGone := false
	bp := sseChunkPool.Get().(*[]byte)
	buf := *bp
	used := 0 // high-water mark of bytes written into buf
	defer func() {
		clear(buf[:used]) // the pooled chunk never carries event bytes to the next stream
		runtime.KeepAlive(buf)
		sseChunkPool.Put(bp)
	}()
	for {
		n, err := resp.Body.Read(buf)
		if n > used {
			used = n
		}
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				clientGone = true // stop reading: the caller closes the upstream body
				break
			}
			if flusher != nil {
				flusher.Flush()
			}
			if tap != nil {
				_, _ = tap.Write(buf[:n])
			}
		}
		if err != nil {
			break
		}
	}
	// An idle client that disconnects cancels the context and ends the Read
	// before any Write fails.
	clientGone = clientGone || r.Context().Err() != nil
	if tap != nil {
		_ = tap.Close() // waits for the decoder to drain
	}
	if !clientGone {
		for k, vs := range resp.Trailer {
			if len(vs) > 0 {
				w.Header()[http.TrailerPrefix+k] = append([]string(nil), vs...)
			}
		}
	}
	if stop != nil {
		// Wait for the refresher, so a late refresh cannot overwrite the
		// final capture.
		close(stop)
		<-done
	}

	final := flow
	final.reqBody = reqCap.Bytes()
	final.status = resp.StatusCode
	final.respHeaders = hdr
	final.respTrailers = resp.Trailer.Clone()
	if tap != nil {
		final.respBody = col.Bytes()
		final.respCut = col.Truncated()
	}
	final.latencyMs = time.Since(start).Milliseconds()
	final.note = "Server-Sent Events stream closed; text is captured and scrubbed" + skipped
	if clientGone {
		final.note = "Server-Sent Events stream closed by the client; text is captured and scrubbed" + skipped
	}
	a.goFinishLive(liveID, final)
}
