package app

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// capTestBuf is an io.Writer that is safe to use while the bar ticker writes.
type capTestBuf struct {
	mu sync.Mutex
	sb strings.Builder
}

func (b *capTestBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.Write(p)
}

func (b *capTestBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.String()
}

func capTestFlow(url string) rawFlow {
	return rawFlow{
		started:     time.Now(),
		method:      http.MethodGet,
		url:         url,
		status:      http.StatusOK,
		reqHeaders:  http.Header{},
		respHeaders: http.Header{},
		respBody:    []byte("ok"),
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func waitForBuf(t *testing.T, b *capTestBuf, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(b.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("output never contained %q", want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDispatchCaptureWithoutPool(t *testing.T) {
	app := newTestApp(t)
	app.stderr = &capTestBuf{}
	app.dispatchCapture(capTestFlow("http://x.test/nopool"))
	waitForRing(t, app, 1)
	if got := app.captureDropped.Load(); got != 0 {
		t.Fatalf("captureDropped = %d, want 0", got)
	}
}

func TestStartCaptureQueuedFlow(t *testing.T) {
	app := newTestApp(t)
	app.stderr = &capTestBuf{}
	app.startCapture()
	if app.capQ.Load() == nil {
		t.Fatal("startCapture did not install the pool")
	}
	const n = 20
	for i := 0; i < n; i++ {
		app.dispatchCapture(capTestFlow("http://x.test/queued"))
	}
	app.stopCapture() // drains: every queued flow is captured before it returns
	if got := app.ring.Len(); got != n {
		t.Fatalf("ring has %d entries, want %d", got, n)
	}
	if got := app.captureDropped.Load(); got != 0 {
		t.Fatalf("captureDropped = %d, want 0", got)
	}
}

func TestDispatchCaptureQueueFullDrops(t *testing.T) {
	app := newTestApp(t)
	app.stderr = &capTestBuf{}
	// A pool with no workers, so nothing drains the queue.
	p := &capturePool{ch: make(chan rawFlow, captureQueueSize)}
	app.capQ.Store(p)
	for i := 0; i < captureQueueSize; i++ {
		app.dispatchCapture(capTestFlow("http://x.test/fill"))
	}
	if got := app.captureDropped.Load(); got != 0 {
		t.Fatalf("dropped %d before the queue was full", got)
	}
	secret := []byte("sk_live_should_be_wiped")
	resp := []byte("response secret")
	f := capTestFlow("http://x.test/overflow")
	f.reqBody, f.respBody = secret, resp
	app.dispatchCapture(f)
	if got := app.captureDropped.Load(); got != 1 {
		t.Fatalf("captureDropped = %d, want 1", got)
	}
	if !allZero(secret) || !allZero(resp) {
		t.Fatal("dropped flow's bodies were not wiped")
	}
	if got := len(p.ch); got != captureQueueSize {
		t.Fatalf("queue holds %d, want %d", got, captureQueueSize)
	}
	app.stopCapture()
}

func TestDispatchCapturePoolClosedDrops(t *testing.T) {
	app := newTestApp(t)
	app.stderr = &capTestBuf{}
	p := &capturePool{ch: make(chan rawFlow, 1), closed: true}
	app.capQ.Store(p)
	body := []byte("late body")
	f := capTestFlow("http://x.test/late")
	f.respBody = body
	app.dispatchCapture(f)
	if got := app.captureDropped.Load(); got != 1 {
		t.Fatalf("captureDropped = %d, want 1", got)
	}
	if !allZero(body) {
		t.Fatal("late flow's body was not wiped")
	}
	if len(p.ch) != 0 {
		t.Fatal("a closed pool must not accept the flow")
	}
	if app.ring.Len() != 0 {
		t.Fatal("a dropped flow must not reach the ring")
	}
}

func TestStopCaptureIdempotent(t *testing.T) {
	app := newTestApp(t)
	app.stopCapture() // never started: no-op
	app.startCapture()
	app.stopCapture()
	app.stopCapture() // second call: no-op, no panic on the closed channel
	if app.capQ.Load() != nil {
		t.Fatal("pool should be cleared after stop")
	}
	// After stop, dispatch falls back to one goroutine per flow.
	app.stderr = &capTestBuf{}
	app.dispatchCapture(capTestFlow("http://x.test/after-stop"))
	waitForRing(t, app, 1)
}

func TestMarkBarWithoutTickerDrawsAtOnce(t *testing.T) {
	app := newTestApp(t)
	buf := &capTestBuf{}
	app.stderr = buf
	app.markBar()
	if !strings.Contains(buf.String(), "NullWire-MCP") {
		t.Fatalf("bar not drawn immediately: %q", buf.String())
	}
	if app.barDirty.Load() {
		t.Fatal("barDirty must stay false without the ticker")
	}
}

func TestBarTickerFlushesDirty(t *testing.T) {
	app := newTestApp(t)
	buf := &capTestBuf{}
	app.stderr = buf
	app.startBarTicker()
	t.Cleanup(app.stopBarTicker)
	if !app.barTick.Load() {
		t.Fatal("barTick not set")
	}
	time.Sleep(3 * barInterval)
	if buf.String() != "" {
		t.Fatalf("ticker drew without a request: %q", buf.String())
	}
	app.markBar()
	waitForBuf(t, buf, "NullWire-MCP")
	app.stopBarTicker()
	if app.barDirty.Load() {
		t.Fatal("barDirty left set after the redraw")
	}
}

func TestStopBarTickerDrawsPendingAndIsIdempotent(t *testing.T) {
	app := newTestApp(t)
	buf := &capTestBuf{}
	app.stderr = buf
	app.startBarTicker()
	app.barDirty.Store(true)
	app.stopBarTicker()
	app.stopBarTicker() // second call: no-op, no double close
	if !strings.Contains(buf.String(), "NullWire-MCP") {
		t.Fatalf("pending redraw was lost: %q", buf.String())
	}
	if app.barTick.Load() || app.barDirty.Load() {
		t.Fatal("ticker state not reset")
	}
	// With the ticker stopped, markBar draws at once again.
	before := len(buf.String())
	app.markBar()
	if len(buf.String()) <= before {
		t.Fatal("markBar should draw directly after the ticker stops")
	}
}

func TestStopBarTickerNeverStarted(t *testing.T) {
	app := newTestApp(t)
	buf := &capTestBuf{}
	app.stderr = buf
	app.stopBarTicker()
	app.stopBarTicker()
	if buf.String() != "" {
		t.Fatalf("unexpected output: %q", buf.String())
	}
}
