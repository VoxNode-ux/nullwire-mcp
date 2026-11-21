package app

import (
	"runtime"
	"sync"
	"time"
)

// captureQueueSize is how many finished flows may wait for a capture worker.
// A flow that finds the queue full is wiped and dropped, so a burst can never
// stall live traffic or grow memory without bound.
const captureQueueSize = 256

// barInterval is how often the status bar is redrawn while traffic flows.
const barInterval = 100 * time.Millisecond

// capturePool is a fixed set of workers that scrub finished flows and push
// them into the RAM ring. The proxy has already forwarded the response to the
// client by the time a flow is queued; only the scrubbed copy goes to the ring.
//
// The queue is closed under mu's write lock and sent to under its read lock,
// so a late dispatch (a hijacked tunnel or a stream that outlives the HTTP
// server) can never send on a closed channel: it sees closed and wipes the
// flow instead.
type capturePool struct {
	mu     sync.RWMutex
	ch     chan rawFlow
	closed bool
	wg     sync.WaitGroup
}

// startCapture starts runtime.NumCPU() capture workers. Until it is called
// (tests build an App directly), dispatchCapture falls back to one goroutine
// per flow, which is how capture always ran before.
func (a *App) startCapture() {
	p := &capturePool{ch: make(chan rawFlow, captureQueueSize)}
	n := runtime.NumCPU()
	if n < 1 {
		n = 1
	}
	p.wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer p.wg.Done()
			for f := range p.ch {
				a.capture(f) // scrubs, pushes, and zeroes the flow's body copies
			}
		}()
	}
	a.capQ.Store(p)
}

// dispatchCapture hands a finished flow to the capture workers without ever
// blocking the caller. If the queue is full (or the pool is shutting down) the
// flow is not captured: its body copies are zeroed right here, so nothing
// sensitive is left behind, and the drop is counted in captureDropped.
func (a *App) dispatchCapture(f rawFlow) {
	p := a.capQ.Load()
	if p == nil {
		go a.capture(f)
		return
	}
	p.mu.RLock()
	if !p.closed {
		select {
		case p.ch <- f:
			p.mu.RUnlock()
			return
		default:
		}
	}
	p.mu.RUnlock()
	f.wipe()
	a.captureDropped.Add(1)
}

// stopCapture stops accepting flows, lets the workers finish every queued
// flow, and waits for them. It is safe to call twice. Call it before the ring
// and the taint table are cleared, so a flow still in the queue is not pushed
// after the wipe.
func (a *App) stopCapture() {
	p := a.capQ.Swap(nil)
	if p == nil {
		return
	}
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		close(p.ch)
	}
	p.mu.Unlock()
	p.wg.Wait()
}

// markBar asks for a status-bar redraw. With the ticker running it only sets a
// flag (one atomic store, no lock, no write(2) per request); without the
// ticker it draws at once, as it always did.
func (a *App) markBar() {
	if a.barTick.Load() {
		a.barDirty.Store(true)
		return
	}
	a.Bar()
}

// startBarTicker redraws the status bar at most every barInterval, and only
// when something asked for it since the last draw.
func (a *App) startBarTicker() {
	done := make(chan struct{})
	a.barStop = done
	a.barTick.Store(true)
	a.barWG.Add(1)
	go func() {
		defer a.barWG.Done()
		t := time.NewTicker(barInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if a.barDirty.Swap(false) {
					a.Bar()
				}
			case <-done:
				return
			}
		}
	}()
}

// stopBarTicker stops the ticker, waits for it, and draws once more if a
// redraw is still pending, so the last bar on screen is current. Safe to call
// twice, and a no-op if the ticker never started.
func (a *App) stopBarTicker() {
	a.barStopOnce.Do(func() {
		if a.barStop == nil {
			return
		}
		close(a.barStop)
		a.barWG.Wait()
		a.barTick.Store(false)
		if a.barDirty.Swap(false) {
			a.Bar()
		}
	})
}
