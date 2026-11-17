package app

import (
	"fmt"
	"time"
)

// wsLiveEvery is the shortest time between two refreshes of a flow whose
// WebSocket is still open.
const wsLiveEvery = 500 * time.Millisecond

// wsLiveNote is the note of a flow whose WebSocket is still open.
func wsLiveNote(upgrade string, up, down *wsCollector) string {
	return fmt.Sprintf("upgraded connection (%s): WebSocket still open; text messages are scrubbed and refreshed about every %d ms while it stays open (client->server: %s; server->client: %s); frames are forwarded unmodified",
		upgrade, wsLiveEvery.Milliseconds(), up.Summary(), down.Summary())
}

// pushLive stores the first entry of a WebSocket flow when the socket opens and
// returns its ID. ok is false when the flow is ignored or could not be built.
func (a *App) pushLive(f rawFlow) (id uint64, ok bool) {
	defer func() {
		if recover() != nil {
			id, ok = 0, false
		}
	}()
	// Detached counters: finishLive counts this flow once, when it ends.
	e, built := a.buildEntryWith(a.scrub.detached(), f)
	if !built {
		return 0, false
	}
	id = a.ring.Push(e)
	a.Bar()
	return id, true
}

// finishLive stores the final capture of a connection. It replaces the live
// entry in place; when that entry has been pushed out of the buffer meanwhile,
// the final capture is pushed as a new entry, as it was before live capture.
func (a *App) finishLive(id uint64, f rawFlow) {
	defer func() { _ = recover() }()
	e, ok := a.buildEntry(f)
	if !ok {
		return
	}
	if id == 0 || !a.ring.Update(id, func(cur *FlowEntry) { *cur = e }) {
		a.ring.Push(e)
	}
	a.Bar()
}

// wsLiveLoop refreshes the entry of an open WebSocket while its collectors
// change. It stops when stop is closed or the entry has been evicted, and
// closes done when it returns.
//
// The whole collected text is scrubbed on every refresh, which for a busy
// stream could cost a lot, so the loop slows itself down: the pause after a
// refresh is at least ten times as long as the refresh took, which keeps the
// scrubbing to about a tenth of one CPU core however fast messages arrive.
func (a *App) wsLiveLoop(id uint64, base rawFlow, upgrade string, up, down *wsCollector, stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	defer func() { _ = recover() }()
	pause := wsLiveEvery
	sc := a.scrub.detached() // refreshes do not raise the global counters; finishLive does
	var seen uint64
	for {
		timer := time.NewTimer(pause)
		select {
		case <-stop:
			timer.Stop()
			return
		case <-timer.C:
		}
		v := up.Version() + down.Version()
		if v == seen {
			pause = wsLiveEvery
			continue
		}
		seen = v
		began := time.Now()
		f := base
		f.reqBody, f.respBody = up.Bytes(), down.Bytes()
		f.latencyMs = time.Since(f.started).Milliseconds()
		f.note = wsLiveNote(upgrade, up, down)
		e, ok := a.buildEntryWith(sc, f)
		if !ok {
			return
		}
		if !a.ring.Update(id, func(cur *FlowEntry) { *cur = e }) {
			return // evicted: nothing to refresh
		}
		a.Bar()
		pause = max(wsLiveEvery, 10*time.Since(began))
	}
}
