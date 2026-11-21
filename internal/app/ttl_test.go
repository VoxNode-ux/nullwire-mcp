package app

import (
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock is a settable clock for the lazy-expiry tests.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func timedRing(ttl, idle time.Duration) (*RingBuffer, *fakeClock) {
	c := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	r := NewRingBuffer()
	r.clock = c.now
	r.SetExpiry(ttl, idle)
	return r, c
}

func ttlEntry(tag string) FlowEntry {
	return FlowEntry{Method: "GET", URL: "http://x.test/" + tag, RequestBody: strings.Repeat(tag, 100)}
}

// rawSize reads the stored count without triggering lazy expiry, so the
// sweeper tests see only what the sweeper itself removed.
func rawSize(r *RingBuffer) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.size
}

func requireAllSlotsZero(t *testing.T, r *RingBuffer) {
	t.Helper()
	r.mu.RLock()
	defer r.mu.RUnlock()
	for i := range r.slots {
		s := &r.slots[i]
		if s.ID != 0 || s.URL != "" || s.RequestBody != "" || !r.born[i].IsZero() {
			t.Fatalf("slot %d not zeroed: %+v born=%v", i, *s, r.born[i])
		}
	}
	if r.size != 0 || r.bytes != 0 {
		t.Fatalf("counters not reset: size=%d bytes=%d", r.size, r.bytes)
	}
}

func TestTTLOffDoesNothing(t *testing.T) {
	r := NewRingBuffer()
	r.Push(ttlEntry("a"))
	if r.timed || r.Len() != 1 || !r.born[0].IsZero() {
		t.Fatal("expiry state touched with the options off")
	}
}

func TestTTLExpiresOldestOnly(t *testing.T) {
	r, c := timedRing(50*time.Millisecond, 0)
	a := r.Push(ttlEntry("a"))
	c.advance(30 * time.Millisecond)
	b := r.Push(ttlEntry("b"))
	c.advance(30 * time.Millisecond) // a is 60ms old, b is 30ms old
	if _, ok := r.GetByID(a); ok {
		t.Fatal("expired entry still readable")
	}
	if _, ok := r.GetByID(b); !ok {
		t.Fatal("young entry was wiped")
	}
	if r.Len() != 1 {
		t.Fatalf("Len = %d, want 1", r.Len())
	}
	r.mu.RLock()
	for i := range r.slots {
		if r.slots[i].ID == a || strings.Contains(r.slots[i].URL, "/a") {
			r.mu.RUnlock()
			t.Fatalf("slot %d still holds the expired entry", i)
		}
	}
	r.mu.RUnlock()
	c.advance(30 * time.Millisecond)
	if got := r.ListRecent(10, "", ""); len(got) != 0 {
		t.Fatalf("ListRecent returned %d expired entries", len(got))
	}
	requireAllSlotsZero(t, r)
}

func TestTTLWithByteBudgetKeepsAccounting(t *testing.T) {
	r, c := timedRing(50*time.Millisecond, 0)
	r.SetMaxBytes(1 << 20)
	r.Push(ttlEntry("a"))
	c.advance(30 * time.Millisecond)
	e := ttlEntry("b")
	r.Push(e)
	c.advance(30 * time.Millisecond)
	if r.Len() != 1 || r.Bytes() != entryCost(&e) {
		t.Fatalf("Len = %d, Bytes = %d, want 1 and %d", r.Len(), r.Bytes(), entryCost(&e))
	}
	c.advance(time.Second)
	if r.Len() != 0 || r.Bytes() != 0 {
		t.Fatalf("Len = %d, Bytes = %d after full expiry", r.Len(), r.Bytes())
	}
}

func TestTTLWithoutBudgetNeverGoesNegative(t *testing.T) {
	r, c := timedRing(10*time.Millisecond, 0)
	r.Push(ttlEntry("a"))
	c.advance(time.Second)
	if r.Len() != 0 || r.bytes != 0 {
		t.Fatalf("Len = %d, bytes = %d", r.Len(), r.bytes)
	}
}

func TestTTLUpdateOfExpiredEntryFails(t *testing.T) {
	r, c := timedRing(50*time.Millisecond, 0)
	id := r.Push(ttlEntry("a"))
	if !r.Update(id, func(e *FlowEntry) { e.StatusCode = 200 }) {
		t.Fatal("Update of a live entry failed")
	}
	c.advance(time.Second)
	if r.Update(id, func(e *FlowEntry) { e.StatusCode = 500 }) {
		t.Fatal("Update of an expired entry must report false")
	}
}

func TestIdleWipeClearsEverything(t *testing.T) {
	r, c := timedRing(0, 50*time.Millisecond)
	r.Push(ttlEntry("a"))
	c.advance(30 * time.Millisecond)
	r.Push(ttlEntry("b")) // a new flow restarts the idle window
	c.advance(30 * time.Millisecond)
	if r.Len() != 2 {
		t.Fatalf("Len = %d, want 2 (idle window was restarted)", r.Len())
	}
	c.advance(50 * time.Millisecond)
	if got := r.ListRecent(10, "", ""); len(got) != 0 {
		t.Fatalf("ListRecent returned %d entries after idle wipe", len(got))
	}
	requireAllSlotsZero(t, r)
	id := r.Push(ttlEntry("c")) // the buffer is usable again
	if _, ok := r.GetByID(id); !ok {
		t.Fatal("push after an idle wipe failed")
	}
}

func TestIdleWipeOnPushAfterQuietPeriod(t *testing.T) {
	r, c := timedRing(0, 50*time.Millisecond)
	old := r.Push(ttlEntry("a"))
	c.advance(time.Second)
	r.Push(ttlEntry("b")) // no read in between: the push itself wipes first
	if _, ok := r.GetByID(old); ok {
		t.Fatal("entry from before the idle window survived")
	}
	if r.Len() != 1 {
		t.Fatalf("Len = %d, want 1", r.Len())
	}
}

func TestSweeperWipesExpiredEntries(t *testing.T) {
	r := NewRingBuffer()
	r.SetExpiry(20*time.Millisecond, 0)
	r.StartSweeper()
	defer r.StopSweeper()
	r.Push(ttlEntry("a"))
	waitFor(t, func() bool { return rawSize(r) == 0 })
	requireAllSlotsZero(t, r)
}

func TestSweeperIdleWipe(t *testing.T) {
	r := NewRingBuffer()
	r.SetExpiry(0, 30*time.Millisecond)
	r.StartSweeper()
	defer r.StopSweeper()
	for i := 0; i < 5; i++ {
		r.Push(ttlEntry("a"))
	}
	waitFor(t, func() bool { return rawSize(r) == 0 })
	requireAllSlotsZero(t, r)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the sweeper")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestSweeperOnlyRunsWhenEnabled(t *testing.T) {
	r := NewRingBuffer()
	r.StartSweeper()
	if r.sweepDone != nil {
		t.Fatal("sweeper started with -ttl and -idle-wipe unset")
	}
	r.StopSweeper() // safe without a sweeper
}

func TestSweeperStopsCleanly(t *testing.T) {
	before := runtime.NumGoroutine()
	for i := 0; i < 5; i++ {
		r := NewRingBuffer()
		r.SetExpiry(10*time.Millisecond, 10*time.Millisecond)
		r.StartSweeper()
		r.StartSweeper() // a second start must not add a goroutine
		r.Push(ttlEntry("a"))
		r.StopSweeper()
		r.StopSweeper() // idempotent
	}
	waitFor(t, func() bool { return runtime.NumGoroutine() <= before })
}

func TestSweeperRace(t *testing.T) {
	r := NewRingBuffer()
	r.SetMaxBytes(64 << 10)
	r.SetExpiry(15*time.Millisecond, 40*time.Millisecond)
	r.StartSweeper()
	var wg sync.WaitGroup
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				id := r.Push(ttlEntry("r"))
				r.Update(id, func(e *FlowEntry) { e.StatusCode = 200 })
				_ = r.ListRecent(5, "", "")
				_, _ = r.GetByID(id)
				_ = r.Len()
				if i%50 == 0 {
					time.Sleep(20 * time.Millisecond)
				}
			}
		}()
	}
	wg.Wait()
	r.StopSweeper()
	if b := r.Bytes(); b < 0 || b > 64<<10 {
		t.Fatalf("Bytes = %d", b)
	}
	r.Clear()
	requireAllSlotsZero(t, r)
}
