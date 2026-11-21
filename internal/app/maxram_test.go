package app

import (
	"strings"
	"sync"
	"testing"
)

func TestParseMaxRAM(t *testing.T) {
	good := map[string]int{
		"": 0, "64m": 64 << 20, "256M": 256 << 20, "400m": 400 << 20, "400mib": 400 << 20,
		"1024k": 1 << 20, " 8 mb ": 8 << 20, "1048576": 1 << 20,
	}
	for in, want := range good {
		got, err := parseMaxRAM(in)
		if err != nil || got != want {
			t.Errorf("parseMaxRAM(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	bad := map[string]string{
		"0": "greater than zero", "-1m": "greater than zero", "401m": "400 MiB",
		"1g": "400 MiB", "400m1": "not a size", "abc": "not a size", "1.5m": "not a size",
		"99999999999999999999": "not a size",
	}
	for in, want := range bad {
		_, err := parseMaxRAM(in)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("parseMaxRAM(%q) err = %v, want one containing %q", in, err, want)
		}
	}
}

func TestValidateMaxRAM(t *testing.T) {
	if err := validateMaxRAM(0, 0); err != nil {
		t.Fatalf("off: %v", err)
	}
	if err := validateMaxRAM(64<<20, 2<<20); err != nil {
		t.Fatalf("64m with 2m bodies: %v", err)
	}
	if err := validateMaxRAM(1<<20, 2<<20); err == nil {
		t.Fatal("1m budget with 2m bodies should be rejected")
	}
}

func ramEntry(n int) FlowEntry {
	return FlowEntry{Method: "GET", URL: "http://x.test/", RequestBody: strings.Repeat("a", n)}
}

func TestMaxRAMOffTracksNothing(t *testing.T) {
	r := NewRingBuffer()
	r.Push(ramEntry(1000))
	if r.Bytes() != 0 {
		t.Fatalf("Bytes = %d with the budget off", r.Bytes())
	}
}

func TestMaxRAMAccountingAndFIFO(t *testing.T) {
	r := NewRingBuffer()
	cost := entryCost(&FlowEntry{Method: "GET", URL: "http://x.test/", RequestBody: strings.Repeat("a", 1000)})
	r.SetMaxBytes(3*cost + cost/2) // room for three entries
	ids := make([]uint64, 0, 5)
	for i := 0; i < 5; i++ {
		ids = append(ids, r.Push(ramEntry(1000)))
		if got, limit := r.Bytes(), 3*cost+cost/2; got > limit {
			t.Fatalf("push %d: Bytes = %d over budget %d", i, got, limit)
		}
	}
	if r.Len() != 3 || r.Bytes() != 3*cost {
		t.Fatalf("Len = %d, Bytes = %d; want 3 and %d", r.Len(), r.Bytes(), 3*cost)
	}
	for _, id := range ids[:2] {
		if _, ok := r.GetByID(id); ok {
			t.Fatalf("entry %d should have been evicted first", id)
		}
	}
	for _, id := range ids[2:] {
		if _, ok := r.GetByID(id); !ok {
			t.Fatalf("entry %d should still be stored", id)
		}
	}
	r.Clear()
	if r.Bytes() != 0 || r.Len() != 0 {
		t.Fatalf("after Clear: Bytes = %d, Len = %d", r.Bytes(), r.Len())
	}
}

func TestMaxRAMEvictedSlotsAreZeroed(t *testing.T) {
	mk := func(c string) FlowEntry {
		e := ramEntry(0)
		e.RequestBody = strings.Repeat(c, 500)
		e.RequestHeaders = map[string]string{"X": "secret-" + c}
		return e
	}
	probe := mk("0")
	cost := entryCost(&probe)
	r := NewRingBuffer()
	r.SetMaxBytes(2*cost + 10)
	r.Push(mk("1"))
	r.Push(mk("2"))
	r.Push(mk("3"))
	live := 0
	for i := range r.slots {
		s := &r.slots[i]
		if strings.Contains(s.RequestBody, "1") || s.RequestHeaders["X"] == "secret-1" {
			t.Fatalf("slot %d still holds the evicted entry", i)
		}
		if s.ID == 0 {
			if s.RequestBody != "" || s.URL != "" || s.Method != "" || s.RequestHeaders != nil {
				t.Fatalf("slot %d is empty but not zeroed", i)
			}
			continue
		}
		live++
	}
	if live != r.Len() || live != 2 {
		t.Fatalf("live slots = %d, Len = %d, want 2", live, r.Len())
	}
}

func TestMaxRAMSlotCapStillApplies(t *testing.T) {
	r := NewRingBuffer()
	r.SetMaxBytes(400 << 20)
	for i := 0; i < ringCapacity+10; i++ {
		r.Push(ramEntry(10))
	}
	if r.Len() != ringCapacity {
		t.Fatalf("Len = %d, want %d", r.Len(), ringCapacity)
	}
	want := 0
	for _, e := range r.ListRecent(ringCapacity, "", "") {
		want += entryCost(&e)
	}
	if r.Bytes() != want {
		t.Fatalf("Bytes = %d, want %d", r.Bytes(), want)
	}
}

func TestMaxRAMOversizedEntryIsCutToBudget(t *testing.T) {
	r := NewRingBuffer()
	r.SetMaxBytes(4096)
	id := r.Push(FlowEntry{Method: "POST", URL: "http://x.test/", RequestBody: strings.Repeat("q", 3000), ResponseBody: strings.Repeat("p", 9000)})
	e, ok := r.GetByID(id)
	if !ok {
		t.Fatal("oversized entry was dropped instead of cut")
	}
	if entryCost(&e) > 4096 || r.Bytes() > 4096 {
		t.Fatalf("cost = %d, Bytes = %d, budget 4096", entryCost(&e), r.Bytes())
	}
	if e.ResponseBody == "" || !strings.HasSuffix(e.ResponseBody, truncMarker) {
		t.Fatalf("response body not cut with a marker: %d bytes", len(e.ResponseBody))
	}
	// Huge headers: bodies go to nothing and the headers are dropped.
	hdr := map[string]string{"X-Big": strings.Repeat("h", 8000)}
	id = r.Push(FlowEntry{Method: "GET", URL: "http://x.test/", RequestHeaders: hdr})
	if e, ok = r.GetByID(id); !ok || r.Bytes() > 4096 || e.RequestHeaders != nil {
		t.Fatalf("header-heavy entry: ok=%v Bytes=%d headers=%v", ok, r.Bytes(), e.RequestHeaders)
	}
}

func TestMaxRAMUpdateAccountsAndEvicts(t *testing.T) {
	r := NewRingBuffer()
	cost := entryCost(&FlowEntry{Method: "GET", URL: "http://x.test/", RequestBody: strings.Repeat("a", 1000)})
	r.SetMaxBytes(3 * cost)
	first := r.Push(ramEntry(1000))
	second := r.Push(ramEntry(1000))
	third := r.Push(ramEntry(1000))
	// Growing the newest entry evicts the oldest ones, never the one updated.
	if !r.Update(third, func(e *FlowEntry) { e.ResponseBody = strings.Repeat("z", 1500) }) {
		t.Fatal("Update lost the entry")
	}
	if _, ok := r.GetByID(first); ok {
		t.Fatal("oldest entry should be evicted")
	}
	if _, ok := r.GetByID(third); !ok {
		t.Fatal("updated entry must stay")
	}
	if r.Bytes() > 3*cost {
		t.Fatalf("Bytes = %d over budget %d", r.Bytes(), 3*cost)
	}
	// Shrinking gives the bytes back.
	before := r.Bytes()
	r.Update(second, func(e *FlowEntry) { e.RequestBody = "" })
	if r.Bytes() != before-1000 {
		t.Fatalf("Bytes = %d, want %d", r.Bytes(), before-1000)
	}
	if r.Update(first, func(*FlowEntry) {}) {
		t.Fatal("Update of an evicted entry must report false")
	}
}

func TestMaxRAMSetAfterEntriesCountsThem(t *testing.T) {
	r := NewRingBuffer()
	for i := 0; i < 10; i++ {
		r.Push(ramEntry(1000))
	}
	cost := entryCost(&FlowEntry{Method: "GET", URL: "http://x.test/", RequestBody: strings.Repeat("a", 1000)})
	r.SetMaxBytes(4 * cost)
	if r.Len() != 4 || r.Bytes() != 4*cost {
		t.Fatalf("Len = %d, Bytes = %d; want 4 and %d", r.Len(), r.Bytes(), 4*cost)
	}
	r.SetMaxBytes(0)
	if r.Bytes() != 0 {
		t.Fatalf("Bytes = %d after turning the budget off", r.Bytes())
	}
}

func TestMaxRAMConcurrent(t *testing.T) {
	r := NewRingBuffer()
	cost := entryCost(&FlowEntry{Method: "GET", URL: "http://x.test/", RequestBody: strings.Repeat("a", 500)})
	budget := 10 * cost
	r.SetMaxBytes(budget)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				id := r.Push(ramEntry(500))
				r.Update(id, func(e *FlowEntry) { e.ResponseBody = "ok" })
				_ = r.ListRecent(5, "", "")
				_, _ = r.GetByID(id)
				if b := r.Bytes(); b > budget {
					t.Errorf("Bytes = %d over budget %d", b, budget)
					return
				}
			}
		}()
	}
	wg.Wait()
	want := 0
	for _, e := range r.ListRecent(ringCapacity, "", "") {
		want += entryCost(&e)
	}
	if r.Bytes() != want || r.Bytes() > budget {
		t.Fatalf("Bytes = %d, recomputed %d, budget %d", r.Bytes(), want, budget)
	}
}
