package app

import (
	"encoding/binary"
	"strings"
	"sync"
	"sync/atomic"
)

// Cross-flow taint ring: a bounded set of keyed hashes of secrets that were
// redacted earlier in this run. If the same secret shows up again in a form the
// rules do not recognise (padded, embedded in a longer run, in another flow),
// it is redacted by identity. Only SipHash values are kept, never the secret.
const (
	taintCap     = 500
	taintMinLen  = 16   // shorter secrets are not tracked
	taintSubMin  = 40   // only secrets this long also store sub-windows
	taintWin     = 24   // sub-window size
	taintStride  = 12   // distance between stored windows
	taintMaxSub  = 8    // most windows stored per secret
	taintMaxScan = 2048 // longest run that is scanned window by window
)

type taintRing struct {
	k0, k1 uint64
	mu     sync.RWMutex
	ring   [taintCap]uint64
	set    map[uint64]struct{}
	pos    int
	filled int
	size   atomic.Int32
}

func newTaintRing(nonce []byte) *taintRing {
	t := &taintRing{set: make(map[uint64]struct{}, taintCap)}
	if len(nonce) >= 16 {
		t.k0 = binary.LittleEndian.Uint64(nonce[0:8])
		t.k1 = binary.LittleEndian.Uint64(nonce[8:16])
	}
	return t
}

func (t *taintRing) insertLocked(h uint64) {
	if _, ok := t.set[h]; ok {
		return
	}
	if t.filled == taintCap {
		delete(t.set, t.ring[t.pos])
	} else {
		t.filled++
	}
	t.ring[t.pos] = h
	t.set[h] = struct{}{}
	t.pos = (t.pos + 1) % taintCap
	t.size.Store(int32(len(t.set)))
}

// add records a redacted secret. Sub-windows are stored only for secrets of
// taintSubMin characters or more, so short tokens are never cut into pieces
// that could match ordinary text.
func (t *taintRing) add(raw string) {
	if len(raw) < taintMinLen {
		return
	}
	var hs [1 + taintMaxSub]uint64
	nh := 0
	hs[nh] = siphash24(t.k0, t.k1, raw)
	nh++
	if len(raw) >= taintSubMin {
		for off := 0; off+taintWin <= len(raw) && nh < len(hs); off += taintStride {
			hs[nh] = siphash24(t.k0, t.k1, raw[off:off+taintWin])
			nh++
		}
	}
	t.mu.Lock()
	for i := 0; i < nh; i++ {
		t.insertLocked(hs[i])
	}
	t.mu.Unlock()
}

// contains reports whether run, or any taintWin-byte window of it, is in the set.
func (t *taintRing) contains(run string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if _, ok := t.set[siphash24(t.k0, t.k1, run)]; ok {
		return true
	}
	if len(run) < taintWin || len(run) > taintMaxScan {
		return false
	}
	for off := 0; off+taintWin <= len(run); off++ {
		if _, ok := t.set[siphash24(t.k0, t.k1, run[off:off+taintWin])]; ok {
			return true
		}
	}
	return false
}

// scrubTainted redacts runs that match a previously redacted secret.
func (s *Scrubber) scrubTainted(in string) (string, int) {
	t := s.taint
	if t == nil || t.size.Load() == 0 || len(in) < taintMinLen {
		return in, 0
	}
	var b strings.Builder
	count, last := 0, 0
	for i := 0; i < len(in); {
		if !isEntropyCandidate(in[i]) {
			i++
			continue
		}
		j := i
		for j < len(in) && isEntropyCandidate(in[j]) {
			j++
		}
		cand := in[i:j]
		if len(cand) >= taintMinLen && !strings.Contains(cand, "REDACTED_") && t.contains(cand) {
			b.WriteString(in[last:i])
			b.WriteString(s.tag("TOKEN", cand))
			s.Tokens.Add(1)
			count++
			last = j
		}
		i = j
	}
	if count == 0 {
		return in, 0
	}
	b.WriteString(in[last:])
	return b.String(), count
}
