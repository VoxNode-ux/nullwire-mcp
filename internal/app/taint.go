package app

import (
	"crypto/fips140"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"strings"
	"sync"
	"sync/atomic"
)

// Cross-flow taint ring: a bounded set of keyed hashes of secrets that were
// redacted earlier in this run. If the same secret shows up again in a form the
// rules do not recognise (padded, embedded in a longer run, in another flow),
// it is redacted by identity. Only 64-bit keyed hashes are kept, never the secret.
//
// The keyed hash is SipHash-2-4 by default: no heap allocation, no locking.
// When the Go FIPS 140-3 module is switched on (GODEBUG=fips140=on or only,
// or a binary built with GOFIPS140), the ring uses HMAC-SHA256 cut to 64 bits
// instead, so every primitive in use is FIPS-approved. HMAC contexts come from
// a sync.Pool; after warm-up the FIPS path does not allocate either.
const (
	taintCap     = 500
	taintMinLen  = 16   // shorter secrets are not tracked
	taintSubMin  = 32   // only secrets this long also store sub-windows (39-char AIza keys, JWT signatures)
	taintWin     = 24   // sub-window size
	taintStride  = 12   // distance between stored windows
	taintMaxSub  = 12   // most windows stored per secret: up to 10 from the head and 2 from the tail
	taintMaxScan = 2048 // longest run that is scanned window by window
	// Only material at least this random is tracked: periodic hex and filler
	// repeat their own windows and would redact unrelated values.
	taintMinEntropy = 3.0
)

type taintRing struct {
	k0, k1 uint64 // SipHash key (default mode)
	fips   bool   // hash with HMAC-SHA256 instead of SipHash
	key    []byte // HMAC key, 32 bytes (FIPS mode only)
	pool   sync.Pool
	mu     sync.RWMutex
	ring   [taintCap]uint64
	set    map[uint64]struct{}
	pos    int
	filled int
	size   atomic.Int64
}

// taintMAC is one reusable HMAC context. buf holds the text being hashed so the
// conversion from string does not allocate; it is wiped before the context goes
// back to the pool.
type taintMAC struct {
	h   hash.Hash
	buf []byte
	sum [sha256.Size]byte
}

// newTaintRing picks the hash from the process FIPS mode.
func newTaintRing(nonce []byte) *taintRing { return newTaintRingMode(nonce, fips140.Enabled()) }

// newTaintRingMode builds a ring with an explicit hash: HMAC-SHA256 when fips
// is true, SipHash-2-4 otherwise.
func newTaintRingMode(nonce []byte, fips bool) *taintRing {
	t := &taintRing{set: make(map[uint64]struct{}, taintCap), fips: fips}
	if len(nonce) >= 16 {
		t.k0 = binary.LittleEndian.Uint64(nonce[0:8])
		t.k1 = binary.LittleEndian.Uint64(nonce[8:16])
	}
	if fips {
		// FIPS 140-3 rejects HMAC keys shorter than 112 bits, so the key is
		// always 32 bytes: the run nonce, zero-padded if a caller gave less.
		t.key = make([]byte, sha256.Size)
		copy(t.key, nonce)
		t.pool = sync.Pool{New: t.newMAC}
	}
	return t
}

func (t *taintRing) newMAC() any {
	return &taintMAC{h: hmac.New(sha256.New, t.key), buf: make([]byte, 0, 256)}
}

// hash returns the keyed 64-bit identity of s. Callers hold t.mu (read or
// write), so clear cannot swap the key while a hash is being computed.
func (t *taintRing) hash(s string) uint64 {
	if !t.fips {
		return siphash24(t.k0, t.k1, s)
	}
	m := t.pool.Get().(*taintMAC)
	m.h.Reset()
	m.buf = append(m.buf[:0], s...)
	_, _ = m.h.Write(m.buf)
	sum := m.h.Sum(m.sum[:0])
	v := binary.BigEndian.Uint64(sum[:8]) // truncated HMAC: the first 64 bits
	clear(m.buf)
	clear(m.sum[:])
	m.buf = m.buf[:0]
	t.pool.Put(m)
	return v
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
	t.size.Store(int64(len(t.set)))
}

// add records a redacted secret. Sub-windows are stored only for secrets of
// taintSubMin characters or more, so short tokens are never cut into pieces
// that could match ordinary text.
func (t *taintRing) add(raw string) {
	if t == nil || len(raw) < taintMinLen || shannonEntropyBits(raw) < taintMinEntropy {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	var hs [1 + taintMaxSub]uint64
	nh := 0
	hs[nh] = t.hash(raw)
	nh++
	if len(raw) >= taintSubMin {
		store := func(off int) {
			if off < 0 || off+taintWin > len(raw) || nh >= len(hs) {
				return
			}
			if shannonEntropyBits(raw[off:off+taintWin]) < taintMinEntropy {
				return
			}
			hs[nh] = t.hash(raw[off : off+taintWin])
			nh++
		}
		for off := 0; off+taintWin <= len(raw) && nh < len(hs)-2; off += taintStride {
			store(off)
		}
		// The tail too: a long token (a JWT) can reach the head limit before its
		// last part, the signature, which may also appear alone.
		store(len(raw) - taintWin)
		store(len(raw) - taintWin - taintStride)
	}
	for i := 0; i < nh; i++ {
		t.insertLocked(hs[i])
	}
}

// windowHit returns the offset of the first taintWin-byte window of run that is stored.
func (t *taintRing) windowHit(run string) (int, bool) {
	if len(run) < taintWin || len(run) > taintMaxScan {
		return 0, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	if shannonEntropyBits(run) < taintMinEntropy {
		return 0, false
	}
	for off := 0; off+taintWin <= len(run); off++ {
		if shannonEntropyBits(run[off:off+taintWin]) < taintMinEntropy {
			continue
		}
		if _, ok := t.set[t.hash(run[off:off+taintWin])]; ok {
			return off, true
		}
	}
	return 0, false
}

// clear forgets every stored hash (clear_ram_buffer).
func (t *taintRing) clear() {
	if t == nil {
		return
	}
	t.mu.Lock()
	clear(t.set)
	clear(t.ring[:])
	t.k0, t.k1 = 0, 0
	if t.fips {
		// Drop every pooled HMAC context: they hold the key schedule.
		clear(t.key)
		t.pool = sync.Pool{New: t.newMAC}
	}
	t.pos = 0
	t.filled = 0
	t.size.Store(0)
	t.mu.Unlock()
}

// isTaintByte reports bytes that can be part of a tracked secret: the usual
// token characters plus those of base64 (/ + =), JWTs (.) and user:password (:).
func isTaintByte(c byte) bool {
	return isEntropyCandidate(c) || c == '/' || c == '+' || c == '=' || c == '.' || c == ':'
}

func (t *taintRing) hasFull(s string) bool {
	if len(s) < taintMinLen {
		return false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	if shannonEntropyBits(s) < taintMinEntropy {
		return false
	}
	_, ok := t.set[t.hash(s)]
	return ok
}

// spans returns the [start, end) parts of run that hold a tracked secret. The run
// is cut at "=" and ":" (key=value, user:password) so a name next to the secret
// is not swallowed; the whole run is tried first, because a secret may itself
// hold those characters (base64 padding, "user:password").
func (t *taintRing) spans(run string) [][2]int {
	lo, hi := 0, len(run)
	for lo < hi && (run[lo] == '.' || run[lo] == ':' || run[lo] == '=') {
		lo++
	}
	for hi > lo && (run[hi-1] == '.' || run[hi-1] == ':') {
		hi--
	}
	if hi-lo < taintMinLen {
		return nil
	}
	if t.hasFull(run[lo:hi]) {
		return [][2]int{{lo, hi}}
	}
	var out [][2]int
	for a := lo; a < hi; {
		b := a
		for b < hi && run[b] != '=' && run[b] != ':' {
			b++
		}
		if b > a {
			end := b
			for end < hi && run[end] == '=' { // base64 padding
				end++
			}
			seg := run[a:b]
			switch {
			case len(seg) >= taintMinLen && strings.Contains(seg, "REDACTED_"):
			case end > b && t.hasFull(run[a:end]):
				out = append(out, [2]int{a, end})
			case len(seg) >= taintMinLen && t.hasFull(seg):
				out = append(out, [2]int{a, b})
			case len(seg) >= taintWin:
				// A stored window inside a longer run: redact the piece around it, cut at "/" and "."
				// so a path or host name next to the secret is kept.
				if off, ok := t.windowHit(seg); ok {
					l, r := off, off+taintWin
					for l > 0 && seg[l-1] != '/' && seg[l-1] != '.' {
						l--
					}
					for r < len(seg) && seg[r] != '/' && seg[r] != '.' {
						r++
					}
					out = append(out, [2]int{a + l, a + r})
				}
			}
			b = end
		}
		for b < hi && (run[b] == '=' || run[b] == ':') {
			b++
		}
		a = b
	}
	return out
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
		if !isTaintByte(in[i]) {
			i++
			continue
		}
		j := i
		for j < len(in) && isTaintByte(in[j]) {
			j++
		}
		if j-i >= taintMinLen && !strings.Contains(in[i:j], "REDACTED_") {
			for _, sp := range t.spans(in[i:j]) {
				b.WriteString(in[last : i+sp[0]])
				b.WriteString(s.tag("TOKEN", in[i+sp[0]:i+sp[1]]))
				s.Tokens.Add(1)
				count++
				last = i + sp[1]
			}
		}
		i = j
	}
	if count == 0 {
		return in, 0
	}
	b.WriteString(in[last:])
	return b.String(), count
}
