package app

import (
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MessagePack and CBOR bodies are binary, so the text rules cannot read them.
// The two walkers (msgpack.go, cbor.go) read such a body once, front to back,
// and write it out as JSON. The JSON then goes through the normal scrubber, so
// every rule that already knows {"password":"x"} applies to it unchanged.
//
// The walkers are read-only and copy out only what can be scrubbed:
//
//   - map keys and UTF-8 strings are copied
//   - numbers, booleans and null are copied
//   - binary strings and extension payloads are never copied: only their size
//     is written, e.g. "[binary 32 bytes]"
//
// They allocate nothing from a length the input claims. Every element uses at
// least one input byte, so the work is bounded by the size of the input, and a
// body cut off by the capture limit still gives valid JSON of what was read.

const binMaxDepth = 64 // deepest nesting followed

var (
	errBinTrunc = errors.New("input ends early")
	errBinBad   = errors.New("not valid for this format")
	errBinLimit = errors.New("depth or size limit reached")
)

// binJSON is the state shared by both walkers: the input, a read position and
// the JSON written so far.
type binJSON struct {
	in    []byte
	pos   int
	out   []byte
	depth int
	limit int // most JSON written; the caller's decoded-body limit
}

// take returns the next n bytes, or what is left of them with errBinTrunc.
func (w *binJSON) take(n uint64) ([]byte, error) {
	if w.pos < 0 || w.pos > len(w.in) {
		return nil, io.ErrUnexpectedEOF
	}
	if n > uint64(len(w.in)-w.pos) { // #nosec G115 -- pos is within [0, len(in)], so the difference is non-negative
		b := w.in[w.pos:]
		w.pos = len(w.in)
		return b, errBinTrunc
	}
	nn := int(n) // #nosec G115 -- n <= len(in)-pos, checked above, so it fits an int
	b := w.in[w.pos : w.pos+nn]
	w.pos += nn
	return b, nil
}

// be reads an n-byte big-endian unsigned integer (n is 1, 2, 4 or 8).
func (w *binJSON) be(n int) (uint64, error) {
	if n < 0 {
		return 0, io.ErrUnexpectedEOF
	}
	b, err := w.take(uint64(n)) // #nosec G115 -- n is non-negative, checked above
	if err != nil {
		return 0, err
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v, nil
}

// enter and leave count nesting. A body nested deeper than binMaxDepth stops
// the walk; it is never followed further.
func (w *binJSON) enter() error {
	if w.depth >= binMaxDepth || len(w.out) >= w.limit {
		return errBinLimit
	}
	w.depth++
	return nil
}

func (w *binJSON) leave() { w.depth-- }

// text writes the next n input bytes as the inside of a JSON string (no
// quotes). If the input ends early, the part that is there is still written,
// because a secret cut by the capture limit must still reach the scrubber.
func (w *binJSON) text(n uint64) error {
	b, err := w.take(n)
	if room := w.limit - len(w.out); len(b) > room {
		b, err = b[:max(room, 0)], errBinLimit
	}
	w.out = appendJSONBytes(w.out, b)
	return err
}

// str writes the next n input bytes as a JSON string.
func (w *binJSON) str(n uint64) error {
	w.out = append(w.out, '"')
	err := w.text(n)
	w.out = append(w.out, '"')
	return err
}

// label writes a string such as "[binary 32 bytes]" for data that is not
// copied. placeholder does the same and also skips the data in the input.
func (w *binJSON) label(kind string, n uint64) {
	w.out = append(w.out, `"[`...)
	w.out = append(w.out, kind...)
	w.out = append(w.out, ' ')
	w.out = appendUint(w.out, n)
	w.out = append(w.out, ` bytes]"`...)
}

func (w *binJSON) placeholder(kind string, n uint64) error {
	_, err := w.take(n)
	w.label(kind, n)
	return err
}

// float writes a floating-point number. JSON has no NaN or Infinity: null.
func (w *binJSON) float(f float64) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		w.out = append(w.out, "null"...)
		return
	}
	w.out = strconv.AppendFloat(w.out, f, 'g', -1, 64)
}

// key writes a map key. JSON keys are always strings: a text key is written
// as it is, any other key (a number, a nested map, ...) is rendered as JSON
// first and then quoted.
func (w *binJSON) key(isText bool, value func() error) error {
	if isText {
		return value()
	}
	start := len(w.out)
	err := value()
	raw := append([]byte(nil), w.out[start:]...)
	if len(raw) == 0 {
		return err
	}
	w.out = append(w.out[:start], '"')
	w.out = appendJSONBytes(w.out, raw)
	w.out = append(w.out, '"')
	return err
}

// items writes the elements of an array or the pairs of a map (key != nil).
// n < 0 means an indefinite length, ended when end reports true. Whatever
// happens, the container is closed, so the output stays valid JSON.
func (w *binJSON) items(n int64, end func() (bool, error), key, value func() error) error {
	if err := w.enter(); err != nil {
		return err
	}
	defer w.leave()
	open, closer := byte('['), byte(']')
	if key != nil {
		open, closer = '{', '}'
	}
	w.out = append(w.out, open)
	var err error
	for i := int64(0); n < 0 || i < n; i++ {
		if n < 0 {
			var done bool
			if done, err = end(); err != nil || done {
				break
			}
		}
		mark := len(w.out)
		if i > 0 {
			w.out = append(w.out, ',')
		}
		at := len(w.out)
		if key != nil {
			if err = key(); err != nil {
				if len(w.out) == at {
					w.out = w.out[:mark] // nothing of this pair was written
				} else {
					w.out = append(w.out, ":null"...)
				}
				break
			}
			w.out = append(w.out, ':')
			at = len(w.out)
		}
		if err = value(); err != nil {
			if len(w.out) > at {
				break
			}
			if key != nil {
				w.out = append(w.out, "null"...)
			} else {
				w.out = w.out[:mark]
			}
			break
		}
	}
	w.out = append(w.out, closer)
	return err
}

// clip turns a length the input claims into a loop count that cannot overflow.
func clip(n uint64) int64 { return int64(min(n, 1<<62)) }

// walkBinary runs one walker over a whole body. limit is the most JSON it
// writes (the decoded-body limit in force, see bodyLimits); 0 means the default. A body can hold several
// values one after another (MessagePack streams, CBOR sequences); they are
// written on separate lines. complete is false when the input ended early,
// went past a limit or was not valid; out then holds what could be read, or
// is empty when not even the first value could be.
func walkBinary(in []byte, limit int, value func(*binJSON) error) (out string, complete bool) {
	if limit <= 0 {
		limit = decodedLimit
	}
	w := &binJSON{in: in, limit: limit}
	var err error
	for w.pos < len(w.in) && err == nil {
		if len(w.out) > 0 {
			w.out = append(w.out, '\n')
		}
		start := len(w.out)
		if err = value(w); err != nil && len(w.out) == start {
			w.out = w.out[:max(start-1, 0)]
		}
	}
	return string(w.out), err == nil
}

// appendJSONBytes appends s as the inside of a JSON string. Bytes that are not
// valid UTF-8 become U+FFFD.
func appendJSONBytes(dst, s []byte) []byte {
	const hex = "0123456789abcdef"
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			dst = append(dst, '\\', c)
			i++
		case c < 0x20:
			dst = append(dst, '\\', 'u', '0', '0', hex[c>>4], hex[c&15])
			i++
		case c < utf8.RuneSelf:
			dst = append(dst, c)
			i++
		default:
			r, n := utf8.DecodeRune(s[i:])
			if r == utf8.RuneError && n == 1 {
				dst = append(dst, `\ufffd`...)
			} else {
				dst = append(dst, s[i:i+n]...)
			}
			i += n
		}
	}
	return dst
}

func appendUint(dst []byte, v uint64) []byte {
	var tmp [20]byte
	i := len(tmp)
	for {
		i--
		tmp[i] = byte('0' + v%10)
		if v /= 10; v == 0 {
			break
		}
	}
	return append(dst, tmp[i:]...)
}

// mediaType returns the lower-case media type of a Content-Type value.
func mediaType(ct string) string {
	mt, _, _ := strings.Cut(ct, ";")
	return strings.ToLower(strings.TrimSpace(mt))
}

// binaryBodyJSON renders a MessagePack or CBOR body, chosen by its
// Content-Type, as JSON text that the normal scrubber then reads. ok is false
// when ct names neither format; the caller keeps its usual path. Bytes that
// could not be read are never stored: text says so instead. limit is the most
// JSON written (bodyLimits.decoded); 0 means the default.
func binaryBodyJSON(ct string, body []byte, limit int) (text, note string, ok bool) {
	var name string
	var walk func([]byte, int) (string, bool)
	switch {
	case isMsgPackContentType(ct):
		name, walk = "MessagePack", msgpackToJSON
	case isCBORContentType(ct):
		name, walk = "CBOR", cborToJSON
	default:
		return "", "", false
	}
	out, complete := walk(body, limit)
	switch {
	case out == "":
		return fmt.Sprintf("[%s body not readable, not captured: %d bytes]", name, len(body)),
			" " + name + " body could not be read.", true
	case complete:
		note = " " + name + " body shown as JSON; binary values not captured."
	default:
		note = " " + name + " body shown as JSON; it ends early or is not valid, so the rest was not read."
	}
	return out, note, true
}

// binaryBodyText is the MessagePack and CBOR step of buildEntry. raw is the
// body as bodyTextMax returned it. When a gzip or deflate body hit the decoded
// limit, decodeBodyMax appended truncMarker to it; that text is not part of
// the binary data, so it is cut off before the walk and the cut is reported.
func binaryBodyText(h http.Header, raw string, limit int) (text, note string, ok bool) {
	if strings.HasPrefix(raw, "[encoded body omitted") {
		return "", "", false
	}
	cut := false
	if ce := strings.TrimSpace(h.Get("Content-Encoding")); ce != "" && !strings.EqualFold(ce, "identity") {
		raw, cut = strings.CutSuffix(raw, truncMarker)
	}
	text, note, ok = binaryBodyJSON(h.Get("Content-Type"), []byte(raw), limit)
	if ok && cut {
		note += " The decoded body reached the size limit and was cut there."
	}
	return text, note, ok
}