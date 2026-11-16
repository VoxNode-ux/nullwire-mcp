package app

import (
	"math"
	"strconv"
	"strings"
)

// A read-only MessagePack walker. It follows the format in
// github.com/msgpack/msgpack/blob/master/spec.md and writes JSON through the
// shared binJSON writer (binary_json.go): maps become objects, arrays become
// arrays, strings are copied, and bin and ext payloads are only counted.

// isMsgPackContentType reports MessagePack payload types.
func isMsgPackContentType(ct string) bool {
	mt := mediaType(ct)
	switch mt {
	case "application/msgpack", "application/x-msgpack", "application/vnd.msgpack",
		"application/messagepack", "application/x-messagepack":
		return true
	}
	return strings.HasSuffix(mt, "+msgpack")
}

// msgpackToJSON reads every MessagePack value in in, one after another, and
// returns them as JSON, one per line, at most limit bytes of it (0: the
// default). complete is false when the input ended early, went past a limit or
// was not valid MessagePack.
func msgpackToJSON(in []byte, limit int) (out string, complete bool) {
	return walkBinary(in, limit, (*binJSON).msgpackValue)
}

func (w *binJSON) msgpackValue() error {
	b, err := w.be(1)
	if err != nil {
		return err
	}
	c := byte(b) // #nosec G115 -- b is a single wire byte (0-255)
	switch {
	case c <= 0x7f: // positive fixint
		w.out = appendUint(w.out, uint64(c))
		return nil
	case c >= 0xe0: // negative fixint
		w.out = strconv.AppendInt(w.out, int64(int8(c)), 10) // #nosec G115 -- c >= 0xe0: reinterpreting the byte as a two's-complement fixint is the format
		return nil
	case c <= 0x8f: // fixmap
		return w.mpMap(uint64(c & 0x0f))
	case c <= 0x9f: // fixarray
		return w.mpArray(uint64(c & 0x0f))
	case c <= 0xbf: // fixstr
		return w.str(uint64(c & 0x1f))
	}

	switch c {
	case 0xc0:
		w.out = append(w.out, "null"...)
	case 0xc2:
		w.out = append(w.out, "false"...)
	case 0xc3:
		w.out = append(w.out, "true"...)
	case 0xc4, 0xc5, 0xc6: // bin 8, 16, 32: never copied
		n, err := w.be(1 << (c - 0xc4))
		if err != nil {
			return err
		}
		return w.placeholder("binary", n)
	case 0xc7, 0xc8, 0xc9: // ext 8, 16, 32
		n, err := w.be(1 << (c - 0xc7))
		if err != nil {
			return err
		}
		return w.mpExt(n)
	case 0xd4, 0xd5, 0xd6, 0xd7, 0xd8: // fixext 1, 2, 4, 8, 16
		return w.mpExt(1 << (c - 0xd4))
	case 0xca: // float 32
		v, err := w.be(4)
		if err != nil {
			return err
		}
		w.float(float64(math.Float32frombits(uint32(v)))) // #nosec G115 -- v was read as 4 bytes, so it fits uint32
	case 0xcb: // float 64
		v, err := w.be(8)
		if err != nil {
			return err
		}
		w.float(math.Float64frombits(v))
	case 0xcc, 0xcd, 0xce, 0xcf: // uint 8, 16, 32, 64
		v, err := w.be(1 << (c - 0xcc))
		if err != nil {
			return err
		}
		w.out = appendUint(w.out, v)
	case 0xd0, 0xd1, 0xd2, 0xd3: // int 8, 16, 32, 64
		size := 1 << (c - 0xd0)
		v, err := w.be(size)
		if err != nil {
			return err
		}
		shift := 64 - 8*size
		w.out = strconv.AppendInt(w.out, int64(v<<shift)>>shift, 10) // #nosec G115 -- shift left then arithmetic shift right sign-extends a size-byte two's-complement value
	case 0xd9, 0xda, 0xdb: // str 8, 16, 32
		n, err := w.be(1 << (c - 0xd9))
		if err != nil {
			return err
		}
		return w.str(n)
	case 0xdc, 0xdd: // array 16, 32
		n, err := w.be(2 << (c - 0xdc))
		if err != nil {
			return err
		}
		return w.mpArray(n)
	case 0xde, 0xdf: // map 16, 32
		n, err := w.be(2 << (c - 0xde))
		if err != nil {
			return err
		}
		return w.mpMap(n)
	default: // 0xc1 is never used
		return errBinBad
	}
	return nil
}

// mpExt reads the type byte of an extension and skips its n payload bytes.
// An extension (timestamps included) is only described, never copied.
func (w *binJSON) mpExt(n uint64) error {
	t, err := w.be(1)
	if err != nil {
		return err
	}
	return w.placeholder("ext("+strconv.Itoa(int(int8(t)))+")", n) // #nosec G115 -- the ext type is a signed byte on the wire
}

func (w *binJSON) mpArray(n uint64) error {
	return w.items(clip(n), nil, nil, w.msgpackValue)
}

func (w *binJSON) mpMap(n uint64) error {
	return w.items(clip(n), nil, w.mpKey, w.msgpackValue)
}

// mpKey writes a map key. A str key is written as is; any other key is
// rendered as JSON and quoted (JSON keys are always strings).
func (w *binJSON) mpKey() error {
	if w.pos >= len(w.in) {
		return errBinTrunc
	}
	c := w.in[w.pos]
	return w.key(c>>5 == 0b101 || c == 0xd9 || c == 0xda || c == 0xdb, w.msgpackValue)
}