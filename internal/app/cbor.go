package app

import (
	"math"
	"strings"
)

// A read-only CBOR walker (RFC 8949). It writes JSON through the shared
// binJSON writer (binary_json.go): maps become objects, arrays become arrays,
// text strings are copied, and byte strings are only counted.
//
// Tags are followed without being written, except tag 24 (a byte string that
// holds another CBOR item): that item is read too, so a secret wrapped in it
// is not hidden from the scrubber. Indefinite-length strings, arrays and maps
// are read, and a map key that is not a text string is written as quoted JSON.

// isCBORContentType reports CBOR payload types, including CBOR sequences and
// the +cbor family (application/senml+cbor, ...).
func isCBORContentType(ct string) bool {
	mt := mediaType(ct)
	return mt == "application/cbor" || mt == "application/x-cbor" || mt == "application/cbor-seq" ||
		strings.HasSuffix(mt, "+cbor") || strings.HasSuffix(mt, "+cbor-seq")
}

// cborToJSON reads every CBOR item in in, one after another, and returns them
// as JSON, one per line. complete is false when the input ended early, went
// past a limit or was not valid CBOR.
func cborToJSON(in []byte) (out string, complete bool) {
	return walkBinary(in, (*binJSON).cborValue)
}

// cborHead reads the initial byte and its argument. For major type 7, arg
// holds the raw bits of a float or the simple value; info tells which.
func (w *binJSON) cborHead() (major, info byte, arg uint64, err error) {
	b, err := w.be(1)
	if err != nil {
		return 0, 0, 0, err
	}
	major, info = byte(b>>5), byte(b&0x1f)
	switch {
	case info < 24:
		arg = uint64(info)
	case info < 28:
		arg, err = w.be(1 << (info - 24)) // 24, 25, 26, 27: 1, 2, 4, 8 bytes
	case info == 31 && major != 0 && major != 1 && major != 6:
		// indefinite length (or the break code); arg stays 0
	default: // 28 to 30 are reserved, and ints and tags cannot be indefinite
		err = errBinBad
	}
	return major, info, arg, err
}

func (w *binJSON) cborValue() error {
	major, info, arg, err := w.cborHead()
	for err == nil && major == 6 { // tags
		if arg == 24 {
			return w.cborEmbedded()
		}
		major, info, arg, err = w.cborHead()
	}
	if err != nil {
		return err
	}
	indefinite := info == 31
	switch major {
	case 0: // unsigned integer
		w.out = appendUint(w.out, arg)
	case 1: // negative integer: -1 - arg
		if arg == math.MaxUint64 {
			w.out = append(w.out, "-18446744073709551616"...)
		} else {
			w.out = appendUint(append(w.out, '-'), arg+1)
		}
	case 2: // byte string: never copied
		if indefinite {
			return w.cborChunks(2)
		}
		return w.placeholder("binary", arg)
	case 3: // text string
		if indefinite {
			return w.cborChunks(3)
		}
		return w.str(arg)
	case 4: // array
		if indefinite {
			return w.items(-1, w.cborEnd, nil, w.cborValue)
		}
		return w.items(clip(arg), nil, nil, w.cborValue)
	case 5: // map
		if indefinite {
			return w.items(-1, w.cborEnd, w.cborKey, w.cborValue)
		}
		return w.items(clip(arg), nil, w.cborKey, w.cborValue)
	default: // 7: simple values and floats
		switch info {
		case 20:
			w.out = append(w.out, "false"...)
		case 21:
			w.out = append(w.out, "true"...)
		case 22, 23: // null, undefined
			w.out = append(w.out, "null"...)
		case 25:
			w.float(halfToFloat(uint16(arg)))
		case 26:
			w.float(float64(math.Float32frombits(uint32(arg))))
		case 27:
			w.float(math.Float64frombits(arg))
		case 31: // a break with nothing to end
			return errBinBad
		default:
			w.out = append(w.out, `"[simple `...)
			w.out = appendUint(w.out, arg)
			w.out = append(w.out, `]"`...)
		}
	}
	return nil
}

// cborKey writes a map key: an untagged text string as is, anything else
// rendered as JSON and quoted.
func (w *binJSON) cborKey() error {
	if w.pos >= len(w.in) {
		return errBinTrunc
	}
	return w.key(w.in[w.pos]>>5 == 3, w.cborValue)
}

// cborEnd reports whether the next byte is the break code that ends an
// indefinite-length array or map, and reads it if so.
func (w *binJSON) cborEnd() (bool, error) {
	if w.pos >= len(w.in) {
		return false, errBinTrunc
	}
	if w.in[w.pos] == 0xff {
		w.pos++
		return true, nil
	}
	return false, nil
}

// cborChunks reads an indefinite-length string: definite-length chunks of the
// same major type up to a break. Text chunks are joined into one JSON string;
// byte chunks are only added up.
func (w *binJSON) cborChunks(major byte) error {
	text := major == 3
	if text {
		w.out = append(w.out, '"')
	}
	var total uint64
	var err error
	for err == nil {
		if w.pos >= len(w.in) {
			err = errBinTrunc
		} else if w.in[w.pos] == 0xff {
			w.pos++
			break
		} else if m, info, n, e := w.cborHead(); e != nil {
			err = e
		} else if m != major || info == 31 { // a chunk must be definite and of the same type
			err = errBinBad
		} else if text {
			err = w.text(n)
		} else {
			_, err = w.take(n)
			total += n
		}
	}
	if text {
		w.out = append(w.out, '"')
	} else {
		w.label("binary", total)
	}
	return err
}

// cborEmbedded reads tag 24: a byte string whose content is one CBOR item.
// The item is read in place, as if it were part of the document.
func (w *binJSON) cborEmbedded() error {
	m, info, n, err := w.cborHead()
	if err != nil {
		return err
	}
	if m != 2 || info == 31 {
		return errBinBad
	}
	b, takeErr := w.take(n)
	if err := w.enter(); err != nil {
		return err
	}
	in, pos := w.in, w.pos
	w.in, w.pos = b, 0
	err = w.cborValue()
	w.in, w.pos = in, pos
	w.leave()
	if err == nil {
		err = takeErr
	}
	return err
}

// halfToFloat converts an IEEE 754 half-precision float.
func halfToFloat(h uint16) float64 {
	sign := 1.0
	if h&0x8000 != 0 {
		sign = -1
	}
	exp, mant := int(h>>10)&0x1f, float64(h&0x3ff)
	switch exp {
	case 0: // zero and subnormals
		return sign * math.Ldexp(mant, -24)
	case 0x1f: // infinity and NaN
		if mant == 0 {
			return sign * math.Inf(1)
		}
		return math.NaN()
	}
	return sign * math.Ldexp(1024+mant, exp-25)
}
