package app

import (
	"math"
	"testing"
)

// The walkers read fixed-size integers through typed readers and decode signed
// values by subtracting 2^bits. These cases pin the edge values.
func TestMsgpackSignedEdges(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"negative fixint -32", "\xe0", "-32"},
		{"negative fixint -1", "\xff", "-1"},
		{"int8 -128", "\xd0\x80", "-128"},
		{"int8 127", "\xd0\x7f", "127"},
		{"int8 -1", "\xd0\xff", "-1"},
		{"int16 min", "\xd1\x80\x00", "-32768"},
		{"int16 max", "\xd1\x7f\xff", "32767"},
		{"int16 -1", "\xd1\xff\xff", "-1"},
		{"int32 min", "\xd2\x80\x00\x00\x00", "-2147483648"},
		{"int32 max", "\xd2\x7f\xff\xff\xff", "2147483647"},
		{"int32 -1", "\xd2\xff\xff\xff\xff", "-1"},
		{"int64 min", "\xd3\x80\x00\x00\x00\x00\x00\x00\x00", "-9223372036854775808"},
		{"int64 max", "\xd3\x7f\xff\xff\xff\xff\xff\xff\xff", "9223372036854775807"},
		{"int64 -1", "\xd3\xff\xff\xff\xff\xff\xff\xff\xff", "-1"},
		{"int64 -2", "\xd3\xff\xff\xff\xff\xff\xff\xff\xfe", "-2"},
		{"ext type -1", "\xd4\xff\x00", `"[ext(-1) 1 bytes]"`},
		{"ext type 127", "\xd4\x7f\x00", `"[ext(127) 1 bytes]"`},
		{"ext type -128", "\xd4\x80\x00", `"[ext(-128) 1 bytes]"`},
		{"float32 1.5", "\xca\x3f\xc0\x00\x00", "1.5"},
		{"float64 -2", "\xcb\xc0\x00\x00\x00\x00\x00\x00\x00", "-2"},
	}
	for _, c := range cases {
		out, ok := msgpackToJSON([]byte(c.in), 0)
		if !ok || out != c.want {
			t.Errorf("%s: got %q complete=%v, want %q", c.name, out, ok, c.want)
		}
	}
}

func TestCBORFloatWidths(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"half 1.0", "\xf9\x3c\x00", "1"},
		{"half -2.0", "\xf9\xc0\x00", "-2"},
		{"half 65504", "\xf9\x7b\xff", "65504"},
		{"half inf", "\xf9\x7c\x00", "null"},
		{"single 1.5", "\xfa\x3f\xc0\x00\x00", "1.5"},
		{"double -4.1", "\xfb\xc0\x10\x66\x66\x66\x66\x66\x66", "-4.1"},
		{"uint8 arg", "\x18\xff", "255"},
		{"uint16 arg", "\x19\x01\x00", "256"},
		{"uint32 arg", "\x1a\x00\x01\x00\x00", "65536"},
		{"uint64 arg", "\x1b\x00\x00\x00\x01\x00\x00\x00\x00", "4294967296"},
	}
	for _, c := range cases {
		out, ok := cborToJSON([]byte(c.in), 0)
		if !ok || out != c.want {
			t.Errorf("%s: got %q complete=%v, want %q", c.name, out, ok, c.want)
		}
	}
	// A float whose argument is cut short is reported, never misread.
	if _, ok := cborToJSON([]byte("\xfa\x3f\xc0"), 0); ok {
		t.Error("truncated single-precision float must not be complete")
	}
}

func TestBinJSONReadersAndTake(t *testing.T) {
	w := &binJSON{in: []byte{0x12, 0x34, 0x56, 0x78, 0x9a}}
	if v, err := w.readU16(); err != nil || v != 0x1234 {
		t.Fatalf("readU16 = %#x, %v", v, err)
	}
	if v, err := w.readByte(); err != nil || v != 0x56 {
		t.Fatalf("readByte = %#x, %v", v, err)
	}
	// Two bytes left: a 4-byte read fails and consumes the rest.
	if _, err := w.readU32(); err != errBinTrunc || w.pos != len(w.in) {
		t.Fatalf("short readU32: err=%v pos=%d", err, w.pos)
	}
	w = &binJSON{in: []byte("abc")}
	if b, err := w.take(math.MaxUint64); err != errBinTrunc || string(b) != "abc" || w.pos != 3 {
		t.Errorf("take(MaxUint64) = %q, %v, pos %d", b, err, w.pos)
	}
	w = &binJSON{in: []byte{1, 2, 3, 4, 5, 6, 7, 8}}
	if v, err := w.be(8); err != nil || v != 0x0102030405060708 {
		t.Errorf("be(8) = %#x, %v", v, err)
	}
	w = &binJSON{in: []byte{1, 2, 3}}
	if v, err := w.be(3); err != nil || v != 0x010203 {
		t.Errorf("be(3) = %#x, %v", v, err)
	}
}
