package app

import "testing"

func TestWSInflaterCloseIsSafe(t *testing.T) {
	var nilInflater *wsInflater
	nilInflater.Close() // must not panic

	z := newWSInflater(true, 1024)
	if out, _, ok := z.decode([]byte{0x4a, 0x4c, 0x4c, 0x04, 0x00}, false); !ok || string(out) != "aaa" { // "aaa", deflated
		t.Fatalf("decode before Close: got (%q, %v)", out, ok)
	}
	z.Close()
	z.Close()
	if z.fr != nil || z.window != nil {
		t.Error("Close left the reader or the dictionary behind")
	}
	if _, _, ok := z.decode([]byte{0x4a, 0x4c, 0x4c, 0x04, 0x00}, false); ok {
		t.Error("a closed inflater must not decode")
	}
}