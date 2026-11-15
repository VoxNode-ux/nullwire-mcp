package main

import (
	"strings"
	"testing"
)

func TestTrainSeparatesIdentifiersFromRandom(t *testing.T) {
	var benign, secret counts
	for i := 0; i < 50; i++ {
		addText(&benign, "getCustomerProfile the_other_thing handleRequest internationalization")
	}
	for _, s := range synthetic(4000) {
		addToken(&secret, s)
	}
	val := map[[2]byte]int8{}
	for _, e := range train(&benign, &secret) {
		val[[2]byte{e.a, e.b}] = e.v
	}
	if v, ok := val[[2]byte{'t', 'h'}]; !ok || v <= 0 {
		t.Errorf("pair th = %d (present %v), want positive", v, ok)
	}
	for _, e := range val {
		if e < lo || e > hi {
			t.Errorf("value %d outside [%d,%d]", e, lo, hi)
		}
	}
}

func TestRenderIsValidGo(t *testing.T) {
	src, err := render([]entry{{'a', 'b', 3}, {'x', 'q', -4}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "{97, 98, 3},") {
		t.Errorf("missing entry in:\n%s", src)
	}
}

func TestSyntheticIsDeterministic(t *testing.T) {
	a, b := synthetic(10), synthetic(10)
	for i := range a {
		if a[i] != b[i] {
			t.Fatal("synthetic output differs between calls")
		}
	}
}
