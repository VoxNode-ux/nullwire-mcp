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

func TestRcovAddTokenIgnoresNonASCII(t *testing.T) {
	var c counts
	addToken(&c, "ab\xc3\xa9cd") // a pair that touches a byte >= 128 is not counted
	var total float64
	for _, v := range c {
		total += v
	}
	if total != 2 { // only "ab" and "cd"
		t.Errorf("counted %v pairs, want 2", total)
	}
	addToken(&c, "a") // too short for any pair
}

func TestRcovTrainClampsAndNeedsBothClasses(t *testing.T) {
	var benign, secret counts
	if got := train(&benign, &secret); got != nil {
		t.Errorf("empty classes: %v, want nil", got)
	}
	benign[int('a')<<7|int('b')] = 1e6
	if got := train(&benign, &secret); got != nil {
		t.Errorf("no secret class: %v, want nil", got)
	}
	secret[int('c')<<7|int('d')] = 1e6
	secret[int('a')<<7|int('b')] = 1
	benign[int('c')<<7|int('d')] = 1
	got := train(&benign, &secret)
	if len(got) != 2 {
		t.Fatalf("entries = %v, want 2", got)
	}
	if got[0].a != 'a' || got[0].b != 'b' || got[0].v != hi {
		t.Errorf("benign-only pair = %+v, want clamped to %d", got[0], hi)
	}
	if got[1].a != 'c' || got[1].b != 'd' || got[1].v != lo {
		t.Errorf("secret-only pair = %+v, want clamped to %d", got[1], lo)
	}
}