package app

import "testing"

func TestSipHash24Vectors(t *testing.T) {
	const k0, k1 = 0x0706050403020100, 0x0f0e0d0c0b0a0908
	var in []byte
	if got := siphash24(k0, k1, ""); got != 0x726fdb47dd0e0e31 {
		t.Fatalf("empty: %#x", got)
	}
	for i := 0; i < 15; i++ {
		in = append(in, byte(i))
	}
	if got := siphash24(k0, k1, string(in)); got != 0xa129ca6149be45e5 {
		t.Fatalf("15 bytes: %#x", got)
	}
}

func TestSipHash24NoAllocs(t *testing.T) {
	s := "0123456789abcdef0123456789"
	if n := testing.AllocsPerRun(100, func() { _ = siphash24(1, 2, s) }); n != 0 {
		t.Fatalf("allocs = %v", n)
	}
}
