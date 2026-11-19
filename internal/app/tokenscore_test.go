package app

import "testing"

func TestTokenLogOdds(t *testing.T) {
	secrets := []string{
		"Zq8Xv3LmP0aTr9YkB2nWd6HsJ4cFe7Gu",
		"9fK2xQ7vLm3Zt8Yb1nPd5RcJ0wHs4Ae6",
		"00000000_Zq8Xv3LmP0aTr9YkB2nWd6HsJ4cFe7Gu",
	}
	idents := []string{
		"getUserAccountBalanceFromCache",
		"handle_incoming_websocket_frames",
		"NewScrubberWithConfigAndOptions",
		"internal_server_error_response_handler",
	}
	for _, s := range secrets {
		if z := tokenLogOdds(s); z <= 0 {
			t.Errorf("secret %q scored %.2f", s, z)
		}
	}
	for _, s := range idents {
		if z := tokenLogOdds(s); z > 0 {
			t.Errorf("identifier %q scored %.2f", s, z)
		}
	}
}

func TestMaxWindowEntropyNoAllocs(t *testing.T) {
	s := "00000000_Zq8Xv3LmP0aTr9YkB2nWd6HsJ4cFe7Gu"
	if n := testing.AllocsPerRun(100, func() { _ = maxWindowEntropy(s) }); n != 0 {
		t.Fatalf("allocs = %v", n)
	}
}

func TestCovBgClass(t *testing.T) {
	for c, want := range map[byte]int{'a': 0, 'z': 0, 'A': 1, 'Z': 1, '0': 2, '9': 2, '_': 3, '-': 3, '!': 4, ' ': 4} {
		if got := bgClass(c); got != want {
			t.Errorf("bgClass(%q) = %d, want %d", c, got, want)
		}
	}
}
