package app

import "testing"

// FuzzUnwrapEscapes checks the offset map that lets the unwrap pass edit the
// original text: whatever the input, the map must stay in range and in order.
func FuzzUnwrapEscapes(f *testing.F) {
	for _, seed := range []string{
		"", "plain", "%41%42", "%4", "%zz", `\"`, `\\`, `{\"a\":\"b\"}`, "a%25b", `\\\"`, "100%", "\\",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		dec, idx := unwrapEscapes(in)
		if len(idx) != len(dec)+1 {
			t.Fatalf("len(idx)=%d, want %d", len(idx), len(dec)+1)
		}
		if int(idx[len(dec)]) != len(in) {
			t.Fatalf("last offset %d, want %d", idx[len(dec)], len(in))
		}
		for i := 1; i < len(idx); i++ {
			if idx[i] < idx[i-1] || int(idx[i]) > len(in) {
				t.Fatalf("offsets out of order or range at %d: %v", i, idx)
			}
		}
		if len(dec) > len(in) {
			t.Fatalf("decoding grew the text: %d > %d", len(dec), len(in))
		}
	})
}

// FuzzScrubContextsNoPanic runs every context on arbitrary text.
func FuzzScrubContextsNoPanic(f *testing.F) {
	for _, seed := range []string{
		"", "token=%73k_live_" + ctxTestBody, `{\"api_key\":\"x\"}`, "Bearer abc%2Fdef", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		randomToken(300),
	} {
		f.Add(seed)
	}
	s := mustScrubber()
	f.Fuzz(func(t *testing.T, in string) {
		for _, ctx := range []ScrubContext{ContextBody, ContextHeader, ContextQuery, ContextPath} {
			out, n := s.ScrubTextIn(in, ctx)
			if n < 0 || (n == 0 && out != in && !containsRedaction(out)) {
				t.Fatalf("context %d: count %d but output changed without a tag: %q -> %q", ctx, n, in, out)
			}
		}
	})
}

func containsRedaction(s string) bool {
	for i := 0; i+9 < len(s); i++ {
		if s[i] == '[' && s[i+1:i+10] == "REDACTED_" {
			return true
		}
	}
	return false
}
