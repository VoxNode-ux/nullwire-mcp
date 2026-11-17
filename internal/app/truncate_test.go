package app

import (
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateKeepsRunesAndTagsWhole(t *testing.T) {
	// A cut inside a multi-byte rune steps back to the rune start.
	in := strings.Repeat("é", 10) // 2 bytes each
	if out := truncate(in, 5); !utf8.ValidString(out) {
		t.Errorf("invalid UTF-8 after cut: %q", out)
	}
	// A cut inside a redaction tag drops the whole tag.
	tag := "[REDACTED_TOKEN#ab12cd]"
	s := "key=" + tag + " tail"
	for cut := 5; cut < 4+len(tag); cut++ {
		out := truncate(s, cut)
		if strings.Contains(out, "[REDACTED_") || strings.Contains(strings.TrimSuffix(out, truncMarker), "[RED") {
			t.Errorf("cut %d left part of a tag: %q", cut, out)
		}
	}
	// A cut after the tag keeps it.
	if out := truncate(s, 4+len(tag)+1); !strings.Contains(out, tag) {
		t.Errorf("complete tag lost: %q", out)
	}
}

func TestStackedContentEncoding(t *testing.T) {
	h := http.Header{}
	h.Add("Content-Encoding", "identity")
	h.Add("Content-Encoding", "gzip")
	if got := effectiveContentEncoding(joinedContentEncoding(h)); got != "gzip" {
		t.Errorf("effective encoding = %q, want gzip", got)
	}
	if _, bad := uninspectableRequestEncoding(h); bad {
		t.Errorf("identity+gzip must be inspectable")
	}
}
