package main

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func isAlnum(s string, min, max int) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return true
}

// FuzzVendorKeysNoLeak checks that whatever characters a Stripe, OpenAI
// project, Google OAuth, GitLab, Hugging Face, npm or SendGrid key body
// contains, no part of the key survives scrubbing.
func FuzzVendorKeysNoLeak(f *testing.F) {
	f.Add("A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0")
	f.Add("0000000000000000000000000000000000000000")
	f.Add("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
	f.Fuzz(func(t *testing.T, body string) {
		if !isAlnum(body, 40, 200) || strings.Contains(body, "REDACTED") {
			t.Skip()
		}
		half := len(body) / 2
		secrets := []string{
			"sk_live_" + body, "rk_live_" + body, "sk-proj-" + body,
			"ya29." + body, "glpat-" + body, "hf_" + body, "npm_" + body,
			"SG." + body[:half] + "." + body[half:],
		}
		s, err := NewScrubber()
		if err != nil {
			t.Fatal(err)
		}
		tail := body[len(body)-12:]
		for _, secret := range secrets {
			in := "found " + secret + " in the body"
			out, n := s.ScrubText(in)
			if n == 0 || strings.Contains(out, secret) || strings.Contains(out, tail) {
				t.Fatalf("key survived scrubbing\ninput:  %q\noutput: %q", in, out)
			}
		}
	})
}

// FuzzIPv6NoLeak builds a real IPv6 address from 16 arbitrary bytes and checks
// it never survives scrubbing, in prose, brackets, JSON, and at the end of a
// sentence. Addresses the scrubber deliberately keeps (loopback, unspecified,
// short all-letter forms) are skipped through the same ipv6Redactable rule the
// scrubber uses.
func FuzzIPv6NoLeak(f *testing.F) {
	f.Add([]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	f.Add([]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x01, 0xff, 0xfe, 0x23, 0x45, 0x67, 0x89, 0x0a})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) != 16 {
			t.Skip()
		}
		var b [16]byte
		copy(b[:], raw)
		addr := netip.AddrFrom16(b)
		if !ipv6Redactable(addr) {
			t.Skip()
		}
		text := addr.String()
		s, err := NewScrubber()
		if err != nil {
			t.Fatal(err)
		}
		for _, ctx := range []string{"%s", "peer %s connected", "[%s]:443", "addr=%s;", `{"ip":"%s"}`, "seen at %s."} {
			in := fmt.Sprintf(ctx, text)
			out, n := s.scrubIPv6(in)
			if n != 1 || strings.Contains(out, text) {
				t.Fatalf("address survived\ninput:  %q\noutput: %q (count %d)", in, out, n)
			}
		}
	})
}

// FuzzIPv6Stable feeds arbitrary text and checks the scrubber is
// well-behaved: the reported count matches the tags it wrote, a second pass
// changes nothing, and text with fewer than two colons is never touched.
func FuzzIPv6Stable(f *testing.F) {
	f.Add("fe80::1 and 12:30:45 and aa:bb:cc:dd:ee:ff and std::vector")
	f.Add("[2001:db8::1]:443 ::ffff:192.0.2.1 v1.2.3 0xdeadbeef")
	f.Add("::::::: ..:.:..: 1:2:3:4:5:6:7:8:9 ::g ::1%")
	f.Fuzz(func(t *testing.T, in string) {
		s, err := NewScrubber()
		if err != nil {
			t.Fatal(err)
		}
		out, n := s.scrubIPv6(in)
		if strings.Count(in, ":") < 2 && (out != in || n != 0) {
			t.Fatalf("touched text with <2 colons: %q -> %q", in, out)
		}
		if got := strings.Count(out, "[REDACTED_IP#") - strings.Count(in, "[REDACTED_IP#"); got != n {
			t.Fatalf("count %d but %d new tags\ninput:  %q\noutput: %q", n, got, in, out)
		}
		if out2, n2 := s.scrubIPv6(out); n2 != 0 || out2 != out {
			t.Fatalf("second pass changed output\nfirst:  %q\nsecond: %q", out, out2)
		}
	})
}
