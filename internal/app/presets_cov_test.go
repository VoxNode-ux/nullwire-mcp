package app

import (
	"strings"
	"testing"
)

func TestNormalizePresetsForms(t *testing.T) {
	join := func(in ...string) (string, error) {
		got, err := normalizePresets(in)
		return strings.Join(got, ","), err
	}
	for _, c := range []struct {
		in   []string
		want string
	}{
		{[]string{"all"}, "gdpr,hipaa,pci-dss"},
		{[]string{"ALL", "pci-dss"}, "gdpr,hipaa,pci-dss"},
		{[]string{"pci-dss", "PCI-DSS", " pci-dss "}, "pci-dss"},
		{[]string{"", "  ", "gdpr", ""}, "gdpr"},
		{[]string{"hipaa", "all", "hipaa"}, "gdpr,hipaa,pci-dss"},
		{[]string{"gdpr", "pci-dss"}, "gdpr,pci-dss"},
		{nil, ""},
		{[]string{"", " "}, ""},
	} {
		got, err := join(c.in...)
		if err != nil || got != c.want {
			t.Errorf("normalizePresets(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	if got, err := normalizePresets(nil); err != nil || got == nil || len(got) != 0 {
		t.Errorf("no presets must give an empty, non-nil list: %v %v", got, err)
	}
	_, err := normalizePresets([]string{"pci-dss", "Bogus"})
	if err == nil || !strings.Contains(err.Error(), `unknown preset "bogus"`) || !strings.Contains(err.Error(), "valid: pci-dss, hipaa, gdpr, all") {
		t.Errorf("unknown preset error: %v", err)
	}
}

func TestSplitPresetFlagAndSet(t *testing.T) {
	if got := splitPresetFlag(" pci-dss, ,gdpr ,"); strings.Join(got, "|") != "pci-dss|gdpr" {
		t.Errorf("splitPresetFlag = %q", got)
	}
	if got := splitPresetFlag(""); got != nil {
		t.Errorf("an empty flag must give nil, got %q", got)
	}
	if newPresetSet(nil).enabled() || newPresetSet([]string{"nope"}).enabled() {
		t.Error("no known preset must mean disabled")
	}
	p := newPresetSet([]string{"hipaa", "gdpr", "nope"})
	if p.pci || !p.hipaa || !p.gdpr || !p.enabled() {
		t.Errorf("newPresetSet = %+v", p)
	}
}

func spanTexts(in string, spans []secretSpan) []string {
	var out []string
	for _, sp := range spans {
		out = append(out, in[sp.start:sp.end])
	}
	return out
}

func TestCardSecuritySpansTrackShapes(t *testing.T) {
	const t1 = "%B4111111111111111^DOE/JOHN^25121010000000000000?"
	const t2 = ";4111111111111111=25121010000000000000?"
	for _, c := range []struct {
		name, in string
		want     []string
	}{
		{"track1 bare", "track1=" + t1, []string{t1}},
		{"track1 json", `{"track1":"` + t1 + `"}`, []string{t1}},
		{"track1 without leading percent", "track-1: B4111111111111111^DOE/JOHN^2512101?", []string{"B4111111111111111^DOE/JOHN^2512101?"}},
		{"track2 bare", "track2=" + t2, []string{t2}},
		{"track2 without semicolon", "track_2_data: 4111111111111111=25121010000000000000", []string{"4111111111111111=25121010000000000000"}},
		{"generic long value", "track1=abcdefgh1234&x=1", []string{"abcdefgh1234"}},
		{"too short", "track1=abc", nil},
		{"key without assignment", "track1 is blank", nil},
		{"already redacted", "track1=[REDACTED_TOKEN#abcdef0123]", nil},
		{"glued to a word", "xtrack1=" + t1, nil},
	} {
		if got := spanTexts(c.in, cardSecuritySpans(c.in)); strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s: %q gave %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

func TestCardSecuritySpansCVVDecimalDot(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string
	}{
		{"cvv: 123.45", ""},
		{"cvv=123.4 x", ""},
		{"cvv: 123.", "123"},
		{"cvv: 123. next", "123"},
		{"cvv=1234,", "1234"},
		{"cvv=123abc", ""},
		{"cvv=123_", ""},
		{"cvv=12", ""},
		{"cvv=12345", ""},
	} {
		got := strings.Join(spanTexts(c.in, cardSecuritySpans(c.in)), "|")
		if got != c.want {
			t.Errorf("%q: got %q, want %q", c.in, got, c.want)
		}
	}
	// A price-like value is left alone through the whole scrubber.
	s := presetScrubber(t, "pci-dss")
	if out, _ := s.ScrubText(`{"cvv": 123.45}`); redacted(out) {
		t.Errorf("a decimal must not be taken for a CVV: %q", out)
	}
}

func TestIBANGroupedAndLengthLimits(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string
	}{
		{"iban GB82 WEST 1234 5698 7654 32 end", "GB82 WEST 1234 5698 7654 32"},
		{"iban NO93 8601 1117 947 end", "NO93 8601 1117 947"},
		{"iban gb82 west 1234 5698 7654 32", "gb82 west 1234 5698 7654 32"},
		{"iban DE89 3704 0044 0532 0130 00.", "DE89 3704 0044 0532 0130 00"},
		{"iban GB82WEST12345698765432", "GB82WEST12345698765432"},
		{"iban GB82WEST12345698765432-x", ""},
		{"iban x-GB82WEST12345698765432", ""},
		{"iban GB82 WEST 1234 5698 7654 3", ""},
		{"iban GB82 WEST 1234 5698 7654 32 1234", "GB82 WEST 1234 5698 7654 32"},
		{"iban " + "GB82 " + strings.Repeat("1234 ", 10), ""},
		{"iban GB82WEST12345698765432" + "0123456789ABCD", ""},
	} {
		got := strings.Join(spanTexts(c.in, ibanSpans(c.in)), "|")
		if got != c.want {
			t.Errorf("%q: got %q, want %q", c.in, got, c.want)
		}
	}
	for _, c := range []struct {
		iban string
		ok   bool
	}{
		{"GB82WEST12345698765432", true},
		{"NO9386011117947", true},
		{"GB82WEST1234569876543", false},
		{"GB82WEST123456987654321", false},
		{strings.Repeat("A", 35), false},
		{"GB82WEST12345698765432" + strings.Repeat("0", 13), false},
		{"NO938601111794", false},
		{"GBXXWEST12345698765432", false},
		{"GB8XWEST12345698765432", false},
		{"GB82west12345698765432", false},
		{"GB82WEST1234569876543!", false},
		{"ZZ82WEST12345698765432", false},
		{"", false},
	} {
		if got := ibanValid(c.iban); got != c.ok {
			t.Errorf("ibanValid(%q) = %v, want %v", c.iban, got, c.ok)
		}
	}
}

func TestScrubPresetsOverlappingSpans(t *testing.T) {
	// The PCI track rule and the IBAN rule both claim the same 22 characters.
	s := presetScrubber(t, "pci-dss", "gdpr")
	const iban = "GB82WEST12345698765432"
	in := "x track1=" + iban + " y"
	if spans := s.presetSpans(in); len(spans) < 2 {
		t.Fatalf("expected two overlapping spans, got %v", spans)
	}
	out, n := s.scrubPresets(in)
	if n != 1 || strings.Count(out, "[REDACTED_TOKEN#") != 1 || strings.Contains(out, iban) {
		t.Errorf("overlap must be redacted once: n=%d out=%q", n, out)
	}
	if !strings.HasPrefix(out, "x track1=") || !strings.HasSuffix(out, " y") {
		t.Errorf("text around the span must survive: %q", out)
	}
	if got := s.Tokens.Load(); got != 1 {
		t.Errorf("Tokens counter = %d, want 1", got)
	}
	// Two separate hits are both redacted, in order.
	out, n = s.scrubPresets("cvv=123 and " + iban)
	if n != 2 || strings.Count(out, "[REDACTED_TOKEN#") != 2 || !strings.Contains(out, "cvv=") || strings.Contains(out, "cvv=123") || strings.Contains(out, iban) {
		t.Errorf("two hits: n=%d out=%q", n, out)
	}
	// Presets on but nothing found: the input is returned unchanged.
	if out, n := s.scrubPresets("hello world, nothing here"); n != 0 || out != "hello world, nothing here" {
		t.Errorf("no match: %q %d", out, n)
	}
	// No preset on: no work and no change.
	off := presetScrubber(t)
	if out, n := off.scrubPresets("cvv=123 " + iban); n != 0 || out != "cvv=123 "+iban {
		t.Errorf("presets off: %q %d", out, n)
	}
	if off.presetSpans("cvv=123") != nil {
		t.Error("presetSpans must be nil with no preset")
	}
}

func TestCardKeyBoundaryCases(t *testing.T) {
	for _, c := range []struct {
		in   string
		i    int
		want bool
	}{
		{"cvv", 0, true},
		{"_cvv", 1, true},
		{"xcvv", 1, false},
		{"Xcvv", 1, false},
		{"XCvv", 1, false},
		{"1cvv", 1, false},
		{"xCvv", 1, true}, // camel case: cardCvv
	} {
		if got := cardKeyBoundary(c.in, c.i); got != c.want {
			t.Errorf("cardKeyBoundary(%q, %d) = %v, want %v", c.in, c.i, got, c.want)
		}
	}
}

func TestIBANValidEdgeCases(t *testing.T) {
	for in, want := range map[string]bool{
		"GB82WEST12345698765432":  true,
		"DE89370400440532013000":  true,
		"GB82WEST":                false, // too short
		"GB83WEST12345698765432":  false, // bad checksum
		"XX82WEST12345698765432":  false, // unknown country
		"GB82WEST1234569876543":   false, // wrong length for GB
		"GBA2WEST12345698765432":  false, // check digits not digits
		"GB82west12345698765432":  false, // not normalised
		"GB82WEST1234569876543!":  false, // stray symbol
		"GB82" + strings.Repeat("W", 40): false, // too long
	} {
		if got := ibanValid(in); got != want {
			t.Errorf("ibanValid(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestIBANSpansMalformedEdges(t *testing.T) {
	for _, c := range []struct {
		name, in string
		want     []string
	}{
		{"compact", "GB82WEST12345698765432", []string{"GB82WEST12345698765432"}},
		{"grouped lower case", "iban: gb82 west 1234 5698 7654 32 ok", []string{"gb82 west 1234 5698 7654 32"}},
		{"preceded by hyphen", "x-GB82WEST12345698765432", nil},
		{"glued to a trailing letter", "GB82WEST12345698765432X", nil},
		{"bad checksum", "GB83WEST12345698765432", nil},
		{"too short to scan", "GB82WEST", nil},
	} {
		if got := spanTexts(c.in, ibanSpans(c.in)); strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s: %q gave %q, want %q", c.name, c.in, got, c.want)
		}
	}
}
