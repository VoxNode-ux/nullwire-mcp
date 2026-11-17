package app

import (
	"os"
	"strings"
	"testing"
)

func writeTestFile(path, body string) error { return os.WriteFile(path, []byte(body), 0o600) }

func presetScrubber(t *testing.T, presets ...string) *Scrubber {
	t.Helper()
	return newAllowScrubber(t, &SecretsConfig{Presets: presets})
}

func redacted(s string) bool { return strings.Contains(s, "[REDACTED_TOKEN#") }

// baselineRedacts reports whether the scrubber without any preset already
// redacts in (the general rules catch some IBAN-looking strings on their own).
// Assertions that a preset leaves such text alone only make sense when it does not.
func baselineRedacts(t *testing.T, in string) bool {
	t.Helper()
	out, _ := presetScrubber(t).ScrubText(in)
	return redacted(out)
}

func TestPresetsOffByDefault(t *testing.T) {
	s := presetScrubber(t)
	for _, in := range []string{
		`{"cvv": "123"}`,
		`ssn: 123-45-6789`,
	} {
		if out, n := s.ScrubText(in); n != 0 || out != in {
			t.Errorf("no preset: %q changed to %q (%d)", in, out, n)
		}
	}
}

func TestPresetNamesValidated(t *testing.T) {
	if _, err := NewScrubberWithConfig(&SecretsConfig{Presets: []string{"pci-dss", "bogus"}}); err == nil {
		t.Error("unknown preset must fail")
	}
	got, err := normalizePresets([]string{" ALL ", "hipaa"})
	if err != nil || len(got) != 3 {
		t.Errorf("all expands to every preset once: %v %v", got, err)
	}
	if _, err := normalizePresets([]string{""}); err != nil {
		t.Errorf("blank entries are ignored: %v", err)
	}
}

func TestPresetPresetIsolation(t *testing.T) {
	ssn, iban, cvv := `ssn: 123-45-6789`, `iban: GB82WEST12345698765432`, `{"cvv": "123"}`
	h := presetScrubber(t, "hipaa")
	if out, _ := h.ScrubText(ssn); !redacted(out) {
		t.Errorf("hipaa must redact SSN: %q", out)
	}
	for _, in := range []string{iban, cvv} {
		if baselineRedacts(t, in) {
			continue
		}
		if out, n := h.ScrubText(in); n != 0 || out != in {
			t.Errorf("hipaa alone changed %q to %q", in, out)
		}
	}
	g := presetScrubber(t, "gdpr")
	if out, _ := g.ScrubText(iban); !redacted(out) {
		t.Errorf("gdpr must redact IBAN: %q", out)
	}
	for _, in := range []string{ssn, cvv} {
		if out, n := g.ScrubText(in); n != 0 || out != in {
			t.Errorf("gdpr alone changed %q to %q", in, out)
		}
	}
	p := presetScrubber(t, "pci-dss")
	if out, _ := p.ScrubText(cvv); !redacted(out) {
		t.Errorf("pci-dss must redact CVV: %q", out)
	}
	for _, in := range []string{ssn, iban} {
		if baselineRedacts(t, in) {
			continue
		}
		if out, n := p.ScrubText(in); n != 0 || out != in {
			t.Errorf("pci-dss alone changed %q to %q", in, out)
		}
	}
	all := presetScrubber(t, "all")
	for _, in := range []string{ssn, iban, cvv} {
		if out, _ := all.ScrubText(in); !redacted(out) {
			t.Errorf("all must redact %q: %q", in, out)
		}
	}
}

func TestPCIPreset(t *testing.T) {
	s := presetScrubber(t, "pci-dss")
	hit := []string{
		`{"cvv": "123"}`, `cvv=123`, `CVC: 1234`, `{"card_cvv2":"987"}`, `cardCvc = 456`, `"cid":"7890"`,
		`track2=;4111111111111111=25121010000000000000?`,
		`{"track1":"%B4111111111111111^DOE/JOHN^25121010000000000000?"}`,
	}
	for _, in := range hit {
		out, n := s.ScrubText(in)
		if n == 0 || !redacted(out) {
			t.Errorf("should redact %q, got %q", in, out)
		}
	}
	if out, _ := s.ScrubText(`{"cvv": "123"}`); strings.Contains(out, "123") {
		t.Errorf("CVV value left in %q", out)
	}
	miss := []string{
		`cvv: 12`, `cvv: 12345`, `{"lcid": 1033}`, `cidr: 1234`, `the cvv code is 123`, `cvv: abc`, `acvv=123x`, `accid=1234`,
	}
	for _, in := range miss {
		if out, _ := s.ScrubText(in); out != in {
			t.Errorf("must not touch %q, got %q", in, out)
		}
	}
	// the Luhn rule stays on without any preset
	plain := presetScrubber(t)
	if out, _ := plain.ScrubText("card 4111 1111 1111 1111"); !strings.Contains(out, "[REDACTED_PAN#") {
		t.Errorf("Luhn PAN redaction must stay always-on: %q", out)
	}
}

func TestSSNPreset(t *testing.T) {
	s := presetScrubber(t, "hipaa")
	hit := []string{
		`ssn: 123-45-6789`, `{"patient_ssn":"123-45-6789"}`, `Social Security Number 123-45-6789`,
		`social_security=123-45-6789`, `TIN: 123-45-6789`, "123-45-6789 (SSN)",
	}
	for _, in := range hit {
		out, _ := s.ScrubText(in)
		if !redacted(out) || strings.Contains(out, "123-45-6789") {
			t.Errorf("should redact %q, got %q", in, out)
		}
	}
	invalid := []string{"000-12-3456", "666-12-3456", "900-12-3456", "987-65-4321", "123-00-6789", "123-45-0000"}
	for _, v := range invalid {
		in := "ssn: " + v
		if out, _ := s.ScrubText(in); out != in {
			t.Errorf("invalid SSA number %q must stay, got %q", v, out)
		}
	}
	for _, v := range invalid {
		if ssnValid(v) {
			t.Errorf("ssnValid(%q) = true", v)
		}
	}
	if !ssnValid("123-45-6789") || !ssnValid("899-99-9999") {
		t.Error("ssnValid rejected a valid number")
	}
	noCtx := []string{
		`order 123-45-6789 shipped`, `ref=123-45-6789`, `date 2024-01-05 id 555-12-3456`, `string 123-45-6789`,
		`tinker 123-45-6789`, `{"phone":"123-45-6789"}`, `x1123-45-6789`, `ssn: 1123-45-67890`,
	}
	for _, in := range noCtx {
		if out, _ := s.ScrubText(in); out != in {
			t.Errorf("without SSN context %q must stay, got %q", in, out)
		}
	}
}

func TestIBANPreset(t *testing.T) {
	s := presetScrubber(t, "gdpr")
	valid := []string{
		"GB82WEST12345698765432", "DE89370400440532013000", "FR1420041010050500013M02606", "NO9386011117947",
		"BE68539007547034", "NL91ABNA0417164300",
	}
	for _, v := range valid {
		if !ibanValid(v) {
			t.Errorf("ibanValid(%q) = false", v)
		}
		in := "pay to " + v + " today"
		out, _ := s.ScrubText(in)
		if !redacted(out) || strings.Contains(out, v) || !strings.HasSuffix(out, " today") {
			t.Errorf("compact %q: %q", v, out)
		}
	}
	// spaced and lower-case forms
	for _, in := range []string{"iban GB82 WEST 1234 5698 7654 32 end", "iban gb82 west 1234 5698 7654 32 end", "iban de89 3704 0044 0532 0130 00.", "iban be68 5390 0754 7034 next word"} {
		out, _ := s.ScrubText(in)
		if !redacted(out) {
			t.Errorf("should redact %q, got %q", in, out)
		}
	}
	if out, _ := s.ScrubText("iban be68 5390 0754 7034 next word"); !strings.HasSuffix(out, " next word") {
		t.Errorf("a following word must not be swallowed: %q", out)
	}
	invalid := []string{
		"GB82WEST12345698765433",   // bad checksum
		"GB82WEST1234569876543",    // wrong length for GB
		"XX82WEST12345698765432",   // unknown country
		"DE89370400440532013001",   // bad checksum
		"GB82 WEST 1234 5698 7654", // truncated
	}
	for _, v := range invalid {
		in := "iban " + v
		if baselineRedacts(t, in) {
			continue
		}
		if out, _ := s.ScrubText(in); redacted(out) {
			t.Errorf("invalid IBAN %q was redacted: %q", v, out)
		}
	}
	if baselineRedacts(t, "id AGB82WEST12345698765432") {
		return
	}
	if out, _ := s.ScrubText("id AGB82WEST12345698765432"); redacted(out) {
		t.Errorf("IBAN glued to a word must stay: %q", out)
	}
}

func TestPresetTagsWorkWithShellQuote(t *testing.T) {
	s := presetScrubber(t, "all")
	out, _ := s.ScrubText(`cvv=123 ssn=123-45-6789 iban=GB82WEST12345698765432`)
	q := shellQuote(out)
	if strings.Contains(q, "123") || strings.Contains(q, "GB82") || !strings.Contains(q, `"$`) {
		t.Errorf("shellQuote did not turn preset tags into env references: %q", q)
	}
}

func TestPresetsInsideEscapedAndEncodedText(t *testing.T) {
	s := presetScrubber(t, "all")
	in := `{\"cvv\":\"123\"}`
	if out, _ := s.ScrubText(in); strings.Contains(out, "123") {
		t.Errorf("escaped JSON CVV leaked: %q", out)
	}
}
