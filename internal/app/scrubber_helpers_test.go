package app

// mustScrubber builds a Scrubber for a test and stops the test run at once if
// that fails. Tests used to write `s, _ := NewScrubber()`, which hid the error
// and left a possibly-nil scrubber in the test body.
func mustScrubber() *Scrubber {
	s, err := NewScrubber()
	if err != nil {
		panic(err)
	}
	return s
}
