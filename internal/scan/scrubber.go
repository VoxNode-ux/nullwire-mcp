package scan

import "strings"

// Scrubber is the part of the redaction engine that the scanner needs.
type Scrubber interface {
	ScrubText(in string) (string, int)
	TokenCount() uint64
	IPCount() uint64
}

// NewScrubber builds the Scrubber that Run uses. The app package sets it at
// start-up, so this package does not have to import the app.
var NewScrubber func() (Scrubber, error)

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
