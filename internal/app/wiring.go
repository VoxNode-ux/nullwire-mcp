package app

import "github.com/VoxNode-ux/nullwire-mcp/internal/scan"

// The scan package only needs a Scrubber, so the app hands it one here.
func init() {
scan.NewScrubber = func() (scan.Scrubber, error) {
s, err := NewScrubber()
if err != nil {
return nil, err
}
return s, nil
}
}
