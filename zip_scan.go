package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
)

// Zip Bomb Shield limits. They are checked against the size an entry declares
// and again while it is read, because a hostile archive can declare less than
// it expands to.
const (
	zipMaxArchive = 10 << 20 // largest archive file that is opened
	zipMaxEntry   = 1 << 20  // largest single entry that is read
	zipMaxTotal   = 20 << 20 // most bytes read from one archive
	zipMaxEntries = 1000     // most entries looked at
)

// scanZipFile looks inside a ZIP archive (nothing is extracted to disk) and
// reports which entries contain secrets. Entry text is never shown.
func scanZipFile(s *Scrubber, path string, report *strings.Builder) (ok bool, hits, tokens int) {
	fi, err := os.Stat(path)
	if err != nil {
		fmt.Fprintf(report, "✗ %s: %v\n", path, err)
		return false, 0, 0
	}
	if fi.Size() > zipMaxArchive {
		fmt.Fprintf(report, "✗ %s: archive larger than %d MiB (Zip Bomb Shield)\n", path, zipMaxArchive>>20)
		return false, 0, 0
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(report, "✗ %s: %v\n", path, err)
		return false, 0, 0
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		fmt.Fprintf(report, "✗ %s: not a valid ZIP archive\n", path)
		return false, 0, 0
	}
	fmt.Fprintf(report, "✓ %s (ZIP archive)\n", path)

	var total uint64
	for i, f := range zr.File {
		if i >= zipMaxEntries {
			fmt.Fprintf(report, "   ⚠️ stopped after %d entries (Zip Bomb Shield)\n", zipMaxEntries)
			break
		}
		if f.FileInfo().IsDir() {
			continue
		}
		if f.UncompressedSize64 > zipMaxEntry {
			fmt.Fprintf(report, "   ⚠️ skipped %q: %d bytes is over the %d MiB entry limit (Zip Bomb Shield)\n", f.Name, f.UncompressedSize64, zipMaxEntry>>20)
			continue
		}
		total += f.UncompressedSize64
		if total > zipMaxTotal {
			fmt.Fprintf(report, "   ⚠️ stopped at %q: archive total is over %d MiB (Zip Bomb Shield)\n", f.Name, zipMaxTotal>>20)
			break
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(rc, zipMaxEntry+1))
		_ = rc.Close()
		if err != nil {
			continue
		}
		if len(b) > zipMaxEntry {
			fmt.Fprintf(report, "   ⚠️ skipped %q: expands past the %d MiB entry limit (Zip Bomb Shield)\n", f.Name, zipMaxEntry>>20)
			continue
		}
		head := b
		if len(head) > 8192 {
			head = head[:8192]
		}
		if bytes.IndexByte(head, 0) >= 0 {
			continue // binary content
		}
		if _, n := s.ScrubText(string(b)); n > 0 {
			fmt.Fprintf(report, "   in %q: %d secret(s) found (text not shown)\n", f.Name, n)
			hits++
			tokens += n
		}
	}
	if hits == 0 {
		fmt.Fprintf(report, "   (no secrets found)\n")
	}
	return true, hits, tokens
}
