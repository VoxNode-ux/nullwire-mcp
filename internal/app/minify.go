package app

import (
	"bytes"
	"encoding/json"
)

// minifyJSON compacts s when it is a complete JSON object or array, and
// returns s unchanged otherwise (plain text, scalars, truncated or invalid
// JSON, several documents in a row). It is used only for the captured copy
// that is already scrubbed, under -minify; it never sees wire bytes.
//
// The compacted text is built in a fresh buffer. The temporary byte copies
// made here are zeroed with clear() before returning.
func minifyJSON(s string) string {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	if i == len(s) || (s[i] != '{' && s[i] != '[') {
		return s
	}
	src := []byte(s)
	defer clear(src)
	var dst bytes.Buffer
	dst.Grow(len(src))
	err := json.Compact(&dst, src)
	out := dst.Bytes()
	defer clear(out)
	if err != nil || len(out) >= len(s) {
		return s
	}
	return string(out)
}
