package app

import (
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"testing"
)

type walkCase struct {
	name, in, want string
	complete       bool
}

func runWalkCases(t *testing.T, walk func([]byte) (string, bool), cases []walkCase) {
	t.Helper()
	for _, c := range cases {
		got, complete := walk([]byte(c.in))
		if got != c.want || complete != c.complete {
			t.Errorf("%s: got (%q, %v), want (%q, %v)", c.name, got, complete, c.want, c.complete)
		}
	}
}

func TestMsgPackWalker(t *testing.T) {
	runWalkCases(t, func(b []byte) (string, bool) { return msgpackToJSON(b, 0) }, []walkCase{
		{"object", "\x82\xa8password\xa7hunter2\xa1n\x95\x01\xff\xc3\xc0\xcb\x3f\xf8\x00\x00\x00\x00\x00\x00",
			`{"password":"hunter2","n":[1,-1,true,null,1.5]}`, true},
		{"ints", "\x93\xcc\xff\xd1\xff\x38\xcf\xff\xff\xff\xff\xff\xff\xff\xff", `[255,-200,18446744073709551615]`, true},
		{"bin and ext are not copied", "\x92\xc4\x04SECR\xd6\x05abcd", `["[binary 4 bytes]","[ext(5) 4 bytes]"]`, true},
		{"number as key", "\x81\x01\xa1x", `{"1":"x"}`, true},
		{"cut inside a string", "\x82\xa8password\xa7hunt", `{"password":"hunt"}`, false},
		{"cut after a key", "\x81\xa1a", `{"a":null}`, false},
		{"unused byte", "\xc1", ``, false},
		{"stream of values", "\x01\xa1a", "1\n\"a\"", true},
		{"claimed length is not trusted", "\xdd\xff\xff\xff\xff\x01", `[1]`, false},
		{"invalid UTF-8", "\xa2\xff\xfe", `"\ufffd\ufffd"`, true},
		{"control characters", "\xa3a\"\n", `"a\"\u000a"`, true},
	})
	out, complete := msgpackToJSON([]byte(strings.Repeat("\x91", 200)), 0)
	if complete || !json.Valid([]byte(out)) || strings.Count(out, "[") > binMaxDepth {
		t.Errorf("deep nesting: complete=%v, %d bytes, valid=%v", complete, len(out), json.Valid([]byte(out)))
	}
}

func TestCBORWalker(t *testing.T) {
	runWalkCases(t, func(b []byte) (string, bool) { return cborToJSON(b, 0) }, []walkCase{
		{"object", "\xa2\x68password\x67hunter2\x61n\x85\x01\x20\xf5\xf6\xfb\x3f\xf8\x00\x00\x00\x00\x00\x00",
			`{"password":"hunter2","n":[1,-1,true,null,1.5]}`, true},
		{"indefinite text", "\x7f\x63abc\x63def\xff", `"abcdef"`, true},
		{"indefinite array", "\x9f\x01\x02\xff", `[1,2]`, true},
		{"indefinite map", "\xbf\x61a\x01\xff", `{"a":1}`, true},
		{"number as key", "\xa1\x01\x61x", `{"1":"x"}`, true},
		{"embedded CBOR (tag 24)", "\xd8\x18\x45\xa1\x61a\x61b", `{"a":"b"}`, true},
		{"other tags are skipped", "\xc1\x1a\x51\x4b\x67\xb0", `1363896240`, true},
		{"negative integers", "\x82\x38\x63\x3b\xff\xff\xff\xff\xff\xff\xff\xff", `[-100,-18446744073709551616]`, true},
		{"floats", "\x83\xf9\x3e\x00\xf9\x7c\x00\xfa\x47\xc3\x50\x00", `[1.5,null,100000]`, true},
		{"byte strings are not copied", "\x82\x43abc\x5f\x42ab\x41c\xff", `["[binary 3 bytes]","[binary 3 bytes]"]`, true},
		{"invalid UTF-8", "\x62\xff\xfe", `"\ufffd\ufffd"`, true},
		{"cut inside a string", "\xa1\x68password\x67hun", `{"password":"hun"}`, false},
		{"stray break", "\xff", ``, false},
		{"reserved info value", "\x1c", ``, false},
		{"indefinite chunk inside a chunk", "\x7f\x7f\xff\xff", `""`, false},
		{"long run of tags", strings.Repeat("\xc1", 100000) + "\x01", `1`, true},
	})
}

func TestBinaryBodiesAreScrubbed(t *testing.T) {
	s := mustScrubber()
	secret := "hunter2-correct-horse"
	for name, c := range map[string]struct{ ct, body string }{
		"msgpack": {"application/msgpack", "\x82\xa4user\xa3sam\xa8password\xb5" + secret},
		"cbor":    {"application/cbor; charset=binary", "\xa2\x64user\x63sam\x68password\x75" + secret},
	} {
		text, _, ok := binaryBodyJSON(c.ct, []byte(c.body), 0)
		if !ok {
			t.Fatalf("%s: content type not recognised", name)
		}
		if out, n := s.ScrubText(text); n == 0 || strings.Contains(out, secret) {
			t.Errorf("%s: secret leaked: %q", name, out)
		}
	}
	if _, _, ok := binaryBodyJSON("application/json", []byte("{}"), 0); ok {
		t.Error("application/json must not be read as a binary format")
	}
	if text, _, ok := binaryBodyJSON("application/msgpack", []byte("\xc1"), 0); !ok || !strings.Contains(text, "not captured") {
		t.Errorf("unreadable body: got (%q, %v)", text, ok)
	}
}

func TestBinaryWalkersHonourTheLimit(t *testing.T) {
	// str 8 holding 100 bytes, with room for 16 bytes of JSON: the quote and 15 bytes.
	long := "\xd9\x64" + strings.Repeat("a", 100)
	if got, complete := msgpackToJSON([]byte(long), 16); got != `"`+strings.Repeat("a", 15)+`"` || complete {
		t.Errorf("msgpack: got (%q, %v)", got, complete)
	}
	if got, complete := cborToJSON([]byte("\x78\x64"+strings.Repeat("a", 100)), 16); got != `"`+strings.Repeat("a", 15)+`"` || complete {
		t.Errorf("cbor: got (%q, %v)", got, complete)
	}
	// The same body is read whole when the limit allows it.
	if got, complete := msgpackToJSON([]byte(long), 4096); len(got) != 102 || !complete {
		t.Errorf("msgpack with room: got %d bytes, complete=%v", len(got), complete)
	}
}

func TestBinaryBodyTextCutsTheTruncationMarker(t *testing.T) {
	h := http.Header{"Content-Type": {"application/msgpack"}, "Content-Encoding": {"gzip"}}
	text, note, ok := binaryBodyText(h, "\x81\xa1a\xa1b"+truncMarker, 0)
	if !ok || text != `{"a":"b"}` || !strings.Contains(note, "cut") {
		t.Errorf("gzip body at the limit: got (%q, %q, %v)", text, note, ok)
	}
	// Without a Content-Encoding the body is used as it is.
	h.Del("Content-Encoding")
	if text, _, _ := binaryBodyText(h, "\x81\xa1a\xa1b", 0); text != `{"a":"b"}` {
		t.Errorf("plain body: got %q", text)
	}
	h.Set("Content-Encoding", "br")
	if _, _, ok := binaryBodyText(h, "[encoded body omitted: Content-Encoding br, 9 bytes captured]", 0); ok {
		t.Error("an omitted body must not be walked")
	}
}

func FuzzBinaryWalkers(f *testing.F) {
	f.Add("\x82\xa8password\xa7hunter2\xa1n\x95\x01\xff\xc3\xc0\xcb\x3f\xf8\x00\x00\x00\x00\x00\x00")
	f.Add("\xa2\x68password\x67hunter2\x61n\x85\x01\x20\xf5\xf6\xfb\x3f\xf8\x00\x00\x00\x00\x00\x00")
	f.Add("\xd8\x18\x45\xa1\x61a\x61b")
	f.Fuzz(func(t *testing.T, in string) {
		for name, walk := range map[string]func([]byte, int) (string, bool){"msgpack": msgpackToJSON, "cbor": cborToJSON} {
			out, _ := walk([]byte(in), 0)
			for _, line := range strings.Split(out, "\n") {
				if line != "" && !json.Valid([]byte(line)) {
					t.Fatalf("%s: input %q gave invalid JSON %q", name, in, line)
				}
			}
		}
	})
}
func TestMsgPackExtBinFloatAndIntBranches(t *testing.T) {
	runWalkCases(t, func(b []byte) (string, bool) { return msgpackToJSON(b, 0) }, []walkCase{
		{"ext 8", "\xc7\x04\x07abcd", `"[ext(7) 4 bytes]"`, true},
		{"ext 16", "\xc8\x00\x02\x05ab", `"[ext(5) 2 bytes]"`, true},
		{"ext 32", "\xc9\x00\x00\x00\x01\x05a", `"[ext(5) 1 bytes]"`, true},
		{"fixext with a negative type", "\xd4\xff\x01", `"[ext(-1) 1 bytes]"`, true},
		{"fixext 16", "\xd8\x01" + strings.Repeat("a", 16), `"[ext(1) 16 bytes]"`, true},
		{"cut ext payload", "\xc7\x04\x07ab", `"[ext(7) 4 bytes]"`, false},
		{"cut ext header", "\xc7\x04", ``, false},
		{"bin 16", "\xc5\x00\x03abc", `"[binary 3 bytes]"`, true},
		{"bin 32", "\xc6\x00\x00\x00\x02ab", `"[binary 2 bytes]"`, true},
		{"float 32", "\xca\x3f\xc0\x00\x00", `1.5`, true},
		{"float 32 NaN", "\xca\x7f\xc0\x00\x00", `null`, true},
		{"float 64", "\xcb\x40\x59\x00\x00\x00\x00\x00\x00", `100`, true},
		{"float 64 infinity", "\xcb\x7f\xf0\x00\x00\x00\x00\x00\x00", `null`, true},
		{"cut float", "\xcb\x3f", ``, false},
		{"uint 16 and 32", "\x92\xcd\x01\x00\xce\x00\x01\x00\x00", `[256,65536]`, true},
		{"signed ints of every width", "\x94\xd0\x80\xd1\xff\x00\xd2\xff\xff\xff\xfe\xd3\xff\xff\xff\xff\xff\xff\xff\xff", `[-128,-256,-2,-1]`, true},
		{"cut uint", "\xcd\x01", ``, false},
		{"fixints", "\x92\x7f\xe0", `[127,-32]`, true},
		{"str 16", "\xda\x00\x02hi", `"hi"`, true},
		{"str 32", "\xdb\x00\x00\x00\x02hi", `"hi"`, true},
		{"empty fixstr", "\xa0", `""`, true},
		{"array 16", "\xdc\x00\x02\x01\x02", `[1,2]`, true},
		{"array 32", "\xdd\x00\x00\x00\x01\x05", `[5]`, true},
		{"map 16", "\xde\x00\x01\xa1a\x01", `{"a":1}`, true},
		{"map 32", "\xdf\x00\x00\x00\x01\xa1a\x02", `{"a":2}`, true},
		{"empty containers", "\x92\x90\x80", `[[],{}]`, true},
	})
}

func TestMsgPackMapKeys(t *testing.T) {
	runWalkCases(t, func(b []byte) (string, bool) { return msgpackToJSON(b, 0) }, []walkCase{
		{"float key", "\x81\xcb\x3f\xf8\x00\x00\x00\x00\x00\x00\xa1x", `{"1.5":"x"}`, true},
		{"bool key", "\x81\xc3\x01", `{"true":1}`, true},
		{"nil key", "\x81\xc0\x01", `{"null":1}`, true},
		{"negative number key", "\x81\xff\x01", `{"-1":1}`, true},
		{"array key", "\x81\x91\x01\xa1x", `{"[1]":"x"}`, true},
		{"map key", "\x81\x81\xa1a\x01\x02", `{"{\"a\":1}":2}`, true},
		{"binary key", "\x81\xc4\x02ab\x01", `{"\"[binary 2 bytes]\"":1}`, true},
		{"str 8 key", "\x81\xd9\x01k\x01", `{"k":1}`, true},
		{"cut before a key", "\x81", `{}`, false},
	})
}

func TestMsgPackLimitStopsNesting(t *testing.T) {
	out, complete := msgpackToJSON([]byte("\x91\x91\x01"), 1)
	if out != `[]` || complete {
		t.Errorf("got (%q, %v)", out, complete)
	}
}

func TestCBORNumbersAndSimpleValues(t *testing.T) {
	runWalkCases(t, func(b []byte) (string, bool) { return cborToJSON(b, 0) }, []walkCase{
		{"integer widths", "\x84\x18\xff\x19\x01\x00\x1a\x00\x01\x00\x00\x1b\x00\x00\x00\x01\x00\x00\x00\x00", `[255,256,65536,4294967296]`, true},
		{"half zero", "\xf9\x00\x00", `0`, true},
		{"half negative zero", "\xf9\x80\x00", `-0`, true},
		{"half one", "\xf9\x3c\x00", `1`, true},
		{"half negative two", "\xf9\xc0\x00", `-2`, true},
		{"half largest", "\xf9\x7b\xff", `65504`, true},
		{"half negative infinity", "\xf9\xfc\x00", `null`, true},
		{"half NaN", "\xf9\x7e\x00", `null`, true},
		{"float 32", "\xfa\x3f\xc0\x00\x00", `1.5`, true},
		{"float 32 NaN", "\xfa\x7f\xc0\x00\x00", `null`, true},
		{"float 64 negative infinity", "\xfb\xff\xf0\x00\x00\x00\x00\x00\x00", `null`, true},
		{"false true null undefined", "\x84\xf4\xf5\xf6\xf7", `[false,true,null,null]`, true},
		{"simple value 0", "\xe0", `"[simple 0]"`, true},
		{"simple value in the next byte", "\xf8\x20", `"[simple 32]"`, true},
		{"text length forms", "\x84\x78\x03abc\x79\x00\x03abc\x7a\x00\x00\x00\x03abc\x7b\x00\x00\x00\x00\x00\x00\x00\x03abc", `["abc","abc","abc","abc"]`, true},
		{"byte string length form", "\x58\x02ab", `"[binary 2 bytes]"`, true},
		{"array and map with a length byte", "\x82\x98\x02\x01\x02\xb8\x01\x61a\x01", `[[1,2],{"a":1}]`, true},
		{"tag with a wider argument", "\xd9\x01\x00\x01", `1`, true},
		{"cut head", "\x19\x01", ``, false},
		{"reserved head in an array", "\x81\x1f", `[]`, false},
	})
}

func TestCBORKeysAndIndefiniteForms(t *testing.T) {
	runWalkCases(t, func(b []byte) (string, bool) { return cborToJSON(b, 0) }, []walkCase{
		{"float key", "\xa1\xf9\x3e\x00\x61x", `{"1.5":"x"}`, true},
		{"negative key", "\xa1\x20\x01", `{"-1":1}`, true},
		{"byte string key", "\xa1\x41a\x01", `{"\"[binary 1 bytes]\"":1}`, true},
		{"tagged text key", "\xa1\xc1\x61a\x01", `{"\"a\"":1}`, true},
		{"array key", "\xa1\x81\x01\x02", `{"[1]":2}`, true},
		{"cut before a key", "\xa1", `{}`, false},
		{"indefinite array cut", "\x9f\x01", `[1]`, false},
		{"indefinite map cut after a key", "\xbf\x61a", `{"a":null}`, false},
		{"indefinite text cut", "\x7f\x63abc", `"abc"`, false},
		{"byte chunk of the wrong type", "\x5f\x61a\xff", `"[binary 0 bytes]"`, false},
		{"embedded item that is not a byte string", "\xd8\x18\x01", ``, false},
		{"embedded item that is indefinite", "\xd8\x18\x5f", ``, false},
		{"embedded item cut short", "\xd8\x18\x45\xa1\x61a", `{"a":null}`, false},
	})
	out, complete := cborToJSON([]byte(strings.Repeat("\x81", 200)), 0)
	if complete || !json.Valid([]byte(out)) || strings.Count(out, "[") > binMaxDepth {
		t.Errorf("deep nesting: complete=%v, valid=%v", complete, json.Valid([]byte(out)))
	}
}

func TestBinaryContentTypes(t *testing.T) {
	for ct, want := range map[string]bool{
		"application/msgpack":             true,
		"application/x-msgpack":           true,
		"application/vnd.msgpack":         true,
		"application/messagepack":         true,
		"application/x-messagepack":       true,
		"application/foo+msgpack":         true,
		"Application/MsgPack; charset=x":  true,
		"application/json":                false,
		"":                                false,
	} {
		if got := isMsgPackContentType(ct); got != want {
			t.Errorf("isMsgPackContentType(%q) = %v, want %v", ct, got, want)
		}
	}
	for ct, want := range map[string]bool{
		"application/cbor":              true,
		"application/x-cbor":            true,
		"application/cbor-seq":          true,
		"application/senml+cbor":        true,
		"application/foo+cbor-seq":      true,
		"application/CBOR; charset=bin": true,
		"application/json":              false,
		"":                              false,
	} {
		if got := isCBORContentType(ct); got != want {
			t.Errorf("isCBORContentType(%q) = %v, want %v", ct, got, want)
		}
	}
}

func TestBinaryBodyJSONNotes(t *testing.T) {
	text, note, ok := binaryBodyJSON("application/msgpack", []byte("\x81\xa1a"), 0)
	if !ok || text != `{"a":null}` || !strings.Contains(note, "ends early") {
		t.Errorf("cut MessagePack: (%q, %q, %v)", text, note, ok)
	}
	text, note, ok = binaryBodyJSON("application/cbor", []byte("\xa1\x61a\x01"), 0)
	if !ok || text != `{"a":1}` || !strings.Contains(note, "CBOR body shown as JSON") {
		t.Errorf("complete CBOR: (%q, %q, %v)", text, note, ok)
	}
	text, note, ok = binaryBodyJSON("application/cbor", []byte("\xff"), 0)
	if !ok || text != "[CBOR body not readable, not captured: 1 bytes]" || !strings.Contains(note, "could not be read") {
		t.Errorf("unreadable CBOR: (%q, %q, %v)", text, note, ok)
	}
}

func TestMsgPackEveryHeaderCutShort(t *testing.T) {
	// Each value is cut inside its length or payload: the walk reports it as
	// incomplete and whatever it wrote is still valid JSON (or nothing).
	for name, in := range map[string]string{
		"str 8 header":     "\xd9",
		"str 16 header":    "\xda\x00",
		"str 32 header":    "\xdb\x00\x00",
		"bin 8 header":     "\xc4",
		"bin 16 header":    "\xc5\x00",
		"bin 32 header":    "\xc6\x00\x00\x00",
		"ext 8 header":     "\xc7",
		"ext 16 header":    "\xc8\x00",
		"ext 32 header":    "\xc9\x00\x00\x00",
		"fixext header":    "\xd4",
		"fixext payload":   "\xd8\x01",
		"array 16 header":  "\xdc\x00",
		"array 32 header":  "\xdd\x00\x00",
		"map 16 header":    "\xde\x00",
		"map 32 header":    "\xdf\x00\x00\x00",
		"uint 32":          "\xce\x00",
		"uint 64":          "\xcf\x00\x00\x00\x00\x00\x00\x00",
		"int 8":            "\xd0",
		"int 32":           "\xd2\xff\xff",
		"int 64":           "\xd3\x00",
		"float 32":         "\xca\x3f\xc0",
		"float 64":         "\xcb",
		"array element":    "\x92\x01",
		"array 16 element": "\xdc\x00\x03\x01",
		"map value":        "\x82\xa1a\x01\xa1b",
		"map key":          "\x82\xa1a\x01",
	} {
		out, complete := msgpackToJSON([]byte(in), 0)
		if complete {
			t.Errorf("%s: must be incomplete", name)
		}
		if out != "" && !json.Valid([]byte(out)) {
			t.Errorf("%s: output %q is not valid JSON", name, out)
		}
	}
}

func TestBinaryWalkerLimits(t *testing.T) {
	// A string longer than the room is cut at the limit.
	if out, complete := msgpackToJSON([]byte("\xd9\x0aabcdefghij"), 5); out != `"abcd"` || complete {
		t.Errorf("long string: (%q, %v)", out, complete)
	}
	// A container that starts after the limit is left out, and the comma with it.
	if out, complete := msgpackToJSON([]byte("\x92\xa5hello\x91\x01"), 8); out != `["hello"]` || complete {
		t.Errorf("container past the limit: (%q, %v)", out, complete)
	}
	// Output stays valid JSON whatever the limit.
	body := []byte("\x83\xa4name\xa5alice\xa5items\x93\x01\x02\x03\xa4meta\x81\xa1k\xa1v")
	for limit := 1; limit < 60; limit++ {
		if out, _ := msgpackToJSON(body, limit); out != "" && !json.Valid([]byte(out)) {
			t.Errorf("limit %d: invalid JSON %q", limit, out)
		}
	}
	// Maps nested past binMaxDepth stop the walk.
	deepMap := strings.Repeat("\x81\xa1a", binMaxDepth+6) + "\x01"
	if out, complete := msgpackToJSON([]byte(deepMap), 0); complete || !json.Valid([]byte(out)) {
		t.Errorf("deep maps: complete=%v valid=%v", complete, json.Valid([]byte(out)))
	}
}

func TestBinJSONHelpers(t *testing.T) {
	// take and be refuse a position outside the input and a negative size.
	w := &binJSON{in: []byte("ab"), pos: -1}
	if _, err := w.take(1); err == nil {
		t.Error("take with a negative position must fail")
	}
	w.pos = 5
	if _, err := w.take(1); err == nil {
		t.Error("take past the end must fail")
	}
	if _, err := w.be(-1); err == nil {
		t.Error("be(-1) must fail")
	}
	w = &binJSON{in: []byte("abc")}
	if b, err := w.take(10); err != errBinTrunc || string(b) != "abc" || w.pos != 3 {
		t.Errorf("take(10) = %q, %v, pos %d", b, err, w.pos)
	}

	if got := string(appendJSONBytes(nil, []byte("a\"b\\c\x01é\xff"))); got != `a\"b\\c\u0001é\ufffd` {
		t.Errorf("appendJSONBytes = %q", got)
	}
	if got := string(appendUint(nil, 0)); got != "0" {
		t.Errorf("appendUint(0) = %q", got)
	}
	if got := string(appendUint(nil, 1<<64-1)); got != "18446744073709551615" {
		t.Errorf("appendUint(max) = %q", got)
	}
	if clip(1<<63) != 1<<62 || clip(5) != 5 {
		t.Error("clip")
	}
	w = &binJSON{limit: 100}
	w.float(1.25)
	w.out = append(w.out, ' ')
	w.float(math.NaN())
	w.out = append(w.out, ' ')
	w.float(math.Inf(-1))
	if string(w.out) != "1.25 null null" {
		t.Errorf("float = %q", w.out)
	}
}

func TestCBORChunkAndTagEdgeCases(t *testing.T) {
	for name, in := range map[string]string{
		"text chunk of the wrong type":  "\x7f\x41a\xff",
		"byte chunk cut":                "\x5f\x42a",
		"text chunk cut":                "\x7f\x62a",
		"indefinite text without break": "\x7f",
		"indefinite bytes no break":     "\x5f",
		"tag without an item":           "\xc1",
		"definite array cut":            "\x83\x01",
		"definite map cut":              "\xa2\x61a\x01",
		"half float cut":                "\xf9\x3e",
		"simple value cut":              "\xf8",
	} {
		out, complete := cborToJSON([]byte(in), 0)
		if complete {
			t.Errorf("%s: must be incomplete", name)
		}
		if out != "" && !json.Valid([]byte(out)) {
			t.Errorf("%s: output %q is not valid JSON", name, out)
		}
	}
	// A nested array that would start past the limit is left out.
	if out, complete := cborToJSON([]byte("\x83\x01\x02\x81\x03"), 3); out != "[1,2]" || complete {
		t.Errorf("array over the limit: (%q, %v)", out, complete)
	}
}

func TestCovHalfToFloat(t *testing.T) {
	for _, c := range []struct {
		h    uint16
		want float64
	}{
		{0x0000, 0},
		{0x3c00, 1},
		{0xc000, -2},
		{0x7bff, 65504},
		{0x0001, math.Ldexp(1, -24)},
		{0x7c00, math.Inf(1)},
		{0xfc00, math.Inf(-1)},
	} {
		if got := halfToFloat(c.h); got != c.want {
			t.Errorf("halfToFloat(%#04x) = %v, want %v", c.h, got, c.want)
		}
	}
	if got := halfToFloat(0x8000); got != 0 || !math.Signbit(got) {
		t.Errorf("halfToFloat(0x8000) = %v, want -0", got)
	}
	if got := halfToFloat(0x7e00); !math.IsNaN(got) {
		t.Errorf("halfToFloat(0x7e00) = %v, want NaN", got)
	}
}
