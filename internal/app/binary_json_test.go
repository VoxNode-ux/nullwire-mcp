package app

import (
	"encoding/json"
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
	runWalkCases(t, msgpackToJSON, []walkCase{
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
	out, complete := msgpackToJSON([]byte(strings.Repeat("\x91", 200)))
	if complete || !json.Valid([]byte(out)) || strings.Count(out, "[") > binMaxDepth {
		t.Errorf("deep nesting: complete=%v, %d bytes, valid=%v", complete, len(out), json.Valid([]byte(out)))
	}
}

func TestCBORWalker(t *testing.T) {
	runWalkCases(t, cborToJSON, []walkCase{
		{"object", "\xa2\x68password\x67hunter2\x61n\x85\x01\x20\xf5\xf6\xfb\x3f\xf8\x00\x00\x00\x00\x00\x00",
			`{"password":"hunter2","n":[1,-1,true,null,1.5]}`, true},
		{"indefinite text", "\x7f\x63abc\x63def\xff", `"abcdef"`, true},
		{"indefinite array", "\x9f\x01\x02\xff", `[1,2]`, true},
		{"indefinite map", "\xbf\x61a\x01\xff", `{"a":1}`, true},
		{"number as key", "\xa1\x01\x61x", `{"1":"x"}`, true},
		{"embedded CBOR (tag 24)", "\xd8\x18\x45\xa1\x61a\x61b", `{"a":"b"}`, true},
		{"other tags are skipped", "\xc1\x1a\x51\x4b\x67\xb0", `1363896240`, true},
		{"negative integers", "\x92\x38\x63\x3b\xff\xff\xff\xff\xff\xff\xff\xff", `[-100,-18446744073709551616]`, true},
		{"floats", "\x93\xf9\x3e\x00\xf9\x7c\x00\xfa\x47\xc3\x50\x00", `[1.5,null,100000]`, true},
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
	s, _ := NewScrubber()
	secret := "hunter2-correct-horse"
	for name, c := range map[string]struct{ ct, body string }{
		"msgpack": {"application/msgpack", "\x82\xa4user\xa3sam\xa8password\xb5" + secret},
		"cbor":    {"application/cbor; charset=binary", "\xa2\x64user\x63sam\x68password\x75" + secret},
	} {
		text, _, ok := binaryBodyJSON(c.ct, []byte(c.body))
		if !ok {
			t.Fatalf("%s: content type not recognised", name)
		}
		if out, n := s.ScrubText(text); n == 0 || strings.Contains(out, secret) {
			t.Errorf("%s: secret leaked: %q", name, out)
		}
	}
	if _, _, ok := binaryBodyJSON("application/json", []byte("{}")); ok {
		t.Error("application/json must not be read as a binary format")
	}
	if text, _, ok := binaryBodyJSON("application/msgpack", []byte("\xc1")); !ok || !strings.Contains(text, "not captured") {
		t.Errorf("unreadable body: got (%q, %v)", text, ok)
	}
}

func FuzzBinaryWalkers(f *testing.F) {
	f.Add("\x82\xa8password\xa7hunter2\xa1n\x95\x01\xff\xc3\xc0\xcb\x3f\xf8\x00\x00\x00\x00\x00\x00")
	f.Add("\xa2\x68password\x67hunter2\x61n\x85\x01\x20\xf5\xf6\xfb\x3f\xf8\x00\x00\x00\x00\x00\x00")
	f.Add("\xd8\x18\x45\xa1\x61a\x61b")
	f.Fuzz(func(t *testing.T, in string) {
		for name, walk := range map[string]func([]byte) (string, bool){"msgpack": msgpackToJSON, "cbor": cborToJSON} {
			out, _ := walk([]byte(in))
			for _, line := range strings.Split(out, "\n") {
				if line != "" && !json.Valid([]byte(line)) {
					t.Fatalf("%s: input %q gave invalid JSON %q", name, in, line)
				}
			}
		}
	})
}