package app

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"strings"
	"testing"
	"time"
)

// MessagePack and CBOR bodies are shown as JSON and scrubbed by buildEntry.
func TestBuildEntryReadsMsgpackAndCBOR(t *testing.T) {
	app := fxApp(t)
	// msgpack {"password":"hunter2hunter2"}  and  CBOR {"password":"hunter2hunter2"}
	mp := "\x81\xa8password\xaehunter2hunter2"
	cb := "\xa1\x68password\x6ehunter2hunter2"
	for ct, body := range map[string]string{"application/msgpack": mp, "application/cbor": cb} {
		e, ok := app.buildEntry(rawFlow{
			started: time.Now(), method: "POST", url: "http://h/x", status: 200,
			reqHeaders:  http.Header{"Content-Type": {ct}},
			respHeaders: http.Header{"Content-Type": {ct}},
			reqBody:     []byte(body), respBody: []byte(body),
		})
		if !ok {
			t.Fatal("flow was ignored")
		}
		for name, got := range map[string]string{"request": e.RequestBody, "response": e.ResponseBody} {
			if strings.Contains(got, "hunter2hunter2") || !strings.Contains(got, `"password"`) {
				t.Errorf("%s %s body: %q", ct, name, got)
			}
		}
		if !strings.Contains(e.Note, "shown as JSON") {
			t.Errorf("%s: note %q", ct, e.Note)
		}
	}
}

// A redaction tag contains a #, which must not start a URL fragment.
func TestHARQueryKeepsRedactionTags(t *testing.T) {
	got := harQuery("https://api.example.com/v1?api_key=[REDACTED_TOKEN#a1b2c3]&page=2&k=[REDACTED_X#ab12cd]#top")
	want := []harNV{{"api_key", "[REDACTED_TOKEN#a1b2c3]"}, {"page", "2"}, {"k", "[REDACTED_X#ab12cd]"}}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("param %d = %v, want %v", i, got[i], want[i])
		}
	}
	if got := harQuery("http://x/p?a=1#frag"); len(got) != 1 || got[0].Value != "1" {
		t.Errorf("a real fragment must still be cut: %v", got)
	}
	if got := harQuery("http://x/p"); len(got) != 0 {
		t.Errorf("no query: %v", got)
	}
}

// "Bearer ..." that happens to parse as one length-delimited field stays text.
func TestProtoTextThatLooksLikeAMessageStaysText(t *testing.T) {
	// "B" is field 8 wire 2 and "e" (101) is the length of the rest, so these
	// 103 printable bytes are a valid one-field message, but they are text.
	text := "Be" + "bc" + strings.Repeat("x", 99)
	if len(text) != 103 {
		t.Fatalf("test text is %d bytes", len(text))
	}
	body := append([]byte{0x0a, byte(len(text))}, text...)
	out, ok := decodeProtoBody(pbHeader("application/protobuf"), body, 1<<20)
	if !ok || !strings.Contains(out, `1: "Bebc`) || strings.Contains(out, "8: {") {
		t.Errorf("text was cut up as a message: %q (ok=%v)", out, ok)
	}
	// A real nested message made of printable bytes is still one.
	inner := pbCat(pbString(1, strings.Repeat("y", 38)), pbInt(2, 1))
	body = append([]byte{0x1a, byte(len(inner))}, inner...)
	if out, ok := decodeProtoBody(pbHeader("application/protobuf"), body, 1<<20); !ok || !strings.Contains(out, "3: {") {
		t.Errorf("nested message lost: %q (ok=%v)", out, ok)
	}
}

func TestGRPCWebWithHTTPContentEncoding(t *testing.T) {
	frame := []byte{0, 0, 0, 0, 4, 0x0a, 0x02, 'h', 'i'}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(frame)
	_ = zw.Close()
	h := http.Header{"Content-Type": {"application/grpc-web+proto"}, "Content-Encoding": {"gzip"}}
	out, ok := decodeProtoBody(h, gz.Bytes(), 1<<20)
	if !ok || !strings.Contains(out, `1: "hi"`) {
		t.Errorf("got %q (ok=%v)", out, ok)
	}
	h.Set("Content-Encoding", "br")
	if _, ok := decodeProtoBody(h, gz.Bytes(), 1<<20); ok {
		t.Error("an encoding that cannot be decoded must not be read")
	}
}

// Once the output is full, later compressed frames are not decompressed.
func TestGRPCStopsDecodingWhenOutputIsFull(t *testing.T) {
	msg := append([]byte{0x0a, 0x7f}, bytes.Repeat([]byte("z"), 127)...)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(msg)
	_ = zw.Close()
	var body []byte
	for i := 0; i < 50; i++ {
		body = append(body, 1, 0, 0, byte(gz.Len()>>8), byte(gz.Len()))
		body = append(body, gz.Bytes()...)
	}
	h := http.Header{"Content-Type": {"application/grpc"}, "Grpc-Encoding": {"gzip"}}
	out, ok := decodeProtoBody(h, body, 300)
	if !ok || !strings.Contains(out, truncMarker) || len(out) > 300+len(truncMarker)+400 {
		t.Errorf("got %d bytes %q (ok=%v)", len(out), out, ok)
	}
	if strings.Count(out, "message ") > 5 {
		t.Errorf("frames were still read after the output was full: %q", out)
	}
}

func TestGraphQLEdgeCases(t *testing.T) {
	ops := gqlOperations(`query A { f(a: """x \""" y""") } mutation B { g }`)
	if len(ops) != 2 || ops[0].name != "A" || ops[1].kind != "mutation" || ops[1].name != "B" {
		t.Errorf("an escaped triple quote ended the block string: %+v", ops)
	}
	if _, ok := gqlFromObject(map[string]any{"extensions": map[string]any{"persistedQuery": "x"}}); ok {
		t.Error("a persistedQuery that is not an object is not a persisted operation")
	}
	if r, ok := gqlFromObject(map[string]any{"extensions": map[string]any{"persistedQuery": map[string]any{"sha256Hash": "ab"}}}); !ok || !r.persisted {
		t.Errorf("a real persisted query: %+v %v", r, ok)
	}
}

func TestUninspectableRequestEncodingValues(t *testing.T) {
	for in, want := range map[string]string{
		"br":           "br",
		"BR":           "br",
		"gzip, br":     "gzip, br",
		"identity, br": "br",
		"zstd":         "zstd",
		"compress":     "compress",
	} {
		h := http.Header{}
		h.Set("Content-Encoding", in)
		if got, bad := uninspectableRequestEncoding(h); !bad || got != want {
			t.Errorf("%q: got (%q, %v), want (%q, true)", in, got, bad, want)
		}
	}
	for _, in := range []string{"", "identity", "gzip", "x-gzip", "deflate", "GZIP", "identity, gzip"} {
		h := http.Header{}
		if in != "" {
			h.Set("Content-Encoding", in)
		}
		if got, bad := uninspectableRequestEncoding(h); bad || got != "" {
			t.Errorf("%q must be inspectable, got (%q, %v)", in, got, bad)
		}
	}
}

func TestScrubMultipartWithEdgeCases(t *testing.T) {
	app := fxApp(t)
	pw := "hunter2hunter2"
	field := func(disposition, value string) string {
		return "--b\r\nContent-Disposition: " + disposition + "\r\n\r\n" + value + "\r\n"
	}

	// Content types that are not usable multipart are scrubbed as plain text.
	for name, ct := range map[string]string{
		"unparsable":       "multipart/form-data; boundary",
		"not multipart":    "text/plain; boundary=b",
		"missing boundary": "multipart/form-data",
		"empty":            "",
	} {
		out, n := app.scrubMultipartWith(app.scrub, ct, []byte("password="+pw), 0)
		if strings.Contains(out, pw) || n < 1 {
			t.Errorf("%s: leaked or uncounted: %q (%d)", name, out, n)
		}
	}

	// A part whose disposition has no form name is shown as (unnamed).
	body := field(`attachment; name="x"`, "value-one") + "--b--\r\n"
	if out, _ := app.scrubMultipartWith(app.scrub, "multipart/form-data; boundary=b", []byte(body), 1<<10); !strings.Contains(out, "(unnamed)=value-one") {
		t.Errorf("unnamed part: %q", out)
	}

	// A body cut off before its closing boundary keeps what was read and says so.
	cut := field(`form-data; name="a"`, "first") + "--b\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n" + pw
	out, n := app.scrubMultipartWith(app.scrub, "multipart/form-data; boundary=b", []byte(cut), 1<<10)
	if !strings.Contains(out, "a=first") || strings.Contains(out, pw) || n < 1 || !strings.Contains(out, "[multipart body truncated or malformed]") {
		t.Errorf("truncated body: %q (%d)", out, n)
	}

	// A valid boundary but no parts: the text is scrubbed as it is.
	if out, n := app.scrubMultipartWith(app.scrub, "multipart/form-data; boundary=b", []byte("noise password="+pw), 1<<10); strings.Contains(out, pw) || n < 1 {
		t.Errorf("no parts: %q (%d)", out, n)
	}

	// The per-part limit applies to fields and files; a file name is scrubbed.
	tok := "ghp_" + strings.Repeat("a1", 20)
	body = field(`form-data; name="long"`, strings.Repeat("a", 100)) +
		field(`form-data; name="up"; filename="`+tok+`.txt"`, strings.Repeat("b", 100)) + "--b--\r\n"
	out, n = app.scrubMultipartWith(app.scrub, "multipart/form-data; boundary=b", []byte(body), 10)
	if !strings.Contains(out, "long="+strings.Repeat("a", 10)+"\n") || strings.Contains(out, strings.Repeat("a", 11)) {
		t.Errorf("field limit: %q", out)
	}
	if !strings.Contains(out, "10 bytes seen, content not stored") || strings.Contains(out, tok) || n < 1 {
		t.Errorf("file limit or file name: %q (%d)", out, n)
	}
}
