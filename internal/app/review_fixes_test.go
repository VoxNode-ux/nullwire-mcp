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
	inner := append([]byte{0x0a, 0x28}, strings.Repeat("y", 40)...)
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
