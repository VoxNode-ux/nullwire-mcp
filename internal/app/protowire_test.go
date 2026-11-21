package app

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Helpers are prefixed pb so they cannot collide with other test files.

func pbInt(field int, v uint64) []byte {
	out := binary.AppendUvarint(nil, uint64(field)<<3)
	return binary.AppendUvarint(out, v)
}

func pbBytes(field int, p []byte) []byte {
	out := binary.AppendUvarint(nil, uint64(field)<<3|2)
	out = binary.AppendUvarint(out, uint64(len(p)))
	return append(out, p...)
}

func pbString(field int, s string) []byte { return pbBytes(field, []byte(s)) }

func pbCat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// pbGRPCFrame builds one gRPC frame. The result is allocated up front with
// make and filled by index, so it is never nil, even for a nil message.
func pbGRPCFrame(flag byte, msg []byte) []byte {
	out := make([]byte, 5+len(msg))
	out[0] = flag
	binary.BigEndian.PutUint32(out[1:5], uint32(len(msg)))
	copy(out[5:], msg)
	return out
}

func pbHeader(ct string) http.Header { return http.Header{"Content-Type": {ct}} }

func TestProtoDecodeFieldsAndSubmessages(t *testing.T) {
	msg := pbCat(
		pbInt(1, 42),
		pbString(2, "hello"),
		pbBytes(3, pbCat(pbString(1, "inner"), pbInt(2, 7))),
		pbBytes(4, []byte{0xff, 0xfe, 0x00}),
		pbString(5, ""),
	)
	out, ok := decodeProtoBody(pbHeader("application/x-protobuf"), msg, 1<<20)
	if !ok {
		t.Fatal("a valid message was not decoded")
	}
	for _, want := range []string{
		protoBanner,
		"1: 42\n",
		"2: \"hello\"\n",
		"3: {\n  1: \"inner\"\n  2: 7\n}\n",
		"4: <3 bytes binary>\n",
		"5: \"\"\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
}

func TestProtoDecodeNeverPrintsRawBytes(t *testing.T) {
	raw := []byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa}
	out, ok := decodeProtoBody(pbHeader("application/x-protobuf"), pbBytes(1, raw), 1<<20)
	if !ok {
		t.Fatal("not decoded")
	}
	for _, c := range raw {
		if strings.IndexByte(out, c) >= 0 {
			t.Errorf("raw byte %#x leaked: %q", c, out)
		}
	}
	if !strings.Contains(out, "1: <6 bytes binary>") {
		t.Errorf("the byte count is missing: %q", out)
	}
}

func TestProtoDecodeRejectsNonProtobuf(t *testing.T) {
	for name, b := range map[string][]byte{
		"empty":         nil,
		"field zero":    {1, 2, 3, 4, 5},
		"group":         []byte("secret-looking-bytes"),
		"wire type 7":   {0x0f, 0x00},
		"only a cutoff": {0x0a, 0x05, 'h'},
	} {
		if out, ok := decodeProtoBody(pbHeader("application/x-protobuf"), b, 1<<20); ok {
			t.Errorf("%s: decoded as %q", name, out)
		}
	}
}

func TestProtoDecodeCutOffMessage(t *testing.T) {
	msg := pbCat(pbInt(1, 5), pbString(2, "hello world"))
	out, ok := decodeProtoBody(pbHeader("application/x-protobuf"), msg[:len(msg)-4], 1<<20)
	if !ok {
		t.Fatal("a message cut off by the capture limit should still be shown")
	}
	if !strings.Contains(out, "1: 5\n") || !strings.Contains(out, "…[message cut off]") {
		t.Errorf("output = %q", out)
	}
}

func TestProtoDecodeGRPCFrames(t *testing.T) {
	body := pbCat(
		pbGRPCFrame(0, pbString(1, "first")),
		pbGRPCFrame(0, nil),
		pbGRPCFrame(0, pbInt(2, 9)),
	)
	out, ok := decodeProtoBody(pbHeader("application/grpc"), body, 1<<20)
	if !ok {
		t.Fatal("not decoded")
	}
	for _, want := range []string{"message 1:\n  1: \"first\"\n", "message 2: (empty)\n", "message 3:\n  2: 9\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
}

func TestProtoDecodeGRPCGzip(t *testing.T) {
	var zb bytes.Buffer
	zw := gzip.NewWriter(&zb)
	if _, err := zw.Write(pbString(1, "compressed value")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	h := pbHeader("application/grpc+proto")
	h.Set("Grpc-Encoding", "gzip")
	out, ok := decodeProtoBody(h, pbGRPCFrame(1, zb.Bytes()), 1<<20)
	if !ok || !strings.Contains(out, "1: \"compressed value\"") {
		t.Errorf("ok=%v out=%q", ok, out)
	}

	// An encoding that cannot be read is named, and its bytes are not shown.
	h.Set("Grpc-Encoding", "snappy")
	out, ok = decodeProtoBody(h, pbGRPCFrame(1, []byte("opaque")), 1<<20)
	if !ok || !strings.Contains(out, "not decoded") || strings.Contains(out, "opaque") {
		t.Errorf("ok=%v out=%q", ok, out)
	}
}

func TestProtoDecodeStopsAtTheLimit(t *testing.T) {
	var msg []byte
	for i := 1; i <= 500; i++ {
		msg = append(msg, pbString(1, strings.Repeat("x", 40))...)
	}
	out, ok := decodeProtoBody(pbHeader("application/x-protobuf"), msg, 1000)
	if !ok || !strings.HasSuffix(strings.TrimSpace(out), truncMarker) || len(out) > 1200 {
		t.Errorf("ok=%v len=%d", ok, len(out))
	}
}

func TestProtoDecodeDepthLimit(t *testing.T) {
	msg := pbString(1, "leaf")
	for i := 0; i < 30; i++ {
		msg = pbBytes(1, msg)
	}
	out, ok := decodeProtoBody(pbHeader("application/x-protobuf"), msg, 1<<20)
	if !ok {
		t.Fatal("not decoded")
	}
	if strings.Count(out, "{") != protoMaxDepth {
		t.Errorf("nesting shown %d levels, want %d:\n%s", strings.Count(out, "{"), protoMaxDepth, out)
	}
}

// The decoded text goes through the normal scrubber, so a secret inside a
// protobuf or gRPC message is redacted in the stored entry.
func TestProtoSecretsAreScrubbedInEntries(t *testing.T) {
	secret := "ghp_" + strings.Repeat("a1", 20)
	app := fxApp(t)
	app.capture(rawFlow{
		started: time.Now(), method: "POST", url: "http://127.0.0.1:9/svc.Auth/Login",
		reqHeaders:  pbHeader("application/grpc"),
		reqBody:     pbGRPCFrame(0, pbCat(pbString(1, "user"), pbBytes(2, pbString(1, secret)))),
		status:      200,
		respHeaders: pbHeader("application/x-protobuf"),
		respBody:    pbString(1, "token="+secret),
	})
	e := app.ring.ListRecent(1, "POST", "/svc.Auth")[0]
	for name, body := range map[string]string{"request": e.RequestBody, "response": e.ResponseBody} {
		if strings.Contains(body, secret) {
			t.Errorf("%s body leaked the secret: %q", name, body)
		}
		if !strings.HasPrefix(body, "[protobuf/gRPC body decoded") {
			t.Errorf("%s body was not decoded: %q", name, body)
		}
	}
	if e.RedactionCount == 0 {
		t.Error("nothing was counted as redacted")
	}
	if !strings.Contains(e.RequestBody, `1: "user"`) {
		t.Errorf("harmless text should stay readable: %q", e.RequestBody)
	}
}

// A decoded protobuf is a debugging view, not something curl could send.
func TestBuildCurlSkipsADecodedProtobuf(t *testing.T) {
	e := FlowEntry{
		Method: "POST", URL: "http://example.com/svc.Method",
		RequestHeaders: map[string]string{"Content-Type": "application/grpc"},
		RequestBody:    protoBanner + "\nmessage 1:\n  1: \"hi\"\n",
	}
	out := buildCurl(e)
	if strings.Contains(out, "--data-raw") || strings.Contains(out, "message 1") {
		t.Errorf("curl command carries the decoded view: %s", out)
	}
}

func FuzzDecodeProtoBodyNoPanic(f *testing.F) {
	f.Add(pbCat(pbInt(1, 1), pbString(2, "abc"), pbBytes(3, pbInt(1, 2))), "application/x-protobuf")
	f.Add(pbGRPCFrame(0, pbString(1, "x")), "application/grpc")
	f.Add(pbGRPCFrame(0x80, []byte("grpc-status: 0\r\n")), "application/grpc-web")
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}, "application/x-protobuf")
	f.Fuzz(func(t *testing.T, b []byte, ct string) {
		_, _ = decodeProtoBody(pbHeader(ct), b, 1<<16)
	})
}

func pbGzip(t *testing.T, b []byte) []byte {
	t.Helper()
	var zb bytes.Buffer
	zw := gzip.NewWriter(&zb)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return zb.Bytes()
}

func TestGRPCWebTextDecode(t *testing.T) {
	frameA := pbGRPCFrame(0, pbInt(1, 42)) // 7 bytes: its base64 carries padding
	frameB := pbGRPCFrame(0, pbInt(2, 5))
	enc := base64.StdEncoding.EncodeToString

	if got, ok := grpcWebTextDecode([]byte(enc(frameA))); !ok || !bytes.Equal(got, frameA) {
		t.Errorf("single frame: ok=%v got %x", ok, got)
	}
	if got, ok := grpcWebTextDecode([]byte(enc(frameA) + enc(frameB))); !ok || !bytes.Equal(got, pbCat(frameA, frameB)) {
		t.Errorf("two padded segments: ok=%v got %x", ok, got)
	}
	spaced := []byte(strings.Join([]string{enc(frameA)[:4], enc(frameA)[4:8], enc(frameA)[8:]}, " \r\n\t"))
	if got, ok := grpcWebTextDecode(spaced); !ok || !bytes.Equal(got, frameA) {
		t.Errorf("whitespace: ok=%v got %x", ok, got)
	}
	// A body cut by the capture limit: the incomplete last group is dropped.
	nine := pbGRPCFrame(0, pbString(1, "hi")) // 9 bytes: 12 characters, no padding
	cutB64 := enc(nine)[:10]
	if got, ok := grpcWebTextDecode([]byte(cutB64)); !ok || !bytes.Equal(got, nine[:6]) {
		t.Errorf("cut body: ok=%v got %x want %x", ok, got, nine[:6])
	}
	for name, in := range map[string]string{
		"not base64":      "!!!!",
		"empty":           "",
		"only whitespace": " \r\n\t",
		"short padded":    "ab=",
		"under one group": "abc",
	} {
		if got, ok := grpcWebTextDecode([]byte(in)); ok || got != nil {
			t.Errorf("%s: got (%x, %v)", name, got, ok)
		}
	}
}

func TestProtoDecodeGRPCWebText(t *testing.T) {
	frame := pbGRPCFrame(0, pbCat(pbInt(1, 42), pbString(2, "web")))
	b64 := []byte(base64.StdEncoding.EncodeToString(frame))
	out, ok := decodeProtoBody(pbHeader("application/grpc-web-text"), b64, 1<<20)
	if !ok || !strings.Contains(out, "message 1:") || !strings.Contains(out, "1: 42") || !strings.Contains(out, `2: "web"`) {
		t.Errorf("ok=%v out=%q", ok, out)
	}
	if out, ok := decodeProtoBody(pbHeader("application/grpc-web-text"), []byte("!!!!"), 1<<20); ok {
		t.Errorf("invalid base64 must not decode: %q", out)
	}
}

func TestProtoDecodeGRPCFrameVariants(t *testing.T) {
	gz := func(b []byte) []byte { return pbGzip(t, b) }
	hdr := func(enc string) http.Header {
		h := pbHeader("application/grpc")
		if enc != "" {
			h.Set("Grpc-Encoding", enc)
		}
		return h
	}
	cases := []struct {
		name string
		h    http.Header
		body []byte
		ok   bool
		want []string
		not  []string
	}{
		{"unknown encoding is named", hdr("snappy"), pbGRPCFrame(1, []byte("opaque")), true,
			[]string{`message 1: [compressed, grpc-encoding "snappy" not decoded, 6 bytes]`}, []string{"opaque"}},
		{"gzip that is not gzip", hdr("gzip"), pbGRPCFrame(1, []byte("not gzip data")), true,
			[]string{"could not be decompressed"}, nil},
		{"gzip frame", hdr("gzip"), pbGRPCFrame(1, gz(pbInt(1, 7))), true, []string{"message 1:", "1: 7"}, nil},
		{"text trailers", hdr(""), pbCat(pbGRPCFrame(0, pbInt(1, 1)), pbGRPCFrame(0x80, []byte("grpc-status: 0\r\n"))), true,
			[]string{`trailers: "grpc-status: 0\r\n"`}, nil},
		{"binary trailers", hdr(""), pbGRPCFrame(0x80, []byte{0xff, 0xfe}), true, []string{"trailers: <2 bytes binary>"}, nil},
		{"undefined flag bits", hdr(""), pbGRPCFrame(0x02, pbInt(1, 1)), false, nil, nil},
		{"frame cut off", hdr(""), []byte{0, 0, 0, 0, 10, 0x08, 0x05}, true, []string{"1: 5", "…[message cut off]"}, nil},
		{"frame cut with no bytes", hdr(""), []byte{0, 0, 0, 0, 5}, true, []string{"message 1: …[message cut off]"}, nil},
		{"empty message", hdr(""), pbGRPCFrame(0, nil), true, []string{"message 1: (empty)"}, nil},
		{"cut unreadable frame after a good one", hdr(""),
			pbCat(pbGRPCFrame(0, pbInt(1, 1)), []byte{0, 0, 0, 0, 9, 0xff, 0xff}), true,
			[]string{"message 2:", "  …[message cut off]"}, nil},
		{"unreadable whole frame", hdr(""), pbGRPCFrame(0, []byte{0x00, 0x01}), false, nil, nil},
		{"shorter than a frame header", hdr(""), []byte{0, 0, 0}, false, nil, nil},
	}
	for _, c := range cases {
		out, ok := decodeProtoBody(c.h, c.body, 1<<20)
		if ok != c.ok {
			t.Errorf("%s: ok = %v, want %v\n%s", c.name, ok, c.ok, out)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(out, w) {
				t.Errorf("%s: output is missing %q:\n%s", c.name, w, out)
			}
		}
		for _, n := range c.not {
			if strings.Contains(out, n) {
				t.Errorf("%s: output must not contain %q:\n%s", c.name, n, out)
			}
		}
	}
}

func TestProtoGRPCDecodedBudget(t *testing.T) {
	plain := pbCat(pbInt(1, 1), pbInt(2, 2)) // 4 bytes
	frame := pbGRPCFrame(1, pbGzip(t, plain))
	h := pbHeader("application/grpc")
	h.Set("Grpc-Encoding", "gzip")
	w := &protoWriter{limit: 1 << 20}
	if !renderGRPCFrames(w, h, pbCat(frame, frame), len(plain)) {
		t.Fatal("frames were not rendered")
	}
	out := w.sb.String()
	if !strings.Contains(out, "message 1:") || !strings.Contains(out, "message 2: [decoded size limit reached]") {
		t.Errorf("the second frame should hit the decoded-size budget:\n%s", out)
	}
}

func TestProtoDecodeWholeBodyEncoding(t *testing.T) {
	h := pbHeader("application/grpc-web")
	h.Set("Content-Encoding", "gzip")
	out, ok := decodeProtoBody(h, pbGzip(t, pbGRPCFrame(0, pbInt(1, 9))), 1<<20)
	if !ok || !strings.Contains(out, "1: 9") {
		t.Errorf("gzip grpc body: ok=%v out=%q", ok, out)
	}
	if _, ok := decodeProtoBody(h, []byte("not gzip"), 1<<20); ok {
		t.Error("a bad gzip grpc body must not decode")
	}

	p := pbHeader("application/x-protobuf")
	p.Set("Content-Encoding", "gzip")
	if out, ok := decodeProtoBody(p, pbGzip(t, pbInt(1, 5)), 1<<20); !ok || !strings.Contains(out, "1: 5") {
		t.Errorf("gzip protobuf body: ok=%v out=%q", ok, out)
	}
	if _, ok := decodeProtoBody(p, []byte("not gzip"), 1<<20); ok {
		t.Error("a bad gzip protobuf body must not decode")
	}
	// A body that hits the decoded-size limit says so.
	big := pbGzip(t, pbCat(pbInt(1, 1), pbString(2, strings.Repeat("a", 4000))))
	if out, ok := decodeProtoBody(p, big, 200); ok && !strings.Contains(out, "cut") && !strings.Contains(out, "truncated") {
		t.Errorf("a decoded body at the limit should be marked:\n%s", out)
	}
	if _, ok := decodeProtoBody(pbHeader("application/x-protobuf"), nil, 100); ok {
		t.Error("an empty body is not a message")
	}
}

func TestProtoFixedWidthFields(t *testing.T) {
	fixed64 := append([]byte{1<<3 | 1}, 1, 0, 0, 0, 0, 0, 0, 0)
	fixed32 := append([]byte{2<<3 | 5}, 2, 0, 0, 0)
	out, ok := decodeProtoBody(pbHeader("application/x-protobuf"), pbCat(fixed64, fixed32), 1<<20)
	if !ok || !strings.Contains(out, "1: 1\n") || !strings.Contains(out, "2: 2\n") {
		t.Errorf("ok=%v out=%q", ok, out)
	}
}

func TestProtoTruncatedFields(t *testing.T) {
	good := pbInt(1, 1)
	cases := map[string][]byte{
		"fixed64":         {0x11, 1, 2},
		"fixed32":         {0x1d, 1, 2},
		"varint value":    {0x10, 0x80},
		"key varint":      {0x80},
		"length varint":   {0x12, 0x80},
		"length too long": {0x12, 0x05, 'a'},
	}
	for name, tail := range cases {
		out, ok := decodeProtoBody(pbHeader("application/x-protobuf"), pbCat(good, tail), 1<<20)
		if !ok || !strings.Contains(out, "1: 1\n") || !strings.Contains(out, "[message cut off]") {
			t.Errorf("%s: ok=%v out=%q", name, ok, out)
		}
		// With nothing complete before the cut, there is no message.
		if _, ok := decodeProtoBody(pbHeader("application/x-protobuf"), tail, 1<<20); ok {
			t.Errorf("%s alone must not decode", name)
		}
	}
}

func TestProtoInvalidFields(t *testing.T) {
	overflow := append(bytes.Repeat([]byte{0xff}, 10), 0x01)
	cases := map[string][]byte{
		"key overflow":     overflow,
		"value overflow":   pbCat(pbInt(1, 1), []byte{0x10}, overflow),
		"length overflow":  pbCat(pbInt(1, 1), []byte{0x12}, overflow),
		"field number 0":   {0x00, 0x01},
		"start group":      {0x0b},
		"end group":        pbCat(pbInt(1, 1), []byte{0x0c}),
		"unused wire type": {0x0e, 0x01},
	}
	for name, b := range cases {
		if out, ok := decodeProtoBody(pbHeader("application/x-protobuf"), b, 1<<20); ok {
			t.Errorf("%s must not decode, got %q", name, out)
		}
	}
}

func TestProtoTextHelpers(t *testing.T) {
	for name, tc := range map[string]struct {
		in   []byte
		want bool
	}{
		"nil":            {nil, false},
		"plain":          {[]byte("hello\n"), true},
		"tab":            {[]byte("a\tb"), true},
		"nul":            {[]byte("a\x00b"), false},
		"invalid utf-8":  {[]byte{0xff, 0xfe}, false},
		"control":        {[]byte("a\x01"), false},
		"unicode":        {[]byte("héllo"), true},
		"replacement ch": {[]byte("a\uFFFDb"), false},
	} {
		if got := protoLooksLikeText(tc.in); got != tc.want {
			t.Errorf("protoLooksLikeText(%s) = %v, want %v", name, got, tc.want)
		}
	}
	if protoTextIsMessage(nil) || protoTextIsMessage([]byte("Bearer abcdef")) {
		t.Error("empty input and a Bearer string are not messages")
	}
	if !protoTextIsMessage(pbString(1, "x")) {
		t.Error("a message that starts with field 1 is a message")
	}
	if !protoTextIsMessage(pbCat(pbString(1, "ab"), pbInt(2, 3))) {
		t.Error("two fields with a length-delimited one are a message")
	}
	if !protoTokenizes(pbInt(1, 1)) || protoTokenizes(nil) || protoTokenizes([]byte{0x80}) {
		t.Error("protoTokenizes is wrong")
	}
	if protoHasLenField(pbInt(1, 1)) || !protoHasLenField(pbString(1, "x")) || protoHasLenField([]byte{0x12}) {
		t.Error("protoHasLenField is wrong")
	}
}

func TestIsGRPCContentType(t *testing.T) {
	for ct, want := range map[string]bool{
		"application/grpc":                     true,
		"Application/GRPC+proto; charset=utf8": true,
		"application/grpc-web-text":            true,
		" application/grpc-web ":               true,
		"application/json":                     false,
		"":                                     false,
	} {
		if got := isGRPCContentType(ct); got != want {
			t.Errorf("isGRPCContentType(%q) = %v, want %v", ct, got, want)
		}
	}
}

func TestProtoGroupInsideNestedMessage(t *testing.T) {
	// A field whose bytes hold a group tag is not a sub-message: it stays text/bytes
	// and the outer message still decodes.
	inner := []byte{0x0b, 0x01, 0x02}
	outer := pbCat(pbString(1, "name"), pbBytes(2, inner))
	if _, ok := decodeProtoBody(pbHeader("application/x-protobuf"), outer, 1<<20); !ok {
		t.Error("a message holding group-like bytes must still decode")
	}
	// A group tag at the top level is invalid.
	for _, b := range [][]byte{{0x0b}, {0x0c}, pbCat(pbString(1, "ok"), []byte{0x0b})} {
		if out, ok := decodeProtoBody(pbHeader("application/x-protobuf"), b, 1<<20); ok {
			t.Errorf("%x decoded as %q", b, out)
		}
	}
}
