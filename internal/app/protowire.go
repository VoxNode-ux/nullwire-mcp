package app

import (
	"encoding/binary"
	"fmt"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Protobuf and gRPC bodies are binary, but their wire format is simple enough
// to read without a .proto schema. decodeProtoBody turns one into text so the
// normal scrubber can search it:
//
//	1: 42
//	2: "hello"
//	3: {
//	  1: "inner"
//	}
//	4: <3 bytes binary>
//
// Without a schema there are no field names, so name-based redaction (the
// "password" or "token" key rules) cannot fire; only the value-based rules do.
// A length-delimited field (wire type 2) is shown as text when it is clean,
// printable UTF-8, as a nested message when it parses completely as one, and
// otherwise as a byte count only: raw bytes are never printed.

const (
	protoMaxDepth  = 8  // deepest nested message shown
	protoMaxFrames = 64 // most gRPC messages shown from one body

	// The first line of every decoded body. export_sanitized_curl looks for the
	// "[protobuf/gRPC body" prefix, because this text is not a replayable body.
	protoBanner = "[protobuf/gRPC body decoded without a schema: field names are numbers; not replayable]"
)

// protoStatus is how reading one field ended.
type protoStatus int

const (
	protoOK     protoStatus = iota
	protoCutOff             // the bytes end in the middle of a field
	protoBad                // not valid protobuf wire format
)

type protoField struct {
	num  uint64
	wire int
	val  uint64 // wire types 0, 1 and 5
	data []byte // wire type 2
}

// nextProtoField reads one field from the front of b (which must not be empty).
func nextProtoField(b []byte) (protoField, []byte, protoStatus) {
	key, n := binary.Uvarint(b)
	if n == 0 {
		return protoField{}, nil, protoCutOff
	}
	if n < 0 {
		return protoField{}, nil, protoBad
	}
	f := protoField{num: key >> 3, wire: int(key & 7)}
	if f.num == 0 || f.num > 1<<29-1 {
		return protoField{}, nil, protoBad
	}
	b = b[n:]
	switch f.wire {
	case 0:
		v, vn := binary.Uvarint(b)
		if vn == 0 {
			return protoField{}, nil, protoCutOff
		}
		if vn < 0 {
			return protoField{}, nil, protoBad
		}
		f.val = v
		b = b[vn:]
	case 1:
		if len(b) < 8 {
			return protoField{}, nil, protoCutOff
		}
		f.val = binary.LittleEndian.Uint64(b)
		b = b[8:]
	case 5:
		if len(b) < 4 {
			return protoField{}, nil, protoCutOff
		}
		f.val = uint64(binary.LittleEndian.Uint32(b))
		b = b[4:]
	case 2:
		l, ln := binary.Uvarint(b)
		if ln == 0 {
			return protoField{}, nil, protoCutOff
		}
		if ln < 0 {
			return protoField{}, nil, protoBad
		}
		b = b[ln:]
		if l > uint64(len(b)) {
			return protoField{}, nil, protoCutOff
		}
		f.data = b[:l]
		b = b[l:]
	default: // groups (3, 4) and the unused types 6 and 7
		return protoField{}, nil, protoBad
	}
	return f, b, protoOK
}

// protoTokenizes reports whether b is, from start to end, a sequence of at
// least one well-formed field. It does not look inside nested fields.
func protoTokenizes(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for len(b) > 0 {
		_, rest, st := nextProtoField(b)
		if st != protoOK {
			return false
		}
		b = rest
	}
	return true
}

// protoHasLenField reports whether b, already known to tokenize, has a
// length-delimited (wire type 2) field.
func protoHasLenField(b []byte) bool {
	for len(b) > 0 {
		f, rest, st := nextProtoField(b)
		if st != protoOK {
			return false
		}
		if f.wire == 2 {
			return true
		}
		b = rest
	}
	return false
}

// protoTextIsMessage decides whether bytes that are both printable text and a
// valid message are the message. They are when they hold a length-delimited
// field and either start with field 1 (the byte is a newline, which text
// rarely starts with) or hold two fields or more. A string like "Bearer ..."
// can parse as one field by chance (B is field 8, e is a length) and must stay
// text, or the nested rendering would cut it up.
func protoTextIsMessage(b []byte) bool {
	if len(b) == 0 || !protoHasLenField(b) {
		return false
	}
	if b[0] == '\n' {
		return true
	}
	fields := 0
	for rest := b; len(rest) > 0 && fields < 2; fields++ {
		_, next, st := nextProtoField(rest)
		if st != protoOK {
			return false
		}
		rest = next
	}
	return fields >= 2
}

// protoTopLevel checks a whole message. ok means at least one field was read
// and nothing was invalid; cut means the bytes stop in the middle of a field,
// which is what a body cut off by the capture limit looks like.
func protoTopLevel(b []byte) (ok, cut bool) {
	n := 0
	for len(b) > 0 {
		_, rest, st := nextProtoField(b)
		switch st {
		case protoOK:
			n++
			b = rest
		case protoCutOff:
			return n > 0, true
		default:
			return false, false
		}
	}
	return n > 0, false
}

// protoLooksLikeText is the strict test for showing bytes as a string: valid
// UTF-8 with no control characters other than tab, newline and carriage return.
func protoLooksLikeText(p []byte) bool {
	if len(p) == 0 || !utf8.Valid(p) {
		return false
	}
	for _, r := range string(p) {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
		case r == utf8.RuneError || !unicode.IsPrint(r):
			return false
		}
	}
	return true
}

var protoEscaper = strings.NewReplacer("\n", `\n`, "\r", `\r`, "\t", `\t`)

// protoWriter collects the text, up to limit bytes.
type protoWriter struct {
	sb    strings.Builder
	limit int
	full  bool
}

func (w *protoWriter) line(indent int, format string, args ...any) {
	if w.full {
		return
	}
	if w.sb.Len() >= w.limit {
		w.full = true
		w.sb.WriteString(truncMarker)
		return
	}
	for i := 0; i < indent; i++ {
		w.sb.WriteString("  ")
	}
	fmt.Fprintf(&w.sb, format, args...)
	w.sb.WriteByte('\n')
}

// renderProtoFields writes the fields of b, which the caller has already
// checked with protoTokenizes or protoTopLevel. It stops quietly at the first
// field it cannot read.
func renderProtoFields(w *protoWriter, b []byte, depth int) {
	for len(b) > 0 && !w.full {
		f, rest, st := nextProtoField(b)
		if st != protoOK {
			return
		}
		b = rest
		switch f.wire {
		case 0, 1, 5:
			w.line(depth, "%d: %d", f.num, f.val)
		case 2:
			tok := depth < protoMaxDepth && protoTokenizes(f.data)
			txt := protoLooksLikeText(f.data)
			switch {
			case len(f.data) == 0:
				w.line(depth, `%d: ""`, f.num)
			case tok && (!txt || protoTextIsMessage(f.data)):
				// A nested message. Clean text that happens to parse as one (the
				// two letters "hi" are a valid varint field) stays text unless it
				// is clearly a message, see protoTextIsMessage.
				w.line(depth, "%d: {", f.num)
				renderProtoFields(w, f.data, depth+1)
				w.line(depth, "}")
			case txt:
				w.line(depth, `%d: "%s"`, f.num, protoEscaper.Replace(string(f.data)))
			default:
				w.line(depth, "%d: <%d bytes binary>", f.num, len(f.data))
			}
		}
	}
}

// renderProtoMessage writes b as one message at the given indent. false means
// b is not a protobuf message.
func renderProtoMessage(w *protoWriter, b []byte, depth int) bool {
	ok, cut := protoTopLevel(b)
	if !ok {
		return false
	}
	renderProtoFields(w, b, depth)
	if cut {
		w.line(depth, "…[message cut off]")
	}
	return true
}

// isGRPCContentType reports gRPC and gRPC-Web payloads, which wrap each
// message in a 5-byte frame header.
func isGRPCContentType(ct string) bool {
	mt := strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(mt, ';'); i >= 0 {
		mt = strings.TrimSpace(mt[:i])
	}
	return strings.HasPrefix(mt, "application/grpc")
}

// renderGRPCFrames writes every message of a gRPC body. Each frame is one flag
// byte (bit 0: compressed; bit 7: a gRPC-Web trailers frame), a 4-byte
// big-endian length and the message.
func renderGRPCFrames(w *protoWriter, h http.Header, b []byte, limit int) bool {
	enc := strings.ToLower(strings.TrimSpace(h.Get("Grpc-Encoding")))
	shown := 0
	budget := limit // text all compressed frames together may be decoded to
	for len(b) >= 5 && shown < protoMaxFrames && !w.full {
		if w.sb.Len() >= w.limit { // output is full: flag it, read no more frames
			w.line(0, "")
			break
		}
		flag := b[0]
		l := binary.BigEndian.Uint32(b[1:5])
		b = b[5:]
		if flag&0x7e != 0 { // only bit 0 and bit 7 are defined
			return false
		}
		cut := false
		var msg []byte
		if uint64(l) > uint64(len(b)) {
			msg, b, cut = b, nil, true
		} else {
			msg, b = b[:l], b[l:]
		}
		shown++

		if flag&0x80 != 0 { // gRPC-Web trailers: "name: value" text lines
			if protoLooksLikeText(msg) {
				w.line(0, "trailers: \"%s\"", protoEscaper.Replace(string(msg)))
			} else {
				w.line(0, "trailers: <%d bytes binary>", len(msg))
			}
			continue
		}

		if flag&1 != 0 {
			if !decodableEncoding(enc) {
				w.line(0, "message %d: [compressed, grpc-encoding %q not decoded, %d bytes]", shown, enc, len(msg))
				continue
			}
			if budget <= 0 {
				w.line(0, "message %d: [decoded size limit reached]", shown)
				break
			}
			text, ok := decodeBodyMax(enc, msg, budget)
			if !ok {
				w.line(0, "message %d: [compressed, could not be decompressed, %d bytes]", shown, len(msg))
				continue
			}
			if strings.HasSuffix(text, truncMarker) {
				text, cut = strings.TrimSuffix(text, truncMarker), true
			}
			budget -= len(text)
			msg = []byte(text)
		}

		switch {
		case len(msg) == 0 && !cut:
			w.line(0, "message %d: (empty)", shown)
		case cut && len(msg) == 0:
			w.line(0, "message %d: …[message cut off]", shown)
		default:
			w.line(0, "message %d:", shown)
			if !renderProtoMessage(w, msg, 1) {
				if cut && shown > 1 { // keep the frames already rendered
					w.line(1, "…[message cut off]")
					break
				}
				return false
			}
			if cut {
				w.line(1, "…[message cut off]")
			}
		}
	}
	return shown > 0
}

// decodeProtoBody renders a protobuf or gRPC body as text without a schema.
// ok is false when the bytes are not something it can read, and the caller
// then keeps its "not captured" placeholder. The text is not scrubbed here:
// buildEntry scrubs it, then cuts it, like any other body.
func decodeProtoBody(h http.Header, b []byte, limit int) (string, bool) {
	if len(b) == 0 {
		return "", false
	}
	w := &protoWriter{limit: limit}
	w.line(0, "%s", protoBanner)

	ct := h.Get("Content-Type")
	if isGRPCContentType(ct) {
		if strings.Contains(strings.ToLower(ct), "-text") { // gRPC-Web text mode is base64
			return "", false
		}
		frames := b
		// Some gRPC-Web servers compress the whole HTTP body instead of, or
		// as well as, the single frames.
		if ce := strings.TrimSpace(h.Get("Content-Encoding")); ce != "" && !strings.EqualFold(ce, "identity") {
			text, ok := decodeBodyMax(ce, b, limit)
			if !ok {
				return "", false
			}
			frames = []byte(strings.TrimSuffix(text, truncMarker))
		}
		if !renderGRPCFrames(w, h, frames, limit) {
			return "", false
		}
		return w.sb.String(), true
	}

	payload := b
	if ce := strings.TrimSpace(h.Get("Content-Encoding")); ce != "" && !strings.EqualFold(ce, "identity") {
		text, ok := decodeBodyMax(ce, b, limit)
		if !ok {
			return "", false
		}
		payload = []byte(strings.TrimSuffix(text, truncMarker))
	}
	if !renderProtoMessage(w, payload, 0) {
		return "", false
	}
	return w.sb.String(), true
}
