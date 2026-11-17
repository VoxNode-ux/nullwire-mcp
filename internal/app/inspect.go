package app

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
)

// maxMultipartPart is how much of one form field is read for capture.
const maxMultipartPart = maxReqBody

// uninspectableRequestEncoding reports a request Content-Encoding that
// NullWire cannot decode (br, zstd, a stack such as "gzip, br", ...). Only
// identity, gzip and deflate can be read, so only those are allowed.
func uninspectableRequestEncoding(h http.Header) (string, bool) {
	ce := strings.ToLower(effectiveContentEncoding(joinedContentEncoding(h)))
	switch ce {
	case "", "gzip", "x-gzip", "deflate":
		return "", false
	}
	return ce, true
}

// scrubMultipart turns a multipart/form-data body into scrubbed "name=value"
// lines. File parts are never stored: only the field name, the file name and
// how many bytes were seen. Whatever happens, the result is scrubbed text. The
// int is the number of redactions.
func (a *App) scrubMultipart(contentType string, body []byte) (string, int) {
	return a.scrubMultipartWith(a.scrub, contentType, body, maxMultipartPart)
}

// scrubMultipartWith is scrubMultipart counting into sc and reading at most
// partLimit bytes of each form field (the -max-body limit plus scrubWindow).
func (a *App) scrubMultipartWith(sc *Scrubber, contentType string, body []byte, partLimit int64) (string, int) {
	if partLimit <= 0 {
		partLimit = maxMultipartPart
	}
	total := 0
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") || params["boundary"] == "" {
		out, n := sc.ScrubText(string(body))
		return out, n
	}

	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	var out strings.Builder
	parts := 0
	var readErr error
	for {
		part, err := mr.NextPart()
		if err != nil {
			if err != io.EOF {
				readErr = err
			}
			break
		}
		parts++
		name := part.FormName()
		if name == "" {
			name = "(unnamed)"
		}
		if file := part.FileName(); file != "" {
			n, _ := io.Copy(io.Discard, io.LimitReader(part, partLimit))
			shownName, c := sc.ScrubText(file)
			total += c
			fmt.Fprintf(&out, "%s=[file %q, %d bytes seen, content not stored]\n", name, shownName, n)
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(part, partLimit))
		scrubbed, c := sc.ScrubText(name + "=" + string(data))
		total += c
		out.WriteString(scrubbed)
		out.WriteString("\n")
	}

	if parts == 0 {
		// Not parseable as multipart (for example cut off by the capture limit):
		// fall back to scrubbing the raw text rather than showing nothing.
		return sc.ScrubText(string(body))
	}
	if readErr != nil {
		out.WriteString("[multipart body truncated or malformed]\n")
	}
	return out.String(), total
}

// isProtobufContentType reports binary protobuf and gRPC payload types.
func isProtobufContentType(ct string) bool {
	mt := strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(mt, ';'); i >= 0 {
		mt = strings.TrimSpace(mt[:i])
	}
	return strings.HasPrefix(mt, "application/grpc") || strings.Contains(mt, "protobuf") || strings.HasSuffix(mt, "+proto")
}

// restrictAcceptEncoding sets dst's Accept-Encoding to what the client offered,
// cut down to the encodings NullWire can read (gzip and deflate), so a server
// never answers in br or zstd. A client that offered nothing usable gets
// "identity". A client that sent no Accept-Encoding header at all is left
// without one, and servers then answer uncompressed.
func restrictAcceptEncoding(dst, src http.Header) {
	vals := src.Values("Accept-Encoding")
	if len(vals) == 0 {
		return
	}
	var keep []string
	seen := map[string]bool{}
	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			keep = append(keep, name)
		}
	}
	for _, v := range vals {
		for _, part := range strings.Split(v, ",") {
			name, params, _ := strings.Cut(strings.ToLower(strings.TrimSpace(part)), ";")
			name = strings.TrimSpace(name)
			if j := strings.Index(params, "q="); j >= 0 {
				if q, err := strconv.ParseFloat(strings.TrimSpace(params[j+2:]), 64); err == nil && q <= 0 {
					continue // "gzip;q=0" means not acceptable
				}
			}
			switch name {
			case "gzip", "x-gzip":
				add("gzip")
			case "deflate":
				add("deflate")
			case "*":
				add("gzip")
				add("deflate")
			}
		}
	}
	if len(keep) == 0 {
		dst.Set("Accept-Encoding", "identity")
		return
	}
	dst.Set("Accept-Encoding", strings.Join(keep, ", "))
}
