package app

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// serverProtocols lets the proxy answer HTTP/1.1 and plain-text HTTP/2 (h2c)
// on its loopback port. gRPC clients speak h2c when they are pointed at a
// plain address, so this is what makes a gRPC call work through the proxy.
// Both come from the standard library; nothing is added to go.mod.
func serverProtocols() *http.Protocols {
	var p http.Protocols
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	return &p
}

// roundTripperFor picks the transport for one request. HTTPS upstreams
// negotiate HTTP/2 on their own. A client that spoke HTTP/2 over plain TCP
// (gRPC does) gets plain HTTP/2 to a plain-HTTP upstream too, because such a
// server only understands the protocol the client used.
func (a *App) roundTripperFor(r *http.Request, out *url.URL) http.RoundTripper {
	if r.ProtoMajor == 2 && out.Scheme == "http" {
		a.h2cOnce.Do(func() {
			t := a.transport.Clone()
			var p http.Protocols
			p.SetUnencryptedHTTP2(true)
			t.Protocols = &p
			a.h2c = t
		})
		return a.h2c
	}
	return a.transport
}

// acceptsTrailers reports whether the client sent "TE: trailers". It is the
// one hop-by-hop value that has to travel on, because gRPC servers look for it.
func acceptsTrailers(h http.Header) bool {
	for _, v := range h.Values("Te") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "trailers") {
				return true
			}
		}
	}
	return false
}

// grpcStatus returns the status code and message of a gRPC call. gRPC sends
// them in the trailers, or in the headers when the call failed before any data.
func grpcStatus(f rawFlow) (status, message string) {
	for _, h := range []http.Header{f.respTrailers, f.respHeaders} {
		s := strings.TrimSpace(h.Get("Grpc-Status"))
		if s == "" {
			continue
		}
		if _, err := strconv.Atoi(s); err != nil {
			return "", ""
		}
		return s, h.Get("Grpc-Message")
	}
	return "", ""
}
