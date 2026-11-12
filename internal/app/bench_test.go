package app

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Benchmarks for the hot paths: scrubbing text, scrubbing headers, and a full
// request through the proxy. Run them with:
//
//	go test -run='^$' -bench=. -benchmem -count=6 ./... > new.txt
//	benchstat old.txt new.txt
//
// They only use fake secrets.

var benchSink string

func benchScrubber(b *testing.B) *Scrubber {
	b.Helper()
	s, err := NewScrubber()
	if err != nil {
		b.Fatalf("NewScrubber: %v", err)
	}
	return s
}

func BenchmarkScrubTextClean(b *testing.B) {
	s := benchScrubber(b)
	in := strings.Repeat(`{"user":"bob","items":[1,2,3],"note":"nothing secret here"}`, 40)
	b.SetBytes(int64(len(in)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, _ := s.ScrubText(in)
		benchSink = out
	}
}

func BenchmarkScrubTextWithSecrets(b *testing.B) {
	s := benchScrubber(b)
	in := strings.Repeat(`{"access_token":"tok_supersecretvalue_12345","password":"hunter2hunter2","ip":"203.0.113.7"} Authorization: Bearer abcdefghijklmnop12345 `, 20)
	b.SetBytes(int64(len(in)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, _ := s.ScrubText(in)
		benchSink = out
	}
}

func BenchmarkScrubTextLarge(b *testing.B) {
	s := benchScrubber(b)
	in := strings.Repeat(`{"id":42,"name":"widget","api_key":"abcd1234secretvalue"}`+"\n", 5000)
	b.SetBytes(int64(len(in)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, _ := s.ScrubText(in)
		benchSink = out
	}
}

func BenchmarkScrubHeaders(b *testing.B) {
	s := benchScrubber(b)
	h := http.Header{}
	h.Set("Authorization", "Bearer abcdefghijklmnop12345")
	h.Set("Cookie", "session=zzzTOPSECRETzzz; theme=dark")
	h.Set("Content-Type", "application/json")
	h.Set("User-Agent", "bench/1.0")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m, _ := s.ScrubHeaders(h)
		benchSink = m["Content-Type"]
	}
}

// BenchmarkProxyRoundTrip measures one captured request through the reverse
// gateway against a local upstream: the latency the person actually feels.
func BenchmarkProxyRoundTrip(b *testing.B) {
	s := benchScrubber(b)
	app := &App{
		ring:      NewRingBuffer(),
		scrub:     s,
		port:      1,
		transport: &http.Transport{Proxy: nil, DisableCompression: true},
	}
	defer app.transport.CloseIdleConnections()

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"tok_supersecretvalue_12345","user":"bob"}`)
	}))
	defer up.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", fmt.Sprintf("/v1/login?n=%d", i), strings.NewReader(`{"password":"hunter2hunter2"}`))
		req.Host = "127.0.0.1:8080"
		req.Header.Set("X-Target-URL", up.URL)
		req.Header.Set("Authorization", "Bearer abcdefghijklmnop12345")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("status = %d", rec.Code)
		}
	}
}
