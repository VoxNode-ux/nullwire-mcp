package app

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMinifyJSON(t *testing.T) {
	same := []string{
		"", "   ", "plain text", "123", " true ", `"str"`, "null",
		"{\n  \"a\": [1,\n 2,", "{\"a\": 1} trailing", "{\"a\":1}\n{\"b\":2}", "[1, 2", "{",
		`{"a":1}`, "<html> {\"a\": 1} </html>", "[encoded body omitted (br)]",
	}
	for _, in := range same {
		if got := minifyJSON(in); got != in {
			t.Errorf("minifyJSON(%q) = %q, want it unchanged", in, got)
		}
	}
	cases := map[string]string{
		"{\n  \"a\": 1,\n  \"b\": [1, 2, 3]\n}\n": `{"a":1,"b":[1,2,3]}`,
		"  [ {\"k\" : \"x  y\"} , null ]  ":       `[{"k":"x  y"},null]`,
		"{\"s\": \"line\\nbreak é <>&\"}":          "{\"s\":\"line\\nbreak é <>&\"}",
		"{ \"t\": \"[REDACTED_TOKEN#ab12cd]\" }":  `{"t":"[REDACTED_TOKEN#ab12cd]"}`,
	}
	for in, want := range cases {
		if got := minifyJSON(in); got != want {
			t.Errorf("minifyJSON(%q) = %q, want %q", in, got, want)
		}
	}
}

const minifyPretty = "{\n  \"user\": \"ann\",\n  \"items\": [\n    1,\n    2\n  ]\n}\n"

func minifyFlow(method, url, req, resp string) rawFlow {
	f := rawFlow{
		started: time.Now(), method: method, url: url, status: 200,
		respHeaders: http.Header{"Content-Type": {"application/json"}},
	}
	if req != "" {
		f.reqHeaders = http.Header{"Content-Type": {"application/json"}}
		f.reqBody = []byte(req)
	}
	f.respBody = []byte(resp)
	return f
}

func TestMinifyOffStoresBodiesAsTheyAre(t *testing.T) {
	app := newTestApp(t)
	app.capture(minifyFlow("POST", "http://x.test/a", minifyPretty, minifyPretty))
	fxWaitRing(t, app, 1)
	e := app.ring.ListRecent(1, "", "")[0]
	if e.RequestBody != minifyPretty || e.ResponseBody != minifyPretty {
		t.Fatalf("bodies changed with -minify off: %q / %q", e.RequestBody, e.ResponseBody)
	}
}

func TestMinifyCompactsStoredCopyOnly(t *testing.T) {
	app := newTestApp(t)
	app.minify = true
	app.capture(minifyFlow("POST", "http://x.test/a", minifyPretty, minifyPretty))
	fxWaitRing(t, app, 1)
	e := app.ring.ListRecent(1, "", "")[0]
	want := `{"user":"ann","items":[1,2]}`
	if e.RequestBody != want || e.ResponseBody != want {
		t.Fatalf("stored bodies = %q / %q, want %q", e.RequestBody, e.ResponseBody, want)
	}
}

func TestMinifyLiveTrafficIsUntouched(t *testing.T) {
	app := newTestApp(t)
	app.minify = true
	reqCh := make(chan string, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		reqCh <- string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(minifyPretty))
	}))
	defer up.Close()

	req := httptest.NewRequest("POST", "/", strings.NewReader(minifyPretty))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("X-Target-URL", up.URL)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	gotReq := <-reqCh
	if gotReq != minifyPretty {
		t.Fatalf("upstream received %q, want the original bytes", gotReq)
	}
	if rec.Body.String() != minifyPretty {
		t.Fatalf("client received %q, want the original bytes", rec.Body.String())
	}
	fxWaitRing(t, app, 1)
	e := app.ring.ListRecent(1, "", "")[0]
	if e.RequestBody != `{"user":"ann","items":[1,2]}` || e.ResponseBody != `{"user":"ann","items":[1,2]}` {
		t.Fatalf("stored copy not compacted: %q / %q", e.RequestBody, e.ResponseBody)
	}
}

func TestMinifyKeepsRedactionInInspectAndHAR(t *testing.T) {
	secret := "ghp_" + strings.Repeat("a1", 20)
	pretty := "{\n  \"token\": \"" + secret + "\",\n  \"ok\": true\n}\n"
	app := newTestApp(t)
	app.minify = true
	app.capture(minifyFlow("POST", "http://127.0.0.1:9/b", pretty, pretty))
	fxWaitRing(t, app, 1)

	p, text := covInspect(t, app, `{"limit":1}`)
	if len(p.Flows) != 1 {
		t.Fatalf("flows = %d", len(p.Flows))
	}
	for _, body := range []string{p.Flows[0].RequestBody, p.Flows[0].ResponseBody} {
		if strings.ContainsAny(body, "\n ") || !strings.HasPrefix(body, `{"token":"[REDACTED`) || !strings.HasSuffix(body, `,"ok":true}`) {
			t.Fatalf("inspect body is not compact and redacted: %q", body)
		}
	}
	if strings.Contains(text, secret) {
		t.Fatal("inspect_traffic leaks the secret")
	}

	_, har := harCall(t, app, `{"limit":1,"include_bodies":true}`)
	if strings.Contains(har, secret) {
		t.Fatal("export_har leaks the secret")
	}
	if !strings.Contains(har, `{\"token\":\"[REDACTED`) || strings.Contains(har, `\n  \"token\"`) {
		t.Fatalf("export_har body is not compact: %s", har)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(har), &doc); err != nil {
		t.Fatalf("export_har is not JSON: %v", err)
	}
}

func TestMinifyLeavesInvalidAndTruncatedJSONIntact(t *testing.T) {
	app := newTestApp(t)
	app.minify = true
	truncated := "{\n  \"a\": [\n    1,\n    2,\n    \"cut"
	text := "hello   world\n"
	app.capture(minifyFlow("POST", "http://x.test/t", truncated, text))
	fxWaitRing(t, app, 1)
	e := app.ring.ListRecent(1, "", "")[0]
	if e.RequestBody != truncated {
		t.Fatalf("truncated JSON changed: %q", e.RequestBody)
	}
	if e.ResponseBody != text {
		t.Fatalf("plain text changed: %q", e.ResponseBody)
	}
}

func TestRunAcceptsMinifyFlag(t *testing.T) {
	stdout, _, err := runCLIApp(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n", "-port=0", "-minify")
	if err != nil || !strings.Contains(stdout, `"tools"`) {
		t.Fatalf("run -minify: err=%v stdout=%q", err, stdout)
	}
}
