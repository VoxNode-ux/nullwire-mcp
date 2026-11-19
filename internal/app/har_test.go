package app

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func harCall(t *testing.T, app *App, args string) (map[string]any, string) {
	t.Helper()
	res := app.toolExportHAR(json.RawMessage(args))
	if res["isError"] == true {
		t.Fatalf("export_har failed: %v", res["content"])
	}
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	var doc map[string]any
	if err := json.Unmarshal([]byte(text), &doc); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	return doc["log"].(map[string]any), text
}

func harFixture(t *testing.T) (*App, string) {
	t.Helper()
	secret := "ghp_" + strings.Repeat("a1", 20)
	app := fxApp(t)
	now := time.Now()
	app.capture(rawFlow{started: now, method: "GET", url: "http://127.0.0.1:9/a?x=1&y=two%20words",
		reqHeaders: http.Header{"Authorization": {"Bearer " + secret}},
		status:     200, respHeaders: http.Header{"Content-Type": {"application/json"}}, respBody: []byte(`{"ok":true}`)})
	app.capture(rawFlow{started: now.Add(time.Second), method: "POST", url: "http://127.0.0.1:9/b",
		reqHeaders: http.Header{"Content-Type": {"application/json"}}, reqBody: []byte(`{"token":"` + secret + `"}`),
		status: 201, respBody: []byte("created " + secret)})
	app.capture(rawFlow{started: now.Add(2 * time.Second), method: "GET", url: "http://127.0.0.1:9/c", status: 404})
	return app, secret
}

func TestExportHARShapeAndOrder(t *testing.T) {
	app, secret := harFixture(t)
	log, text := harCall(t, app, `{}`)
	if log["version"] != "1.2" {
		t.Errorf("version = %v", log["version"])
	}
	entries := log["entries"].([]any)
	if len(entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(entries))
	}
	var urls []string
	for _, e := range entries {
		urls = append(urls, e.(map[string]any)["request"].(map[string]any)["url"].(string))
	}
	if !strings.HasSuffix(urls[0], "/a?x=1&y=two%20words") || !strings.HasSuffix(urls[2], "/c") {
		t.Errorf("entries are not oldest first: %v", urls)
	}
	q := entries[0].(map[string]any)["request"].(map[string]any)["queryString"].([]any)
	if len(q) != 2 || q[1].(map[string]any)["value"] != "two words" {
		t.Errorf("queryString = %v", q)
	}
	if strings.Contains(text, secret) {
		t.Error("the HAR leaked the token")
	}
	// Bodies are off by default.
	if strings.Contains(text, "postData") || strings.Contains(text, `"text"`) {
		t.Errorf("bodies were included by default")
	}
	post := entries[1].(map[string]any)
	if post["response"].(map[string]any)["status"].(float64) != 201 {
		t.Errorf("status = %v", post["response"])
	}
	if post["_nullwire"].(map[string]any)["redaction_count"].(float64) == 0 {
		t.Error("redaction count missing")
	}
}

func TestExportHARIncludeBodies(t *testing.T) {
	app, secret := harFixture(t)
	log, text := harCall(t, app, `{"include_bodies":true,"method":"POST"}`)
	entries := log["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	e := entries[0].(map[string]any)
	post := e["request"].(map[string]any)["postData"].(map[string]any)
	if post["mimeType"] != "application/json" || !strings.Contains(post["text"].(string), `"token"`) {
		t.Errorf("postData = %v", post)
	}
	if !strings.Contains(e["response"].(map[string]any)["content"].(map[string]any)["text"].(string), "created") {
		t.Errorf("response text missing")
	}
	if strings.Contains(text, secret) {
		t.Error("bodies leaked the token")
	}
}

func TestExportHARFilters(t *testing.T) {
	app, _ := harFixture(t)
	if log, _ := harCall(t, app, `{"url_contains":"/B"}`); len(log["entries"].([]any)) != 1 {
		t.Errorf("url_contains should match case-insensitively")
	}
	if log, _ := harCall(t, app, `{"limit":2}`); len(log["entries"].([]any)) != 2 {
		t.Errorf("limit not applied")
	}
	log, _ := harCall(t, app, `{"url_contains":"nothing-matches"}`)
	if e, ok := log["entries"].([]any); !ok || len(e) != 0 {
		t.Errorf("an empty result must be [] , got %v", log["entries"])
	}
}

func TestExportHARIsCapped(t *testing.T) {
	app := fxApp(t)
	big := []byte(strings.Repeat("lorem ipsum dolor ", 14000)) // about 250 KB each
	for i := 0; i < 10; i++ {
		app.capture(rawFlow{started: time.Now(), method: "GET", url: "http://127.0.0.1:9/big", status: 200,
			respHeaders: http.Header{"Content-Type": {"text/plain"}}, respBody: big})
	}
	log, text := harCall(t, app, `{"limit":10,"include_bodies":true}`)
	if len(text) > harMaxBytes {
		t.Errorf("document is %d bytes, over the %d cap", len(text), harMaxBytes)
	}
	meta := log["_nullwire"].(map[string]any)
	if meta["entries_with_bodies_left_out_for_size"].(float64) == 0 {
		t.Errorf("expected some bodies to be left out: %v", meta)
	}
	if meta["returned"].(float64) != 10 {
		t.Errorf("returned = %v", meta["returned"])
	}
}

func TestExportHARBadArguments(t *testing.T) {
	app := fxApp(t)
	if res := app.toolExportHAR(json.RawMessage(`{"limit":"ten"}`)); res["isError"] != true {
		t.Error("a bad limit should be an error")
	}
}

func TestExportHARIsListedAndDispatched(t *testing.T) {
	found := false
	for _, raw := range toolDefinitions() {
		if raw.(map[string]any)["name"] == "export_har" {
			found = true
		}
	}
	if !found {
		t.Fatal("export_har missing from tools/list")
	}
	app := fxApp(t)
	resp := app.dispatchTo(rpcRequest{ID: json.RawMessage(`1`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"export_har","arguments":{}}`)})
	if resp.Error != nil {
		t.Errorf("dispatch failed: %v", resp.Error)
	}
}

func TestHARFitBudgets(t *testing.T) {
	e := FlowEntry{ID: 1, Method: "POST", URL: "http://h/x",
		RequestBody: strings.Repeat("a", 5000), ResponseBody: strings.Repeat("b", 5000)}
	if raw, cut, ok := harFit(e, true, 1<<20); !ok || cut || len(raw) < 10000 {
		t.Errorf("roomy budget: ok=%v cut=%v len=%d", ok, cut, len(raw))
	}
	// Too big with bodies, fine without: the bodies are left out and the entry says so.
	raw, cut, ok := harFit(e, true, 3000)
	if !ok || !cut || strings.Contains(string(raw), strings.Repeat("a", 100)) || !strings.Contains(string(raw), "bodies_left_out_for_size") {
		t.Errorf("tight budget: ok=%v cut=%v raw=%.200s", ok, cut, raw)
	}
	// Too big even without bodies: the entry is dropped.
	if _, _, ok := harFit(e, true, 10); ok {
		t.Error("an entry that cannot fit must be dropped")
	}
	// Without bodies nothing is "cut".
	if _, cut, ok := harFit(e, false, 3000); !ok || cut {
		t.Errorf("no bodies requested: ok=%v cut=%v", ok, cut)
	}
}

func TestHARCutFragmentAndQuery(t *testing.T) {
	tag := "[REDACTED_TOKEN#0a1b2c]"
	for in, want := range map[string]string{
		"a=1#frag":                  "a=1",
		"a=1":                       "a=1",
		"":                          "",
		"#":                         "",
		"a=" + tag + "&b=2":         "a=" + tag + "&b=2",
		"a=" + tag + "#frag":        "a=" + tag,
		"a=[REDACTED_X#12#frag":     "a=[REDACTED_X",
		"a=" + tag + tag + "#x":     "a=" + tag + tag,
		"a=#" + tag:                 "a=",
	} {
		if got := harCutFragment(in); got != want {
			t.Errorf("harCutFragment(%q) = %q, want %q", in, got, want)
		}
	}
	got := harQuery("http://h/p?a=1&&b=%zz&c=%41#frag")
	if len(got) != 3 || got[0] != (harNV{"a", "1"}) || got[1] != (harNV{"b", "%zz"}) || got[2] != (harNV{"c", "A"}) {
		t.Errorf("harQuery = %v", got)
	}
	if got := harQuery("http://h/p"); got == nil || len(got) != 0 {
		t.Errorf("no query: %#v", got)
	}
	if got := harQuery("http://h/p?"); len(got) != 0 {
		t.Errorf("empty query: %v", got)
	}
	if got := harQuery("http://h/p?flag"); len(got) != 1 || got[0] != (harNV{"flag", ""}) {
		t.Errorf("bare key: %v", got)
	}
	if got := harQuery("http://h/?k=" + tag + "&z=1#f"); len(got) != 2 || got[0].Value != tag || got[1] != (harNV{"z", "1"}) {
		t.Errorf("redaction tag in query: %v", got)
	}
}

func TestToolLimitBounds(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	for _, c := range []struct {
		in   *float64
		want int
	}{
		{nil, 10}, {f(0), 1}, {f(-5), 1}, {f(0.5), 1}, {f(1), 1}, {f(7.9), 7},
		{f(ringCapacity), ringCapacity}, {f(1000), ringCapacity},
	} {
		if got := toolLimit(c.in); got != c.want {
			t.Errorf("toolLimit(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestExportHAROmitsOversizedAndCutsBodies(t *testing.T) {
	app := fxApp(t)
	app.ring.Push(FlowEntry{Method: "GET", URL: "http://h/small", StatusCode: 200})
	app.ring.Push(FlowEntry{Method: "GET", URL: "http://h/big", StatusCode: 200,
		RequestHeaders: map[string]string{"X-Big": strings.Repeat("a", 2<<20)}})
	log, _ := harCall(t, app, `{"limit":50}`)
	meta := log["_nullwire"].(map[string]any)
	if meta["omitted_for_size"] != float64(1) || meta["returned"] != float64(1) {
		t.Errorf("oversized entry: %v", meta)
	}

	app = fxApp(t)
	for _, u := range []string{"http://h/1", "http://h/2"} {
		app.ring.Push(FlowEntry{Method: "GET", URL: u, StatusCode: 200, ResponseBody: strings.Repeat("a", 700000)})
	}
	log, _ = harCall(t, app, `{"include_bodies":true}`)
	meta = log["_nullwire"].(map[string]any)
	if meta["returned"] != float64(2) || meta["entries_with_bodies_left_out_for_size"] != float64(1) {
		t.Errorf("bodies over budget: %v", meta)
	}
}
