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
