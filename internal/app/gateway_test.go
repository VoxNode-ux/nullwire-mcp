package app

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestParseTargetMap(t *testing.T) {
	m, err := parseTargetMap("auth=https://auth.example.com, Billing=http://127.0.0.1:9000/base")
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 || m["auth"].Host != "auth.example.com" || m["billing"].Path != "/base" {
		t.Errorf("map = %v", m)
	}
	for _, bad := range []string{
		"",                                   // nothing given
		"https://bare.example.com",           // no name
		"auth=https://a.test,auth=https://b", // name used twice
		"auth=ftp://a.test",                  // not http(s)
		"auth=",                              // no URL
		"bad name=https://a.test",            // not a valid name, so it reads as a bare URL
	} {
		if _, err := parseTargetMap(bad); err == nil {
			t.Errorf("parseTargetMap(%q) should fail", bad)
		}
	}
}

func TestGatewayPrefixRouting(t *testing.T) {
	app := newTestApp(t)
	seenAuth, seenOld, seenDef := &upstreamSeen{}, &upstreamSeen{}, &upstreamSeen{}
	upAuth, upOld, upDef := newUpstream(t, seenAuth), newUpstream(t, seenOld), newUpstream(t, seenDef)
	ua, _ := url.Parse(upAuth.URL + "/base") // a local upstream is allowed
	uo, _ := url.Parse(upOld.URL)
	ud, _ := url.Parse(upDef.URL)
	app.gwMap = map[string]*url.URL{"auth": ua}
	app.upstreams = map[string]*url.URL{"old": uo}
	app.target = ud

	do := func(path string, hdr ...string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		req.Host = "127.0.0.1:8080"
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, req)
		return rec
	}
	pathOf := func(s *upstreamSeen) string {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.path
	}

	if rec := do("/_gw/auth/v1/login?x=1"); rec.Code != 200 || pathOf(seenAuth) != "/base/v1/login?x=1" {
		t.Errorf("map route: %d, upstream saw %q", rec.Code, pathOf(seenAuth))
	}
	if rec := do("/_GW/AUTH"); rec.Code != 200 || pathOf(seenAuth) != "/base/" {
		t.Errorf("case-insensitive, bare name: %d, upstream saw %q", rec.Code, pathOf(seenAuth))
	}
	if rec := do("/_gw/old/x"); rec.Code != 200 || pathOf(seenOld) != "/x" {
		t.Errorf("a -target name also works under /_gw/: %d, saw %q", rec.Code, pathOf(seenOld))
	}

	// A path that is not under /_gw/ is untouched: a route name cannot take
	// over a path of the default upstream.
	if rec := do("/auth/x"); rec.Code != 200 || pathOf(seenDef) != "/auth/x" {
		t.Errorf("default upstream: %d, saw %q", rec.Code, pathOf(seenDef))
	}
	if got := pathOf(seenAuth); got != "/base/" {
		t.Errorf("/auth/x leaked to the map route: %q", got)
	}

	before := pathOf(seenDef)
	for _, p := range []string{"/_gw/nope/x", "/_gw/", "/_gw"} {
		rec := do(p)
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "auth") {
			t.Errorf("%s: %d %q, want 404 naming the routes", p, rec.Code, rec.Body.String())
		}
	}
	if pathOf(seenDef) != before {
		t.Error("an unknown /_gw/ name was forwarded to the default upstream")
	}

	// The prefix must not be percent-encoded, as with named upstreams.
	if rec := do("/_gw/a%75th/x"); rec.Code != http.StatusBadRequest {
		t.Errorf("encoded prefix: %d, want 400", rec.Code)
	}
}

func TestGatewayOnlyWithMapAndNoDefault(t *testing.T) {
	app := newTestApp(t)
	seen := &upstreamSeen{}
	up := newUpstream(t, seen)
	u, _ := url.Parse(up.URL)
	app.gwMap = map[string]*url.URL{"api": u}

	req := httptest.NewRequest("GET", "/plain/path", nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "/_gw/<name>/") {
		t.Errorf("no route: %d %q", rec.Code, rec.Body.String())
	}

	// A route to the proxy itself is still refused.
	self, _ := url.Parse("http://127.0.0.1:1")
	app.gwMap["loop"] = self
	req = httptest.NewRequest("GET", "/_gw/loop/x", nil)
	req.Host = "127.0.0.1:8080"
	rec = httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != http.StatusLoopDetected {
		t.Errorf("self route: %d, want 508", rec.Code)
	}
}

// Without -target-map the /_gw/ prefix means nothing special.
func TestGatewayPrefixIsOnlyReservedWithAMap(t *testing.T) {
	app := newTestApp(t)
	seen := &upstreamSeen{}
	up := newUpstream(t, seen)
	u, _ := url.Parse(up.URL)
	app.target = u
	req := httptest.NewRequest("GET", "/_gw/x", nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	seen.mu.Lock()
	defer seen.mu.Unlock()
	if rec.Code != 200 || seen.path != "/_gw/x" {
		t.Errorf("%d, upstream saw %q", rec.Code, seen.path)
	}
}

func TestGatewayPrefixAndNames(t *testing.T) {
	for in, want := range map[string]bool{
		"/_gw": true, "/_gw/": true, "/_gw/auth/x": true, "/_GW/x": true,
		"/_gwx": false, "/_g": false, "": false, "/x/_gw": false, "_gw/x": false,
	} {
		if got := hasGatewayPrefix(in); got != want {
			t.Errorf("hasGatewayPrefix(%q) = %v, want %v", in, got, want)
		}
	}
	u := func(s string) *url.URL { v, _ := url.Parse(s); return v }
	a := &App{
		gwMap:     map[string]*url.URL{"b": u("http://b.test"), "a": u("http://a.test")},
		upstreams: map[string]*url.URL{"a": u("http://a2.test"), "c": u("http://c.test")},
	}
	if got := strings.Join(a.gatewayNames(), ","); got != "a,b,c" {
		t.Errorf("gatewayNames = %q, want a,b,c (merged, sorted, without duplicates)", got)
	}
	if got := (&App{}).gatewayNames(); len(got) != 0 {
		t.Errorf("no routes: %v", got)
	}
}

func TestMatchGatewayRawPathChecks(t *testing.T) {
	u, _ := url.Parse("http://auth.test/base")
	a := &App{gwMap: map[string]*url.URL{"auth": u}}

	// The prefix must not be percent-encoded in the raw path.
	for name, raw := range map[string]string{
		"encoded underscore": "/%5Fgw/auth/x",
		"raw path too short": "/_gw/au",
		"name continues":     "/_gw/authz/x",
		"other name":         "/_gw/other/x",
	} {
		if _, _, _, status, err := a.matchGateway("/_gw/auth/x", raw); status != http.StatusBadRequest || err == nil {
			t.Errorf("%s: status=%d err=%v, want 400", name, status, err)
		}
	}
	// A valid raw path keeps its encoding in rawRest.
	base, rest, rawRest, status, err := a.matchGateway("/_gw/auth/a/b", "/_gw/auth/a%2Fb")
	if err != nil || status != 0 || base != u || rest != "/a/b" || rawRest != "/a%2Fb" {
		t.Errorf("valid: base=%v rest=%q rawRest=%q status=%d err=%v", base, rest, rawRest, status, err)
	}
	// The route name is not case-sensitive, in the path or in the raw path.
	if _, rest, rawRest, _, err = a.matchGateway("/_gw/AUTH/x", "/_gw/AUTH/x"); err != nil || rest != "/x" || rawRest != "/x" {
		t.Errorf("upper case name: rest=%q rawRest=%q err=%v", rest, rawRest, err)
	}
	// Without a tail the rest is "/".
	if _, rest, rawRest, _, err = a.matchGateway("/_gw/auth", ""); err != nil || rest != "/" || rawRest != "" {
		t.Errorf("no tail: rest=%q rawRest=%q err=%v", rest, rawRest, err)
	}
	if _, rest, _, _, err = a.matchGateway("/_gw/auth/", "/_gw/auth/"); err != nil || rest != "/" {
		t.Errorf("trailing slash: rest=%q err=%v", rest, err)
	}
	// An unknown name is a 404 that lists the known ones.
	if _, _, _, status, err = a.matchGateway("/_gw/nope/x", ""); status != http.StatusNotFound || err == nil || !strings.Contains(err.Error(), "auth") {
		t.Errorf("unknown name: status=%d err=%v", status, err)
	}
	if _, _, _, status, _ = a.matchGateway("/_gw", ""); status != http.StatusNotFound {
		t.Errorf("no name at all: status=%d", status)
	}
}
