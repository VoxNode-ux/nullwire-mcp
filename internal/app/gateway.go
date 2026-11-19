package app

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// -target-map name=URL,... gives SDKs that cannot send an X-Target-URL header
// a fixed way to pick an upstream: the path /_gw/<name>/rest is forwarded to
// <URL>/rest. The map is an explicit allowlist. A name that is not in it gets
// a 404, never a guess, so there is no open "forward anywhere" route, and
// local upstreams (127.0.0.1, localhost) stay allowed because they are normal
// development backends. The existing checks still apply: only loopback Host
// headers are answered, and a route that points back at the proxy itself is
// refused.
//
// The /_gw/ prefix is reserved only while -target-map is in use. It keeps a
// route name from taking over a path of the default -target upstream, which
// is what a bare /<name>/ prefix would do. Names given to -target also work
// under /_gw/.

const gwBase = "/_gw"

// parseTargetMap reads -target-map. Every entry must be name=URL.
func parseTargetMap(spec string) (map[string]*url.URL, error) {
	def, named, err := parseTargets(spec)
	if err != nil {
		return nil, err
	}
	if def != nil {
		return nil, fmt.Errorf("every entry must look like name=URL; a bare URL has no name to route by")
	}
	return named, nil
}

func hasGatewayPrefix(p string) bool {
	return len(p) >= len(gwBase) && strings.EqualFold(p[:len(gwBase)], gwBase) &&
		(len(p) == len(gwBase) || p[len(gwBase)] == '/')
}

// gatewayNames lists the names that work under /_gw/, sorted.
func (a *App) gatewayNames() []string {
	set := map[string]bool{}
	for n := range a.gwMap {
		set[n] = true
	}
	for n := range a.upstreams {
		set[n] = true
	}
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sortStrings(names)
	return names
}

// matchGateway resolves /_gw/<name>/rest. The rest is returned the way
// matchUpstream returns it, with its raw form when the request had one. A
// name that is not configured is a 404 with the names that are.
func (a *App) matchGateway(p, rawPath string) (base *url.URL, rest, rawRest string, status int, err error) {
	seg, tail := strings.TrimPrefix(p[len(gwBase):], "/"), ""
	if i := strings.IndexByte(seg, '/'); i >= 0 {
		seg, tail = seg[:i], seg[i:]
	}
	key := strings.ToLower(seg)
	base = a.gwMap[key]
	if base == nil {
		base = a.upstreams[key]
	}
	if base == nil {
		return nil, "", "", http.StatusNotFound,
			fmt.Errorf("unknown gateway name %q: use %s/<name>/ with one of: %s", seg, gwBase, strings.Join(a.gatewayNames(), ", "))
	}
	if rawPath != "" {
		pre := gwBase + "/" + seg
		if len(rawPath) < len(pre) || !strings.EqualFold(rawPath[:len(pre)], pre) || (len(rawPath) > len(pre) && rawPath[len(pre)] != '/') {
			return nil, "", "", http.StatusBadRequest, fmt.Errorf("the gateway prefix %q must not be percent-encoded", pre)
		}
		rawRest = rawPath[len(pre):]
	}
	if tail == "" {
		tail = "/"
	}
	return base, tail, rawRest, 0, nil
}
