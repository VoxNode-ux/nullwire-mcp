package app

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// export_har turns flows that are already scrubbed into a HAR 1.2 document and
// returns it as the tool result. Nothing is written to disk: the document is
// built in memory and goes out over stdio like any other tool result.
//
// A stdio frame (and the model's context) can be hurt by a very large reply,
// so the tool is bounded three ways: limit and the method/url_contains filters
// choose which flows, bodies are left out unless include_bodies is true, and
// the whole document is capped at harMaxBytes whatever the arguments are.

const harMaxBytes = 1 << 20

type harNV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harPost struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type harRequest struct {
	Method      string   `json:"method"`
	URL         string   `json:"url"`
	HTTPVersion string   `json:"httpVersion"`
	Cookies     []harNV  `json:"cookies"`
	Headers     []harNV  `json:"headers"`
	QueryString []harNV  `json:"queryString"`
	PostData    *harPost `json:"postData,omitempty"`
	HeadersSize int      `json:"headersSize"`
	BodySize    int      `json:"bodySize"`
}

type harContent struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
}

type harResponse struct {
	Status      int        `json:"status"`
	StatusText  string     `json:"statusText"`
	HTTPVersion string     `json:"httpVersion"`
	Cookies     []harNV    `json:"cookies"`
	Headers     []harNV    `json:"headers"`
	Content     harContent `json:"content"`
	RedirectURL string     `json:"redirectURL"`
	HeadersSize int        `json:"headersSize"`
	BodySize    int        `json:"bodySize"`
}

type harTimings struct {
	Send    int64 `json:"send"`
	Wait    int64 `json:"wait"`
	Receive int64 `json:"receive"`
}

type harExtra struct {
	FlowID         uint64 `json:"flow_id"`
	RedactionCount int    `json:"redaction_count"`
	Note           string `json:"note,omitempty"`
	BodiesCut      bool   `json:"bodies_left_out_for_size,omitempty"`
}

type harEntry struct {
	Started  string      `json:"startedDateTime"`
	Time     int64       `json:"time"`
	Request  harRequest  `json:"request"`
	Response harResponse `json:"response"`
	Cache    struct{}    `json:"cache"`
	Timings  harTimings  `json:"timings"`
	NullWire harExtra    `json:"_nullwire"`
}

func harHeaders(m map[string]string) []harNV {
	out := make([]harNV, 0, len(m))
	for k, v := range m {
		out = append(out, harNV{Name: k, Value: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func harHeader(m map[string]string, name string) string {
	for k, v := range m {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// harQuery lists the query string parameters in the order they appear.
func harQuery(raw string) []harNV {
	out := []harNV{}
	u, err := url.Parse(raw)
	if err != nil || u.RawQuery == "" {
		return out
	}
	for _, part := range strings.Split(u.RawQuery, "&") {
		if part == "" {
			continue
		}
		name, value, _ := strings.Cut(part, "=")
		if n, err := url.QueryUnescape(name); err == nil {
			name = n
		}
		if v, err := url.QueryUnescape(value); err == nil {
			value = v
		}
		out = append(out, harNV{Name: name, Value: value})
	}
	return out
}

// buildHAREntry converts one stored flow. Every string in it was scrubbed when
// the flow was captured; nothing is read from anywhere else.
func buildHAREntry(e FlowEntry, withBodies bool) harEntry {
	const unknown = "unknown" // the HTTP version is not recorded
	req := harRequest{
		Method: e.Method, URL: e.URL, HTTPVersion: unknown,
		Cookies: []harNV{}, Headers: harHeaders(e.RequestHeaders), QueryString: harQuery(e.URL),
		HeadersSize: -1, BodySize: len(e.RequestBody),
	}
	if e.RequestBody != "" && withBodies {
		req.PostData = &harPost{MimeType: harHeader(e.RequestHeaders, "Content-Type"), Text: e.RequestBody}
	}
	resp := harResponse{
		Status: e.StatusCode, StatusText: http.StatusText(e.StatusCode), HTTPVersion: unknown,
		Cookies: []harNV{}, Headers: harHeaders(e.ResponseHeaders),
		Content:     harContent{Size: len(e.ResponseBody), MimeType: harHeader(e.ResponseHeaders, "Content-Type")},
		HeadersSize: -1, BodySize: len(e.ResponseBody),
	}
	if withBodies {
		resp.Content.Text = e.ResponseBody
	}
	return harEntry{
		Started: e.Timestamp, Time: e.LatencyMs, Request: req, Response: resp,
		Timings:  harTimings{Wait: e.LatencyMs},
		NullWire: harExtra{FlowID: e.ID, RedactionCount: e.RedactionCount, Note: e.Note},
	}
}

// harFit encodes one entry within budget bytes. If it does not fit with its
// bodies it is tried without them. ok is false when even that is too big.
func harFit(e FlowEntry, withBodies bool, budget int) (raw []byte, cut, ok bool) {
	if withBodies {
		s, err := marshalJSON(buildHAREntry(e, true), false)
		if err == nil && len(s) <= budget {
			return []byte(s), false, true
		}
	}
	he := buildHAREntry(e, false)
	he.NullWire.BodiesCut = withBodies
	s, err := marshalJSON(he, false)
	if err != nil || len(s) > budget {
		return nil, false, false
	}
	return []byte(s), withBodies, true
}

func toolLimit(p *float64) int {
	switch {
	case p == nil:
		return 10
	case *p < 1:
		return 1
	case *p > ringCapacity:
		return ringCapacity
	default:
		return int(*p)
	}
}

func (a *App) toolExportHAR(args json.RawMessage) map[string]any {
	var in struct {
		Limit         *float64 `json:"limit"`
		Method        string   `json:"method"`
		URLContains   string   `json:"url_contains"`
		IncludeBodies bool     `json:"include_bodies"`
	}
	if !isEmptyArgs(args) {
		if err := json.Unmarshal(args, &in); err != nil {
			return toolResult("invalid arguments: "+err.Error(), true)
		}
	}
	flows := a.ring.ListRecent(toolLimit(in.Limit), in.Method, in.URLContains) // newest first

	budget := harMaxBytes - 1024 // room for the document around the entries
	picked := make([]json.RawMessage, 0, len(flows))
	omitted, cutBodies := 0, 0
	for i, e := range flows {
		raw, cut, ok := harFit(e, in.IncludeBodies, budget)
		if !ok {
			omitted = len(flows) - i
			break
		}
		budget -= len(raw) + 1
		if cut {
			cutBodies++
		}
		picked = append(picked, raw)
	}
	// HAR lists entries oldest first.
	for i, j := 0, len(picked)-1; i < j; i, j = i+1, j-1 {
		picked[i], picked[j] = picked[j], picked[i]
	}

	doc := map[string]any{"log": map[string]any{
		"version": "1.2",
		"creator": map[string]any{"name": serverName, "version": serverVersion},
		"comment": "Scrubbed copy from the RAM ring buffer. Sizes are of the stored, scrubbed text.",
		"entries": picked,
		"_nullwire": map[string]any{
			"scrubbed": true, "include_bodies": in.IncludeBodies, "returned": len(picked),
			"omitted_for_size": omitted, "entries_with_bodies_left_out_for_size": cutBodies,
			"ring_size": a.ring.Len(),
		},
	}}
	text, err := marshalJSON(doc, false)
	if err != nil {
		return toolResult("failed to encode HAR: "+err.Error(), true)
	}
	return toolResult(text, false)
}
