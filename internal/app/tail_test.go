package app

import (
	"bytes"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// lockedBuf is a bytes.Buffer that is safe for concurrent use.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func tailTestApp(t *testing.T) (*App, *lockedBuf, *lockedBuf) {
	t.Helper()
	app := newTestApp(t)
	out, errb := &lockedBuf{}, &lockedBuf{}
	app.stdout, app.stderr = out, errb
	return app, out, errb
}

func tailFlowFor(url string) rawFlow {
	return rawFlow{
		started: time.Now(), method: "POST", url: url, status: 200, latencyMs: 142,
		reqHeaders:  http.Header{"Authorization": {"Bearer hunter2-hunter2-hunter2"}, "Content-Type": {"application/json"}},
		reqBody:     []byte(`{"password":"correct-horse-battery-staple-9"}`),
		respHeaders: http.Header{}, respBody: []byte(`{"ok":true}`),
	}
}

func TestTailLineFormat(t *testing.T) {
	now := time.Date(2026, 11, 21, 14, 2, 11, 0, time.Local)
	e := FlowEntry{Method: "POST", URL: "https://api.example.com/v1/chat", StatusCode: 200, LatencyMs: 142, RedactionCount: 3}
	want := "[14:02:11] POST https://api.example.com/v1/chat 200 142ms (3 redacted)\n"
	if got := tailLine(now, &e); got != want {
		t.Fatalf("tailLine = %q, want %q", got, want)
	}
}

func TestTailLineNeutralisesControlBytes(t *testing.T) {
	e := FlowEntry{Method: "GE\x1bT", URL: "https://x.test/a\r\nFAKE\x1b[2J\x07"}
	got := tailLine(time.Now(), &e)
	if strings.Count(got, "\n") != 1 || !strings.HasSuffix(got, "\n") {
		t.Fatalf("line is not a single line: %q", got)
	}
	if strings.ContainsAny(got[:len(got)-1], "\x1b\r\x07") {
		t.Fatalf("control bytes survived: %q", got)
	}
}

func TestTailLineCapsLongURL(t *testing.T) {
	e := FlowEntry{Method: "GET", URL: "https://x.test/" + strings.Repeat("a", 5000)}
	if got := tailLine(time.Now(), &e); len(got) > 450 {
		t.Fatalf("line is %d bytes; the URL should be cut", len(got))
	}
}

func TestTailOffKeepsStatusBarAndPrintsNoLines(t *testing.T) {
	app, _, errb := tailTestApp(t)
	app.capture(tailFlowFor("https://api.example.com/v1/chat"))
	got := errb.String()
	if !strings.Contains(got, "[NullWire-MCP]") {
		t.Fatalf("status bar missing with -tail off: %q", got)
	}
	if regexp.MustCompile(`\[\d\d:\d\d:\d\d\] POST`).MatchString(got) {
		t.Fatalf("tail line printed with -tail off: %q", got)
	}
}

func TestTailPrintsOnlyScrubbedFlowSummary(t *testing.T) {
	app, out, errb := tailTestApp(t)
	app.tail = true
	app.capture(tailFlowFor("https://api.example.com/pay/sk_live_" + ctxTestBody))
	got := errb.String()
	line := regexp.MustCompile(`^\[\d\d:\d\d:\d\d\] POST https://api\.example\.com/pay/\S+ 200 142ms \((\d+) redacted\)\n$`)
	m := line.FindStringSubmatch(got)
	if m == nil {
		t.Fatalf("unexpected tail output: %q", got)
	}
	if m[1] == "0" {
		t.Fatalf("redaction count should be non-zero: %q", got)
	}
	for _, leak := range []string{ctxTestBody, "hunter2", "correct-horse", "Authorization", "password", `"ok"`, "\r", "\x1b", "⚡"} {
		if strings.Contains(got, leak) {
			t.Fatalf("tail output leaks or redraws %q: %q", leak, got)
		}
	}
	if out.String() != "" {
		t.Fatalf("stdout polluted: %q", out.String())
	}
}

func TestTailSkipsIgnoredFlows(t *testing.T) {
	app, _, errb := tailTestApp(t)
	app.tail = true
	app.ignoreURLSubstrings = []string{"/health"}
	app.capture(tailFlowFor("https://api.example.com/health"))
	if errb.String() != "" {
		t.Fatalf("ignored flow was printed: %q", errb.String())
	}
}

func TestTailFinishLiveAlsoPrints(t *testing.T) {
	app, _, errb := tailTestApp(t)
	app.tail = true
	app.finishLive(0, tailFlowFor("https://api.example.com/v1/chat"))
	if !strings.Contains(errb.String(), "POST https://api.example.com/v1/chat 200 142ms") {
		t.Fatalf("finishLive tail line missing: %q", errb.String())
	}
}

func TestTailLogfIsPlainLine(t *testing.T) {
	app, _, errb := tailTestApp(t)
	app.tail = true
	app.Logf("hello %d", 7)
	app.Bar()
	if got := errb.String(); got != "hello 7\n" {
		t.Fatalf("Logf/Bar output with -tail = %q", got)
	}
}

func TestTailConcurrentWritesStayWholeLines(t *testing.T) {
	app, out, errb := tailTestApp(t)
	app.tail = true
	const workers, per = 8, 50
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				app.capture(tailFlowFor(fmt.Sprintf("https://api.example.com/n%d-%d", w, i)))
				app.markBar()
				if i%10 == 0 {
					app.Logf("log-%d-%d", w, i)
				}
			}
		}()
	}
	wg.Wait()
	tailRe := regexp.MustCompile(`^\[\d\d:\d\d:\d\d\] POST https://api\.example\.com/n\d+-\d+ 200 142ms \(\d+ redacted\)$`)
	logRe := regexp.MustCompile(`^log-\d+-\d+$`)
	tails, logs := 0, 0
	for _, l := range strings.Split(strings.TrimSuffix(errb.String(), "\n"), "\n") {
		switch {
		case tailRe.MatchString(l):
			tails++
		case logRe.MatchString(l):
			logs++
		default:
			t.Fatalf("interleaved or unexpected line: %q", l)
		}
	}
	if tails != workers*per || logs != workers*(per/10) {
		t.Fatalf("tails = %d, logs = %d", tails, logs)
	}
	if out.String() != "" {
		t.Fatalf("stdout polluted: %q", out.String())
	}
}

func TestRunAcceptsTailFlag(t *testing.T) {
	stdout, stderr, err := runCLIApp(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n", "-port=0", "-tail")
	if err != nil {
		t.Fatalf("run -tail: %v", err)
	}
	if !strings.Contains(stdout, `"tools"`) {
		t.Fatalf("stdout lost the JSON-RPC reply: %q", stdout)
	}
	if strings.Contains(stderr, "⚡") || strings.Contains(stdout, "[NullWire-MCP]") {
		t.Fatalf("status bar drawn with -tail: stderr=%q", stderr)
	}
}
