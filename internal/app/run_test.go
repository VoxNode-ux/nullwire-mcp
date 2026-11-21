package app

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// runCLIApp drives the whole command line in-process: flags are parsed,
// the proxy starts on a free port, and stdin is the MCP stream.
func runCLIApp(t *testing.T, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	t.Setenv(tokenEnv, "") // run() unsets it; t.Setenv restores the old value
	var out, errb bytes.Buffer
	err = run(args, strings.NewReader(stdin), &out, &errb)
	return out.String(), errb.String(), err
}

func TestRunStartupValidation(t *testing.T) {
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "not.pem")
	if err := os.WriteFile(notPEM, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"port too high", []string{"-port=70000"}, "-port must be between"},
		{"port negative", []string{"-port=-1"}, "-port must be between"},
		{"max-body", []string{"-port=0", "-max-body=zzz"}, "-max-body"},
		{"max-ram too big", []string{"-port=0", "-max-ram=401m"}, "above the 400 MiB limit"},
		{"max-ram zero", []string{"-port=0", "-max-ram=0"}, "greater than zero"},
		{"max-ram negative", []string{"-port=0", "-max-ram=-5m"}, "greater than zero"},
		{"max-ram junk", []string{"-port=0", "-max-ram=zzz"}, "-max-ram"},
		{"max-ram too small", []string{"-port=0", "-max-ram=64k"}, "cannot hold one flow"},
		{"ttl negative", []string{"-port=0", "-ttl=-1s"}, "-ttl"},
		{"idle-wipe negative", []string{"-port=0", "-idle-wipe=-5m"}, "-idle-wipe"},
		{"policy lock", []string{"-port=0", "-policy-pubkey=ab", "-allow-uninspectable"}, "cannot be weakened"},
		{"pubkey needs config", []string{"-port=0", "-policy-pubkey=ab"}, "needs -secrets-config"},
		{"missing config", []string{"-port=0", "-secrets-config=" + filepath.Join(dir, "nope.json")}, "-secrets-config"},
		{"preset", []string{"-port=0", "-preset=nope"}, "-preset"},
		{"disable-tools", []string{"-port=0", "-disable-tools=nope"}, "unknown tool"},
		{"token too short", []string{"-port=0", "-proxy-token=short"}, "at least"},
		{"token bad chars", []string{"-port=0", "-proxy-token=abcdefghijklmnop!!"}, "may only hold"},
		{"attest-key missing", []string{"-port=0", "-attest-key=" + filepath.Join(dir, "nope.key")}, "-attest-key"},
		{"dns", []string{"-port=0", "-dns=notanip"}, "-dns"},
		{"cacert missing", []string{"-port=0", "-cacert=" + filepath.Join(dir, "nope.pem")}, "-cacert"},
		{"cacert without PEM", []string{"-port=0", "-cacert=" + notPEM}, "no PEM certificates"},
		{"client-cert alone", []string{"-port=0", "-client-cert=x"}, "must be given together"},
		{"client-cert unreadable", []string{"-port=0", "-client-cert=x", "-client-key=y"}, "client certificate"},
		{"target twice", []string{"-port=0", "-target=a=http://example.com,a=http://example.org"}, "-target"},
		{"target-map bare url", []string{"-port=0", "-target-map=http://example.com"}, "-target-map"},
		{"target-map name reused", []string{"-port=0", "-target=a=http://example.com", "-target-map=a=http://example.org"}, "also used in -target"},
		{"listen not unix", []string{"-listen=tcp://x"}, "unix://"},
		{"listen relative", []string{"-listen=unix://rel.sock"}, "absolute path"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := runCLIApp(t, "", c.args...)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("run(%v) = %v, want an error containing %q", c.args, err, c.want)
			}
			var pe flagParseError
			if errors.As(err, &pe) {
				t.Fatalf("a validation error must not be reported as a flag error: %v", err)
			}
		})
	}
}

func TestRunFlagErrors(t *testing.T) {
	_, errOut, err := runCLIApp(t, "", "-no-such-flag")
	var pe flagParseError
	if !errors.As(err, &pe) {
		t.Fatalf("an unknown flag must be a flagParseError, got %v", err)
	}
	if !strings.Contains(errOut, "no-such-flag") {
		t.Errorf("the flag set should explain the failure on stderr: %q", errOut)
	}
	_, errOut, err = runCLIApp(t, "", "-h")
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("-h must surface flag.ErrHelp, got %v", err)
	}
	if !strings.Contains(errOut, "-port") {
		t.Errorf("usage should list the flags: %q", errOut)
	}
}

func TestRunStdinEOFExitsCleanly(t *testing.T) {
	out, errOut, err := runCLIApp(t, "", "-port=0")
	if err != nil {
		t.Fatalf("a clean stdin EOF must return nil, got %v", err)
	}
	if out != "" {
		t.Errorf("nothing should reach stdout without requests: %q", out)
	}
	for _, want := range []string{"MCP stdio server ready", "stdin closed; wiping RAM"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr is missing %q:\n%s", want, errOut)
		}
	}
}

func TestRunServesMCPOverInjectedStdio(t *testing.T) {
	in := "\n" + `{"jsonrpc":"2.0","id":7,"method":"initialize","params":{}}` + "\n"
	out, _, err := runCLIApp(t, in, "-port=0", "-scrub-headers=X-Foo, X-Bar", "-preset=pci-dss", "-dns=system", "-max-body=64k")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"id":7`) || !strings.Contains(out, `"jsonrpc":"2.0"`) {
		t.Errorf("the initialize response must go to the injected stdout: %q", out)
	}
}

func TestRunTargetsAndGatewayLog(t *testing.T) {
	_, errOut, err := runCLIApp(t, "", "-port=0", "-dns=auto",
		"-target=http://example.com", "-target-map=gw=http://example.org")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut, "gateway route") || !strings.Contains(errOut, "example.org") {
		t.Errorf("the gateway route should be logged:\n%s", errOut)
	}
}

func TestRunProxyTokenModes(t *testing.T) {
	_, errOut, err := runCLIApp(t, "", "-port=0", "-proxy-token=auto")
	if err != nil || !strings.Contains(errOut, "HTTP_PROXY=http://nw:") {
		t.Fatalf("auto token over TCP: err=%v\n%s", err, errOut)
	}
	_, errOut, err = runCLIApp(t, "", "-port=0", "-proxy-token=abcdefghijklmnop")
	if err != nil || !strings.Contains(errOut, "proxy token required (Proxy-Authorization password") {
		t.Fatalf("fixed token: err=%v\n%s", err, errOut)
	}
	// The environment variable is the third source; the flag wins over it.
	t.Setenv(tokenEnv, "envtokenenvtoken1234")
	var out, errb bytes.Buffer
	if err := run([]string{"-port=0"}, strings.NewReader(""), &out, &errb); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errb.String(), "proxy token required (") {
		t.Errorf("a token from %s must switch the check on:\n%s", tokenEnv, errb.String())
	}
	if os.Getenv(tokenEnv) != "" {
		t.Errorf("%s must be unset after startup", tokenEnv)
	}
	t.Setenv(tokenEnv, "bad token!")
	if err := run([]string{"-port=0"}, strings.NewReader(""), &out, &errb); err == nil {
		t.Error("an invalid token from the environment must be refused")
	}
}

func TestRunListenUnixAndAttest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets")
	}
	dir, err := os.MkdirTemp("", "nw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s.sock")
	keyPrefix := filepath.Join(dir, "k")
	if code, _, e := runPolicyCmd(t, "keygen", "-out", keyPrefix); code != 0 {
		t.Fatalf("keygen: %d %s", code, e)
	}
	report := filepath.Join(dir, "att.json")
	_, errOut, err := runCLIApp(t, "", "-listen=unix://"+sock, "-proxy-token=auto",
		"-attest-out="+report, "-attest-key="+keyPrefix+".key")
	if err != nil {
		t.Fatalf("run: %v\n%s", err, errOut)
	}
	if !strings.Contains(errOut, "unix socket "+sock) || !strings.Contains(errOut, "Send Proxy-Authorization") {
		t.Errorf("unix-socket banner / token hint missing:\n%s", errOut)
	}
	if _, statErr := os.Stat(sock); !os.IsNotExist(statErr) {
		t.Errorf("the socket file must be removed at exit: %v", statErr)
	}
	b, err := os.ReadFile(report)
	if err != nil {
		t.Fatalf("-attest-out was not written: %v", err)
	}
	_, signer, mode, err := verifyAttestation(b)
	if err != nil || mode != "provided" || signer == "" {
		t.Fatalf("report: err=%v mode=%q", err, mode)
	}
	// Unix socket with a token given by the user (not generated).
	sock2 := filepath.Join(dir, "t.sock")
	_, errOut, err = runCLIApp(t, "", "-listen=unix://"+sock2, "-proxy-token=abcdefghijklmnop")
	if err != nil || !strings.Contains(errOut, "proxy token required (Proxy-Authorization password") {
		t.Fatalf("unix + fixed token: err=%v\n%s", err, errOut)
	}
}

func TestRunWithSignedPolicy(t *testing.T) {
	_, policy, pub := signedPack(t)
	_, _, err := runCLIApp(t, "", "-port=0", "-secrets-config="+policy, "-policy-pubkey="+pub)
	if err != nil {
		t.Fatalf("a correctly signed policy must start: %v", err)
	}
	if err := os.WriteFile(policy, []byte(`{"presets":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCLIApp(t, "", "-port=0", "-secrets-config="+policy, "-policy-pubkey="+pub); err == nil {
		t.Fatal("a tampered policy must be refused at startup")
	}
}

// ---------------------------------------------------------------------------
// run(): remaining startup paths
// ---------------------------------------------------------------------------

func TestRcovRunDNSModes(t *testing.T) {
	if _, _, err := runCLIApp(t, "", "-port=0", "-dns=system"); err != nil {
		t.Fatalf("-dns system: %v", err)
	}
	if _, _, err := runCLIApp(t, "", "-port=0", "-dns=1.1.1.1:53"); err != nil {
		t.Fatalf("-dns 1.1.1.1:53: %v", err)
	}
	// auto on Termux logs the notice and switches to the Android resolvers.
	t.Setenv("TERMUX_VERSION", "1")
	_, errOut, err := runCLIApp(t, "", "-port=0", "-dns=auto")
	if err != nil || !strings.Contains(errOut, "Termux/Android detected") {
		t.Fatalf("-dns auto on Termux: err=%v\n%s", err, errOut)
	}
}

func TestRcovRunTargetMapNameCollidesWithNamedTarget(t *testing.T) {
	_, _, err := runCLIApp(t, "", "-port=0",
		"-target=upstream=http://example.com", "-target-map=upstream=http://example.org")
	if err == nil || !strings.Contains(err.Error(), `name "upstream" is also used in -target`) {
		t.Fatalf("err = %v, want the name collision", err)
	}
}

func TestRcovRunProxyTokenSources(t *testing.T) {
	// "auto" taken from the environment makes a fresh token and prints it.
	t.Setenv(tokenEnv, "auto")
	var out, errb bytes.Buffer
	if err := run([]string{"-port=0"}, strings.NewReader(""), &out, &errb); err != nil {
		t.Fatalf("env auto: %v", err)
	}
	if !strings.Contains(errb.String(), "HTTP_PROXY=http://nw:") {
		t.Errorf("a generated token must be printed:\n%s", errb.String())
	}
	if os.Getenv(tokenEnv) != "" {
		t.Errorf("%s must be unset after startup", tokenEnv)
	}

	// A bad literal on the command line is refused before anything starts.
	_, _, err := runCLIApp(t, "", "-port=0", "-proxy-token=bad token with spaces!")
	if err == nil || !strings.Contains(err.Error(), "may only hold") {
		t.Fatalf("bad literal token: %v", err)
	}

	// auto + unix socket prints the socket form of the hint.
	if runtime.GOOS == "windows" {
		return
	}
	dir, derr := os.MkdirTemp("", "nw")
	if derr != nil {
		t.Fatal(derr)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	_, errOut, err := runCLIApp(t, "", "-listen=unix://"+filepath.Join(dir, "a.sock"), "-proxy-token=auto")
	if err != nil || !strings.Contains(errOut, "Send Proxy-Authorization (any user, password ") {
		t.Fatalf("auto + unix: err=%v\n%s", err, errOut)
	}
}

func TestRcovRunAttestOutIsADirectory(t *testing.T) {
	base := t.TempDir()
	outDir := filepath.Join(base, "report")
	if err := os.Mkdir(outDir, 0o700); err != nil {
		t.Fatal(err)
	}
	_, errOut, err := runCLIApp(t, "", "-port=0", "-attest-out="+outDir)
	if err != nil {
		t.Fatalf("a failed report write must not fail the run: %v", err)
	}
	if !strings.Contains(errOut, "cannot write -attest-out") {
		t.Errorf("the write failure must be logged:\n%s", errOut)
	}
}

func TestRcovRunCACertAndClientCertFailures(t *testing.T) {
	dir := t.TempDir()
	junkDir := filepath.Join(dir, "cas")
	if err := os.Mkdir(junkDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(junkDir, "junk.txt"), []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCLIApp(t, "", "-port=0", "-cacert="+junkDir); err == nil || !strings.Contains(err.Error(), "no PEM certificates") {
		t.Fatalf("-cacert dir with only junk: %v", err)
	}
	crt := filepath.Join(dir, "c.pem")
	key := filepath.Join(dir, "k.pem")
	for _, p := range []string{crt, key} {
		if err := os.WriteFile(p, []byte("junk"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := runCLIApp(t, "", "-port=0", "-client-cert="+crt, "-client-key="+key); err == nil || !strings.Contains(err.Error(), "client certificate") {
		t.Fatalf("junk client cert/key: %v", err)
	}
}

// ---------------------------------------------------------------------------
// safeDispatch panic recovery, batch edges, marshalJSON
// ---------------------------------------------------------------------------

func TestRcovSafeDispatchRecoversPanic(t *testing.T) {
	var errb, out bytes.Buffer
	app := newTestApp(t)
	app.stderr, app.stdout = &errb, &out
	app.ring = nil // clear_ram_buffer now dereferences nil and panics

	req := rpcRequest{ID: json.RawMessage(`9`), Method: "tools/call", Params: json.RawMessage(`{"name":"clear_ram_buffer"}`)}
	resp := app.safeDispatch(req)
	if resp == nil || resp.Error == nil || resp.Error.Code != -32603 || string(resp.ID) != "9" {
		t.Fatalf("recovered response = %+v", resp)
	}
	if !strings.Contains(errb.String(), "panic:") {
		t.Errorf("the panic must be logged:\n%s", errb.String())
	}

	// Through the line handler the client still gets a JSON-RPC error frame.
	app.handleLine([]byte(`{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"clear_ram_buffer"}}`))
	if !strings.Contains(out.String(), `"id":10`) || !strings.Contains(out.String(), "-32603") {
		t.Errorf("frame = %q", out.String())
	}
}

func TestRcovHandleBatchEdges(t *testing.T) {
	var out bytes.Buffer
	app := newTestApp(t)
	app.stdout = &out

	app.handleBatch([]byte(`{"not":"an array"}`)) // non-array
	if !strings.Contains(out.String(), "-32700") {
		t.Errorf("non-array batch: %q", out.String())
	}
	out.Reset()
	app.handleBatch([]byte(`["x", 1]`)) // entries that are not objects
	if n := strings.Count(out.String(), "-32600"); n != 2 {
		t.Errorf("want two invalid-request entries, got %d: %q", n, out.String())
	}
}

func TestRcovMarshalJSON(t *testing.T) {
	s, err := marshalJSON(map[string]any{"k": "<&>"}, true)
	if err != nil || s != "{\n  \"k\": \"<&>\"\n}" {
		t.Errorf("indented, unescaped = %q, %v", s, err)
	}
	if s, err = marshalJSON(make(chan int), false); err == nil || s != "" {
		t.Errorf("an unencodable value must error: %q, %v", s, err)
	}
}

// ---------------------------------------------------------------------------
// ServeHTTP / handleConnect / handleUpgrade failure branches
// ---------------------------------------------------------------------------

func TestRcovServeHTTPInvalidXTargetURL(t *testing.T) {
	app := newTestApp(t)
	for _, bad := range []string{"ftp://example.test", "http://"} {
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, covReq("GET", "/x", "127.0.0.1:8080", "X-Target-URL", bad))
		if rec.Code < 400 || rec.Code >= 500 {
			t.Errorf("X-Target-URL %q: status %d, want a 4xx", bad, rec.Code)
		}
	}
}

// rcovHijackRec hands out one end of a pipe as the hijacked client connection.
type rcovHijackRec struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (h rcovHijackRec) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.conn, bufio.NewReadWriter(bufio.NewReader(h.conn), bufio.NewWriter(h.conn)), nil
}

// rcovDeadClient returns a client connection whose peer is already gone, so
// the first write to it fails.
func rcovDeadClient(t *testing.T) net.Conn {
	t.Helper()
	c1, c2 := net.Pipe()
	_ = c2.Close()
	t.Cleanup(func() { _ = c1.Close() })
	return c1
}

func TestRcovConnectClientWriteFails(t *testing.T) {
	app := newTestApp(t)
	addr := startEchoTCP(t)
	app.handleConnect(rcovHijackRec{httptest.NewRecorder(), rcovDeadClient(t)}, covConnect(addr), time.Now())
	if n := app.tunnels.Load(); n != 0 {
		t.Errorf("tunnel slot leaked after a failed 200 write: %d", n)
	}
}

func TestRcovUpgradeClientWriteFails(t *testing.T) {
	app := newTestApp(t)
	u1, u2 := net.Pipe()
	t.Cleanup(func() { _ = u1.Close(); _ = u2.Close() })
	resp := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header: http.Header{
			"Upgrade":        []string{"foo"},
			"Connection":     []string{"Upgrade"},
			"Content-Length": []string{"0"}, // skipped when the 101 head is built
		},
		Body: u1,
	}
	flow := rawFlow{started: time.Now(), method: "GET", url: "http://x.test/up", reqHeaders: http.Header{}}
	app.handleUpgrade(rcovHijackRec{httptest.NewRecorder(), rcovDeadClient(t)}, resp, flow, false)
	if n := app.tunnels.Load(); n != 0 {
		t.Errorf("tunnel slot leaked after a failed 101 write: %d", n)
	}
}
