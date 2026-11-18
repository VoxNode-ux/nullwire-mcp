package app

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
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
