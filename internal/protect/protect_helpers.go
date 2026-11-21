package protect

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/VoxNode-ux/nullwire-mcp/internal/scan"
)

// runScanQuiet runs a scan and prints its report to stderr, keeping stdout
// free for the MCP protocol. It returns the scan's exit code.
func runScanQuiet(args []string) int {
	var buf bytes.Buffer
	code := scan.RunTo(&buf, &buf, args)
	fmt.Fprintf(os.Stderr, "\r\033[K⚡ pre-scan (exit %d):\n%s\n", code, buf.String())
	return code
}

// executable returns the path of the running program. Tests replace it.
var executable = os.Executable

// reexecServe runs this program again with args and passes the signals it
// receives on to the child, so stopping protect also stops the server.
func reexecServe(args []string) int { return reexecServeEnv(args, nil) }

// reexecServeEnv is reexecServe with extra environment variables for the child.
func reexecServeEnv(args, env []string) int {
	self, err := executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "nullwire-mcp protect: cannot locate self: %v\n", err)
		return 1
	}
	// Register for signals before the child exists, so the handler is already
	// active whenever the child first writes anything. The channel is
	// buffered, so a signal that arrives before the forwarding goroutine
	// starts is held, not lost.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	// self is the running executable's own path, so no PATH lookup is involved.
	cmd := &exec.Cmd{
		Path:   self,
		Args:   append([]string{self}, args...),
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Env:    append(os.Environ(), env...),
	}
	if err := cmd.Start(); err != nil {
		signal.Stop(sigs)
		fmt.Fprintf(os.Stderr, "nullwire-mcp protect: %v\n", err)
		return 1
	}

	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-sigs:
				_ = cmd.Process.Signal(sig)
			case <-done:
				return
			}
		}
	}()

	err = cmd.Wait()
	signal.Stop(sigs)
	close(done)
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "nullwire-mcp protect: %v\n", err)
		return 1
	}
	return 0
}