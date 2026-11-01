package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// runScanQuiet runs a scan and prints its report to stderr, keeping stdout
// free for the MCP protocol. It returns the scan's exit code.
func runScanQuiet(args []string) int {
	var buf bytes.Buffer
	code := runScanTo(&buf, &buf, args)
	fmt.Fprintf(os.Stderr, "\r\033[K⚡ pre-scan (exit %d):\n%s\n", code, buf.String())
	return code
}

// reexecServe runs this program again with args and passes the signals it
// receives on to the child, so stopping protect also stops the server.
func reexecServe(args []string) int {
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "nullwire-mcp protect: cannot locate self: %v\n", err)
		return 1
	}
	cmd := exec.Command(self, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = os.Environ()
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "nullwire-mcp protect: %v\n", err)
		return 1
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
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
