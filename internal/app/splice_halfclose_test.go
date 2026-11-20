package app

import (
	"io"
	"net"
	"testing"
	"time"
)

// noCW hides CloseWrite, like the *http.readWriteCloserBody of a 101 response.
type noCW struct{ c net.Conn }

func (n noCW) Read(p []byte) (int, error)  { return n.c.Read(p) }
func (n noCW) Write(p []byte) (int, error) { return n.c.Write(p) }
func (n noCW) Close() error                { return n.c.Close() }

// Bug A: the client half-closes; the upstream has no CloseWrite. Its reply
// (a Close frame) must still reach the client.
func TestSpliceHalfCloseKeepsUpstreamOpenForReply(t *testing.T) {
	old := halfCloseDrain
	halfCloseDrain = 2 * time.Second
	t.Cleanup(func() { halfCloseDrain = old })
	cc, cs := net.Pipe() // cs is the proxy's client side
	uc, us := net.Pipe() // uc is the proxy's upstream side
	done := make(chan struct{})
	go func() { splice(cs, noCW{uc}, 0, nil); close(done) }()
	go func() {
		b := make([]byte, 5)
		_, _ = io.ReadFull(us, b)
		_, _ = us.Write([]byte("close")) // server's reply after seeing the client's frame
		_ = us.Close()
	}()
	_, _ = cc.Write([]byte("hello"))
	_ = cc.Close() // half-close stand-in: client input ends
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("splice did not return")
	}
}

// Bug B: a failed write towards the upstream must not discard what the
// upstream already sent.
func TestSpliceWriteErrorStillDeliversReverseData(t *testing.T) {
	old := halfCloseDrain
	halfCloseDrain = 2 * time.Second
	t.Cleanup(func() { halfCloseDrain = old })
	cc, cs := net.Pipe()
	uc, us := net.Pipe()
	go splice(cs, uc, 0, nil)
	go func() { _, _ = us.Write([]byte("close")); _ = us.Close() }()
	time.Sleep(50 * time.Millisecond)
	go func() { _, _ = cc.Write([]byte("junk")) }() // upstream side is closed: write fails
	b, _ := io.ReadAll(cc)
	if string(b) != "close" {
		t.Fatalf("client got %q, want the upstream's close data", b)
	}
}
