package health

import (
	"net"
	"strings"
	"testing"
	"time"
)

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

// serve runs a minimal accept loop like sshserv/telserv.
func serve(ln net.Listener) {
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
}

func waitHealthy(t *testing.T, tr *Tracker) error {
	t.Helper()
	var err error
	for i := 0; i < 100; i++ {
		if err = tr.Healthy(time.Now(), 30*time.Second); err == nil {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return err
}

func TestAllListenersAcceptingIsHealthy(t *testing.T) {
	tr := NewTracker("ssh", "http")
	a := tr.Wrap("ssh")(listen(t))
	b := tr.Wrap("http")(listen(t))
	defer a.Close()
	defer b.Close()
	serve(a)
	serve(b)
	if err := waitHealthy(t, tr); err != nil {
		t.Fatalf("idle accepting listeners must be healthy: %v", err)
	}
	// traffic keeps it healthy
	c, err := net.Dial("tcp", a.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if err := waitHealthy(t, tr); err != nil {
		t.Fatal(err)
	}
}

func TestMissingListenerIsUnhealthy(t *testing.T) {
	tr := NewTracker("ssh", "telnet")
	a := tr.Wrap("ssh")(listen(t))
	defer a.Close()
	serve(a)
	time.Sleep(20 * time.Millisecond)
	err := tr.Healthy(time.Now(), 30*time.Second)
	if err == nil || !strings.Contains(err.Error(), "telnet: not listening") {
		t.Fatalf("got %v", err)
	}
}

func TestServeLoopNotStartedIsUnhealthy(t *testing.T) {
	tr := NewTracker("ssh")
	a := tr.Wrap("ssh")(listen(t))
	defer a.Close()
	if err := tr.Healthy(time.Now(), 30*time.Second); err == nil || !strings.Contains(err.Error(), "not started") {
		t.Fatalf("got %v", err)
	}
}

func TestClosedListenerIsUnhealthy(t *testing.T) {
	tr := NewTracker("ssh", "http")
	a := tr.Wrap("ssh")(listen(t))
	b := tr.Wrap("http")(listen(t))
	defer b.Close()
	serve(a)
	serve(b)
	if err := waitHealthy(t, tr); err != nil {
		t.Fatal(err)
	}
	_ = a.Close()
	time.Sleep(20 * time.Millisecond)
	err := tr.Healthy(time.Now(), 30*time.Second)
	if err == nil || !strings.Contains(err.Error(), "ssh: closed") {
		t.Fatalf("closed listener must be unhealthy, got %v", err)
	}
}

func TestInnerListenerFailureIsUnhealthy(t *testing.T) {
	// inner fd closed behind the wrapper's back (Accept returns a permanent error)
	tr := NewTracker("telnet")
	inner := listen(t)
	a := tr.Wrap("telnet")(inner)
	serve(a)
	if err := waitHealthy(t, tr); err != nil {
		t.Fatal(err)
	}
	_ = inner.Close()
	time.Sleep(20 * time.Millisecond)
	if err := tr.Healthy(time.Now(), 30*time.Second); err == nil {
		t.Fatal("accept error must mark the listener dead")
	}
}

func TestStalledServeLoopIsUnhealthy(t *testing.T) {
	tr := NewTracker("http")
	inner := listen(t)
	defer inner.Close()
	l := tr.Wrap("http")(inner).(*Listener)
	// one Accept that returns a conn, then the loop never comes back
	go func() {
		c, _ := l.Accept()
		if c != nil {
			_ = c.Close()
		}
	}()
	time.Sleep(10 * time.Millisecond)
	c, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	time.Sleep(20 * time.Millisecond)
	if err := tr.Healthy(time.Now(), 30*time.Second); err != nil {
		t.Fatalf("just returned from Accept: healthy, got %v", err)
	}
	if err := tr.Healthy(time.Now().Add(time.Minute), 30*time.Second); err == nil || !strings.Contains(err.Error(), "not back in Accept") {
		t.Fatalf("stalled loop must be unhealthy, got %v", err)
	}
}
