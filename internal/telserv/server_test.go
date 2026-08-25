package telserv

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/j-a-r-n-i-s/honeypot/internal/queue"
)

func startTel(t *testing.T, report func(queue.Event)) *Server {
	t.Helper()
	s := &Server{
		Addr:   "127.0.0.1:0",
		Banner: func() string { return "monitored\n" },
		Report: report,
	}
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		t.Fatal(err)
	}
	s.listener = ln
	s.Addr = ln.Addr().String()
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(c)
		}
	}()
	return s
}

func waitOne(t *testing.T, mu *sync.Mutex, evs *[]queue.Event) queue.Event {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		if len(*evs) > 0 {
			ev := (*evs)[0]
			mu.Unlock()
			return ev
		}
		mu.Unlock()
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatal("timeout waiting for event")
	return queue.Event{}
}

func TestTelnetLoginAttempt(t *testing.T) {
	var mu sync.Mutex
	var got []queue.Event
	s := startTel(t, func(ev queue.Event) {
		mu.Lock()
		got = append(got, ev)
		mu.Unlock()
	})
	c, err := net.Dial("tcp", s.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 256)
	_, _ = c.Read(buf) // banner / IAC / login prompt
	if _, err := io.WriteString(c, "alice\r\n"); err != nil {
		t.Fatal(err)
	}
	_, _ = c.Read(buf)
	if _, err := io.WriteString(c, "secret\r\n"); err != nil {
		t.Fatal(err)
	}
	ev := waitOne(t, &mu, &got)
	if ev.EventType != "login_attempt" || ev.Service != "telnet" {
		t.Fatalf("%+v", ev)
	}
	if ev.Username != "alice" || ev.Password != "secret" {
		t.Fatalf("creds %+v", ev)
	}
	mu.Lock()
	n := len(got)
	mu.Unlock()
	if n != 1 {
		t.Fatalf("creds must not also emit connection, got %d events", n)
	}
}

func TestTelnetConnectWithoutCreds(t *testing.T) {
	var mu sync.Mutex
	var got []queue.Event
	s := startTel(t, func(ev queue.Event) {
		mu.Lock()
		got = append(got, ev)
		mu.Unlock()
	})
	c, err := net.Dial("tcp", s.Addr)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	ev := waitOne(t, &mu, &got)
	if ev.EventType != "connection" || ev.Service != "telnet" {
		t.Fatalf("%+v", ev)
	}
	if ev.Username != "" || ev.Password != "" {
		t.Fatalf("connection must have empty creds: %+v", ev)
	}
	if ev.SourceIP == "" || ev.SourcePort < 1 {
		t.Fatalf("missing source %+v", ev)
	}
}
