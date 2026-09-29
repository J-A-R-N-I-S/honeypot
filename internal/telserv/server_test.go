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

// Bots send username and password in one segment; both must be captured.
func TestTelnetPipelinedCredentials(t *testing.T) {
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
	if _, err := io.WriteString(c, "bob\r\nhunter2\r\n"); err != nil {
		t.Fatal(err)
	}
	ev := waitOne(t, &mu, &got)
	if ev.EventType != "login_attempt" || ev.Username != "bob" || ev.Password != "hunter2" {
		t.Fatalf("%+v", ev)
	}
}

func TestTelnetPanicIsRecovered(t *testing.T) {
	s := &Server{Addr: "127.0.0.1:0", Banner: func() string { panic("boom") }}
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	go func() { _ = s.Serve() }()
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", s.ListenAddr().String())
		if err != nil {
			t.Fatalf("listener gone after panic: %v", err)
		}
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.ReadAll(c) // server closes after recovering
		_ = c.Close()
	}
}

func telnetCapture(t *testing.T, input []byte) queue.Event {
	t.Helper()
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
	if _, err := c.Write(input); err != nil {
		t.Fatal(err)
	}
	return waitOne(t, &mu, &got)
}

func TestTelnetLineEndingsAndNegotiation(t *testing.T) {
	const IAC, SB, SE, WILL, DO = 255, 250, 240, 251, 253
	cases := map[string][]byte{
		"CR NUL":  []byte("bob\r\x00hunter2\r\x00"),
		"bare CR": []byte("bob\rhunter2\r"),
		"LF":      []byte("bob\nhunter2\n"),
		"SB terminal type": append(append([]byte{IAC, WILL, 24, IAC, SB, 24, 0},
			[]byte("xterm-256color")...), append([]byte{IAC, SE, IAC, DO, 1}, []byte("bob\r\nhunter2\r\n")...)...),
		"SB with escaped IAC": append([]byte{IAC, SB, 31, 0, IAC, IAC, 0, 24, IAC, SE}, []byte("bob\r\nhunter2\r\n")...),
		"IAC IAC in data":     append([]byte("bo"), append([]byte{IAC, IAC}, []byte("b\r\nhunter2\r\n")...)...),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			ev := telnetCapture(t, in)
			if ev.EventType != "login_attempt" || ev.Username != "bob" || ev.Password != "hunter2" {
				t.Fatalf("%+v", ev)
			}
		})
	}
}

func TestTelnetEndlessSubnegotiationIsBounded(t *testing.T) {
	in := append([]byte{255, 250, 24}, make([]byte, 5000)...)
	in = append(in, []byte("\r\nbob\r\nhunter2\r\n")...)
	ev := telnetCapture(t, in)
	if ev.EventType != "login_attempt" {
		t.Fatalf("%+v", ev)
	}
}
