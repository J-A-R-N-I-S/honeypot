package sshserv

import (
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/j-a-r-n-i-s/honeypot/internal/queue"
	"golang.org/x/crypto/ssh"
)

func startSSH(t *testing.T, report func(queue.Event)) *Server {
	t.Helper()
	dir := t.TempDir()
	s := &Server{
		Addr:    "127.0.0.1:0",
		KeyPath: filepath.Join(dir, "hostkey"),
		Banner:  func() string { return "monitored\n" },
		Report:  report,
	}
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		t.Fatal(err)
	}
	s.listener = ln
	s.Addr = ln.Addr().String()
	signer, err := loadOrCreateHostKey(s.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(c, signer)
		}
	}()
	return s
}

func waitEvents(t *testing.T, mu *sync.Mutex, evs *[]queue.Event, n int) []queue.Event {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		if len(*evs) >= n {
			out := append([]queue.Event(nil), *evs...)
			mu.Unlock()
			return out
		}
		mu.Unlock()
		time.Sleep(15 * time.Millisecond)
	}
	mu.Lock()
	out := append([]queue.Event(nil), *evs...)
	mu.Unlock()
	return out
}

func TestSSHPasswordAlwaysDenied(t *testing.T) {
	var mu sync.Mutex
	var got []queue.Event
	s := startSSH(t, func(ev queue.Event) {
		mu.Lock()
		got = append(got, ev)
		mu.Unlock()
	})

	cfg := &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.Password("letmein")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         4 * time.Second,
	}
	_, err := ssh.Dial("tcp", s.Addr, cfg)
	if err == nil {
		t.Fatal("ssh login must never succeed")
	}
	evs := waitEvents(t, &mu, &got, 1)
	if len(evs) != 1 {
		t.Fatalf("password session must not also emit connection, got %+v", evs)
	}
	ev := evs[0]
	if ev.Username != "root" || ev.Password != "letmein" || ev.Service != "ssh" {
		t.Fatalf("capture %+v (dial err %v)", ev, err)
	}
	if ev.EventType != "login_attempt" {
		t.Fatalf("eventType %q", ev.EventType)
	}
	if ev.SourceIP == "" || ev.SourcePort < 1 {
		t.Fatalf("expected source ip/port, got %+v", ev)
	}
	if ev.Raw["clientVersion"] == "" {
		t.Fatalf("expected clientVersion in raw, got %+v", ev.Raw)
	}
}

func TestSSHHandshakeWithoutPasswordReportsConnection(t *testing.T) {
	var mu sync.Mutex
	var got []queue.Event
	s := startSSH(t, func(ev queue.Event) {
		mu.Lock()
		got = append(got, ev)
		mu.Unlock()
	})

	c, err := net.Dial("tcp", s.Addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("SSH-2.0-probeclient\r\n")); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()

	evs := waitEvents(t, &mu, &got, 1)
	if len(evs) != 1 {
		t.Fatalf("want 1 connection event, got %+v", evs)
	}
	ev := evs[0]
	if ev.EventType != "connection" || ev.Service != "ssh" {
		t.Fatalf("%+v", ev)
	}
	if ev.Username != "" || ev.Password != "" {
		t.Fatalf("connection must have empty creds: %+v", ev)
	}
	if ev.SourceIP == "" || ev.SourcePort < 1 {
		t.Fatalf("missing source %+v", ev)
	}
	if ev.Raw["clientVersion"] != "SSH-2.0-probeclient" {
		t.Fatalf("clientVersion %+v", ev.Raw)
	}
}
