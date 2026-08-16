package sshserv

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/jarnis/honeypot/internal/queue"
	"golang.org/x/crypto/ssh"
)

func TestSSHPasswordAlwaysDenied(t *testing.T) {
	dir := t.TempDir()
	var got queue.Event
	s := &Server{
		Addr:    "127.0.0.1:0",
		KeyPath: filepath.Join(dir, "hostkey"),
		Banner:  func() string { return "monitored\n" },
		Report:  func(ev queue.Event) { got = ev },
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
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		s.handle(c, signer)
	}()

	cfg := &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.Password("letmein")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         4 * time.Second,
	}
	_, err = ssh.Dial("tcp", s.Addr, cfg)
	if err == nil {
		t.Fatal("ssh login must never succeed")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && got.Username == "" {
		time.Sleep(20 * time.Millisecond)
	}
	if got.Username != "root" || got.Password != "letmein" || got.Service != "ssh" {
		t.Fatalf("capture %+v (dial err %v)", got, err)
	}
}
