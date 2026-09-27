package sshserv

import (
	"net"
	"os"
	"path/filepath"
	"strings"
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

func TestHostKeyPersistsAcrossLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "ssh_host_ecdsa")
	a, err := loadOrCreateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := loadOrCreateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if ssh.FingerprintSHA256(a.PublicKey()) != ssh.FingerprintSHA256(b.PublicKey()) {
		t.Fatalf("host key changed between loads: %s vs %s",
			ssh.FingerprintSHA256(a.PublicKey()), ssh.FingerprintSHA256(b.PublicKey()))
	}
}

func fp(t *testing.T, s ssh.Signer) string {
	t.Helper()
	return ssh.FingerprintSHA256(s.PublicKey())
}

func TestHostKeyWriteIsAtomicNoTempLeftovers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh_host_ecdsa")
	if _, err := loadOrCreateHostKey(path); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v, want 0600", st.Mode().Perm())
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		names := []string{}
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Fatalf("unexpected files in state dir: %v", names)
	}
}

func TestHostKeyCorruptIsBackedUpAndReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh_host_ecdsa")
	garbage := []byte("not a key\n")
	if err := os.WriteFile(path, garbage, 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := loadOrCreateHostKey(path)
	if err != nil {
		t.Fatalf("corrupt key must not be fatal: %v", err)
	}
	var bak string
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "ssh_host_ecdsa.bad-") {
			bak = filepath.Join(dir, e.Name())
		}
	}
	if bak == "" {
		t.Fatal("no backup of the corrupt key")
	}
	if b, _ := os.ReadFile(bak); string(b) != string(garbage) {
		t.Fatalf("backup content changed: %q", b)
	}
	// the replacement is persisted and stable
	b, err := loadOrCreateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if fp(t, a) != fp(t, b) {
		t.Fatalf("replacement key not persisted: %s vs %s", fp(t, a), fp(t, b))
	}
}

func TestHostKeyUnreadableIsNotFatal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read mode 0000 files")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh_host_ecdsa")
	if err := os.WriteFile(path, []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	a, err := loadOrCreateHostKey(path)
	if err != nil {
		t.Fatalf("unreadable key must not be fatal: %v", err)
	}
	b, err := loadOrCreateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if fp(t, a) != fp(t, b) {
		t.Fatal("replacement for unreadable key not persisted")
	}
}

func TestHostKeyReadOnlyDirFallsBackToEphemeral(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if _, err := loadOrCreateHostKey(filepath.Join(dir, "ssh_host_ecdsa")); err != nil {
		t.Fatalf("read-only state dir must not be fatal: %v", err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 0 {
		t.Fatalf("nothing should be written to a read-only dir, got %d entries", len(ents))
	}
}
