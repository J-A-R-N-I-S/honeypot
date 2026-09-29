package sshserv

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// readIdentWithoutSending connects and reads the server's first line without
// writing a single byte, the way banner grabbers do.
func readIdentWithoutSending(t *testing.T, addr string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("no identification line before the client spoke: %v (got %q)", err, line)
	}
	if !strings.HasSuffix(line, "\r\n") {
		t.Fatalf("ident line must end in CRLF: %q", line)
	}
	return strings.TrimSuffix(line, "\r\n")
}

func TestIdentSentImmediatelyOnConnect(t *testing.T) {
	const want = "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u5"
	s := startSSHWith(t, &Server{Version: func() string { return want }})
	start := time.Now()
	got := readIdentWithoutSending(t, s.Addr)
	if got != want {
		t.Fatalf("ident %q want %q", got, want)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("ident took %v", d)
	}
}

func TestIdentDefaultIsPerInstallFromPrivateKey(t *testing.T) {
	s := startSSHWith(t, &Server{})
	_, secret, err := loadOrCreateHostKeySecret(s.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	pemOnDisk, _ := os.ReadFile(s.KeyPath)
	if !bytes.Equal(secret, pemOnDisk) {
		t.Fatal("secret must be the persisted private key")
	}
	want := VersionForSecret(secret)
	if got := readIdentWithoutSending(t, s.Addr); got != want {
		t.Fatalf("ident %q want per-install default %q", got, want)
	}
}

func TestIdentInvalidOverrideFallsBackToDefault(t *testing.T) {
	s := startSSHWith(t, &Server{Version: func() string { return "OpenSSH_9.6 no prefix" }})
	got := readIdentWithoutSending(t, s.Addr)
	if !ValidVersion(got) || !contains(DefaultVersions, got) {
		t.Fatalf("invalid override must fall back to a default, got %q", got)
	}
}

// The early ident must not break the handshake: key exchange signs the
// server version, so a duplicate or mismatching line would fail kex.
func TestHandshakeCompletesAfterEarlyIdent(t *testing.T) {
	const want = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
	s := startSSHWith(t, &Server{Version: func() string { return want }})
	var sawKey, sawBanner bool
	cfg := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{ssh.Password("x")},
		HostKeyCallback: func(string, net.Addr, ssh.PublicKey) error {
			sawKey = true
			return nil
		},
		BannerCallback: func(string) error { sawBanner = true; return nil },
		Timeout:        4 * time.Second,
	}
	_, err := ssh.Dial("tcp", s.Addr, cfg)
	if err == nil {
		t.Fatal("auth must be denied")
	}
	if !strings.Contains(err.Error(), "unable to authenticate") {
		t.Fatalf("want auth failure after a completed kex, got %v", err)
	}
	if !sawKey || !sawBanner {
		t.Fatalf("handshake incomplete: hostkey=%v banner=%v", sawKey, sawBanner)
	}
}

func TestValidVersion(t *testing.T) {
	for _, v := range DefaultVersions {
		if !ValidVersion(v) {
			t.Errorf("default %q invalid", v)
		}
	}
	bad := []string{
		"",
		"SSH-2.0-",
		"SSH-1.99-OpenSSH_9.6",
		"OpenSSH_9.6",
		"SSH-2.0-Open-SSH",
		"SSH-2.0-OpenSSH_9.6\r\nX",
		"SSH-2.0-OpenSSH_9.6\x00",
		"SSH-2.0-OpenSSH_9.6 \xc3\xa4",
		"SSH-2.0-" + strings.Repeat("a", 250),
	}
	for _, v := range bad {
		if ValidVersion(v) {
			t.Errorf("%q must be invalid", v)
		}
	}
	if !ValidVersion("SSH-2.0-OpenSSH_9.6") {
		t.Error("comment-less ident must be valid")
	}
}

func TestVersionForSecretDeterministicAndVaried(t *testing.T) {
	if VersionForSecret(nil) != DefaultVersion {
		t.Fatal("no secret must give DefaultVersion")
	}
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			t.Fatal(err)
		}
		v := VersionForSecret(secret)
		if v != VersionForSecret(append([]byte(nil), secret...)) {
			t.Fatal("not deterministic")
		}
		if !contains(DefaultVersions, v) {
			t.Fatalf("%q not in DefaultVersions", v)
		}
		seen[v] = true
	}
	if len(seen) < 3 {
		t.Fatalf("64 secrets mapped to only %v", seen)
	}
}

// The choice must depend on the private key: two keys with the same public
// half do not exist, so check instead that the public key alone is not the
// HMAC input (a scanner only sees the public key).
func TestVersionNotDerivedFromPublicKey(t *testing.T) {
	signer, secret, err := loadOrCreateHostKeySecret(filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(secret, signer.PublicKey().Marshal()) {
		t.Fatal("secret must be the private key PEM, not public key bytes")
	}
	if !strings.Contains(string(secret), "PRIVATE KEY") {
		t.Fatalf("secret is not a private key PEM")
	}
}

func TestIdentSentConnDropsOnlyTheDuplicate(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	line := []byte("SSH-2.0-X\r\n")
	c := &identSentConn{Conn: a, sent: line}
	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := b.Read(buf)
		got <- buf[:n]
	}()
	if n, err := c.Write(line); err != nil || n != len(line) {
		t.Fatalf("duplicate write n=%d err=%v", n, err)
	}
	if _, err := c.Write([]byte("next")); err != nil {
		t.Fatal(err)
	}
	if g := <-got; !bytes.Equal(g, []byte("next")) {
		t.Fatalf("peer got %q", g)
	}
	// A different first write passes through.
	a2, b2 := net.Pipe()
	defer a2.Close()
	defer b2.Close()
	c2 := &identSentConn{Conn: a2, sent: line}
	go func() {
		buf := make([]byte, 64)
		n, _ := b2.Read(buf)
		got <- buf[:n]
	}()
	if _, err := c2.Write([]byte("other")); err != nil {
		t.Fatal(err)
	}
	if g := <-got; !bytes.Equal(g, []byte("other")) {
		t.Fatalf("peer got %q", g)
	}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func TestPanicInConnectionIsRecovered(t *testing.T) {
	var calls atomic.Int32
	s := startSSHWith(t, &Server{Banner: func() string {
		if calls.Add(1) == 1 {
			panic("boom")
		}
		return "ok\n"
	}})
	cfg := &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.Password("x")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         4 * time.Second,
	}
	_, _ = ssh.Dial("tcp", s.Addr, cfg) // panics server-side, must be recovered
	// The listener still serves.
	if got := readIdentWithoutSending(t, s.Addr); !strings.HasPrefix(got, "SSH-2.0-") {
		t.Fatalf("server gone after panic: %q", got)
	}
	if calls.Load() < 1 {
		t.Fatal("banner callback (panic) never ran")
	}
}
