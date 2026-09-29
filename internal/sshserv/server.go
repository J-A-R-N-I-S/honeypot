package sshserv

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/j-a-r-n-i-s/honeypot/internal/jarnis"
	"github.com/j-a-r-n-i-s/honeypot/internal/netaddr"
	"github.com/j-a-r-n-i-s/honeypot/internal/queue"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	Addr    string
	KeyPath string
	Banner  func() string
	// Version returns the SSH identification string override (for example
	// from SSH_SERVER_VERSION). "" or an invalid value means the per-install
	// default picked from the host key (VersionForHostKey).
	Version func() string
	Report  func(queue.Event)

	mu             sync.Mutex
	listener       net.Listener
	signer         ssh.Signer
	defaultVersion string
}

// Listen loads (or creates) the host key and opens the TCP listener. It does
// not accept connections yet; call Serve for that. Splitting the two lets the
// caller open every port before doing slow work such as the config fetch.
func (s *Server) Listen() error {
	signer, secret, err := loadOrCreateHostKeySecret(s.KeyPath)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = ln
	s.signer = signer
	s.defaultVersion = VersionForSecret(secret)
	s.mu.Unlock()
	log.Printf("ssh listen %s (auth always denied, ident %q)", ln.Addr(), s.serverVersion())
	return nil
}

// Serve accepts connections on the listener opened by Listen.
func (s *Server) Serve() error {
	s.mu.Lock()
	ln, signer := s.listener, s.signer
	s.mu.Unlock()
	if ln == nil || signer == nil {
		return errors.New("sshserv: Serve called before Listen")
	}
	sem := make(chan struct{}, 64)
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		select {
		case sem <- struct{}{}:
			go func(c net.Conn) {
				defer func() { <-sem }()
				s.handle(c, signer)
			}(c)
		default:
			_ = c.Close()
		}
	}
}

func (s *Server) ListenAndServe() error {
	if err := s.Listen(); err != nil {
		return err
	}
	return s.Serve()
}

// ListenAddr is the bound address after Listen (useful with port 0).
func (s *Server) ListenAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// serverVersion is the identification string for the next connection:
// a valid override, else the per-install default, else DefaultVersion.
func (s *Server) serverVersion() string {
	if s.Version != nil {
		if v := s.Version(); v != "" && ValidVersion(v) {
			return v
		}
	}
	s.mu.Lock()
	d := s.defaultVersion
	s.mu.Unlock()
	if d != "" {
		return d
	}
	return DefaultVersion
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) handle(nc net.Conn, signer ssh.Signer) {
	defer nc.Close()
	_ = nc.SetDeadline(time.Now().Add(45 * time.Second))
	src, sport := netaddr.Split(nc.RemoteAddr().String())
	// A panic in one connection (e.g. a bug in the SSH library triggered by
	// a hostile client) must not take down the sensor: log and close.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("ssh: recovered panic in connection from %s: %v", src, r)
		}
	}()

	// Send our identification string first, before reading anything: real
	// sshd does, and banner grabbers / scanners wait for it (RFC 4253 4.2
	// allows either side to send first). x/crypto/ssh would only send it
	// after we have peeked the client's line, which stalls clients that wait
	// for the server. identSentConn drops the library's duplicate.
	version := s.serverVersion()
	line := []byte(version + "\r\n")
	if _, err := nc.Write(line); err != nil {
		return
	}

	br := bufio.NewReader(nc)
	ident := peekSSHIdent(br)
	nc = &readerConn{Conn: &identSentConn{Conn: nc, sent: line}, r: br}

	sawPassword := false
	defer func() {
		if sawPassword || s.Report == nil {
			return
		}
		raw := map[string]any{}
		if ident != "" {
			raw["clientVersion"] = ident
		}
		s.Report(queue.Event{
			Service:    "ssh",
			SourceIP:   src,
			SourcePort: sport,
			EventType:  "connection",
			Summary:    "SSH connection",
			Raw:        raw,
		})
	}()

	cfg := &ssh.ServerConfig{
		MaxAuthTries: 4,
		PasswordCallback: func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			sawPassword = true
			user := conn.User()
			ver := string(conn.ClientVersion())
			if ver == "" {
				ver = ident
			}
			if s.Report != nil {
				s.Report(queue.Event{
					Service:    "ssh",
					Username:   user,
					Password:   string(pass),
					SourceIP:   src,
					SourcePort: sport,
					SessionID:  fmt.Sprintf("%x", conn.SessionID()),
					EventType:  "login_attempt",
					Summary:    "SSH login_attempt user=" + user,
					Raw: map[string]any{
						"clientVersion": ver,
					},
				})
			}
			jarnis.Logf("ssh capture %s user=%s (denied)", src, user)
			return nil, fmt.Errorf("permission denied")
		},
		PublicKeyCallback: rejectKey,
		AuthLogCallback:   nil,
		ServerVersion:     version,
		BannerCallback: func(conn ssh.ConnMetadata) string {
			if s.Banner != nil {
				b := s.Banner()
				if b != "" && b[len(b)-1] != '\n' {
					return b + "\n"
				}
				return b
			}
			return ""
		},
	}
	cfg.AddHostKey(signer)

	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		// Handshake / auth failure is expected. Connection event via defer unless a password was seen.
		return
	}
	if v := string(conn.ClientVersion()); v != "" {
		ident = v
	}
	// If we ever got here, a future bug granted auth. Tear down immediately.
	log.Printf("ssh unexpected authenticated conn from %s user=%s — closing", src, conn.User())
	_ = conn.Close()
	go ssh.DiscardRequests(reqs)
	for ch := range chans {
		ch.Reject(ssh.Prohibited, "no")
	}
}

type readerConn struct {
	net.Conn
	r io.Reader
}

func (c *readerConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func peekSSHIdent(br *bufio.Reader) string {
	for n := 1; n <= 256; n++ {
		b, err := br.Peek(n)
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			line := strings.TrimSpace(string(b[:i]))
			if strings.HasPrefix(line, "SSH-") {
				return line
			}
			return ""
		}
		if err != nil {
			line := strings.TrimSpace(string(b))
			if strings.HasPrefix(line, "SSH-") {
				return line
			}
			return ""
		}
	}
	return ""
}

func rejectKey(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	return nil, fmt.Errorf("permission denied")
}

// loadOrCreateHostKey returns the persisted host key or creates one. It never
// fails because of the key file: an unreadable or corrupt key is moved aside
// (path + ".bad-<unix time>") and replaced, and a key that cannot be written
// is used in memory only. A returned error means key generation itself failed.
func loadOrCreateHostKey(path string) (ssh.Signer, error) {
	signer, _, err := loadOrCreateHostKeySecret(path)
	return signer, err
}

// loadOrCreateHostKeySecret is loadOrCreateHostKey that also returns the
// private key PEM (secret material for VersionForSecret).
func loadOrCreateHostKeySecret(path string) (ssh.Signer, []byte, error) {
	if path == "" {
		path = "/var/lib/jarnis-honeypot/ssh_host_ecdsa"
	}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		signer, perr := ssh.ParsePrivateKey(b)
		if perr == nil {
			return signer, b, nil
		}
		log.Printf("ssh host key %s is corrupt (%v) — keeping a backup and generating a new key", path, perr)
		backupHostKey(path)
	case errors.Is(err, fs.ErrNotExist):
		// first start
	default:
		log.Printf("ssh host key %s is unreadable (%v) — keeping a backup and generating a new key", path, err)
		backupHostKey(path)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	// Persist when possible; otherwise ephemeral key (read-only root without
	// a volume on /var/lib/jarnis-honeypot). An ephemeral key changes on every
	// container recreate, which lets scanners fingerprint the sensor.
	if err := writeFileAtomic(path, pemBytes, 0o600); err != nil {
		log.Printf("ssh host key not persisted (%v) — mount a volume on %s to keep the fingerprint across recreates", err, filepath.Dir(path))
	} else {
		log.Printf("ssh host key created at %s", path)
	}
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, nil, err
	}
	return signer, pemBytes, nil
}

// backupHostKey moves an unusable key out of the way so it is not lost and
// the replacement can be written. Best effort.
func backupHostKey(path string) {
	bak := fmt.Sprintf("%s.bad-%d", path, time.Now().Unix())
	if err := os.Rename(path, bak); err != nil {
		log.Printf("ssh host key backup %s failed: %v", bak, err)
		return
	}
	log.Printf("ssh host key backup: %s", bak)
}

// writeFileAtomic writes data to a temp file in the target directory, fsyncs
// it, renames it over path and fsyncs the directory, so a crash never leaves
// a truncated key behind.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(perm); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
