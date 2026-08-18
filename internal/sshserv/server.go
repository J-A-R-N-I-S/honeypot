package sshserv

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/j-a-r-n-i-s/honeypot/internal/jarnis"
	"github.com/j-a-r-n-i-s/honeypot/internal/queue"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	Addr     string
	KeyPath  string
	Banner   func() string
	Report   func(queue.Event)
	mu       sync.Mutex
	listener net.Listener
}

func (s *Server) ListenAndServe() error {
	signer, err := loadOrCreateHostKey(s.KeyPath)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()
	log.Printf("ssh listen %s (auth always denied)", s.Addr)

	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(c, signer)
	}
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
	src := hostOnly(nc.RemoteAddr().String())

	cfg := &ssh.ServerConfig{
		MaxAuthTries:      4,
		PasswordCallback:  s.onPassword(src),
		PublicKeyCallback: rejectKey,
		AuthLogCallback:   nil,
		ServerVersion:     "SSH-2.0-OpenSSH_9.6",
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
		// Handshake / auth failure is expected. Do not open a session.
		return
	}
	// If we ever got here, a future bug granted auth. Tear down immediately.
	log.Printf("ssh unexpected authenticated conn from %s user=%s — closing", src, conn.User())
	_ = conn.Close()
	go ssh.DiscardRequests(reqs)
	for ch := range chans {
		ch.Reject(ssh.Prohibited, "no")
	}
}

func (s *Server) onPassword(src string) func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		user := conn.User()
		if s.Report != nil {
			s.Report(queue.Event{
				Service:   "ssh",
				Username:  user,
				Password:  string(pass),
				SourceIP:  src,
				SessionID: fmt.Sprintf("%x", conn.SessionID()),
				EventType: "login_attempt",
				Summary:   "SSH login_attempt user=" + user,
				Raw: map[string]any{
					"clientVersion": string(conn.ClientVersion()),
				},
			})
		}
		jarnis.Logf("ssh capture %s user=%s (denied)", src, user)
		return nil, fmt.Errorf("permission denied")
	}
}

func rejectKey(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	return nil, fmt.Errorf("permission denied")
}

func hostOnly(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

func loadOrCreateHostKey(path string) (ssh.Signer, error) {
	if path == "" {
		path = "/var/lib/jarnis-honeypot/ssh_host_ecdsa"
	}
	if b, err := os.ReadFile(path); err == nil {
		return ssh.ParsePrivateKey(b)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err == nil {
		_ = os.WriteFile(path, pemBytes, 0o600)
	}
	// Persist when possible; otherwise ephemeral key (read-only / scratch).
	return ssh.ParsePrivateKey(pemBytes)
}
