package telserv

import (
	"bufio"
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/j-a-r-n-i-s/honeypot/internal/jarnis"
	"github.com/j-a-r-n-i-s/honeypot/internal/netaddr"
	"github.com/j-a-r-n-i-s/honeypot/internal/queue"
)

const (
	iac  = 255
	dont = 254
	do   = 253
	wont = 252
	will = 251
	echo = 1
)

type Server struct {
	Addr     string
	Banner   func() string
	Report   func(queue.Event)
	mu       sync.Mutex
	listener net.Listener
}

// Listen opens the TCP listener without accepting yet (see Serve).
func (s *Server) Listen() error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()
	log.Printf("telnet listen %s (auth always denied)", ln.Addr())
	return nil
}

// Serve accepts connections on the listener opened by Listen.
func (s *Server) Serve() error {
	s.mu.Lock()
	ln := s.listener
	s.mu.Unlock()
	if ln == nil {
		return errors.New("telserv: Serve called before Listen")
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
				s.handle(c)
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

// ListenAddr is the bound address after Listen.
func (s *Server) ListenAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	src, sport := netaddr.Split(c.RemoteAddr().String())

	captured := false
	defer func() {
		if captured || s.Report == nil {
			return
		}
		s.Report(queue.Event{
			Service:    "telnet",
			SourceIP:   src,
			SourcePort: sport,
			EventType:  "connection",
			Summary:    "TELNET connection",
		})
	}()

	// Refuse option negotiation; never enable a real terminal session.
	_, _ = c.Write([]byte{iac, wont, echo, iac, dont, echo})

	banner := ""
	if s.Banner != nil {
		banner = s.Banner()
	}
	if banner != "" {
		if !strings.HasSuffix(banner, "\n") {
			banner += "\r\n"
		} else {
			banner = strings.ReplaceAll(banner, "\n", "\r\n")
		}
		_, _ = io.WriteString(c, banner)
	}
	_, _ = io.WriteString(c, "login: ")
	user, err := readLine(c)
	if err != nil {
		return
	}
	_, _ = io.WriteString(c, "Password: ")
	pass, err := readLine(c)
	if err != nil {
		return
	}
	captured = true
	if s.Report != nil {
		s.Report(queue.Event{
			Service:    "telnet",
			Username:   user,
			Password:   pass,
			SourceIP:   src,
			SourcePort: sport,
			EventType:  "login_attempt",
			Summary:    "TELNET login_attempt user=" + user,
		})
	}
	jarnis.Logf("telnet capture %s user=%s (denied)", src, user)
	time.Sleep(400 * time.Millisecond)
	_, _ = io.WriteString(c, "\r\nLogin incorrect\r\n")
}

func readLine(c net.Conn) (string, error) {
	r := bufio.NewReader(c)
	var b strings.Builder
	for {
		by, err := r.ReadByte()
		if err != nil {
			return strings.TrimSpace(b.String()), err
		}
		if by == iac {
			cmd, err := r.ReadByte()
			if err != nil {
				return "", err
			}
			if cmd == will || cmd == wont || cmd == do || cmd == dont {
				_, _ = r.ReadByte()
			}
			continue
		}
		if by == '\n' {
			break
		}
		if by == '\r' {
			continue
		}
		if by == 0x7f || by == 0x08 {
			s := b.String()
			if s != "" {
				b.Reset()
				b.WriteString(s[:len(s)-1])
			}
			continue
		}
		if by >= 32 && by < 127 && b.Len() < 200 {
			b.WriteByte(by)
		}
	}
	return strings.TrimSpace(b.String()), nil
}
