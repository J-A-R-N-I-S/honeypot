package telserv

import (
	"bufio"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/j-a-r-n-i-s/honeypot/internal/jarnis"
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

func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()
	log.Printf("telnet listen %s (auth always denied)", s.Addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(c)
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

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	src := hostOnly(c.RemoteAddr().String())

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
	if s.Report != nil {
		s.Report(queue.Event{
			Service:   "telnet",
			Username:  user,
			Password:  pass,
			SourceIP:  src,
			EventType: "login_attempt",
			Summary:   "TELNET login_attempt user=" + user,
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

func hostOnly(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}
