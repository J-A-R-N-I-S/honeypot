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
	defer func() {
		if r := recover(); r != nil {
			log.Printf("telnet: recovered panic in connection from %s: %v", src, r)
		}
	}()

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
	// One reader per connection: bots pipeline "user\r\npass\r\n", and a
	// fresh bufio.Reader per line would drop the buffered password.
	lr := &lineReader{r: bufio.NewReader(c)}
	user, err := lr.readLine()
	if err != nil {
		return
	}
	_, _ = io.WriteString(c, "Password: ")
	pass, err := lr.readLine()
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
	jarnis.Logf("telnet capture %s user=%q (denied)", src, user)
	time.Sleep(400 * time.Millisecond)
	_, _ = io.WriteString(c, "\r\nLogin incorrect\r\n")
}

// lineReader reads telnet lines. It understands the parts of RFC 854 that
// clients actually send before the login: option negotiation (IAC
// WILL/WONT/DO/DONT x), subnegotiation (IAC SB ... IAC SE, e.g. terminal
// type), escaped IAC IAC, and all three line endings: CR LF, CR NUL, LF.
type lineReader struct {
	r       *bufio.Reader
	afterCR bool // swallow the LF/NUL that follows a CR ending a line
}

const (
	se = 240
	sb = 250

	maxSubnegotiation = 1024
)

func (lr *lineReader) readLine() (string, error) {
	var b strings.Builder
	for {
		by, err := lr.r.ReadByte()
		if err != nil {
			return strings.TrimSpace(b.String()), err
		}
		if lr.afterCR {
			lr.afterCR = false
			if by == '\n' || by == 0 {
				continue
			}
		}
		if by == iac {
			if err := lr.skipCommand(); err != nil {
				return "", err
			}
			continue
		}
		if by == '\n' {
			break
		}
		if by == '\r' {
			lr.afterCR = true
			break
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

// skipCommand consumes the rest of a command after IAC.
func (lr *lineReader) skipCommand() error {
	cmd, err := lr.r.ReadByte()
	if err != nil {
		return err
	}
	switch cmd {
	case will, wont, do, dont:
		_, err = lr.r.ReadByte()
		return err
	case sb:
		// Skip to IAC SE; IAC IAC inside is an escaped data byte. Bounded so
		// a client cannot keep us in here forever.
		for n := 0; n < maxSubnegotiation; n++ {
			c, err := lr.r.ReadByte()
			if err != nil {
				return err
			}
			if c != iac {
				continue
			}
			c, err = lr.r.ReadByte()
			if err != nil {
				return err
			}
			if c == se {
				return nil
			}
		}
		return nil
	default:
		// IAC IAC (escaped 0xFF, not printable), NOP, GA, AYT, ...: ignore.
		return nil
	}
}
