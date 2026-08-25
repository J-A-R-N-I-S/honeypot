package httpserv

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/j-a-r-n-i-s/honeypot/internal/jarnis"
	"github.com/j-a-r-n-i-s/honeypot/internal/queue"
)

func TestLoginNeverGrantsSession(t *testing.T) {
	var got queue.Event
	s := &Server{
		Designs: func() []jarnis.Design { return nil },
		Mode:    func() string { return "sticky-per-ip" },
		Report:  func(ev queue.Event) { got = ev },
	}
	form := url.Values{"username": {"admin"}, "password": {"hunter2"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.9:5555"
	rr := httptest.NewRecorder()
	s.handle(rr, req)
	res := rr.Result()
	if res.Header.Get("Set-Cookie") != "" {
		t.Fatalf("must not set session cookie")
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Sign-in failed") {
		t.Fatalf("expected failure message, got %q", body[:min(200, len(body))])
	}
	if got.Username != "admin" || got.Password != "hunter2" || got.Service != "http" {
		t.Fatalf("capture mismatch: %+v", got)
	}
	if got.EventType != "login_attempt" {
		t.Fatalf("POST creds must stay login_attempt, got %q", got.EventType)
	}
	if got.SourceIP != "203.0.113.9" {
		t.Fatalf("source ip %q", got.SourceIP)
	}
	if got.SourcePort != 5555 {
		t.Fatalf("source port %d", got.SourcePort)
	}
}

func TestIgnoresForwardedFor(t *testing.T) {
	var got queue.Event
	s := &Server{Report: func(ev queue.Event) { got = ev }}
	form := url.Values{"username": {"x"}, "password": {"y"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.RemoteAddr = "203.0.113.9:5555"
	s.handle(httptest.NewRecorder(), req)
	if got.SourceIP != "203.0.113.9" {
		t.Fatalf("xff must be ignored, got %q", got.SourceIP)
	}
	if got.SourcePort != 5555 {
		t.Fatalf("source port %d", got.SourcePort)
	}
}

func TestHealthzSilent(t *testing.T) {
	var got queue.Event
	s := &Server{Report: func(ev queue.Event) { got = ev }}
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.RemoteAddr = "203.0.113.9:1"
	rr := httptest.NewRecorder()
	s.handle(rr, req)
	if got.EventType == "login_attempt" {
		t.Fatal("GET /healthz must not report a login")
	}
	if got.EventType != "connection" || got.Service != "http" {
		t.Fatalf("GET /healthz should report connection, got %+v", got)
	}
	if got.Username != "" || got.Password != "" {
		t.Fatalf("connection must have empty creds: %+v", got)
	}
	if got.Raw["method"] != "GET" || got.Raw["path"] != "/healthz" {
		t.Fatalf("raw %+v", got.Raw)
	}
}

func TestHTTPHeadConnection(t *testing.T) {
	var got queue.Event
	s := &Server{Report: func(ev queue.Event) { got = ev }}
	req := httptest.NewRequest(http.MethodHead, "/", nil)
	req.RemoteAddr = "203.0.113.9:9"
	s.handle(httptest.NewRecorder(), req)
	if got.EventType != "connection" || got.SourcePort != 9 {
		t.Fatalf("%+v", got)
	}
}

func TestHTTPPostWithoutCredsIsConnection(t *testing.T) {
	var got queue.Event
	s := &Server{Report: func(ev queue.Event) { got = ev }}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("foo=bar"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.9:8"
	s.handle(httptest.NewRecorder(), req)
	if got.EventType != "connection" || got.Username != "" {
		t.Fatalf("POST without creds should be connection, got %+v", got)
	}
}

func TestStickyDesign(t *testing.T) {
	s := &Server{
		Designs: func() []jarnis.Design {
			return []jarnis.Design{
				{ID: "a", HTMLContent: "PAGE-A"},
				{ID: "b", HTMLContent: "PAGE-B"},
			}
		},
		Mode: func() string { return "sticky-per-ip" },
	}
	p1 := s.pageFor("1.1.1.1")
	p2 := s.pageFor("1.1.1.1")
	if p1 != p2 {
		t.Fatal("sticky-per-ip must be stable")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
