package httpserv

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jarnis/honeypot/internal/jarnis"
	"github.com/jarnis/honeypot/internal/queue"
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
	if got.SourceIP != "203.0.113.9" {
		t.Fatalf("source ip %q", got.SourceIP)
	}
}

func TestHealthzSilent(t *testing.T) {
	called := false
	_ = &Server{Report: func(queue.Event) { called = true }}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok\n"))
	})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if called {
		t.Fatal("healthz must not report")
	}
	if rr.Body.String() != "ok\n" {
		t.Fatalf("body %q", rr.Body.String())
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
