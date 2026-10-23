package httpserv

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/j-a-r-n-i-s/honeypot/internal/queue"
)

// captureLog redirects the std logger for one test (P28).
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

func TestPlainHTTPHitIsLogged(t *testing.T) {
	buf := captureLog(t)
	s := &Server{Report: func(queue.Event) {}}
	req := httptest.NewRequest(http.MethodGet, "/wp-login.php", nil)
	req.Header.Set("User-Agent", "zgrab/0.x")
	req.RemoteAddr = "203.0.113.50:5000"
	s.handle(httptest.NewRecorder(), req)
	out := buf.String()
	if !strings.Contains(out, `http hit 203.0.113.50 GET path="/wp-login.php" ua="zgrab/0.x"`) {
		t.Fatalf("plain hit not logged: %q", out)
	}
}

func TestHTTPHitLoggedWithoutReporter(t *testing.T) {
	buf := captureLog(t)
	s := &Server{}
	req := httptest.NewRequest(http.MethodHead, "/", nil)
	req.RemoteAddr = "203.0.113.51:1"
	s.handle(httptest.NewRecorder(), req)
	if !strings.Contains(buf.String(), "http hit 203.0.113.51 HEAD") {
		t.Fatalf("hit must be logged even with no backhaul: %q", buf.String())
	}
}

func TestDisallowedMethodIsLogged(t *testing.T) {
	buf := captureLog(t)
	s := &Server{Report: func(queue.Event) {}}
	req := httptest.NewRequest(http.MethodPut, "/x", nil)
	req.RemoteAddr = "203.0.113.52:1"
	rr := httptest.NewRecorder()
	s.handle(rr, req)
	if rr.Code != http.StatusMethodNotAllowed || !strings.Contains(buf.String(), "http hit 203.0.113.52 PUT") {
		t.Fatalf("code %d log %q", rr.Code, buf.String())
	}
}

func TestPHP2ShellProbeIsLogged(t *testing.T) {
	buf := captureLog(t)
	s := &Server{Report: func(queue.Event) {}}
	body, ct := multipartBody(t, map[string]string{php2shellField: "1"})
	req := httptest.NewRequest(http.MethodPost, "/index.php", body)
	req.Header.Set("Content-Type", ct)
	req.RemoteAddr = "203.0.113.53:4400"
	s.handle(httptest.NewRecorder(), req)
	out := buf.String()
	if !strings.Contains(out, `http php2shell probe 203.0.113.53 POST path="/index.php"`) {
		t.Fatalf("php2shell probe not logged: %q", out)
	}
	if strings.Contains(out, "http hit") {
		t.Fatalf("php2shell must be logged once, as probe: %q", out)
	}
}

func TestCaptureLogNeverContainsPassword(t *testing.T) {
	buf := captureLog(t)
	s := &Server{Report: func(queue.Event) {}}
	form := url.Values{"username": {"admin"}, "password": {"s3cr3t-pw"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.54:1"
	s.handle(httptest.NewRecorder(), req)
	out := buf.String()
	if !strings.Contains(out, `http capture 203.0.113.54 user="admin"`) || strings.Contains(out, "s3cr3t-pw") {
		t.Fatalf("capture log %q", out)
	}
	if strings.Count(strings.TrimRight(out, "\n"), "\n") != 0 {
		t.Fatalf("exactly one line per request: %q", out)
	}
}

func TestHitLogIsSingleLineAndClipped(t *testing.T) {
	buf := captureLog(t)
	s := &Server{Report: func(queue.Event) {}}
	req := httptest.NewRequest(http.MethodGet, "/a%0aFORGED/"+strings.Repeat("x", 500), nil)
	req.Header.Set("User-Agent", "ua\r\nFORGED "+strings.Repeat("y", 500))
	req.RemoteAddr = "203.0.113.55:1"
	s.handle(httptest.NewRecorder(), req)
	out := strings.TrimRight(buf.String(), "\n")
	if strings.Contains(out, "\n") || len(out) > 600 {
		t.Fatalf("log injection / unclipped: %d %q", len(out), out)
	}
}

func TestCaptureLogClipsUserTo64(t *testing.T) {
	buf := captureLog(t)
	var got queue.Event
	s := &Server{Report: func(ev queue.Event) { got = ev }}
	long := strings.Repeat("u", 64) + "TAIL-NOT-LOGGED"
	form := url.Values{"username": {long}, "password": {"x"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.56:1"
	s.handle(httptest.NewRecorder(), req)
	out := buf.String()
	if !strings.Contains(out, `user="`+strings.Repeat("u", 64)+`"`) || strings.Contains(out, "TAIL-NOT-LOGGED") {
		t.Fatalf("user must be clipped to 64 in the log: %q", out)
	}
	if got.Username != long {
		t.Fatalf("report to JARNIS keeps the full username, got %q", got.Username)
	}
}
