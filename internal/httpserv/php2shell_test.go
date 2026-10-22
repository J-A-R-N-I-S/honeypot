package httpserv

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/j-a-r-n-i-s/honeypot/internal/queue"
)

func multipartBody(t *testing.T, fields map[string]string) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range fields {
		fw, err := w.CreateFormField(k)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(fw, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf, w.FormDataContentType()
}

func TestPHP2ShellMultipartIsTagged(t *testing.T) {
	var got queue.Event
	s := &Server{Report: func(ev queue.Event) { got = ev }}
	body, ct := multipartBody(t, map[string]string{php2shellField: "1"})
	req := httptest.NewRequest(http.MethodPost, "/login", body)
	req.Header.Set("Content-Type", ct)
	req.RemoteAddr = "203.0.113.40:4400"
	rr := httptest.NewRecorder()
	s.handle(rr, req)
	if got.EventType != "connection" || got.Summary != "PHP2Shell probe" {
		t.Fatalf("event %+v", got)
	}
	if got.Raw["attack"] != "php2shell" || got.Raw["method"] != "POST" || got.Raw["path"] != "/login" {
		t.Fatalf("raw %+v", got.Raw)
	}
	if got.Username != "" || got.Password != "" {
		t.Fatalf("must not invent credentials: %+v", got)
	}
	if len(got.Raw) != 3 {
		t.Fatalf("body must not be stored: %+v", got.Raw)
	}
	if strings.Contains(rr.Body.String(), php2shellField) {
		t.Fatal("response echoed the field name")
	}
}

func TestPHP2ShellDoesNotKeepFieldValue(t *testing.T) {
	var got queue.Event
	s := &Server{Report: func(ev queue.Event) { got = ev }}
	body, ct := multipartBody(t, map[string]string{
		"username":     "admin",
		php2shellField: "1",
	})
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", ct)
	req.RemoteAddr = "203.0.113.41:4401"
	s.handle(httptest.NewRecorder(), req)
	if got.Summary != "PHP2Shell probe" || got.Raw["attack"] != "php2shell" {
		t.Fatalf("tag %+v summary %q", got.Raw, got.Summary)
	}
	if got.Username != "" || got.Password != "" {
		t.Fatalf("field value stored as credentials: %+v", got)
	}
	if len(got.Raw) != 3 {
		t.Fatalf("raw %+v", got.Raw)
	}
}

func TestURLEncodedFieldIsNotPHP2Shell(t *testing.T) {
	var got queue.Event
	s := &Server{Report: func(ev queue.Event) { got = ev }}
	form := url.Values{php2shellField: {"1"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.42:4402"
	s.handle(httptest.NewRecorder(), req)
	if got.EventType != "connection" || got.Summary != "HTTP connection POST /login" {
		t.Fatalf("%+v", got)
	}
	if _, ok := got.Raw["attack"]; ok {
		t.Fatalf("urlencoded must not be tagged: %+v", got.Raw)
	}
}

func TestOrdinaryMultipartIsNotTagged(t *testing.T) {
	var got queue.Event
	s := &Server{Report: func(ev queue.Event) { got = ev }}
	body, ct := multipartBody(t, map[string]string{"note": "hello"})
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", ct)
	req.RemoteAddr = "203.0.113.43:4403"
	s.handle(httptest.NewRecorder(), req)
	if _, ok := got.Raw["attack"]; ok || got.Summary == "PHP2Shell probe" {
		t.Fatalf("plain multipart tagged: %+v", got)
	}
}
