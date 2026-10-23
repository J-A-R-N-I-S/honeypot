package httpserv

import (
	"bytes"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/j-a-r-n-i-s/honeypot/internal/queue"
)

func n2sRun(t *testing.T, method, target string, body []byte, hdr map[string]string) queue.Event {
	t.Helper()
	var got queue.Event
	s := &Server{Report: func(ev queue.Event) { got = ev }}
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	req.RemoteAddr = "203.0.113.70:4400"
	s.handle(httptest.NewRecorder(), req)
	return got
}

func n2sKind(ev queue.Event) string {
	if ev.Raw["attack"] != "node2shell" {
		return ""
	}
	k, _ := ev.Raw["attack_kind"].(string)
	return k
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func TestNode2ShellBrotli(t *testing.T) {
	// valid-looking brotli stream ("hello" compressed), random bytes, list header
	valid := []byte{0x0b, 0x02, 0x80, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x03}
	cases := []struct {
		name, enc string
		body      []byte
	}{
		{"valid-looking", "br", valid},
		{"random", "BR", randBytes(512)},
		{"list", "gzip, br", randBytes(64)},
	}
	for _, c := range cases {
		ev := n2sRun(t, http.MethodPost, "/api/data", c.body, map[string]string{"Content-Encoding": c.enc, "Content-Type": "application/json"})
		if n2sKind(ev) != "brotli" || ev.Summary != "Node2Shell probe (brotli)" {
			t.Fatalf("%s: %+v", c.name, ev)
		}
		if ev.Raw["body_len"] != len(c.body) || len(ev.Raw["body_sha256_prefix"].(string)) != 16 || ev.Raw["content_type"] != "application/json" {
			t.Fatalf("%s raw %+v", c.name, ev.Raw)
		}
	}
	ev := n2sRun(t, http.MethodPut, "/x", randBytes(10), map[string]string{"Content-Encoding": "br"})
	if n2sKind(ev) != "brotli" {
		t.Fatalf("PUT: %+v", ev.Raw)
	}
}

func TestNode2ShellBrotliNoBody(t *testing.T) {
	ev := n2sRun(t, http.MethodPost, "/api", nil, map[string]string{"Content-Encoding": "br"})
	if n2sKind(ev) != "" {
		t.Fatalf("empty body must not match: %+v", ev.Raw)
	}
}

func TestNode2ShellBodyLimit(t *testing.T) {
	ev := n2sRun(t, http.MethodPost, "/api", randBytes(postBodyLimit*3), map[string]string{"Content-Encoding": "br"})
	if n2sKind(ev) != "brotli" || ev.Raw["body_len"].(int) > postBodyLimit {
		t.Fatalf("limit: %+v", ev.Raw)
	}
	// marker beyond 32 KiB is not seen
	big := append(bytes.Repeat([]byte("a"), postBodyLimit+10), []byte("child_process")...)
	if k := n2sKind(n2sRun(t, http.MethodPost, "/api", big, nil)); k != "" {
		t.Fatalf("marker past limit matched: %q", k)
	}
}

func TestNode2ShellSubtypes(t *testing.T) {
	cases := []struct {
		name, method, target, want string
		body                       string
		hdr                        map[string]string
	}{
		{"rsc-header", "POST", "/", "rsc", "[]", map[string]string{"Next-Action": "abc"}},
		{"rsc-tree", "GET", "/", "rsc", "", map[string]string{"Next-Router-State-Tree": "x"}},
		{"rsc-1", "GET", "/", "rsc", "", map[string]string{"RSC": "1"}},
		{"rsc-ct", "POST", "/", "rsc", "x", map[string]string{"Content-Type": "text/x-component"}},
		{"rsc-body", "POST", "/", "rsc", `{"then":"$1:__x"}`, nil},
		{"rsc-action", "POST", "/", "rsc", `$ACTION_ID_1=x`, nil},
		{"proto-query", "GET", "/?__proto__[x]=1", "proto", "", nil},
		{"proto-body", "POST", "/", "proto", `constructor[prototype][a]=1`, nil},
		{"rce", "POST", "/", "rce", `{"a":"require('child_process').execSync('id')"}`, nil},
		{"rce-main", "POST", "/", "rce", `process.mainModule`, nil},
		{"probe-next", "GET", "/_next/static/x.js", "probe", "", nil},
		{"probe-stack", "GET", "/__nextjs_original-stack-frame?f=1", "probe", "", nil},
	}
	for _, c := range cases {
		ev := n2sRun(t, c.method, c.target, []byte(c.body), c.hdr)
		if got := n2sKind(ev); got != c.want {
			t.Fatalf("%s: got %q raw %+v", c.name, got, ev.Raw)
		}
	}
}

func TestNode2ShellNegatives(t *testing.T) {
	if k := n2sKind(n2sRun(t, "POST", "/login", []byte("username=a&password=b"), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})); k != "" {
		t.Fatalf("login POST: %q", k)
	}
	if k := n2sKind(n2sRun(t, "GET", "/", nil, nil)); k != "" {
		t.Fatalf("GET /: %q", k)
	}
	if k := n2sKind(n2sRun(t, "POST", "/api", randBytes(100), map[string]string{"Content-Encoding": "gzip"})); k != "" {
		t.Fatalf("gzip: %q", k)
	}
}

func TestPHP2ShellWinsOverNode2Shell(t *testing.T) {
	body, ct := multipartBody(t, map[string]string{php2shellField: "1", "x": "child_process"})
	ev := n2sRun(t, "POST", "/", body.Bytes(), map[string]string{"Content-Type": ct})
	if ev.Raw["attack"] != "php2shell" {
		t.Fatalf("precedence: %+v", ev.Raw)
	}
}

func TestNode2ShellNeverDecompresses(t *testing.T) {
	src, err := os.ReadFile("node2shell.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`"compress/`, "andybalholm/brotli", "google/brotli", "gzip.", "flate.", "zlib.", "NewReader("} {
		if strings.Contains(string(src), bad) {
			t.Fatalf("node2shell.go must not decode: found %q", bad)
		}
	}
}

func TestNode2ShellIsLogged(t *testing.T) {
	buf := captureLog(t)
	n2sRun(t, "GET", "/_next/x", nil, nil)
	if !strings.Contains(buf.String(), `http node2shell probe kind=probe 203.0.113.70 GET path="/_next/x"`) {
		t.Fatalf("log %q", buf.String())
	}
}
