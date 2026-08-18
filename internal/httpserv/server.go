package httpserv

import (
	"crypto/sha1"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/j-a-r-n-i-s/honeypot/internal/jarnis"
	"github.com/j-a-r-n-i-s/honeypot/internal/queue"
)

type Server struct {
	Addr     string
	Designs  func() []jarnis.Design
	Mode     func() string
	Report   func(queue.Event)
	rr       atomic.Uint64
	server   *http.Server
}

func (s *Server) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handle)
	s.server = &http.Server{
		Addr:              s.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 8 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	log.Printf("http listen %s (no real sessions)", s.Addr)
	return s.server.ListenAndServe()
}

func (s *Server) Close() error {
	if s.server != nil {
		return s.server.Close()
	}
	return nil
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	src := hostOnly(r.RemoteAddr)

	user, pass := extractCreds(r)
	if r.Method == http.MethodPost || user != "" || pass != "" {
		if s.Report != nil {
			s.Report(queue.Event{
				Service:   "http",
				Username:  user,
				Password:  pass,
				SourceIP:  src,
				UserAgent: clip(r.UserAgent(), 400),
				EventType: "login_attempt",
				Summary:   "HTTP login_attempt user=" + user,
				Raw: map[string]any{
					"path":   r.URL.Path,
					"method": r.Method,
				},
			})
		}
		jarnis.Logf("http capture %s user=%s path=%s (denied)", src, user, r.URL.Path)
	}

	page := s.pageFor(src)
	if r.Method == http.MethodPost || user != "" {
		page = injectError(page)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	// Never set a session cookie.
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, page)
	}
}

func extractCreds(r *http.Request) (user, pass string) {
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(nil, r.Body, 32<<10)
		_ = r.ParseForm()
	}
	form := r.Form
	if form == nil {
		form = r.URL.Query()
	}
	user = first(form, "username", "user", "email", "login", "userid", "account")
	pass = first(form, "password", "pass", "passwd", "pwd")
	if u, p, ok := r.BasicAuth(); ok {
		if user == "" {
			user = u
		}
		if pass == "" {
			pass = p
		}
	}
	return clip(user, 200), clip(pass, 200)
}

func first(v map[string][]string, keys ...string) string {
	for _, k := range keys {
		if xs := v[k]; len(xs) > 0 && xs[0] != "" {
			return xs[0]
		}
	}
	return ""
}

func (s *Server) pageFor(ip string) string {
	var designs []jarnis.Design
	if s.Designs != nil {
		designs = s.Designs()
	}
	if len(designs) == 0 {
		return defaultPage()
	}
	idx := 0
	mode := "sticky-per-ip"
	if s.Mode != nil {
		mode = strings.ToLower(s.Mode())
	}
	switch mode {
	case "round-robin":
		idx = int(s.rr.Add(1)-1) % len(designs)
	case "random":
		idx = int(s.rr.Add(1)-1) % len(designs)
	default:
		sum := sha1.Sum([]byte(ip))
		idx = int(sum[0]) % len(designs)
	}
	d := designs[idx]
	html := d.HTMLContent
	if html == "" {
		html = defaultPage()
	}
	if d.CSSContent != "" && !strings.Contains(html, d.CSSContent) {
		html = injectCSS(html, d.CSSContent)
	}
	return html
}

func injectCSS(html, css string) string {
	tag := "<style>" + css + "</style>"
	if i := strings.Index(strings.ToLower(html), "</head>"); i >= 0 {
		return html[:i] + tag + html[i:]
	}
	return tag + html
}

func injectError(html string) string {
	msg := `<p style="color:#b91c1c;font:14px/1.4 system-ui,sans-serif;margin:12px 0">Sign-in failed. Check your credentials and try again.</p>`
	low := strings.ToLower(html)
	if i := strings.Index(low, "<form"); i >= 0 {
		return html[:i] + msg + html[i:]
	}
	if i := strings.Index(low, "<body"); i >= 0 {
		if j := strings.Index(html[i:], ">"); j >= 0 {
			at := i + j + 1
			return html[:at] + msg + html[at:]
		}
	}
	return msg + html
}

func defaultPage() string {
	return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0f0f1a;color:#fff;font-family:system-ui,sans-serif}
.card{width:min(22rem,92vw);background:#171728;border:1px solid #ffffff22;border-radius:1.25rem;padding:1.5rem}
label{display:block;font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:#ffffff73;margin:12px 0 6px}
input{width:100%;box-sizing:border-box;border-radius:12px;border:1px solid #ffffff26;background:#ffffff0d;color:#fff;padding:10px 12px}
button{margin-top:16px;width:100%;border:0;border-radius:12px;padding:12px;font-weight:600;color:#fff;background:linear-gradient(180deg,#7c3aed,#5b21b6);cursor:pointer}
h1{margin:0 0 4px;font-size:1.25rem}p{margin:0 0 8px;color:#ffffff8a;font-size:.9rem}</style></head>
<body><div class="card"><h1>Sign in</h1><p>Enter your credentials to continue</p>
<form method="post" action="/login"><label>Username</label><input name="username" autocomplete="username">
<label>Password</label><input name="password" type="password" autocomplete="current-password">
<button type="submit">Sign in</button></form></div></body></html>`
}

func hostOnly(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Escape is available if templates ever interpolate attacker text into HTML.
func Escape(s string) string { return html.EscapeString(s) }
