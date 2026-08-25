package probe

import (
	"strings"
	"testing"
	"time"

	"github.com/j-a-r-n-i-s/honeypot/internal/queue"
)

type step struct {
	offset    time.Duration
	service   string
	ip        string
	eventType string
	user      string
	pass      string
	wantTypes []string
}

func TestRateLimitAndScanWindow(t *testing.T) {
	cases := []struct {
		name  string
		steps []step
	}{
		{
			name: "second connection same ip+service dropped within a minute",
			steps: []step{
				{0, "ssh", "203.0.113.10", "connection", "", "", []string{"connection"}},
				{30 * time.Second, "ssh", "203.0.113.10", "connection", "", "", nil},
				{time.Minute, "ssh", "203.0.113.10", "connection", "", "", []string{"connection"}},
			},
		},
		{
			name: "login_attempt never rate-limited",
			steps: []step{
				{0, "ssh", "203.0.113.11", "login_attempt", "root", "x", []string{"login_attempt"}},
				{time.Second, "ssh", "203.0.113.11", "login_attempt", "root", "y", []string{"login_attempt"}},
				{2 * time.Second, "ssh", "203.0.113.11", "login_attempt", "admin", "z", []string{"login_attempt"}},
			},
		},
		{
			name: "connection after login_attempt same service still allowed",
			steps: []step{
				{0, "http", "203.0.113.12", "login_attempt", "u", "p", []string{"login_attempt"}},
				{time.Second, "http", "203.0.113.12", "connection", "", "", []string{"connection"}},
			},
		},
		{
			name: "different IPs do not share a rate-limit bucket",
			steps: []step{
				{0, "ssh", "203.0.113.13", "connection", "", "", []string{"connection"}},
				{time.Second, "ssh", "203.0.113.14", "connection", "", "", []string{"connection"}},
			},
		},
		{
			name: "two distinct bait services within 60s become scan",
			steps: []step{
				{0, "ssh", "198.51.100.1", "connection", "drop-me", "drop-me", []string{"connection"}},
				{10 * time.Second, "http", "198.51.100.1", "connection", "drop-me", "drop-me", []string{"scan"}},
			},
		},
		{
			name: "second service at exactly 60s is a new window not a scan",
			steps: []step{
				{0, "ssh", "198.51.100.2", "connection", "", "", []string{"connection"}},
				{60 * time.Second, "http", "198.51.100.2", "connection", "", "", []string{"connection"}},
			},
		},
		{
			name: "same service twice is not a scan",
			steps: []step{
				{0, "telnet", "198.51.100.3", "connection", "", "", []string{"connection"}},
				{5 * time.Second, "telnet", "198.51.100.3", "connection", "", "", nil},
			},
		},
		{
			name: "three services listed in first-seen order",
			steps: []step{
				{0, "telnet", "198.51.100.4", "connection", "", "", []string{"connection"}},
				{1 * time.Second, "ssh", "198.51.100.4", "connection", "", "", []string{"scan"}},
				{2 * time.Second, "http", "198.51.100.4", "connection", "", "", []string{"scan"}},
			},
		},
		{
			name: "login_attempt on second service emits extra scan",
			steps: []step{
				{0, "ssh", "198.51.100.5", "login_attempt", "root", "secret", []string{"login_attempt"}},
				{5 * time.Second, "http", "198.51.100.5", "login_attempt", "admin", "pw", []string{"login_attempt", "scan"}},
			},
		},
		{
			name: "login_attempt then connection on other service is scan",
			steps: []step{
				{0, "ssh", "198.51.100.6", "login_attempt", "root", "x", []string{"login_attempt"}},
				{8 * time.Second, "telnet", "198.51.100.6", "connection", "", "", []string{"scan"}},
			},
		},
		{
			name: "scan still rate-limited per ip+service",
			steps: []step{
				{0, "ssh", "198.51.100.7", "connection", "", "", []string{"connection"}},
				{1 * time.Second, "http", "198.51.100.7", "connection", "", "", []string{"scan"}},
				{2 * time.Second, "http", "198.51.100.7", "connection", "", "", nil},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
			var now time.Time
			tr := NewWithClock(func() time.Time { return now })
			for i, st := range tc.steps {
				now = start.Add(st.offset)
				got := tr.Observe(queue.Event{
					Service:   st.service,
					SourceIP:  st.ip,
					EventType: st.eventType,
					Username:  st.user,
					Password:  st.pass,
					Summary:   st.eventType + " " + st.service,
					Raw:       map[string]any{"i": i},
				})
				if len(got) != len(st.wantTypes) {
					t.Fatalf("step %d: got %d events %v want %v", i, len(got), typesOf(got), st.wantTypes)
				}
				for j, ev := range got {
					if ev.EventType != st.wantTypes[j] {
						t.Fatalf("step %d event %d type=%q want %q", i, j, ev.EventType, st.wantTypes[j])
					}
					if ev.EventType == "login_attempt" {
						if ev.Username != st.user || ev.Password != st.pass {
							t.Fatalf("login_attempt stripped creds: %+v", ev)
						}
						continue
					}
					if ev.Username != "" || ev.Password != "" {
						t.Fatalf("%s must have empty user/pass: %+v", ev.EventType, ev)
					}
					if ev.Service == "" || ev.SourceIP != st.ip {
						t.Fatalf("missing service/ip on %+v", ev)
					}
					if ev.EventType == "scan" {
						if !strings.HasPrefix(ev.Summary, "probe across ") {
							t.Fatalf("scan summary %q", ev.Summary)
						}
						low := strings.ToLower(ev.Summary)
						if strings.Contains(low, "nmap") || strings.Contains(low, "syn scan") || strings.Contains(low, "syn-scan") {
							t.Fatalf("scan summary must not claim nmap/SYN: %q", ev.Summary)
						}
					}
				}
			}
		})
	}
}

func TestScanSummaryHonest(t *testing.T) {
	start := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	now := start
	tr := NewWithClock(func() time.Time { return now })
	_ = tr.Observe(queue.Event{Service: "ssh", SourceIP: "192.0.2.9", EventType: "connection"})
	now = start.Add(2 * time.Second)
	got := tr.Observe(queue.Event{Service: "http", SourceIP: "192.0.2.9", EventType: "connection"})
	if len(got) != 1 || got[0].EventType != "scan" {
		t.Fatalf("got %+v", got)
	}
	if got[0].Summary != "probe across ssh+http" {
		t.Fatalf("summary %q", got[0].Summary)
	}
	svcs, _ := got[0].Raw["services"].([]string)
	if len(svcs) != 2 || svcs[0] != "ssh" || svcs[1] != "http" {
		t.Fatalf("raw services %v", got[0].Raw["services"])
	}
}

func TestReportWrapper(t *testing.T) {
	var got []queue.Event
	tr := New()
	rep := tr.Report(func(ev queue.Event) { got = append(got, ev) })
	rep(queue.Event{Service: "ssh", SourceIP: "192.0.2.8", EventType: "connection"})
	rep(queue.Event{Service: "ssh", SourceIP: "192.0.2.8", EventType: "connection"})
	if len(got) != 1 {
		t.Fatalf("rate limit via Report: %d events", len(got))
	}
}

func typesOf(evs []queue.Event) []string {
	out := make([]string, len(evs))
	for i, ev := range evs {
		out[i] = ev.EventType
	}
	return out
}
