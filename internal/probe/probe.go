package probe

import (
	"strings"
	"sync"
	"time"

	"github.com/j-a-r-n-i-s/honeypot/internal/queue"
)

const (
	// RateInterval caps connection/scan noise per source IP per bait service.
	RateInterval = time.Minute
	// ScanWindow is how long distinct bait-port hits count toward a scan tag.
	ScanWindow = 60 * time.Second
)

type hit struct {
	service string
	at      time.Time
}

// Tracker rate-limits connection/scan events and tags cross-service probes.
// login_attempt is never rate-limited.
type Tracker struct {
	mu   sync.Mutex
	now  func() time.Time
	last map[string]time.Time // ip\x00service → last connection/scan emit
	hits map[string][]hit     // ip → recent distinct service hits (first-seen order)
}

func New() *Tracker {
	return NewWithClock(time.Now)
}

func NewWithClock(now func() time.Time) *Tracker {
	if now == nil {
		now = time.Now
	}
	return &Tracker{
		now:  now,
		last: make(map[string]time.Time),
		hits: make(map[string][]hit),
	}
}

func rateKey(ip, service string) string {
	return ip + "\x00" + service
}

// Report wraps sink so servers keep calling func(queue.Event).
func (t *Tracker) Report(sink func(queue.Event)) func(queue.Event) {
	return func(ev queue.Event) {
		if t == nil {
			if sink != nil {
				sink(ev)
			}
			return
		}
		for _, out := range t.Observe(ev) {
			if sink != nil {
				sink(out)
			}
		}
	}
}

// Observe records ev and returns the events that should be queued.
func (t *Tracker) Observe(ev queue.Event) []queue.Event {
	now := t.now()
	login := strings.EqualFold(ev.EventType, "login_attempt")

	if ev.SourceIP == "" || ev.Service == "" {
		if login {
			return []queue.Event{ev}
		}
		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	t.recordHitLocked(ev.SourceIP, ev.Service, now)
	services := t.servicesInWindowLocked(ev.SourceIP, now)
	multi := len(services) >= 2

	if login {
		out := []queue.Event{ev}
		if multi {
			if scan, ok := t.maybeScanLocked(ev, services, now); ok {
				out = append(out, scan)
			}
		}
		return out
	}

	if !t.allowLocked(ev.SourceIP, ev.Service, now) {
		return nil
	}
	ev.Username = ""
	ev.Password = ""
	if multi {
		ev.EventType = "scan"
		ev.Summary = scanSummary(services)
		ev.Raw = withServices(ev.Raw, services)
	} else if ev.EventType == "" {
		ev.EventType = "connection"
	}
	return []queue.Event{ev}
}

func (t *Tracker) allowLocked(ip, service string, now time.Time) bool {
	t.pruneLastLocked(now)
	k := rateKey(ip, service)
	if prev, ok := t.last[k]; ok && now.Sub(prev) < RateInterval {
		return false
	}
	t.last[k] = now
	return true
}

func (t *Tracker) pruneLastLocked(now time.Time) {
	if len(t.last) < 4096 {
		return
	}
	for k, ts := range t.last {
		if now.Sub(ts) >= RateInterval {
			delete(t.last, k)
		}
	}
}

func (t *Tracker) maybeScanLocked(trigger queue.Event, services []string, now time.Time) (queue.Event, bool) {
	if !t.allowLocked(trigger.SourceIP, trigger.Service, now) {
		return queue.Event{}, false
	}
	return queue.Event{
		Service:    trigger.Service,
		SourceIP:   trigger.SourceIP,
		SourcePort: trigger.SourcePort,
		UserAgent:  trigger.UserAgent,
		SessionID:  trigger.SessionID,
		EventType:  "scan",
		Summary:    scanSummary(services),
		Raw:        withServices(trigger.Raw, services),
	}, true
}

func (t *Tracker) recordHitLocked(ip, service string, now time.Time) {
	old := t.hits[ip]
	kept := make([]hit, 0, len(old)+1)
	found := false
	for _, h := range old {
		if h.service == service {
			h.at = now
			kept = append(kept, h)
			found = true
			continue
		}
		if now.Sub(h.at) >= ScanWindow {
			continue
		}
		kept = append(kept, h)
	}
	if !found {
		kept = append(kept, hit{service: service, at: now})
	}
	if len(kept) == 0 {
		delete(t.hits, ip)
		return
	}
	t.hits[ip] = kept
}

func (t *Tracker) servicesInWindowLocked(ip string, now time.Time) []string {
	svcs := make([]string, 0, 3)
	for _, h := range t.hits[ip] {
		if now.Sub(h.at) >= ScanWindow {
			continue
		}
		svcs = append(svcs, h.service)
	}
	return svcs
}

func scanSummary(services []string) string {
	return "probe across " + strings.Join(services, "+")
}

func withServices(raw map[string]any, services []string) map[string]any {
	out := make(map[string]any, len(raw)+1)
	for k, v := range raw {
		out[k] = v
	}
	copied := make([]string, len(services))
	copy(copied, services)
	out["services"] = copied
	return out
}
