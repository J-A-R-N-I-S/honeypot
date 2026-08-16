package queue

import (
	"sync"
	"time"
)

// Event is one captured attempt waiting to be sent to JARNIS.
type Event struct {
	Service   string
	Username  string
	Password  string
	SourceIP  string
	UserAgent string
	SessionID string
	EventType string
	Summary   string
	Raw       map[string]any
	Tries     int
	NextTry   time.Time
}

// Queue keeps a bounded in-memory backlog if the control plane is down.
type Queue struct {
	mu      sync.Mutex
	items   []Event
	max     int
	dropped int
}

func New(max int) *Queue {
	if max < 16 {
		max = 16
	}
	return &Queue{max: max}
}

func (q *Queue) Push(ev Event) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) >= q.max {
		q.items = q.items[1:]
		q.dropped++
	}
	q.items = append(q.items, ev)
}

func (q *Queue) PopReady(now time.Time) (Event, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i := range q.items {
		if q.items[i].NextTry.After(now) {
			continue
		}
		ev := q.items[i]
		q.items = append(q.items[:i], q.items[i+1:]...)
		return ev, true
	}
	return Event{}, false
}

func (q *Queue) Retry(ev Event, backoff time.Duration) {
	ev.Tries++
	if ev.Tries > 12 {
		return
	}
	if backoff < time.Second {
		backoff = time.Second
	}
	ev.NextTry = time.Now().Add(backoff)
	q.Push(ev)
}

func (q *Queue) Stats() (n, dropped int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items), q.dropped
}
