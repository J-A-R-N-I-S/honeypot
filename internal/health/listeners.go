package health

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// Tracker couples the heartbeat to the decoy listeners (review H1): the
// heartbeat is only refreshed while every expected listener is still
// accepting. A listener counts as accepting when its serve loop is blocked in
// Accept() right now, or returned from Accept() less than `stall` ago (it is
// handing the connection off). It is dead once Accept() returned a permanent
// error or the listener was closed. An idle listener (no traffic) stays
// healthy because its loop sits in Accept().
type Tracker struct {
	mu     sync.Mutex
	expect []string
	ls     map[string]*Listener
}

// NewTracker expects the given listener names (e.g. "ssh", "telnet", "http").
func NewTracker(names ...string) *Tracker {
	return &Tracker{expect: append([]string(nil), names...), ls: map[string]*Listener{}}
}

// Wrap returns a func usable as Server.WrapListener for the named listener.
func (t *Tracker) Wrap(name string) func(net.Listener) net.Listener {
	return func(inner net.Listener) net.Listener {
		l := &Listener{Listener: inner, name: name}
		t.mu.Lock()
		t.ls[name] = l
		t.mu.Unlock()
		return l
	}
}

// Healthy returns nil when every expected listener is accepting.
func (t *Tracker) Healthy(now time.Time, stall time.Duration) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	var bad []string
	for _, n := range t.expect {
		l, ok := t.ls[n]
		if !ok {
			bad = append(bad, n+": not listening")
			continue
		}
		if err := l.state(now, stall); err != nil {
			bad = append(bad, n+": "+err.Error())
		}
	}
	if len(bad) == 0 {
		return nil
	}
	sort.Strings(bad)
	return fmt.Errorf("listeners unhealthy: %v", bad)
}

// Listener wraps a net.Listener and records its Accept state.
type Listener struct {
	net.Listener
	name string

	mu         sync.Mutex
	inAccept   bool
	everAccept bool
	lastReturn time.Time
	dead       error
	now        func() time.Time // tests
}

func (l *Listener) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

func (l *Listener) Accept() (net.Conn, error) {
	l.mu.Lock()
	l.inAccept, l.everAccept = true, true
	l.mu.Unlock()
	c, err := l.Listener.Accept()
	l.mu.Lock()
	l.inAccept = false
	l.lastReturn = l.clock()
	if err != nil {
		var ne net.Error
		if !(errors.As(err, &ne) && ne.Timeout()) { // http.Server retries only timeouts/temporary
			l.dead = err
		}
	}
	l.mu.Unlock()
	return c, err
}

func (l *Listener) Close() error {
	l.mu.Lock()
	if l.dead == nil {
		l.dead = net.ErrClosed
	}
	l.mu.Unlock()
	return l.Listener.Close()
}

func (l *Listener) state(now time.Time, stall time.Duration) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case l.dead != nil:
		return fmt.Errorf("closed (%v)", l.dead)
	case l.inAccept:
		return nil
	case !l.everAccept:
		return errors.New("serve loop not started")
	case now.Sub(l.lastReturn) > stall:
		return fmt.Errorf("not back in Accept for %s", now.Sub(l.lastReturn).Round(time.Second))
	}
	return nil
}
