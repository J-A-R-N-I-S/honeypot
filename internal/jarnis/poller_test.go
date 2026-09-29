package jarnis

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestBackoffSequence(t *testing.T) {
	want := []time.Duration{5 * time.Second, 10 * time.Second, 30 * time.Second, 60 * time.Second, 60 * time.Second, 60 * time.Second}
	for i, w := range want {
		if got := BackoffDelay(i + 1); got != w {
			t.Fatalf("BackoffDelay(%d)=%v want %v", i+1, got, w)
		}
	}
	if BackoffDelay(0) != 5*time.Second || BackoffDelay(1000) != 60*time.Second {
		t.Fatal("out-of-range failures")
	}
}

type pollHarness struct {
	applied []string
	sleeps  []time.Duration
}

// newPoller returns a poller whose fetch results come from results (nil
// config = error) and that stops after len(results) fetches.
func newPoller(h *pollHarness, cache string, results []*Config) *Poller {
	i := 0
	p := &Poller{
		CachePath: cache,
		Apply:     func(c *Config) { h.applied = append(h.applied, c.Name) },
		Interval:  func() time.Duration { return 300 * time.Second },
		Fetch: func() (*Config, error) {
			r := results[i]
			i++
			if r == nil {
				return nil, errors.New("api unreachable")
			}
			return r, nil
		},
	}
	p.sleep = func(_ context.Context, d time.Duration) bool {
		h.sleeps = append(h.sleeps, d)
		if i >= len(results) {
			return false
		}
		return true
	}
	return p
}

func TestPollerFallsBackToCacheAndBacksOff(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "config.json")
	if _, err := SaveConfigCache(cache, sampleConfig("cached")); err != nil {
		t.Fatal(err)
	}
	h := &pollHarness{}
	p := newPoller(h, cache, []*Config{nil, nil, nil, nil, nil, sampleConfig("fresh")})
	if !p.LoadCache() {
		t.Fatal("cache not loaded")
	}
	p.Run(context.Background())

	if !reflect.DeepEqual(h.applied, []string{"cached", "fresh"}) {
		t.Fatalf("applied %v", h.applied)
	}
	s := time.Second
	want := []time.Duration{5 * s, 10 * s, 30 * s, 60 * s, 60 * s, 300 * s}
	if !reflect.DeepEqual(h.sleeps, want) {
		t.Fatalf("sleeps %v want %v", h.sleeps, want)
	}
	got, err := LoadConfigCache(cache)
	if err != nil || got.Name != "fresh" {
		t.Fatalf("cache after success: %+v %v", got, err)
	}
}

func TestPollerBackoffResetsAfterSuccess(t *testing.T) {
	h := &pollHarness{}
	p := newPoller(h, "", []*Config{nil, sampleConfig("a"), nil, nil})
	p.Run(context.Background())
	s := time.Second
	want := []time.Duration{5 * s, 300 * s, 5 * s, 10 * s}
	if !reflect.DeepEqual(h.sleeps, want) {
		t.Fatalf("sleeps %v want %v", h.sleeps, want)
	}
}

func TestPollerNoCacheFile(t *testing.T) {
	h := &pollHarness{}
	p := newPoller(h, filepath.Join(t.TempDir(), "none.json"), []*Config{nil})
	if p.LoadCache() {
		t.Fatal("missing cache must not load")
	}
	p.Run(context.Background())
	if len(h.applied) != 0 {
		t.Fatalf("applied %v", h.applied)
	}
}

func TestFallbackDialer(t *testing.T) {
	run := func(d *fallbackDialer, addr string, failFor map[string]bool) ([]string, error) {
		var calls []string
		d.Dial = func(_ context.Context, _, a string) (net.Conn, error) {
			calls = append(calls, a)
			if failFor[a] {
				return nil, errors.New("dial " + a + " failed")
			}
			c1, c2 := net.Pipe()
			_ = c2.Close()
			return c1, nil
		}
		c, err := d.DialContext(context.Background(), "tcp", addr)
		if c != nil {
			_ = c.Close()
		}
		return calls, err
	}

	// DNS/connect by name works: no fallback.
	calls, err := run(&fallbackDialer{Host: "jarnis.io", FallbackIP: "192.0.2.7"}, "jarnis.io:443", nil)
	if err != nil || !reflect.DeepEqual(calls, []string{"jarnis.io:443"}) {
		t.Fatalf("calls %v err %v", calls, err)
	}
	// By name fails: fallback IP, same port.
	calls, err = run(&fallbackDialer{Host: "jarnis.io", FallbackIP: "192.0.2.7"}, "jarnis.io:443", map[string]bool{"jarnis.io:443": true})
	if err != nil || !reflect.DeepEqual(calls, []string{"jarnis.io:443", "192.0.2.7:443"}) {
		t.Fatalf("calls %v err %v", calls, err)
	}
	// Both fail: error mentions both.
	_, err = run(&fallbackDialer{Host: "jarnis.io", FallbackIP: "192.0.2.7"}, "jarnis.io:443", map[string]bool{"jarnis.io:443": true, "192.0.2.7:443": true})
	if err == nil {
		t.Fatal("want error")
	}
	// Fallback disabled.
	calls, _ = run(&fallbackDialer{Host: "jarnis.io"}, "jarnis.io:443", map[string]bool{"jarnis.io:443": true})
	if len(calls) != 1 {
		t.Fatalf("disabled fallback dialed %v", calls)
	}
	// Other hosts never use the fallback.
	calls, _ = run(&fallbackDialer{Host: "jarnis.io", FallbackIP: "192.0.2.7"}, "api.ipify.org:443", map[string]bool{"api.ipify.org:443": true})
	if len(calls) != 1 {
		t.Fatalf("foreign host dialed %v", calls)
	}
}
