package jarnis

import (
	"context"
	"errors"
	"testing"
	"time"
)

var e401 = &StatusError{Op: "config", Code: 401, Body: "unauthorized"}

func TestAuthWatchNeverOKWaitsAtFirstRejection(t *testing.T) {
	a := &AuthWatch{}
	t0 := time.Unix(1_000, 0)
	a.Observe(errors.New("timeout"), t0)
	if w, _ := a.Waiting(); w {
		t.Fatal("network error must not mean waiting-token")
	}
	a.Observe(&StatusError{Op: "config", Code: 403}, t0)
	if w, since := a.Waiting(); !w || !since.Equal(t0) {
		t.Fatalf("token never worked + 403 => waiting since t0, got %v %v", w, since)
	}
}

func TestAuthWatchRevokedAfterThreshold(t *testing.T) {
	a := &AuthWatch{}
	a.Observe(nil, time.Unix(0, 0)) // token worked once
	t1 := time.Unix(5_000, 0)
	for i := 1; i < AuthFailThreshold; i++ {
		a.Observe(e401, t1.Add(time.Duration(i-1)*AuthRetryDelay))
		a.Observe(errors.New("eof"), t1) // transient errors neither reset nor count
		if w, _ := a.Waiting(); w {
			t.Fatalf("waiting after only %d 401s", i)
		}
	}
	a.Observe(&StatusError{Op: "credentials", Code: 401}, t1.Add(time.Hour)) // check-in counts too
	w, since := a.Waiting()
	if !w || !since.Equal(t1) {
		t.Fatalf("after %d consecutive 401s => waiting since first 401, got %v %v", AuthFailThreshold, w, since)
	}
	a.Observe(nil, t1.Add(2*time.Hour))
	if w, _ := a.Waiting(); w {
		t.Fatal("success must leave waiting-token")
	}
	// a success in between resets the streak
	for i := 0; i < AuthFailThreshold-1; i++ {
		a.Observe(e401, t1)
	}
	a.Observe(nil, t1)
	a.Observe(e401, t1)
	if w, _ := a.Waiting(); w {
		t.Fatal("streak must reset on success")
	}
}

func TestPollerRevokedTokenKeepsBackoffAndEntersWaiting(t *testing.T) {
	n := 0
	auth := &AuthWatch{}
	var sleeps []time.Duration
	p := &Poller{
		Auth:  auth,
		Apply: func(*Config) {},
		Fetch: func() (*Config, error) {
			n++
			if n == 1 {
				return &Config{}, nil
			}
			return nil, e401
		},
		jitter: noJitter,
		now:    func() time.Time { return time.Unix(int64(n), 0) },
	}
	p.sleep = func(_ context.Context, d time.Duration) bool {
		sleeps = append(sleeps, d)
		if n == AuthFailThreshold { // 11 rejections so far
			if w, _ := auth.Waiting(); w {
				t.Fatal("waiting too early")
			}
		}
		return n < 1+AuthFailThreshold
	}
	p.Run(context.Background())
	w, since := auth.Waiting()
	if !w || since.Unix() != 2 {
		t.Fatalf("revoked token: want waiting since 2nd fetch, got %v %v", w, since)
	}
	for _, d := range sleeps[1:] {
		if d != AuthRetryDelay {
			t.Fatalf("401 retry must stay on AuthRetryDelay (no tight loop): %v", sleeps)
		}
	}
}
