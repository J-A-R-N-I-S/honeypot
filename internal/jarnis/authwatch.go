package jarnis

import (
	"sync"
	"time"
)

// AuthFailThreshold: consecutive 401/403 answers (config fetch or credential
// check-in) after which a sensor that HAD a working token counts as
// "waiting for a valid token" (token revoked/rotated). 12 matches the
// queue's retry limit per event. Before the first success a single 401/403
// is enough (the token never worked).
const AuthFailThreshold = 12

// AuthWatch tracks whether the API currently accepts HONEYPOT_TOKEN. It only
// classifies; retry timing stays with the callers (AuthRetryDelay backoff),
// so a revoked token never turns into a tight 401 loop.
type AuthWatch struct {
	Threshold int // 0 = AuthFailThreshold

	mu          sync.Mutex
	everOK      bool
	consecutive int
	since       time.Time // first 401/403 of the current streak
	waiting     bool
}

// Observe records one API result. nil = success (resets), a 401/403 extends
// the streak, any other error (network, 5xx) changes nothing.
func (a *AuthWatch) Observe(err error, now time.Time) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err == nil {
		if a.waiting {
			Logf("JARNIS accepts HONEYPOT_TOKEN again — leaving waiting-token state")
		}
		a.everOK, a.consecutive, a.waiting, a.since = true, 0, false, time.Time{}
		return
	}
	if !IsAuthError(err) {
		return
	}
	a.consecutive++
	if a.consecutive == 1 {
		a.since = now
	}
	th := a.Threshold
	if th <= 0 {
		th = AuthFailThreshold
	}
	if !a.waiting && (!a.everOK || a.consecutive >= th) {
		a.waiting = true
		Logf("HONEYPOT_TOKEN rejected %d× in a row (401/403) — waiting-token state; healthcheck turns unhealthy after JARNIS_TOKEN_WAIT_MAX (default 24h)", a.consecutive)
	}
}

// Waiting reports the waiting-token state and since when it applies (the
// first rejection of the streak).
func (a *AuthWatch) Waiting() (bool, time.Time) {
	if a == nil {
		return false, time.Time{}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.waiting, a.since
}
