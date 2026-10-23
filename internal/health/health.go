// Package health implements the container HEALTHCHECK (P31) without touching
// the decoy listeners: probing 22/23/8080 from inside the container would be
// reported to JARNIS as attacker traffic from 127.0.0.1. Instead the running
// sensor refreshes a heartbeat file once its listeners are up, and
// `jarnis-honeypot healthcheck` checks the file is fresh.
package health

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Heartbeat states written by the sensor.
const (
	StateServing      = "serving"       // all decoy listeners accepting
	StateWaitingToken = "waiting-token" // no valid HONEYPOT_TOKEN yet (review H2)
)

// DefaultPath lives on the /tmp tmpfs (read-only rootfs; recreated per
// container, so a stale file from a previous run cannot look healthy).
const DefaultPath = "/tmp/jarnis-honeypot.health"

// MaxAge: heartbeat interval is 15s, so 90s tolerates a few missed beats.
const MaxAge = 90 * time.Second

// Touch writes a "serving" heartbeat.
func Touch(path string, now time.Time) error { return TouchState(path, now, StateServing) }

// TouchState writes the heartbeat atomically: "<unix time> <state>\n".
func TouchState(path string, now time.Time, state string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(fmt.Sprintf("%d %s\n", now.Unix(), state)), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Check returns nil when the heartbeat exists and is younger than maxAge.
func Check(path string, now time.Time, maxAge time.Duration) error {
	_, err := CheckState(path, now, maxAge)
	return err
}

// CheckState is Check plus the recorded state. A fresh "waiting-token"
// heartbeat is healthy on purpose: a restart cannot conjure a missing
// HONEYPOT_TOKEN, so reporting unhealthy would only feed autoheal-style
// restart loops (see README "Health check").
func CheckState(path string, now time.Time, maxAge time.Duration) (string, error) {
	st, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", errors.New("no heartbeat yet (sensor starting)")
	}
	if err != nil {
		return "", err
	}
	age := now.Sub(st.ModTime())
	if age > maxAge {
		return "", fmt.Errorf("heartbeat stale (%s old): listeners not accepting or process hung", age.Round(time.Second))
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	state := StateServing
	if f := strings.Fields(string(b)); len(f) >= 2 {
		state = f[1]
	}
	return state, nil
}

// Path honours JARNIS_HEALTH_FILE (tests / custom tmpfs), else DefaultPath.
func Path() string {
	if p := os.Getenv("JARNIS_HEALTH_FILE"); p != "" {
		return p
	}
	return DefaultPath
}
