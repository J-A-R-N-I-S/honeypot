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
	"strconv"
	"strings"
	"time"
)

// DefaultTokenWaitMax: how long "waiting for a valid HONEYPOT_TOKEN" (token
// missing, or rejected by JARNIS with 401/403) counts as healthy. After that
// the healthcheck reports unhealthy so the stuck sensor becomes visible (H2a).
const DefaultTokenWaitMax = 24 * time.Hour

// TokenWaitMaxEnv overrides DefaultTokenWaitMax (Go duration, e.g. "24h", "90m").
const TokenWaitMaxEnv = "JARNIS_TOKEN_WAIT_MAX"

// TokenWaitMax returns the limit and, for an unusable env value, a warning
// (the default is used then).
func TokenWaitMax() (time.Duration, string) {
	v := strings.TrimSpace(os.Getenv(TokenWaitMaxEnv))
	if v == "" {
		return DefaultTokenWaitMax, ""
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return DefaultTokenWaitMax, fmt.Sprintf("ignoring invalid %s=%q (want e.g. 24h), using %s", TokenWaitMaxEnv, v, DefaultTokenWaitMax)
	}
	return d, ""
}

// Beat is a parsed heartbeat. Since is when the waiting-token state began
// (zero for serving, or for an old-format file).
type Beat struct {
	State string
	Since time.Time
}

// TouchWaiting writes a waiting-token heartbeat that remembers when waiting began.
func TouchWaiting(path string, now, since time.Time) error {
	return writeBeat(path, fmt.Sprintf("%d %s %d\n", now.Unix(), StateWaitingToken, since.Unix()))
}

// ReadBeat is CheckState plus the waiting start time.
func ReadBeat(path string, now time.Time, maxAge time.Duration) (Beat, error) {
	b, err := readFresh(path, now, maxAge)
	if err != nil {
		return Beat{}, err
	}
	beat := Beat{State: StateServing}
	f := strings.Fields(string(b))
	if len(f) >= 2 {
		beat.State = f[1]
	}
	if len(f) >= 3 {
		if u, err := strconv.ParseInt(f[2], 10, 64); err == nil {
			beat.Since = time.Unix(u, 0)
		}
	}
	if beat.State == StateWaitingToken && beat.Since.IsZero() {
		beat.Since = now // old format: unknown start, count from now
	}
	return beat, nil
}

// Evaluate applies the token-wait limit: serving is healthy; waiting-token is
// healthy (with a message) for at most limit, then unhealthy.
func Evaluate(beat Beat, now time.Time, limit time.Duration) (msg string, err error) {
	if beat.State != StateWaitingToken {
		return "healthy: " + beat.State, nil
	}
	waited := now.Sub(beat.Since)
	if waited < 0 {
		waited = 0
	}
	if waited > limit {
		return "", fmt.Errorf("waiting for a valid HONEYPOT_TOKEN for %s (limit %s=%s): token missing or rejected (401/403) — set/rotate the token and recreate the container",
			waited.Round(time.Minute), TokenWaitMaxEnv, limit)
	}
	return fmt.Sprintf("healthy (process alive) but waiting for a valid HONEYPOT_TOKEN for %s of max %s — token missing or rejected by JARNIS (401/403); unhealthy after the limit",
		waited.Round(time.Second), limit), nil
}

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
	return writeBeat(path, fmt.Sprintf("%d %s\n", now.Unix(), state))
}

func writeBeat(path, line string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(line), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Check returns nil when the heartbeat exists and is younger than maxAge.
func Check(path string, now time.Time, maxAge time.Duration) error {
	_, err := CheckState(path, now, maxAge)
	return err
}

// CheckState is Check plus the recorded state. Whether a fresh
// "waiting-token" heartbeat is healthy is decided by Evaluate (24h limit).
func CheckState(path string, now time.Time, maxAge time.Duration) (string, error) {
	b, err := ReadBeat(path, now, maxAge)
	return b.State, err
}

func readFresh(path string, now time.Time, maxAge time.Duration) ([]byte, error) {
	st, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("no heartbeat yet (sensor starting)")
	}
	if err != nil {
		return nil, err
	}
	age := now.Sub(st.ModTime())
	if age > maxAge {
		return nil, fmt.Errorf("heartbeat stale (%s old): listeners not accepting or process hung", age.Round(time.Second))
	}
	return os.ReadFile(path)
}

// Path honours JARNIS_HEALTH_FILE (tests / custom tmpfs), else DefaultPath.
func Path() string {
	if p := os.Getenv("JARNIS_HEALTH_FILE"); p != "" {
		return p
	}
	return DefaultPath
}
