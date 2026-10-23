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
	"time"
)

// DefaultPath lives on the /tmp tmpfs (read-only rootfs; recreated per
// container, so a stale file from a previous run cannot look healthy).
const DefaultPath = "/tmp/jarnis-honeypot.health"

// MaxAge: heartbeat interval is 15s, so 90s tolerates a few missed beats.
const MaxAge = 90 * time.Second

// Touch writes the heartbeat (content is the unix time, for debugging).
func Touch(path string, now time.Time) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(fmt.Sprintf("%d\n", now.Unix())), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Check returns nil when the heartbeat exists and is younger than maxAge.
func Check(path string, now time.Time, maxAge time.Duration) error {
	st, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("no heartbeat yet (waiting for HONEYPOT_TOKEN or listeners not up)")
	}
	if err != nil {
		return err
	}
	age := now.Sub(st.ModTime())
	if age > maxAge {
		return fmt.Errorf("heartbeat stale (%s old)", age.Round(time.Second))
	}
	return nil
}

// Path honours JARNIS_HEALTH_FILE (tests / custom tmpfs), else DefaultPath.
func Path() string {
	if p := os.Getenv("JARNIS_HEALTH_FILE"); p != "" {
		return p
	}
	return DefaultPath
}
