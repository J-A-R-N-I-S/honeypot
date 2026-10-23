package health

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMissingHeartbeatIsUnhealthy(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hb")
	if err := Check(p, time.Now(), MaxAge); err == nil {
		t.Fatal("missing heartbeat must be unhealthy")
	}
}

func TestFreshHeartbeatIsHealthy(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hb")
	now := time.Now()
	if err := Touch(p, now); err != nil {
		t.Fatal(err)
	}
	if err := Check(p, now.Add(10*time.Second), MaxAge); err != nil {
		t.Fatalf("fresh heartbeat: %v", err)
	}
	if _, err := os.Stat(p + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("tmp file left behind")
	}
}

func TestStaleHeartbeatIsUnhealthy(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hb")
	old := time.Now().Add(-5 * time.Minute)
	if err := Touch(p, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	if err := Check(p, time.Now(), MaxAge); err == nil {
		t.Fatal("stale heartbeat must be unhealthy")
	}
}

func TestPathEnvOverride(t *testing.T) {
	t.Setenv("JARNIS_HEALTH_FILE", "/tmp/x.health")
	if Path() != "/tmp/x.health" {
		t.Fatal(Path())
	}
	t.Setenv("JARNIS_HEALTH_FILE", "")
	if Path() != DefaultPath {
		t.Fatal(Path())
	}
}

func TestStateRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hb")
	now := time.Now()
	if err := TouchState(p, now, StateWaitingToken); err != nil {
		t.Fatal(err)
	}
	st, err := CheckState(p, now, MaxAge)
	if err != nil || st != StateWaitingToken {
		t.Fatalf("waiting-token heartbeat must be healthy with its state: %q %v", st, err)
	}
	if err := Touch(p, now); err != nil {
		t.Fatal(err)
	}
	if st, _ := CheckState(p, now, MaxAge); st != StateServing {
		t.Fatalf("state %q", st)
	}
}

func TestTokenWaitLimit(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hb")
	t0 := time.Unix(1_700_000_000, 0)
	now := t0.Add(23 * time.Hour)
	if err := TouchWaiting(p, now, t0); err != nil {
		t.Fatal(err)
	}
	// file mtime is "now" on disk; evaluate with the real clock for freshness
	b, err := ReadBeat(p, time.Now(), MaxAge)
	if err != nil || b.State != StateWaitingToken || !b.Since.Equal(t0) {
		t.Fatalf("beat %+v %v", b, err)
	}
	if msg, err := Evaluate(b, now, DefaultTokenWaitMax); err != nil || !strings.Contains(msg, "waiting for a valid HONEYPOT_TOKEN") {
		t.Fatalf("23h waiting must be healthy with message: %q %v", msg, err)
	}
	if _, err := Evaluate(b, t0.Add(24*time.Hour+time.Second), DefaultTokenWaitMax); err == nil || !strings.Contains(err.Error(), TokenWaitMaxEnv) {
		t.Fatalf("24h+ waiting must be unhealthy and name the env: %v", err)
	}
	if _, err := Evaluate(Beat{State: StateServing}, now, time.Second); err != nil {
		t.Fatal("serving is unaffected by the limit")
	}
}

func TestTokenWaitMaxEnv(t *testing.T) {
	t.Setenv(TokenWaitMaxEnv, "")
	if d, w := TokenWaitMax(); d != 24*time.Hour || w != "" {
		t.Fatalf("default %v %q", d, w)
	}
	t.Setenv(TokenWaitMaxEnv, "90m")
	if d, _ := TokenWaitMax(); d != 90*time.Minute {
		t.Fatalf("override %v", d)
	}
	for _, bad := range []string{"tomorrow", "-1h", "0"} {
		t.Setenv(TokenWaitMaxEnv, bad)
		if d, w := TokenWaitMax(); d != DefaultTokenWaitMax || w == "" {
			t.Fatalf("%q: %v %q", bad, d, w)
		}
	}
}

func TestOldFormatWaitingCountsFromNow(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hb")
	if err := TouchState(p, time.Now(), StateWaitingToken); err != nil {
		t.Fatal(err)
	}
	b, err := ReadBeat(p, time.Now(), MaxAge)
	if err != nil || b.Since.IsZero() {
		t.Fatalf("%+v %v", b, err)
	}
}
