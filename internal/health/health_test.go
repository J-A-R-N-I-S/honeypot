package health

import (
	"os"
	"path/filepath"
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
