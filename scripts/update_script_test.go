// Package scripts holds tests for the host-side shell scripts.
package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type stubHost struct {
	t     *testing.T
	state string
	bin   string
}

func newStubHost(t *testing.T) *stubHost {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	dir := t.TempDir()
	h := &stubHost{t: t, state: filepath.Join(dir, "state"), bin: filepath.Join(dir, "bin")}
	for _, d := range []string{filepath.Join(h.state, "c"), h.bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	stub, err := filepath.Abs("testdata/docker-stub.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(stub, filepath.Join(h.bin, "docker")); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *stubHost) addContainer(id, name, image string, running bool) {
	h.t.Helper()
	h.addContainerLabels(id, name, image, running, "com.jarnis.honeypot=1")
}

func (h *stubHost) addContainerLabels(id, name, image string, running bool, labels string) {
	h.t.Helper()
	d := filepath.Join(h.state, "c", id)
	if err := os.MkdirAll(d, 0o755); err != nil {
		h.t.Fatal(err)
	}
	r := "false"
	if running {
		r = "true"
	}
	for f, v := range map[string]string{"name": name, "image": image, "running": r, "labels": labels} {
		if err := os.WriteFile(filepath.Join(d, f), []byte(v+"\n"), 0o644); err != nil {
			h.t.Fatal(err)
		}
	}
}

func (h *stubHost) field(id, f string) string {
	h.t.Helper()
	b, err := os.ReadFile(filepath.Join(h.state, "c", id, f))
	if err != nil {
		h.t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// run executes the updater against the stub; returns exit code and output.
func (h *stubHost) run(extraEnv ...string) (int, string) {
	h.t.Helper()
	cmd := exec.Command("sh", "jarnis-honeypot-update.sh")
	cmd.Env = append([]string{
		"PATH=" + h.bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"STUB_STATE=" + h.state,
		"STUB_IMAGE=jarnis/honeypot:latest",
		"STUB_NEW_ID=sha256:new",
		"LOCK_FILE=" + filepath.Join(h.state, "lock"),
		"TMPDIR=" + h.state,
		"HEALTH_WAIT=3",
	}, extraEnv...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		h.t.Fatal(err)
	}
	return code, string(out)
}

// Review follow-up: a half-done `docker create` leaves a container under the
// target name. Rollback removes it (it carries this attempt's unique
// com.jarnis.update-run label), so the old sensor gets its name back and runs.
func TestRollbackRemovesHalfCreatedContainer(t *testing.T) {
	h := newStubHost(t)
	h.addContainer("old1", "jarnis-honeypot", "sha256:old", true)
	h.addContainerLabels("other", "unrelated", "sha256:x", true, "")

	code, out := h.run("STUB_CREATE_FAIL_LEAVE=1")
	if code == 0 {
		t.Fatalf("failed recreate must exit non-zero\n%s", out)
	}
	if h.field("old1", "name") != "jarnis-honeypot" || h.field("old1", "running") != "true" {
		t.Fatalf("old sensor not restored\n%s", out)
	}
	if !strings.Contains(out, "removed half-created container") || !strings.Contains(out, "previous container jarnis-honeypot restored") {
		t.Fatalf("missing log\n%s", out)
	}
	ents, _ := os.ReadDir(filepath.Join(h.state, "c"))
	if len(ents) != 2 {
		t.Fatalf("containers left: %v", ents)
	}
	if h.field("other", "running") != "true" {
		t.Fatal("unrelated container touched")
	}
}

// Issue #17: if renaming the old sensor back fails anyway, it must still be
// restarted (by ID) and the run must fail.
func TestRollbackStartsOldContainerWhenRenameBackFails(t *testing.T) {
	h := newStubHost(t)
	h.addContainer("old1", "jarnis-honeypot", "sha256:old", true)

	code, out := h.run("STUB_CREATE_FAIL=1", "STUB_RENAME_FAIL_TO=jarnis-honeypot")
	if code == 0 {
		t.Fatalf("failed restore must exit non-zero\n%s", out)
	}
	if h.field("old1", "running") != "true" {
		t.Fatalf("old sensor left stopped\n%s", out)
	}
	if !strings.Contains(out, "NOT fully restored") || !strings.Contains(out, "restarted by ID") {
		t.Fatalf("log must say the restore is incomplete\n%s", out)
	}
}

// Issue #17: a stopped container with the current image under the name must
// not pass as "up to date" with exit 0 — unless ALLOW_STOPPED=1.
func TestStoppedUpToDateContainerFailsUnlessAllowed(t *testing.T) {
	h := newStubHost(t)
	h.addContainer("c1", "jarnis-honeypot", "sha256:new", false)
	code, out := h.run()
	if code == 0 || !strings.Contains(out, "NOT running") || strings.Contains(out, "up to date jarnis-honeypot") {
		t.Fatalf("code=%d\n%s", code, out)
	}
	code, out = h.run("ALLOW_STOPPED=1")
	if code != 0 || !strings.Contains(out, "ALLOW_STOPPED=1") {
		t.Fatalf("ALLOW_STOPPED=1: code=%d\n%s", code, out)
	}
	if h.field("c1", "running") != "false" {
		t.Fatal("stopped sensor must not be started by the updater")
	}
}

func TestSuccessfulRecreateCarriesNoStaleRunLabel(t *testing.T) {
	h := newStubHost(t)
	h.addContainer("old1", "jarnis-honeypot", "sha256:old", true)
	code, out := h.run()
	if code != 0 || !strings.Contains(out, "recreated jarnis-honeypot") {
		t.Fatalf("code=%d\n%s", code, out)
	}
	ents, _ := os.ReadDir(filepath.Join(h.state, "c"))
	if len(ents) != 1 || ents[0].Name() == "old1" {
		t.Fatalf("containers: %v", ents)
	}
	labels := h.field(ents[0].Name(), "labels")
	if strings.Count(labels, "com.jarnis.update-run=") != 1 {
		t.Fatalf("labels %q", labels)
	}
}

func TestUpToDateRunningContainerExitsZero(t *testing.T) {
	h := newStubHost(t)
	h.addContainer("c1", "jarnis-honeypot", "sha256:new", true)
	code, out := h.run()
	if code != 0 || !strings.Contains(out, "up to date jarnis-honeypot") {
		t.Fatalf("code=%d\n%s", code, out)
	}
}

func TestRollbackRestoresNameAndStartsOnCleanFailure(t *testing.T) {
	h := newStubHost(t)
	h.addContainer("old1", "jarnis-honeypot", "sha256:old", true)
	code, out := h.run("STUB_CREATE_FAIL=1")
	if code == 0 {
		t.Fatalf("failed recreate must exit non-zero\n%s", out)
	}
	if h.field("old1", "name") != "jarnis-honeypot" || h.field("old1", "running") != "true" {
		t.Fatalf("old sensor not restored: name=%s running=%s\n%s", h.field("old1", "name"), h.field("old1", "running"), out)
	}
	if !strings.Contains(out, "previous container jarnis-honeypot restored") {
		t.Fatalf("missing restore log\n%s", out)
	}
}

// P19: a stopped sensor on an old image is recreated onto the new image but
// left stopped (never started, no health gate); the old container is removed
// and the run passes. The next run applies the ALLOW_STOPPED check.
func TestStoppedOutdatedContainerIsRecreatedButLeftStopped(t *testing.T) {
	h := newStubHost(t)
	h.addContainer("old1", "jarnis-honeypot", "sha256:old", false)
	code, out := h.run()
	if code != 0 || !strings.Contains(out, "recreated jarnis-honeypot (sha256:new) — left stopped, as it was") {
		t.Fatalf("code=%d\n%s", code, out)
	}
	ents, _ := os.ReadDir(filepath.Join(h.state, "c"))
	if len(ents) != 1 || ents[0].Name() == "old1" {
		t.Fatalf("containers: %v", ents)
	}
	id := ents[0].Name()
	if h.field(id, "name") != "jarnis-honeypot" || h.field(id, "image") != "sha256:new" || h.field(id, "running") != "false" {
		t.Fatalf("new container: name=%s image=%s running=%s", h.field(id, "name"), h.field(id, "image"), h.field(id, "running"))
	}
	calls, _ := os.ReadFile(filepath.Join(h.state, "calls.log"))
	if strings.Contains("\n"+string(calls), "\nstart ") {
		t.Fatalf("updater must not start a stopped sensor; calls:\n%s", calls)
	}
	code, out = h.run()
	if code == 0 || !strings.Contains(out, "NOT running") {
		t.Fatalf("second run without ALLOW_STOPPED: code=%d\n%s", code, out)
	}
	code, out = h.run("ALLOW_STOPPED=1")
	if code != 0 || !strings.Contains(out, "ALLOW_STOPPED=1") {
		t.Fatalf("second run with ALLOW_STOPPED=1: code=%d\n%s", code, out)
	}
}

// P19: rollback of a stopped sensor gives it its name back and leaves it
// stopped.
func TestRollbackLeavesStoppedContainerStopped(t *testing.T) {
	h := newStubHost(t)
	h.addContainer("old1", "jarnis-honeypot", "sha256:old", false)
	code, out := h.run("STUB_CREATE_FAIL=1")
	if code == 0 || !strings.Contains(out, "previous container jarnis-honeypot restored") {
		t.Fatalf("code=%d\n%s", code, out)
	}
	if h.field("old1", "name") != "jarnis-honeypot" || h.field("old1", "running") != "false" {
		t.Fatalf("old sensor: name=%s running=%s\n%s", h.field("old1", "name"), h.field("old1", "running"), out)
	}
}
