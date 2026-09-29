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
	d := filepath.Join(h.state, "c", id)
	if err := os.MkdirAll(d, 0o755); err != nil {
		h.t.Fatal(err)
	}
	r := "false"
	if running {
		r = "true"
	}
	for f, v := range map[string]string{"name": name, "image": image, "running": r} {
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

// Issue #17: a half-done `docker create` leaves a container under the
// target name, so renaming the old sensor back fails. The old sensor must
// still be restarted (by ID) and the run must fail; the next run must not
// report the stopped container under the name as "up to date" with exit 0.
func TestRollbackStartsOldContainerWhenRenameBackFails(t *testing.T) {
	h := newStubHost(t)
	h.addContainer("old1", "jarnis-honeypot", "sha256:old", true)

	code, out := h.run("STUB_CREATE_FAIL_LEAVE=1")
	if code == 0 {
		t.Fatalf("failed restore must exit non-zero\n%s", out)
	}
	if h.field("old1", "running") != "true" {
		t.Fatalf("old sensor left stopped\n%s", out)
	}
	if !strings.Contains(out, "NOT fully restored") || !strings.Contains(out, "restarted by ID") {
		t.Fatalf("log must say the restore is incomplete\n%s", out)
	}

	// Second run: the half-created container (current image, stopped) holds
	// the name.
	code, out = h.run()
	if code == 0 {
		t.Fatalf("stopped container under the name must fail the run\n%s", out)
	}
	if !strings.Contains(out, "NOT running") {
		t.Fatalf("missing warning\n%s", out)
	}
	if strings.Contains(out, "up to date jarnis-honeypot") {
		t.Fatalf("stopped container reported as up to date\n%s", out)
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
