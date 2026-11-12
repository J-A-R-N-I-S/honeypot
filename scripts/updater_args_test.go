// Package scripts holds tests for the host-side shell scripts.
package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Live bug 2026-11-12: `jarnis-honeypot-update --help` ignored the flag and
// ran a real update (image pull + container recreate); a manual run also
// left no start/end line in the update log. These cases run under sh
// (dash on Debian), dash and bash (if installed), with the docker stub.

func argShells(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, s := range []string{"sh", "dash", "bash"} {
		if _, err := exec.LookPath(s); err == nil {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		t.Skip("no POSIX shell available")
	}
	return out
}

// runWith executes the updater under shell with optional CLI args.
func (h *stubHost) runWith(shell string, args []string, extraEnv ...string) (int, string) {
	h.t.Helper()
	if shell == "" {
		shell = "sh"
	}
	cmdArgs := append([]string{"jarnis-honeypot-update.sh"}, args...)
	cmd := exec.Command(shell, cmdArgs...)
	logFile := filepath.Join(h.state, "update.log")
	cmd.Env = append([]string{
		"PATH=" + h.bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"STUB_STATE=" + h.state,
		"STUB_IMAGE=jarnis/honeypot:latest",
		"STUB_NEW_ID=sha256:new",
		"LOCK_FILE=" + filepath.Join(h.state, "lock"),
		"TMPDIR=" + h.state,
		"HEALTH_WAIT=3",
		"LOG_FILE=" + logFile,
		"UPDATE_TRIGGER=cron",
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

func (h *stubHost) calls() string {
	h.t.Helper()
	b, err := os.ReadFile(filepath.Join(h.state, "calls.log"))
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		h.t.Fatal(err)
	}
	return string(b)
}

func (h *stubHost) logFile() string {
	h.t.Helper()
	b, err := os.ReadFile(filepath.Join(h.state, "update.log"))
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		h.t.Fatal(err)
	}
	return string(b)
}

var utcStamp = regexp.MustCompile(`(?m)^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z `)

func TestHelpAndUnknownArgsDoNotCallDocker(t *testing.T) {
	cases := []struct {
		name string
		args []string
		code int
		want string
		err  bool
	}{
		{name: "long-help", args: []string{"--help"}, code: 0, want: "Usage: jarnis-honeypot-update"},
		{name: "short-help", args: []string{"-h"}, code: 0, want: "Usage: jarnis-honeypot-update"},
		{name: "unknown-flag", args: []string{"--foo"}, code: 2, want: "unknown option: --foo", err: true},
		{name: "positional", args: []string{"jarnis-honeypot"}, code: 2, want: "unexpected argument: jarnis-honeypot", err: true},
		{name: "two-positionals", args: []string{"foo", "bar"}, code: 2, want: "unexpected argument: foo", err: true},
	}
	for _, sh := range argShells(t) {
		for _, tc := range cases {
			sh, tc := sh, tc
			t.Run(sh+"/"+tc.name, func(t *testing.T) {
				h := newStubHost(t)
				h.addContainer("old1", "jarnis-honeypot", "sha256:old", true)
				code, out := h.runWith(sh, tc.args)
				if code != tc.code {
					t.Fatalf("code=%d want %d\n%s", code, tc.code, out)
				}
				if !strings.Contains(out, tc.want) {
					t.Fatalf("missing %q\n%s", tc.want, out)
				}
				if calls := h.calls(); calls != "" {
					t.Fatalf("docker was invoked:\n%s", calls)
				}
				if lf := h.logFile(); lf != "" {
					t.Fatalf("help/usage must not write a run log:\n%s", lf)
				}
				// And no token leakage on the usage path.
				if strings.Contains(out, "hpt_") || strings.Contains(out, "HONEYPOT_TOKEN") {
					t.Fatalf("token in output:\n%s", out)
				}
			})
		}
	}
}

// --help must work even when the only "docker" on PATH is a tripwire
// (standard /bin and /usr/bin stay, so helpers like cat remain available).
func TestHelpWorksWithoutDockerOnPath(t *testing.T) {
	for _, sh := range argShells(t) {
		sh := sh
		t.Run(sh, func(t *testing.T) {
			dir := t.TempDir()
			trip := filepath.Join(dir, "docker")
			body := "#!/bin/sh\necho tripwire-docker \"$@\" >> \"" + filepath.Join(dir, "docker.calls") + "\"\nexit 99\n"
			if err := os.WriteFile(trip, []byte(body), 0o755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(sh, "jarnis-honeypot-update.sh", "--help")
			cmd.Env = []string{
				"PATH=" + dir + string(os.PathListSeparator) + "/usr/bin:/bin",
				"HOME=" + dir,
				"LOG_FILE=" + filepath.Join(dir, "update.log"),
				"LOCK_FILE=" + filepath.Join(dir, "lock"),
			}
			out, err := cmd.CombinedOutput()
			code := 0
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != 0 || !strings.Contains(string(out), "Usage: jarnis-honeypot-update") {
				t.Fatalf("code=%d\n%s", code, out)
			}
			if _, err := os.Stat(filepath.Join(dir, "update.log")); !os.IsNotExist(err) {
				t.Fatalf("help wrote a log: %v", err)
			}
			if _, err := os.Stat(filepath.Join(dir, "docker.calls")); !os.IsNotExist(err) {
				t.Fatal("help invoked docker")
			}
		})
	}
}

func TestNormalRunUnchangedAndWritesLog(t *testing.T) {
	for _, sh := range argShells(t) {
		sh := sh
		t.Run(sh+"/recreate", func(t *testing.T) {
			h := newStubHost(t)
			h.addContainer("old1", "jarnis-honeypot", "sha256:old", true)
			code, out := h.runWith(sh, nil, "UPDATE_TRIGGER=manual")
			if code != 0 || !strings.Contains(out, "recreated jarnis-honeypot") {
				t.Fatalf("code=%d\n%s", code, out)
			}
			ents, _ := os.ReadDir(filepath.Join(h.state, "c"))
			if len(ents) != 1 || ents[0].Name() == "old1" {
				t.Fatalf("containers: %v", ents)
			}
			lf := h.logFile()
			if !utcStamp.MatchString(lf) {
				t.Fatalf("missing UTC Z timestamp in log:\n%s", lf)
			}
			if !strings.Contains(lf, "start trigger=manual") || !strings.Contains(lf, "end trigger=manual") {
				t.Fatalf("missing start/end or trigger:\n%s", lf)
			}
			if !strings.Contains(lf, "new=sha256:new") {
				t.Fatalf("missing new digest:\n%s", lf)
			}
			if !strings.Contains(lf, "old=jarnis-honeypot=sha256:old") {
				t.Fatalf("missing old digest:\n%s", lf)
			}
			if !strings.Contains(lf, "result=done found=1 updated=1 skipped=0 failed=0 stopped=0") {
				t.Fatalf("missing result:\n%s", lf)
			}
			if !strings.Contains(lf, "exit=0") {
				t.Fatalf("missing exit:\n%s", lf)
			}
			if strings.Contains(lf, "hpt_") || strings.Contains(lf, "HONEYPOT_TOKEN") || strings.Contains(out, "hpt_stub") {
				t.Fatalf("token leaked:\nlog=%s\nout=%s", lf, out)
			}
			calls := h.calls()
			if !strings.Contains(calls, "pull ") {
				t.Fatalf("normal run must still pull; calls:\n%s", calls)
			}
		})
		t.Run(sh+"/uptodate", func(t *testing.T) {
			h := newStubHost(t)
			h.addContainer("c1", "jarnis-honeypot", "sha256:new", true)
			code, out := h.runWith(sh, nil, "UPDATE_TRIGGER=cron")
			if code != 0 || !strings.Contains(out, "up to date jarnis-honeypot") {
				t.Fatalf("code=%d\n%s", code, out)
			}
			lf := h.logFile()
			if !strings.Contains(lf, "start trigger=cron") || !strings.Contains(lf, "end trigger=cron") {
				t.Fatalf("missing cron trigger:\n%s", lf)
			}
			if !strings.Contains(lf, "old=jarnis-honeypot=sha256:new") || !strings.Contains(lf, "new=sha256:new") {
				t.Fatalf("missing digests:\n%s", lf)
			}
			if !strings.Contains(lf, "result=done found=1 updated=0") {
				t.Fatalf("missing result:\n%s", lf)
			}
		})
	}
}

func TestDryRunDoesNotPullOrRecreate(t *testing.T) {
	for _, sh := range argShells(t) {
		sh := sh
		t.Run(sh, func(t *testing.T) {
			h := newStubHost(t)
			h.addContainer("old1", "jarnis-honeypot", "sha256:old", true)
			code, out := h.runWith(sh, []string{"--dry-run"}, "UPDATE_TRIGGER=manual")
			if code != 0 || !strings.Contains(out, "dry-run: would recreate jarnis-honeypot") {
				t.Fatalf("code=%d\n%s", code, out)
			}
			if h.field("old1", "name") != "jarnis-honeypot" || h.field("old1", "image") != "sha256:old" || h.field("old1", "running") != "true" {
				t.Fatalf("container was modified")
			}
			calls := "\n" + h.calls()
			for _, banned := range []string{"\npull ", "\ncreate ", "\nstart ", "\nrm ", "\nstop ", "\nrename "} {
				if strings.Contains(calls, banned) {
					t.Fatalf("dry-run invoked docker %q; calls:%s", strings.TrimSpace(banned), calls)
				}
			}
			lf := h.logFile()
			if !strings.Contains(lf, "start trigger=manual") || !strings.Contains(lf, "result=dry-run found=1") {
				t.Fatalf("missing dry-run log:\n%s", lf)
			}
		})
	}
}

func runBare(t *testing.T, h *stubHost, extraEnv ...string) (int, string) {
	t.Helper()
	cmd := exec.Command("sh", "jarnis-honeypot-update.sh")
	cmd.Env = append([]string{
		"PATH=" + h.bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"STUB_STATE=" + h.state,
		"STUB_IMAGE=jarnis/honeypot:latest",
		"STUB_NEW_ID=sha256:new",
		"LOCK_FILE=" + filepath.Join(h.state, "lock"),
		"TMPDIR=" + h.state,
		"HEALTH_WAIT=3",
		"LOG_FILE=" + filepath.Join(h.state, "update.log"),
	}, extraEnv...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, string(out)
}

func TestTriggerEnvAndDefaultNoTtyIsCron(t *testing.T) {
	// Tests run without a tty, so the default trigger is cron when
	// UPDATE_TRIGGER and INVOCATION_ID are unset. runWith always sets
	// UPDATE_TRIGGER, so this case uses runBare with no such variable.
	h := newStubHost(t)
	h.addContainer("c1", "jarnis-honeypot", "sha256:new", true)
	code, out := runBare(t, h)
	if code != 0 {
		t.Fatalf("code=%d\n%s", code, out)
	}
	lf := h.logFile()
	if !strings.Contains(lf, "start trigger=cron") || !strings.Contains(lf, "end trigger=cron") {
		t.Fatalf("default no-tty trigger should be cron:\n%s\nout:\n%s", lf, out)
	}

	h2 := newStubHost(t)
	h2.addContainer("c1", "jarnis-honeypot", "sha256:new", true)
	code, out = h2.runWith("sh", nil, "UPDATE_TRIGGER=manual", "INVOCATION_ID=should-be-ignored")
	if code != 0 {
		t.Fatalf("code=%d\n%s", code, out)
	}
	lf = h2.logFile()
	if !strings.Contains(lf, "start trigger=manual") {
		t.Fatalf("UPDATE_TRIGGER must win over INVOCATION_ID:\n%s", lf)
	}

	h3 := newStubHost(t)
	h3.addContainer("c1", "jarnis-honeypot", "sha256:new", true)
	code, out = runBare(t, h3, "INVOCATION_ID=deadbeef")
	if code != 0 {
		t.Fatalf("code=%d\n%s", code, out)
	}
	lf = h3.logFile()
	if !strings.Contains(lf, "start trigger=timer") {
		t.Fatalf("INVOCATION_ID without UPDATE_TRIGGER should be timer:\n%s", lf)
	}
}
