package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Seniba gate 2026-11-09 F1: carried options are one flag per LINE. Log
// defaults (json-file, max-size=10m, max-file=3) may only be added when the
// old container had no --log-opt at all and its effective driver is
// json-file. Custom opts and other drivers must survive the recreate.
// Every case runs under sh (dash on Debian), dash and bash (if installed).

type logCase struct {
	name      string
	opts      string // carried_options inspect lines; "" = stub default
	daemonLog string // docker info LoggingDriver
	want      []string
	notWant   []string
}

var logCases = []logCase{
	{
		name: "no opts json-file daemon default", daemonLog: "json-file",
		want:    []string{"--log-opt\nmax-size=10m", "--log-opt\nmax-file=3"},
		notWant: []string{"--log-driver"},
	},
	{
		name: "custom max-size only", daemonLog: "json-file",
		opts:    "logdrv|json-file\nlogopt|max-size=50m\n",
		want:    []string{"--log-opt\nmax-size=50m"},
		notWant: []string{"max-size=10m", "max-file=3", "--log-driver"},
	},
	{
		name: "multi-line opts network hostname then log-opt", daemonLog: "json-file",
		opts:    "net|jarnis-net\nhost|sensor-a\nlogdrv|json-file\nlogopt|max-file=5\nlogopt|max-size=50m\n",
		want:    []string{"--network\njarnis-net", "--hostname\nsensor-a", "--log-opt\nmax-size=50m", "--log-opt\nmax-file=5"},
		notWant: []string{"max-size=10m", "max-file=3", "--log-driver"},
	},
	{
		name: "journald without opts", daemonLog: "json-file",
		opts:    "net|bridge\nlogdrv|journald\n",
		want:    []string{"--log-driver\njournald"},
		notWant: []string{"--log-opt", "json-file"},
	},
	{
		name: "local with custom opt after network", daemonLog: "json-file",
		opts:    "net|jarnis-net\nlogdrv|local\nlogopt|max-size=20m\n",
		want:    []string{"--log-driver\nlocal", "--log-opt\nmax-size=20m"},
		notWant: []string{"max-size=10m", "max-file=3", "json-file"},
	},
	{
		name: "local without opts", daemonLog: "json-file",
		opts:    "logdrv|local\n",
		want:    []string{"--log-driver\nlocal"},
		notWant: []string{"--log-opt", "json-file"},
	},
	{
		name: "syslog with address", daemonLog: "json-file",
		opts:    "net|bridge\nlogdrv|syslog\nlogopt|syslog-address=udp://192.0.2.10:514\n",
		want:    []string{"--log-driver\nsyslog", "--log-opt\nsyslog-address=udp://192.0.2.10:514"},
		notWant: []string{"max-size=10m", "max-file=3", "json-file"},
	},
	{
		name: "daemon journald default carried as-is", daemonLog: "journald",
		opts:    "net|bridge\nlogdrv|journald\n",
		notWant: []string{"--log-opt", "--log-driver", "json-file"},
	},
	{
		name: "explicit json-file on journald daemon gets defaults", daemonLog: "journald",
		opts: "net|bridge\nlogdrv|json-file\n",
		want: []string{"--log-driver\njson-file", "--log-opt\nmax-size=10m", "--log-opt\nmax-file=3"},
	},
}

func logShells(t *testing.T) []string {
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

func TestRecreateLogDefaults(t *testing.T) {
	for _, sh := range logShells(t) {
		for _, tc := range logCases {
			sh, tc := sh, tc
			t.Run(sh+"/"+tc.name, func(t *testing.T) {
				h := newStubHost(t)
				h.shell = sh
				h.addContainer("old1", "jarnis-honeypot", "sha256:old", true)
				if tc.opts != "" {
					if err := os.WriteFile(filepath.Join(h.state, "c", "old1", "opts"), []byte(tc.opts), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				code, out := h.run("STUB_DAEMON_LOG=" + tc.daemonLog)
				if code != 0 || !strings.Contains(out, "recreated jarnis-honeypot") {
					t.Fatalf("code=%d\n%s", code, out)
				}
				ents, _ := os.ReadDir(filepath.Join(h.state, "c"))
				if len(ents) != 1 {
					t.Fatalf("containers: %v", ents)
				}
				args := "\n" + h.field(ents[0].Name(), "create_args") + "\n"
				for _, w := range tc.want {
					if !strings.Contains(args, "\n"+w+"\n") {
						t.Errorf("missing %q in create args:%s", w, args)
					}
				}
				for _, nw := range tc.notWant {
					if strings.Contains(args, nw) {
						t.Errorf("unexpected %q in create args:%s", nw, args)
					}
				}
			})
		}
	}
}
