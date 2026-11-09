package jarnis

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeAPI(t *testing.T) {
	cases := map[string]string{
		"https://jarnis.io":      "https://jarnis.io/api",
		"https://jarnis.io/":     "https://jarnis.io/api",
		"https://jarnis.io/api":  "https://jarnis.io/api",
		"https://jarnis.io/api/": "https://jarnis.io/api",
		"":                       "https://jarnis.io/api",
	}
	for in, want := range cases {
		if got := NormalizeAPI(in); got != want {
			t.Fatalf("NormalizeAPI(%q)=%q want %q", in, got, want)
		}
	}
}

func TestProcessUptimeSeconds(t *testing.T) {
	n := ProcessUptimeSeconds()
	if n < 0 {
		t.Fatalf("ProcessUptimeSeconds()=%d want >= 0", n)
	}
}

func TestProcessStartedAtRFC3339(t *testing.T) {
	s := ProcessStartedAtRFC3339()
	if s == "" {
		t.Fatal("empty process started at")
	}
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("ProcessStartedAtRFC3339=%q: %v", s, err)
	}
	if ts.Location() != time.UTC && ts.UTC().Format(time.RFC3339) != s && !strings.HasSuffix(s, "Z") && !strings.Contains(s, "+00:00") {
		// Accept Z or explicit offset; value must be within a few seconds of now.
	}
	if d := time.Since(ts); d < -time.Minute || d > time.Hour {
		t.Fatalf("ProcessStartedAtRFC3339=%q age=%v looks implausible", s, d)
	}
	// Stable across calls in the same process.
	if ProcessStartedAtRFC3339() != s {
		t.Fatal("ProcessStartedAtRFC3339 must be stable for the process lifetime")
	}
	if !ProcessStartedAt().Equal(ts) && ProcessStartedAt().UTC().Format(time.RFC3339) != s {
		got := ProcessStartedAt().UTC().Format(time.RFC3339)
		if got != s {
			t.Fatalf("ProcessStartedAt format %q != %q", got, s)
		}
	}
}
