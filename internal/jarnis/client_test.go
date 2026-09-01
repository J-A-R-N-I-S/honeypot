package jarnis

import "testing"

func TestNormalizeAPI(t *testing.T) {
	cases := map[string]string{
		"https://jarnis.io":     "https://jarnis.io/api",
		"https://jarnis.io/":    "https://jarnis.io/api",
		"https://jarnis.io/api": "https://jarnis.io/api",
		"https://jarnis.io/api/": "https://jarnis.io/api",
		"":                      "https://jarnis.io/api",
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

