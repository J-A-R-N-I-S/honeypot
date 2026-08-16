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
