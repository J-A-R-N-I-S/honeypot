package jarnis

import "testing"

func TestIsPublicIPv4(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8":     true,
		"1.1.1.1":     true,
		"10.0.0.1":    false,
		"192.168.1.1": false,
		"172.16.5.5":  false,
		"127.0.0.1":   false,
		"169.254.1.1": false,
		"100.64.1.1":  false,
		"203.0.113.10": false,
		"198.18.0.1":  false,
		"240.0.0.1":   false,
		"0.0.0.0":     false,
		"::1":         false,
		"2001:db8::1": false,
		"not-an-ip":   false,
		"":            false,
		" 8.8.4.4\n":  true,
	}
	for in, want := range cases {
		if got := isPublicIPv4(in); got != want {
			t.Fatalf("isPublicIPv4(%q)=%v want %v", in, got, want)
		}
	}
}
