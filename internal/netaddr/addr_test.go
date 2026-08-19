package netaddr

import "testing"

func TestSplit(t *testing.T) {
	h, p := Split("203.0.113.9:5555")
	if h != "203.0.113.9" || p != 5555 {
		t.Fatalf("got %q %d", h, p)
	}
	h, p = Split("[2001:db8::1]:443")
	if h != "2001:db8::1" || p != 443 {
		t.Fatalf("v6 got %q %d", h, p)
	}
	h, p = Split("no-port")
	if h != "no-port" || p != 0 {
		t.Fatalf("bare got %q %d", h, p)
	}
}
