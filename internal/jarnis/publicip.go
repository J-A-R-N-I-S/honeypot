package jarnis

import (
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Process-lifetime cache of the sensor's public egress IPv4.
var (
	publicIPMu     sync.Mutex
	cachedPublicIP string
)

// discoverPublicIPv4 is replaced in tests.
var discoverPublicIPv4 = defaultDiscoverPublicIPv4

func defaultDiscoverPublicIPv4() string {
	// Prefer cloud metadata, then public echo services. First public IPv4 wins.
	sources := []struct {
		url     string
		timeout time.Duration
	}{
		{"http://169.254.169.254/hetzner/v1/metadata/public-ipv4", time.Second},
		{"https://api.ipify.org", 2 * time.Second},
		{"https://ifconfig.me/ip", 2 * time.Second},
	}
	for _, s := range sources {
		if ip := fetchCandidateIP(s.url, s.timeout); isPublicIPv4(ip) {
			return ip
		}
	}
	return ""
}

func fetchCandidateIP(rawURL string, timeout time.Duration) string {
	cli := &http.Client{Timeout: timeout}
	res, err := cli.Get(rawURL)
	if err != nil {
		return ""
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 64))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}

func isPublicIPv4(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	// Skip private, loopback, link-local, multicast, unspecified, and other non-global.
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	if isReservedIPv4(ip4) {
		return false
	}
	return true
}

// isReservedIPv4 rejects common non-routable / special-use ranges that
// net.IP.IsPrivate does not cover (CGNAT, benchmarking, class E, etc.).
func isReservedIPv4(ip4 net.IP) bool {
	// Shared Address Space / CGNAT 100.64.0.0/10 (RFC 6598)
	if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
		return true
	}
	// IETF Protocol Assignments 192.0.0.0/24
	if ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 0 {
		return true
	}
	// TEST-NET-1 192.0.2.0/24
	if ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2 {
		return true
	}
	// TEST-NET-2 198.51.100.0/24
	if ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100 {
		return true
	}
	// TEST-NET-3 203.0.113.0/24
	if ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113 {
		return true
	}
	// Benchmarking 198.18.0.0/15
	if ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19) {
		return true
	}
	// Reserved for future use 240.0.0.0/4
	if ip4[0] >= 240 {
		return true
	}
	return false
}

// refreshPublicIP rediscovers (best-effort) and updates the process cache.
// Returns the cached value (possibly empty if discovery failed and cache was empty).
func refreshPublicIP() string {
	ip := discoverPublicIPv4()
	publicIPMu.Lock()
	defer publicIPMu.Unlock()
	if ip != "" {
		cachedPublicIP = ip
	}
	return cachedPublicIP
}

func getCachedPublicIP() string {
	publicIPMu.Lock()
	defer publicIPMu.Unlock()
	return cachedPublicIP
}
