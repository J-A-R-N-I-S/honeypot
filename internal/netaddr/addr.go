package netaddr

import (
	"net"
	"strconv"
)

// Split pulls host and TCP/UDP port from net.Conn.RemoteAddr() / http.Request.RemoteAddr.
// Port is 0 if missing or invalid.
func Split(remote string) (host string, port int) {
	host, p, err := net.SplitHostPort(remote)
	if err != nil {
		return remote, 0
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return host, 0
	}
	return host, n
}
