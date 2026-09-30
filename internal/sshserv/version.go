package sshserv

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"strings"
	"sync"
)

// DefaultVersion is the SSH identification string used when no override is
// set and no host key secret is available to pick a per-install default.
const DefaultVersion = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.19"

// DefaultVersions are stock OpenSSH identification strings of currently
// supported Ubuntu / Debian releases (package versions as published in
// Sept 2026; the ident is "OpenSSH_<upstream> <Distro>-<revision>"). Each
// install picks one with VersionForSecret, so JARNIS sensors do not all share
// one banner. Refresh when the distributions ship new revisions.
var DefaultVersions = []string{
	DefaultVersion, // Ubuntu 24.04 noble-updates/-security 1:9.6p1-3ubuntu13.19
	"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.15", // Ubuntu 24.04, earlier update
	"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.17",  // Ubuntu 22.04 jammy-updates/-security
	"SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3.6",  // Ubuntu 26.04 resolute-updates/-security
	"SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3",    // Ubuntu 26.04 release
	"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10",   // Debian 12 bookworm (point release)
	"SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4",   // Debian 13 trixie (point release)
	"SSH-2.0-OpenSSH_10.0p2 Debian-7",           // Debian 13 trixie release
}

// maxVersionLen keeps "<version>\r\n" within the 255 bytes of RFC 4253 4.2.
const maxVersionLen = 253

// ValidVersion reports whether v is a usable SSH-2.0 identification string
// (RFC 4253 4.2): "SSH-2.0-<softwareversion>[ <comments>]", printable
// US-ASCII only, softwareversion non-empty without '-' or spaces.
func ValidVersion(v string) bool {
	const prefix = "SSH-2.0-"
	if !strings.HasPrefix(v, prefix) || len(v) > maxVersionLen {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7e {
			return false
		}
	}
	sw := v[len(prefix):]
	if i := strings.IndexByte(sw, ' '); i >= 0 {
		sw = sw[:i]
	}
	return sw != "" && !strings.Contains(sw, "-")
}

// VersionForSecret picks one of DefaultVersions with HMAC-SHA256 keyed by
// secret (the PEM of the persisted PRIVATE host key). It must not depend on
// public data only: the repository is public, so a choice derived from the
// public host key could be recomputed by a scanner and used to spot JARNIS
// sensors. The key is persisted on the state volume, so the choice is stable
// per install and differs between installs.
func VersionForSecret(secret []byte) string {
	if len(secret) == 0 || len(DefaultVersions) == 0 {
		return DefaultVersion
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("jarnis-honeypot/ssh-ident/v1"))
	sum := mac.Sum(nil)
	n := binary.BigEndian.Uint64(sum[:8])
	return DefaultVersions[n%uint64(len(DefaultVersions))]
}

// identSentConn swallows the library's own identification line: the server
// writes it itself right after accept (before reading anything from the
// client), and x/crypto/ssh writes the very same bytes again as its first
// write in NewServerConn. Any other first write passes through unchanged.
type identSentConn struct {
	net.Conn
	sent []byte
	mu   sync.Mutex
	done bool
}

func (c *identSentConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if !c.done {
		c.done = true
		if bytes.Equal(p, c.sent) {
			c.mu.Unlock()
			return len(p), nil
		}
	}
	c.mu.Unlock()
	return c.Conn.Write(p)
}
