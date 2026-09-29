package sshserv

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// DefaultVersion is the SSH identification string used when no override is
// set and no host key is available to pick a per-install default.
const DefaultVersion = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"

// DefaultVersions are realistic stock OpenSSH identification strings of
// current Ubuntu / Debian LTS releases. Each install picks one
// deterministically from its host key (see VersionForHostKey), so JARNIS
// sensors do not all share one fingerprint.
var DefaultVersions = []string{
	DefaultVersion, // Ubuntu 24.04
	"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.8", // Ubuntu 24.04
	"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10", // Ubuntu 22.04
	"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",  // Ubuntu 22.04
	"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",   // Debian 12
	"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u5",   // Debian 12
	"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",   // Debian 11
	"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11", // Ubuntu 20.04
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

// VersionForHostKey picks one of DefaultVersions from the SHA-256 of the host
// public key. The host key is persisted on the state volume, so the choice is
// stable across restarts and recreates of one install and differs between
// installs.
func VersionForHostKey(pub ssh.PublicKey) string {
	if pub == nil || len(DefaultVersions) == 0 {
		return DefaultVersion
	}
	sum := sha256.Sum256(pub.Marshal())
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
