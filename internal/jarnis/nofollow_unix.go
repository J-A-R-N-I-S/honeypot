//go:build unix

package jarnis

import "syscall"

// openFlagsNoFollow: never follow a symlink in the last path component, and
// never block on a FIFO/device when opening.
const openFlagsNoFollow = syscall.O_NOFOLLOW | syscall.O_NONBLOCK
