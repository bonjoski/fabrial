//go:build !windows

package doctor

import (
	"os"
	"syscall"
)

// VerifySocketSecurity validates that a socket file is not a symlink,
// has strict 0600 or 0700 permissions (no group/other access),
// and is owned by the current user.
func VerifySocketSecurity(path string) (bool, string) {
	fi, err := os.Lstat(path)
	if err != nil {
		return false, "socket file not accessible"
	}

	if fi.Mode()&os.ModeSymlink != 0 {
		return false, "insecure symlink detected (symlinked sockets forbidden)"
	}

	if fi.Mode()&os.ModeSocket == 0 {
		return false, "path exists but is not a valid unix domain socket"
	}

	if fi.Mode().Perm()&0077 != 0 {
		return false, "insecure permissions (must not permit group or world access; chmod 0600 required)"
	}

	if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
		if stat.Uid != uint32(os.Getuid()) {
			return false, "socket owned by another user (uid mismatch)"
		}
	}

	return true, ""
}
