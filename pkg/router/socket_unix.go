//go:build !windows

package router

import (
	"os"
	"syscall"
)

func verifySocketSecurity(fi os.FileInfo) bool {
	// Must be a socket and NOT a symlink
	if fi.Mode()&os.ModeSymlink != 0 || fi.Mode()&os.ModeSocket == 0 {
		return false
	}

	// Invariant: Fail-closed if socket permission is insecure (must not permit group/other access)
	if fi.Mode().Perm()&0077 != 0 {
		return false
	}

	// Verify UID ownership on Unix
	if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
		if stat.Uid != uint32(os.Getuid()) {
			return false
		}
	}

	return true
}
