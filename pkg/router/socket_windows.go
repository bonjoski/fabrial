//go:build windows

package router

import (
	"os"
)

func verifySocketSecurity(fi os.FileInfo) bool {
	// On Windows, Unix domain sockets are emulated or named pipes are used.
	// Symlink checks still apply.
	if fi.Mode()&os.ModeSymlink != 0 {
		return false
	}
	return true
}
