//go:build !windows

package hooks

import (
	"fmt"
	"os"
	"syscall"
)

// verifySocketSecurity enforces that a local UDS socket is non-symlink, mode 0600,
// and owned by the current user UID.
func verifySocketSecurity(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: socket %s is a symlink", ErrHooksSymlinkDetected, path)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("path %s is not a unix domain socket", path)
	}
	if fi.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("socket %s has unsafe mode %04o (require 0600)", path, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if st.Uid != uint32(os.Getuid()) {
			return fmt.Errorf("socket %s owned by uid %d (want %d)", path, st.Uid, os.Getuid())
		}
	}
	return nil
}
