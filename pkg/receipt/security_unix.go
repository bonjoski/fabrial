//go:build !windows

package receipt

import (
	"fmt"
	"os"
	"syscall"
)

func verifySocketSecurity(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat locksmith socket %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: locksmith socket %s is a symlink", ErrSymlinkDetected, path)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("path %s is not a unix domain socket", path)
	}
	if fi.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("%w: locksmith socket %s has overly permissive mode %04o (require 0600)", ErrUnsafePermissions, path, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if st.Uid != uint32(os.Getuid()) {
			return fmt.Errorf("%w: locksmith socket %s owned by uid %d (want %d)", ErrUnsafePermissions, path, st.Uid, os.Getuid())
		}
	}
	return nil
}

func verifyOwnerUID(fi os.FileInfo, label string) error {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if st.Uid != uint32(os.Getuid()) {
			return fmt.Errorf("%w: %s owned by uid %d (want %d)", ErrUnsafePermissions, label, st.Uid, os.Getuid())
		}
	}
	return nil
}
