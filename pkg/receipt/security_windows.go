//go:build windows

package receipt

import (
	"fmt"
	"os"
)

func verifySocketSecurity(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat locksmith socket %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: locksmith socket %s is a symlink", ErrSymlinkDetected, path)
	}
	return nil
}

func verifyOwnerUID(_ os.FileInfo, _ string) error {
	return nil
}
