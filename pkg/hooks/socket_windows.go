//go:build windows

package hooks

import (
	"fmt"
	"os"
)

func verifySocketSecurity(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: socket %s is a symlink", ErrHooksSymlinkDetected, path)
	}
	return nil
}
