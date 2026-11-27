//go:build !windows

package topui

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// killVerifiedProcessGroup dispatches SIGKILL to the target's verified process group
// (-pgid), refusing to target PID <= 1 or the caller's own process group.
func killVerifiedProcessGroup(pid int) error {
	if pid <= 1 || pid == os.Getpid() {
		return fmt.Errorf("refusing to signal protected pid %d", pid)
	}
	selfPGID, err := syscall.Getpgid(os.Getpid())
	if err != nil {
		selfPGID = -1
	}
	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	if pgid > 1 && pgid != selfPGID {
		if kErr := syscall.Kill(-pgid, syscall.SIGKILL); kErr != nil && !errors.Is(kErr, syscall.ESRCH) {
			return kErr
		}
		return nil
	}
	// If target shares our own PGID, signal only the specific verified PID.
	if kErr := syscall.Kill(pid, syscall.SIGKILL); kErr != nil && !errors.Is(kErr, syscall.ESRCH) {
		return kErr
	}
	return nil
}
