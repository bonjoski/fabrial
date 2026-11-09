//go:build !windows

package supervisor

import (
	"fmt"
	"os"
	"syscall"
)

func verifyPIDFileOwnership(fi os.FileInfo) error {
	if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
		if stat.Uid != uint32(os.Getuid()) {
			return fmt.Errorf("PID file owned by UID %d, expected %d", stat.Uid, os.Getuid())
		}
	}
	return nil
}

func isProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}

func signalDaemonGroup(pid int, force bool) error {
	sig := syscall.SIGTERM
	if force {
		sig = syscall.SIGKILL
	}
	if pgid, err := syscall.Getpgid(pid); err == nil && pgid > 1 && pgid == pid {
		_ = syscall.Kill(-pid, sig)
	}
	return syscall.Kill(pid, sig)
}
