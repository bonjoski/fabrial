//go:build windows

package topui

import (
	"fmt"
	"os"
)

// killVerifiedProcessGroup terminates the verified process on Windows.
func killVerifiedProcessGroup(pid int) error {
	if pid <= 1 || pid == os.Getpid() {
		return fmt.Errorf("refusing to signal protected pid %d", pid)
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Kill()
}
