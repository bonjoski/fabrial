//go:build windows

package supervisor

import (
	"os"
)

func verifyPIDFileOwnership(_ os.FileInfo) error {
	return nil
}

func isProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil || proc == nil {
		return false
	}
	return true
}

func signalDaemonGroup(pid int, _ bool) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Kill()
}
