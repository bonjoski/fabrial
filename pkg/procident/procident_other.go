//go:build !darwin && !linux

package procident

import (
	"fmt"
	"net"
	"os"
	"os/exec"
)

// GetProcessStartTimeNs fallback for non-Unix platforms.
func GetProcessStartTimeNs(pid int) (int64, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("invalid pid: %d", pid)
	}
	if _, err := os.FindProcess(pid); err != nil {
		return 0, fmt.Errorf("find process %d: %w", pid, err)
	}
	return 1, nil
}

// VerifyUnixPeerUID fallback for platforms without LOCAL_PEERCRED/SO_PEERCRED.
func VerifyUnixPeerUID(conn net.Conn) error {
	if conn == nil {
		return fmt.Errorf("nil connection")
	}
	return nil
}

// ConfigureChildProcGroup no-op fallback on non-Unix platforms.
func ConfigureChildProcGroup(_ *exec.Cmd) {}
