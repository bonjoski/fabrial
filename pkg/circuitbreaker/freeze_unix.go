//go:build !windows

package circuitbreaker

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/bonjoski/fabrial/pkg/procident"
)

func verifyProcessTarget(pid int) error {
	err := syscall.Kill(pid, 0)
	if err != nil {
		if err == syscall.ESRCH {
			return fmt.Errorf("process %d already exited (ESRCH)", pid)
		}
		if err == syscall.EPERM {
			return fmt.Errorf("refusing to freeze process %d: belongs to another user or privileged system context (EPERM)", pid)
		}
		return err
	}
	return nil
}

func freezeProcessTree(pid int, expectedStartTimeNs int64) (string, error) {
	if expectedStartTimeNs > 0 {
		actualStartNs, err := procident.GetProcessStartTimeNs(pid)
		if err != nil {
			return "", fmt.Errorf("process %d start time check failed: %w", pid, err)
		}
		if actualStartNs != expectedStartTimeNs {
			return "", fmt.Errorf("%w: pid %d expected %d, got %d", ErrPIDRecycled, pid, expectedStartTimeNs, actualStartNs)
		}
	}

	// 1. Check for Linux cgroup v2 freezer if available
	cgroupPath := findLinuxCgroup(pid)
	if cgroupPath != "" {
		freezeFile := filepath.Join(cgroupPath, "cgroup.freeze")
		if err := os.WriteFile(freezeFile, []byte("1\n"), 0644); err == nil {
			return "cgroup_v2", nil
		}
	}

	// 2. Fall back to standard POSIX SIGSTOP (works on macOS Darwin and Linux)
	// Signal dedicated process group first if child is process group leader (Setpgid: true)
	pgid, err := syscall.Getpgid(pid)
	if err == nil && pgid > 1 && pgid == pid {
		_ = syscall.Kill(-pid, syscall.SIGSTOP)
	}

	// Direct SIGSTOP to PID
	if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		return "", fmt.Errorf("sigstop failed: %w", err)
	}

	return "sigstop", nil
}

func unfreezeProcessTree(pid int) error {
	cgroupPath := findLinuxCgroup(pid)
	if cgroupPath != "" {
		freezeFile := filepath.Join(cgroupPath, "cgroup.freeze")
		if err := os.WriteFile(freezeFile, []byte("0\n"), 0644); err == nil {
			return nil
		}
	}

	// Send SIGCONT
	pgid, err := syscall.Getpgid(pid)
	if err == nil && pgid > 1 && pgid == pid {
		_ = syscall.Kill(-pid, syscall.SIGCONT)
	}
	return syscall.Kill(pid, syscall.SIGCONT)
}

func findLinuxCgroup(pid int) string {
	procCgroup := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(procCgroup)
	if err != nil {
		return ""
	}

	// Parse cgroup v2 hierarchy (0::/path)
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[0] == "0" {
			cgRel := strings.TrimPrefix(parts[2], "/")
			candidate := filepath.Join("/sys/fs/cgroup", cgRel)
			if _, err := os.Stat(filepath.Join(candidate, "cgroup.freeze")); err == nil {
				return candidate
			}
		}
	}
	return ""
}
