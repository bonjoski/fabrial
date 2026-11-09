package circuitbreaker

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/bonjoski/fabrial/pkg/procident"
)

// ErrPIDRecycled indicates that a target PID's kernel start timestamp no longer matches
// the originally registered session child process.
var ErrPIDRecycled = errors.New("process start time mismatch (PID recycled)")

// FreezeResult captures the outcome and latency of a process suspension.
type FreezeResult struct {
	PID           int
	Method        string // "sigstop", "cgroup_v2"
	Latency       time.Duration
	AlreadyFrozen bool
}

// Freeze freezes the offending process tree immediately with self-freeze and PID-recycling checks.
func Freeze(pid int) (*FreezeResult, error) {
	startNs, _ := procident.GetProcessStartTimeNs(pid)
	return FreezeVerified(pid, startNs)
}

// FreezeVerified freezes pid only after verifying that its kernel process start timestamp
// matches expectedStartTimeNs (when expectedStartTimeNs > 0), preventing PID-recycling kills.
func FreezeVerified(pid int, expectedStartTimeNs int64) (*FreezeResult, error) {
	if pid <= 1 {
		return nil, fmt.Errorf("refusing to freeze system or invalid PID: %d", pid)
	}
	if pid == os.Getpid() || pid == os.Getppid() {
		return nil, fmt.Errorf("refusing to freeze self (PID %d) or caller parent (PID %d)", os.Getpid(), os.Getppid())
	}

	if err := verifyProcessTarget(pid); err != nil {
		return nil, err
	}

	if expectedStartTimeNs > 0 {
		actualStartNs, err := procident.GetProcessStartTimeNs(pid)
		if err != nil {
			return nil, fmt.Errorf("failed to verify process %d start time: %w", pid, err)
		}
		if actualStartNs != expectedStartTimeNs {
			return nil, fmt.Errorf("%w: pid %d expected start %d, got %d", ErrPIDRecycled, pid, expectedStartTimeNs, actualStartNs)
		}
	}

	start := time.Now()
	method, err := freezeProcessTree(pid, expectedStartTimeNs)
	latency := time.Since(start)

	if err != nil {
		return nil, fmt.Errorf("failed to freeze process %d: %w", pid, err)
	}

	return &FreezeResult{
		PID:     pid,
		Method:  method,
		Latency: latency,
	}, nil
}

// Unfreeze resumes a previously frozen process tree (primarily for testing and remediation).
func Unfreeze(pid int) error {
	if pid <= 1 {
		return errors.New("invalid PID")
	}
	return unfreezeProcessTree(pid)
}
