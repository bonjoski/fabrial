package circuitbreaker

import (
	"errors"
	"fmt"
	"time"
)

// FreezeResult captures the outcome and latency of a process suspension.
type FreezeResult struct {
	PID           int
	Method        string // "sigstop", "cgroup_v2"
	Latency       time.Duration
	AlreadyFrozen bool
}

// Freeze freezes the offending process tree immediately.
func Freeze(pid int) (*FreezeResult, error) {
	if pid <= 1 {
		return nil, fmt.Errorf("refusing to freeze system or invalid PID: %d", pid)
	}

	start := time.Now()
	method, err := freezeProcessTree(pid)
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
