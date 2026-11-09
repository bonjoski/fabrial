package queue

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAdversarial_FAB08_EightSubagentFlockConcurrency verifies that N=8 parallel autonomous
// subagents coordinating via a flock-backed MicroVMQueue never exceed MaxSlots (2) concurrently.
func TestAdversarial_FAB08_EightSubagentFlockConcurrency(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix flock concurrency matrix")
	}

	lockDir := t.TempDir()
	const subagents = 8
	const maxSlots = 2

	var currentActive atomic.Int32
	var peakActive atomic.Int32
	var completed atomic.Int32
	var wg sync.WaitGroup

	for i := 0; i < subagents; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Each subagent creates its own MicroVMQueue instance pointing at the shared flock dir
			q := NewCrossProcessMicroVMQueue(
				lockDir,
				WithMaxSlots(maxSlots),
				WithMaxQueueCapacity(16),
				WithPerSessionLimit(1),
				WithDefaultWaitTimeout(5*time.Second),
			)
			lease, err := q.AcquireSlot(context.Background(), WorkloadRequest{
				SessionID: "subagent_" + string(rune('A'+idx)),
				Command:   []string{"aegisbox", "exec"},
			})
			if err != nil {
				t.Errorf("subagent %d failed to acquire slot: %v", idx, err)
				return
			}
			cur := currentActive.Add(1)
			for {
				prev := peakActive.Load()
				if cur <= prev || peakActive.CompareAndSwap(prev, cur) {
					break
				}
			}
			time.Sleep(25 * time.Millisecond)
			currentActive.Add(-1)
			lease.Release()
			completed.Add(1)
		}(i)
	}

	wg.Wait()

	if completed.Load() != subagents {
		t.Fatalf("expected all %d subagents to complete cleanly, got %d", subagents, completed.Load())
	}
	if peakActive.Load() > maxSlots {
		t.Fatalf("FAIL-OPEN (FAB-08): peak concurrent microVMs reached %d, exceeding MaxSlots=%d!", peakActive.Load(), maxSlots)
	}
}
