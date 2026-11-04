package circuitbreaker

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

// TestAdversarial_PIDRecycling_DeadProcessRejection verifies that when a process exits
// before the tripwire signal arrives, Fabrial safely recognizes the dead PID and avoids
// misdirected signaling on recycled PIDs.
func TestAdversarial_PIDRecycling_DeadProcessRejection(t *testing.T) {
	cmd := exec.Command("sleep", "0.01")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start transient process: %v", err)
	}

	deadPID := cmd.Process.Pid
	_ = cmd.Wait() // Process is now definitively dead

	res, err := Freeze(deadPID)
	if err == nil {
		t.Fatalf("expected error when freezing dead PID %d, but Freeze succeeded: %+v", deadPID, res)
	}
	t.Logf("PASS: Dead PID %d safely rejected: %v", deadPID, err)
}

// TestAdversarial_PIDFreeze_SelfAndParentImmunity asserts that a rogue or hallucinated alert
// targeting the agent orchestrator itself or its parent caller is strictly rejected.
func TestAdversarial_PIDFreeze_SelfAndParentImmunity(t *testing.T) {
	selfPID := os.Getpid()
	parentPID := os.Getppid()

	// 1. Refuse freeze on self
	_, err := Freeze(selfPID)
	if err == nil {
		t.Fatalf("CRITICAL SECURITY VULNERABILITY: Freeze allowed targeting self PID %d!", selfPID)
	}
	t.Logf("PASS: Self PID %d freeze refused: %v", selfPID, err)

	// 2. Refuse freeze on parent caller
	if parentPID > 1 {
		_, err := Freeze(parentPID)
		if err == nil {
			t.Fatalf("CRITICAL SECURITY VULNERABILITY: Freeze allowed targeting parent PID %d!", parentPID)
		}
		t.Logf("PASS: Parent PID %d freeze refused: %v", parentPID, err)
	}

	// 3. Refuse freeze on system root PID 1
	_, err = Freeze(1)
	if err == nil {
		t.Fatal("CRITICAL: Freeze allowed targeting PID 1!")
	}
	t.Log("PASS: PID 1 freeze refused")
}

// TestAdversarial_HighConcurrency_TripwireFlood floods the circuit breaker with 50 concurrent
// tripwire alerts while processes are actively registering and unregistering, asserting zero deadlocks.
func TestAdversarial_HighConcurrency_TripwireFlood(t *testing.T) {
	tw := NewTripwire(TripwireOptions{
		SocketPath:  filepath.Join(t.TempDir(), "flood.sock"),
		ForensicDir: t.TempDir(),
	})

	workers := 50
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			sessID := "session_flood"
			fakePID := 100000 + id

			tw.RegisterSessionPID(sessID, fakePID)
			tw.UnregisterSessionPID(sessID, fakePID)

			// Trigger trip with alert
			alert := &Alert{
				RuleName:  "concurrency_flood_test",
				Severity:  "high",
				AgentPID:  999999, // dead PID
				SessionID: sessID,
			}
			_ = tw.Trip(alert)
		}(i)
	}

	wg.Wait()

	if tw.trippedCount.Load() != int64(workers) {
		t.Fatalf("expected trippedCount=%d, got %d", workers, tw.trippedCount.Load())
	}
	t.Logf("PASS: %d concurrent tripwire alerts handled with zero deadlocks or mutex lockups", workers)
}

// TestAdversarial_SessionTokenRevocationUnderContention tests rapid concurrent session derivations
// and invalidations under heavy load with race detector enabled.
func TestAdversarial_SessionTokenRevocationUnderContention(t *testing.T) {
	mockSM := &mockSessionManager{
		invalidated: make(map[string]bool),
	}

	tw := NewTripwire(TripwireOptions{
		SocketPath:     filepath.Join(t.TempDir(), "contention.sock"),
		ForensicDir:    t.TempDir(),
		SessionManager: mockSM,
	})

	workers := 30
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			sess := "sess_contention"
			alert := &Alert{
				RuleName:  "concurrent_revocation",
				SessionID: sess,
			}
			_ = tw.Trip(alert)
		}(i)
	}

	wg.Wait()

	mockSM.mu.Lock()
	invalidated := mockSM.invalidated["sess_contention"]
	mockSM.mu.Unlock()

	if !invalidated {
		t.Fatal("expected session to be invalidated under contention")
	}
	t.Log("PASS: Session revocation executed cleanly under concurrent contention")
}
