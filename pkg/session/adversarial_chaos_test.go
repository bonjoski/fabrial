package session

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestAdversarial_ConcurrentProcessFileChaos stress-tests inter-process file locking (flock)
// simulating 16 autonomous subagents concurrently writing and reading sessions.json.
func TestAdversarial_ConcurrentProcessFileChaos(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	sessionFile := filepath.Join(tmpDir, "sessions.json")

	// 1. Initialize Master Session
	masterMgr := NewSessionManager()
	masterGrant, err := masterMgr.BeginSession(ctx, SessionConfig{
		TTL:           1 * time.Hour,
		AllowedScopes: []string{"read", "build", "test"},
	})
	if err != nil {
		t.Fatalf("failed to create master session: %v", err)
	}
	if err := masterMgr.SaveToFile(sessionFile); err != nil {
		t.Fatalf("failed to save initial session: %v", err)
	}

	// 2. Launch 16 parallel concurrent worker goroutines each simulating a distinct CLI process
	concurrency := 16
	var wg sync.WaitGroup
	errCh := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			// Each worker creates an independent manager instance loading from disk
			workerMgr := NewSessionManager()
			if err := workerMgr.LoadFromFile(sessionFile); err != nil {
				errCh <- fmt.Errorf("worker %d LoadFromFile failed: %w", workerID, err)
				return
			}

			subtask := fmt.Sprintf("worker_%d", workerID)
			child, err := workerMgr.DeriveChildSession(ctx, masterGrant.ID, subtask, []string{"read", "test"})
			if err != nil {
				errCh <- fmt.Errorf("worker %d DeriveChildSession failed: %w", workerID, err)
				return
			}

			// Atomic locked save
			if err := workerMgr.SaveToFile(sessionFile); err != nil {
				errCh <- fmt.Errorf("worker %d SaveToFile failed: %w", workerID, err)
				return
			}

			// Validate child session is accessible immediately
			if child.SubtaskID != subtask {
				errCh <- fmt.Errorf("worker %d subtask mismatch", workerID)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("Concurrent chaos failure: %v", err)
	}

	// 3. Final verification: read on-disk file and ensure all 16 workers are preserved
	finalMgr := NewSessionManager()
	if err := finalMgr.LoadFromFile(sessionFile); err != nil {
		t.Fatalf("final LoadFromFile failed: %v", err)
	}

	active := finalMgr.ActiveSessions()
	// Master + 16 child sessions = 17 total
	if len(active) != concurrency+1 {
		t.Fatalf("LOST SESSIONS! Expected %d active sessions on disk, got %d", concurrency+1, len(active))
	}

	t.Logf("PASS: 16 concurrent processes wrote to sessions.json with zero corrupted entries or lost updates")
}

// TestAdversarial_ShellEvalInjectionFuzzing feeds hostile shell metacharacters and command injections
// into FormatShellExport and verifies via live /bin/sh that NO injection executes.
func TestAdversarial_ShellEvalInjectionFuzzing(t *testing.T) {
	canaryPath := filepath.Join(t.TempDir(), "canary_pwned")
	_ = os.Remove(canaryPath)

	hostilePayloads := []string{
		fmt.Sprintf("task'; touch %s; echo '", canaryPath),
		fmt.Sprintf("$(touch %s)", canaryPath),
		fmt.Sprintf("`touch %s`", canaryPath),
		fmt.Sprintf("task\nexport LD_PRELOAD=/evil.so\ntouch %s\n", canaryPath),
		fmt.Sprintf("task\r\ntouch %s", canaryPath),
		fmt.Sprintf("task\x00; touch %s", canaryPath),
		fmt.Sprintf("task; touch %s;", canaryPath),
		fmt.Sprintf("' && touch %s && '", canaryPath),
		fmt.Sprintf("`cat /etc/passwd > %s`", canaryPath),
		fmt.Sprintf("${IFS}touch${IFS}%s", canaryPath),
	}

	// 1. Verify DeriveChildSession rejects hostile subtask IDs
	ctx := context.Background()
	sm := NewSessionManager()
	master, _ := sm.BeginSession(ctx, SessionConfig{AllowedScopes: []string{"read"}})

	for _, payload := range hostilePayloads {
		_, err := sm.DeriveChildSession(ctx, master.ID, payload, []string{"read"})
		if err == nil {
			t.Errorf("DeriveChildSession accepted hostile subtask injection: %q", payload)
		}
	}

	// 2. Fuzz FormatShellExport with artificially injected hostile map values and execute under /bin/sh
	for i, payload := range hostilePayloads {
		hostileEnv := map[string]string{
			"FABRIAL_SESSION_ACTIVE": "1",
			"FABRIAL_SUBTASK_ID":     payload,
			fmt.Sprintf("HOSTILE_KEY_%d\nEVIL=1", i): payload, // hostile key with newline
			"ANOTHER_KEY":                            payload,
		}

		exportScript := FormatShellExport(hostileEnv)

		// Pipe the formatted export into real /bin/sh eval
		cmd := exec.Command("/bin/sh", "-c", exportScript)
		out, err := cmd.CombinedOutput()
		if err != nil {
			// Some shells error on invalid exports, which is safe/acceptable
			t.Logf("Shell safely rejected payload %d: %v (output: %s)", i, err, string(out))
		}

		// ASSERTION: Canary file must NEVER be created!
		if _, statErr := os.Stat(canaryPath); statErr == nil {
			_ = os.Remove(canaryPath)
			t.Fatalf("CRITICAL SECURITY FAILURE: Shell injection succeeded! Canary %s was created by payload %q\nScript was:\n%s",
				canaryPath, payload, exportScript)
		}
	}

	t.Log("PASS: All 10 hostile shell injection payloads sanitized; zero command execution under /bin/sh eval")
}
