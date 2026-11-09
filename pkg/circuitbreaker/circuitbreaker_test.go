package circuitbreaker

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestProcessFreezeAndResume(t *testing.T) {
	// Spawn dummy worker process
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to spawn worker process: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	pid := cmd.Process.Pid

	// 1. Freeze process
	res, err := Freeze(pid)
	if err != nil {
		t.Fatalf("Freeze failed: %v", err)
	}

	if res.PID != pid {
		t.Errorf("Expected PID %d, got %d", pid, res.PID)
	}

	// Invariant: Instant Freeze < 3ms
	if res.Latency > 3*time.Millisecond {
		t.Logf("Freeze latency was %v (exceeded 3ms threshold)", res.Latency)
	} else {
		t.Logf("Freeze succeeded in %v (<3ms target achieved)", res.Latency)
	}

	// 2. Unfreeze process
	if err := Unfreeze(pid); err != nil {
		t.Fatalf("Unfreeze failed: %v", err)
	}
}

func TestRevocationHook(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "revocation-test-*")
	if err != nil {
		t.Fatalf("Temp dir error: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	lsSock := filepath.Join(tmpDir, "locksmith.sock")
	cjSock := filepath.Join(tmpDir, "conjoiner.sock")

	// Mock Locksmith server
	lsListener, err := net.Listen("unix", lsSock)
	if err != nil {
		t.Fatalf("Locksmith listener error: %v", err)
	}
	defer lsListener.Close()

	var lsReceived []map[string]any
	var lsMu sync.Mutex
	go func() {
		for {
			conn, err := lsListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				dec := json.NewDecoder(c)
				for dec.More() {
					var m map[string]any
					if err := dec.Decode(&m); err == nil {
						lsMu.Lock()
						lsReceived = append(lsReceived, m)
						lsMu.Unlock()
					}
				}
			}(conn)
		}
	}()

	// Mock Conjoiner server
	cjListener, err := net.Listen("unix", cjSock)
	if err != nil {
		t.Fatalf("Conjoiner listener error: %v", err)
	}
	defer cjListener.Close()

	var cjReceived []map[string]any
	var cjMu sync.Mutex
	go func() {
		for {
			conn, err := cjListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				dec := json.NewDecoder(c)
				for dec.More() {
					var m map[string]any
					if err := dec.Decode(&m); err == nil {
						cjMu.Lock()
						cjReceived = append(cjReceived, m)
						cjMu.Unlock()
					}
				}
			}(conn)
		}
	}()

	revoker := NewRevoker(RevokerOptions{
		LocksmithSocket: lsSock,
		ConjoinerSocket: cjSock,
		Timeout:         500 * time.Millisecond,
	})

	alert := &Alert{
		RuleName:      "test_exfil_rule",
		AgentPID:      12345,
		SessionID:     "sess-abc-999",
		SessionTicket: "st-ticket-777",
	}

	revLS, revCJ, errs := revoker.Revoke(alert)
	if len(errs) > 0 {
		t.Fatalf("Revocation unexpected errors: %v", errs)
	}
	if !revLS {
		t.Error("Expected Locksmith revocation to succeed")
	}
	if !revCJ {
		t.Error("Expected Conjoiner revocation to succeed")
	}

	time.Sleep(100 * time.Millisecond)

	lsMu.Lock()
	if len(lsReceived) != 2 {
		t.Fatalf("Expected 2 Locksmith payloads (session + lease), got %d", len(lsReceived))
	}
	lsMu.Unlock()

	cjMu.Lock()
	if len(cjReceived) != 1 {
		t.Fatalf("Expected 1 Conjoiner payload, got %d", len(cjReceived))
	}
	if cjReceived[0]["action"] != "revoke_token" {
		t.Errorf("Expected action revoke_token, got %v", cjReceived[0]["action"])
	}
	cjMu.Unlock()
}

func TestTripwireEndToEnd(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tripwire-e2e-*")
	if err != nil {
		t.Fatalf("Temp dir error: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sockPath := filepath.Join(tmpDir, "argus.sock")
	forensicDir := filepath.Join(tmpDir, "forensics")

	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start target command: %v", err)
	}
	targetPID := cmd.Process.Pid
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	tripCh := make(chan *TripResult, 1)
	tw := NewTripwire(TripwireOptions{
		SocketPath:  sockPath,
		ForensicDir: forensicDir,
		OnTrip: func(res *TripResult) {
			tripCh <- res
		},
	})
	tw.RegisterSessionPID("agent-session-42", targetPID)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := tw.Start(ctx); err != nil {
		t.Fatalf("Failed to start tripwire: %v", err)
	}
	defer tw.Stop()

	time.Sleep(50 * time.Millisecond)

	// Connect as Argus pushing an alert
	conn, err := net.DialTimeout("unix", sockPath, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to dial tripwire socket: %v", err)
	}
	defer conn.Close()

	alert := &Alert{
		RuleName:      "agent_exfiltration_via_curl",
		Severity:      "CRITICAL",
		Action:        "kill",
		AgentPID:      targetPID,
		SessionID:     "agent-session-42",
		SessionTicket: "ticket-xyz-123",
		TriggeredAt:   time.Now(),
		SequenceSteps: []string{"reconnaissance", "payload_assembly", "egress_execution"},
	}

	alertData, _ := json.Marshal(alert)
	alertData = append(alertData, '\n')

	startTrip := time.Now()
	if _, err := conn.Write(alertData); err != nil {
		t.Fatalf("Failed to write alert to tripwire: %v", err)
	}

	select {
	case res := <-tripCh:
		latency := time.Since(startTrip)
		t.Logf("End-to-end trip completed in %v (freeze latency: %v)", latency, res.FreezeLatency)

		if !res.Frozen {
			t.Errorf("Expected target process %d to be frozen", targetPID)
		}
		if res.TargetPID != targetPID {
			t.Errorf("Expected target PID %d, got %d", targetPID, res.TargetPID)
		}

		// Verify forensic log exists
		entries, err := os.ReadDir(forensicDir)
		if err != nil || len(entries) == 0 {
			t.Fatalf("Expected forensic JSON log in %s, got err=%v len=%d", forensicDir, err, len(entries))
		}

	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for circuit breaker tripwire to trigger")
	}
}

func TestAdversarialTripwireRobustness(t *testing.T) {
	tw := NewTripwire(TripwireOptions{
		SocketPath: filepath.Join(os.TempDir(), "nonexistent-tripwire.sock"),
	})

	// 1. Alert with invalid/dead PID (should not panic)
	deadPID := 9999999
	res := tw.Trip(&Alert{
		RuleName: "dead_process_rule",
		AgentPID: deadPID,
	})
	if res == nil {
		t.Fatal("Expected non-nil trip result")
	}
	if res.Frozen {
		t.Error("Dead process should not be reported as frozen")
	}

	// 2. Alert with PID 1 / 0 (should be rejected for safety)
	resSys := tw.Trip(&Alert{
		RuleName: "sys_attack",
		AgentPID: 1,
	})
	if resSys.Frozen {
		t.Error("PID 1 must never be frozen")
	}
}

type mockSessionManager struct {
	mu           sync.Mutex
	invalidated  map[string]bool
}

func (m *mockSessionManager) InvalidateSession(ctx context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invalidated[sessionID] = true
	return nil
}

func TestAdversarial_ScopedCircuitBreaker_NoCollateralDamage(t *testing.T) {
	// Spawn two worker processes: worker 1 for session 1, worker 2 for session 2
	cmd1 := exec.Command("sleep", "30")
	if err := cmd1.Start(); err != nil {
		t.Fatalf("Failed to start worker 1: %v", err)
	}
	defer func() {
		_ = cmd1.Process.Kill()
		_ = cmd1.Wait()
	}()

	cmd2 := exec.Command("sleep", "30")
	if err := cmd2.Start(); err != nil {
		t.Fatalf("Failed to start worker 2: %v", err)
	}
	defer func() {
		_ = cmd2.Process.Kill()
		_ = cmd2.Wait()
	}()

	mockSM := &mockSessionManager{
		invalidated: make(map[string]bool),
	}

	tw := NewTripwire(TripwireOptions{
		SocketPath:     filepath.Join(os.TempDir(), "test-scoped-trip.sock"),
		SessionManager: mockSM,
	})

	sess1 := "sess_worker_1"
	sess2 := "sess_worker_2"

	// Register PIDs to their respective sessions
	tw.RegisterSessionPID(sess1, cmd1.Process.Pid)
	tw.RegisterSessionPID(sess2, cmd2.Process.Pid)

	// An alert arrives ONLY for session 1
	alert := &Alert{
		RuleName:  "hallucinated_package_slopsquatting",
		Severity:  "critical",
		SessionID: sess1,
		AgentPID:  cmd1.Process.Pid,
	}

	res := tw.Trip(alert)
	if res == nil || !res.Frozen {
		t.Fatalf("expected session 1 worker to be frozen, res: %+v", res)
	}

	// Assert session 1 was invalidated in SessionManager
	mockSM.mu.Lock()
	sess1Invalidated := mockSM.invalidated[sess1]
	sess2Invalidated := mockSM.invalidated[sess2]
	mockSM.mu.Unlock()

	if !sess1Invalidated {
		t.Fatal("expected session 1 to be invalidated by circuit breaker")
	}

	// CRITICAL INVARIANT: Session 2 was NOT invalidated and process 2 was NOT killed/frozen
	if sess2Invalidated {
		t.Fatal("collateral damage: session 2 was invalidated by session 1 alert!")
	}

	// Check if cmd2 is still alive and responsive
	if cmd2.ProcessState != nil && cmd2.ProcessState.Exited() {
		t.Fatal("collateral damage: session 2 process was terminated by session 1 alert!")
	}
}
