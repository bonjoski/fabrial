package circuitbreaker

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestSimulatedMultiStepExfiltrationTriggeringCircuitBreaker tests the full causal chain:
// Step 1: Recon -> Step 2: Read -> Step 3: Kernel Egress -> Alert dispatched over Unix socket ->
// Fabrial Tripwire catches alert -> Offending agent process is FROZEN (<3ms) -> Credentials revoked.
func TestSimulatedMultiStepExfiltrationTriggeringCircuitBreaker(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "quarry-cb-integ-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sockPath := filepath.Join(tmpDir, "argus.sock")
	lsSock := filepath.Join(tmpDir, "locksmith.sock")
	cjSock := filepath.Join(tmpDir, "conjoiner.sock")
	forensicDir := filepath.Join(tmpDir, "forensics")

	// 1. Mock Locksmith & Conjoiner Sockets
	lsListener, _ := net.Listen("unix", lsSock)
	defer lsListener.Close()
	var revokedTickets []string
	var mockMu sync.Mutex
	go func() {
		for {
			c, err := lsListener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				dec := json.NewDecoder(conn)
				for dec.More() {
					var p map[string]any
					if err := dec.Decode(&p); err == nil {
						if tk, ok := p["ticket_id"].(string); ok {
							mockMu.Lock()
							revokedTickets = append(revokedTickets, tk)
							mockMu.Unlock()
						}
					}
				}
			}(c)
		}
	}()

	cjListener, _ := net.Listen("unix", cjSock)
	defer cjListener.Close()
	var revokedSessions []string
	go func() {
		for {
			c, err := cjListener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				dec := json.NewDecoder(conn)
				for dec.More() {
					var p map[string]any
					if err := dec.Decode(&p); err == nil {
						if sess, ok := p["session_id"].(string); ok {
							mockMu.Lock()
							revokedSessions = append(revokedSessions, sess)
							mockMu.Unlock()
						}
					}
				}
			}(c)
		}
	}()

	// 2. Launch target agent process
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start target agent process: %v", err)
	}
	targetPID := cmd.Process.Pid
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	// 3. Launch Fabrial Circuit Breaker Tripwire
	tripCh := make(chan *TripResult, 1)
	tw := NewTripwire(TripwireOptions{
		SocketPath:      sockPath,
		LocksmithSocket: lsSock,
		ConjoinerSocket: cjSock,
		ForensicDir:     forensicDir,
		OnTrip: func(res *TripResult) {
			tripCh <- res
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := tw.Start(ctx); err != nil {
		t.Fatalf("Failed to start tripwire: %v", err)
	}
	defer tw.Stop()

	time.Sleep(50 * time.Millisecond)

	// 4. Connect Argus alert dispatcher to socket
	argusConn, err := net.DialTimeout("unix", sockPath, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to connect to tripwire socket: %v", err)
	}
	defer argusConn.Close()

	// 5. Construct simulated Quarry multi-step exfiltration alert
	attackAlert := &Alert{
		RuleName:      "agent_exfiltration_via_curl",
		RuleVersion:   "1.0",
		Severity:      "CRITICAL",
		Action:        "kill",
		AgentPID:      targetPID,
		SessionID:     "agent-session-adversarial-01",
		SessionTicket: "st-session-ticket-secret-99",
		TriggeredAt:   time.Now(),
		SequenceSteps: []string{"reconnaissance", "payload_assembly", "egress_execution"},
		MatchedEvents: []MatchedEvent{
			{
				Layer:     "l7_mcp",
				Action:    "list_directory",
				Path:      "/workspace/.env",
				Timestamp: time.Now().Add(-10 * time.Second),
			},
			{
				Layer:     "l7_mcp",
				Action:    "read_file",
				Path:      "/workspace/.env",
				Timestamp: time.Now().Add(-5 * time.Second),
			},
			{
				Layer:       "l3_kernel",
				Action:      "syscall_connect",
				Destination: "attacker-exfil.xyz:443",
				Timestamp:   time.Now(),
			},
		},
	}

	// 6. Dispatch alert over argus.sock
	payload, _ := json.Marshal(attackAlert)
	payload = append(payload, '\n')

	dispatchStart := time.Now()
	if _, err := argusConn.Write(payload); err != nil {
		t.Fatalf("Failed to dispatch alert: %v", err)
	}

	// 7. Verify Tripwire caught alert and froze offending process
	select {
	case res := <-tripCh:
		totalLatency := time.Since(dispatchStart)
		t.Logf("Circuit breaker tripped in %v (process freeze latency: %v)", totalLatency, res.FreezeLatency)

		if !res.Frozen {
			t.Fatalf("Target process %d was NOT frozen", targetPID)
		}
		if res.TargetPID != targetPID {
			t.Errorf("Expected target PID %d, got %d", targetPID, res.TargetPID)
		}

		// Verify freeze latency < 3ms
		if res.FreezeLatency > 3*time.Millisecond {
			t.Errorf("Freeze latency %v exceeded 3ms SLA threshold", res.FreezeLatency)
		}

		// Verify process is actually frozen (cannot execute or is in stopped state)
		// On Unix, sending signal 0 confirms process exists
		if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
			t.Errorf("Process unexpectedly died instead of pausing: %v", err)
		}

		// Verify session revocations dispatched
		time.Sleep(50 * time.Millisecond)
		mockMu.Lock()
		if len(revokedTickets) == 0 || revokedTickets[0] != "st-session-ticket-secret-99" {
			t.Errorf("Locksmith ticket revocation missing or incorrect: %v", revokedTickets)
		}
		if len(revokedSessions) == 0 || revokedSessions[0] != "agent-session-adversarial-01" {
			t.Errorf("Conjoiner session revocation missing or incorrect: %v", revokedSessions)
		}
		mockMu.Unlock()

		// Verify forensic log
		entries, err := os.ReadDir(forensicDir)
		if err != nil || len(entries) == 0 {
			t.Errorf("Forensic log was not written to %s", forensicDir)
		}

	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for circuit breaker to freeze offending process")
	}
}
