package session

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestLauncher_SessionLaunch(t *testing.T) {
	sm := NewSessionManager()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cfg := LaunchConfig{
		Profile:       "test-agent",
		TargetCommand: "/bin/sh",
		TargetArgs:    []string{"-c", "if [ \"$FABRIAL_SESSION_ACTIVE\" != \"1\" ]; then exit 1; fi"},
		TTL:           10 * time.Minute,
		ProxyAddr:     "127.0.0.1:8443",
		UseAirlock:    false,
		Biometric:     false,
	}

	start := time.Now()
	err := LaunchSession(ctx, sm, cfg)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("LaunchSession failed: %v", err)
	}

	if elapsed > 500*time.Millisecond {
		t.Fatalf("expected launch to complete in < 500ms, took %v", elapsed)
	}

	// Verify session was registered in session manager
	sessions := sm.ActiveSessions()
	if len(sessions) == 0 {
		t.Fatalf("expected active session in manager")
	}
	if !sessions[0].IsMaster {
		t.Fatalf("expected master session")
	}

	// Clean up session file if created
	_ = os.Remove(DefaultSessionFilePath())
}
