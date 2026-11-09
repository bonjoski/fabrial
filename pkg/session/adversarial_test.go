package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestAdversarial_FAB01_FailClosedWhenAirlockMissing verifies that LaunchSession NEVER silently
// spawns TargetCommand unconfined when UseAirlock is true and airlock cannot be found.
func TestAdversarial_FAB01_FailClosedWhenAirlockMissing(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("FABRIAL_SESSION_FILE", filepath.Join(tmpDir, "sessions.json"))

	origResolver := resolveExecutable
	resolveExecutable = func(name string) (string, error) {
		return "", fmt.Errorf("%s binary missing", name)
	}
	t.Cleanup(func() {
		resolveExecutable = origResolver
	})

	markerFile := filepath.Join(tmpDir, "unconfined_executed.marker")
	sm := NewSessionManager()

	err := LaunchSession(context.Background(), sm, LaunchConfig{
		Profile:       "agent",
		TargetCommand: "touch",
		TargetArgs:    []string{markerFile},
		UseAirlock:    true,
	})
	if err == nil {
		t.Fatal("FAIL-OPEN (FAB-01): LaunchSession succeeded without airlock installed!")
	}
	if !errors.Is(err, ErrAirlockUnavailable) {
		t.Fatalf("expected ErrAirlockUnavailable, got: %v", err)
	}
	if _, statErr := os.Stat(markerFile); !os.IsNotExist(statErr) {
		t.Fatal("FAIL-OPEN (FAB-01): TargetCommand executed unconfined despite missing airlock!")
	}
}

// TestAdversarial_FAB01_NoSpoofedAirlockActiveSentinel verifies that BuildEnvironment and
// LaunchSession never inject AIRLOCK_ACTIVE=1 prior to actual Airlock confinement.
func TestAdversarial_FAB01_NoSpoofedAirlockActiveSentinel(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix shell env check")
	}

	envMap := BuildEnvironment("master_0123456789abcdef01234567", "", "tok_123", "127.0.0.1:8443", "")
	if _, exists := envMap["AIRLOCK_ACTIVE"]; exists {
		t.Fatalf("FAIL-OPEN (FAB-01): BuildEnvironment injected AIRLOCK_ACTIVE=%q before confinement", envMap["AIRLOCK_ACTIVE"])
	}
	if envMap["FABRIAL_SESSION_ACTIVE"] != "1" {
		t.Fatalf("expected FABRIAL_SESSION_ACTIVE=1, got %q", envMap["FABRIAL_SESSION_ACTIVE"])
	}

	tmpDir := t.TempDir()
	t.Setenv("FABRIAL_SESSION_FILE", filepath.Join(tmpDir, "sessions.json"))
	t.Setenv("AIRLOCK_ACTIVE", "")
	_ = os.Unsetenv("AIRLOCK_ACTIVE")

	origResolver := resolveExecutable
	resolveExecutable = func(name string) (string, error) {
		return "", fmt.Errorf("%s unavailable", name)
	}
	t.Cleanup(func() {
		resolveExecutable = origResolver
	})

	envDump := filepath.Join(tmpDir, "env.txt")
	sm := NewSessionManager()
	err := LaunchSession(context.Background(), sm, LaunchConfig{
		Profile:          "agent",
		TargetCommand:    "sh",
		TargetArgs:       []string{"-c", "printf '%s' \"${AIRLOCK_ACTIVE:-UNSET}\" > " + envDump},
		UseAirlock:       true,
		AllowUnsandboxed: true, // explicit --allow-degraded-local opt-in
	})
	if err != nil {
		t.Fatalf("expected explicit AllowUnsandboxed opt-in to run command, got: %v", err)
	}

	got, readErr := os.ReadFile(envDump)
	if readErr != nil {
		t.Fatalf("failed reading env dump: %v", readErr)
	}
	if string(got) != "UNSET" {
		t.Fatalf("FAIL-OPEN (FAB-01): degraded launch leaked AIRLOCK_ACTIVE=%q", string(got))
	}
}

// TestAdversarial_FAB04_RevokedSessionTombstonePreventsResurrection verifies that revoked
// sessions persist tombstones and cannot be resurrected by concurrent SaveToFile merges.
func TestAdversarial_FAB04_RevokedSessionTombstonePreventsResurrection(t *testing.T) {
	ctx := context.Background()
	sessionFile := filepath.Join(t.TempDir(), "sessions.json")

	// Process 1 mints master + child session and persists to disk
	sm1 := NewSessionManager()
	master, err := sm1.BeginSession(ctx, SessionConfig{
		TTL:           10 * time.Minute,
		AllowedScopes: []string{"read", "build"},
	})
	if err != nil {
		t.Fatalf("BeginSession failed: %v", err)
	}
	child, err := sm1.DeriveChildSession(ctx, master.ID, "subtask_1", []string{"read"})
	if err != nil {
		t.Fatalf("DeriveChildSession failed: %v", err)
	}
	if err := sm1.SaveToFile(sessionFile); err != nil {
		t.Fatalf("sm1 SaveToFile failed: %v", err)
	}

	// Process 2 loads sessions.json BEFORE revocation occurs (stale active copy in memory)
	sm2 := NewSessionManager()
	if err := sm2.LoadFromFile(sessionFile); err != nil {
		t.Fatalf("sm2 LoadFromFile failed: %v", err)
	}

	// Process 1 revokes master session (cascading to child) and saves tombstones to disk
	if err := sm1.InvalidateSession(ctx, master.ID); err != nil {
		t.Fatalf("InvalidateSession failed: %v", err)
	}
	if err := sm1.SaveToFile(sessionFile); err != nil {
		t.Fatalf("sm1 post-revoke SaveToFile failed: %v", err)
	}

	// Process 2 (holding stale unrevoked grant in memory) saves back to disk!
	if err := sm2.SaveToFile(sessionFile); err != nil {
		t.Fatalf("sm2 SaveToFile failed: %v", err)
	}

	// Process 3 loads from disk — neither master nor child may be resurrected!
	sm3 := NewSessionManager()
	if err := sm3.LoadFromFile(sessionFile); err != nil {
		t.Fatalf("sm3 LoadFromFile failed: %v", err)
	}

	if _, err := sm3.ValidateSession(master.ID); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("FAIL-OPEN (FAB-04): master session resurrected after concurrent SaveToFile! err=%v", err)
	}
	if _, err := sm3.GetSession(master.ID); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("FAIL-OPEN (FAB-04): GetSession accepted revoked master session! err=%v", err)
	}
	if _, err := sm3.ValidateSession(child.ID); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("FAIL-OPEN (FAB-04): child session resurrected after parent revocation! err=%v", err)
	}
	if len(sm3.ActiveSessions()) != 0 {
		t.Fatalf("FAIL-OPEN (FAB-04): expected 0 active sessions, got %d", len(sm3.ActiveSessions()))
	}
}
