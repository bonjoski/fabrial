package session

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSession_BeginAndDerive(t *testing.T) {
	ctx := context.Background()
	biometricCalls := 0
	verifier := func(ctx context.Context, reason string) error {
		biometricCalls++
		return nil
	}

	sm := NewSessionManager(WithBiometricVerifier(verifier))

	// 1. Begin Master Session (should call biometric verifier once)
	masterCfg := SessionConfig{
		TTL:                10 * time.Minute,
		AllowedScopes:      []string{"read", "test", "build"},
		BiometricPreflight: true,
		ShieldProxyAddr:    "127.0.0.1:8443",
		ShieldCACertPath:   "/tmp/shield-ca.crt",
	}

	masterGrant, err := sm.BeginSession(ctx, masterCfg)
	if err != nil {
		t.Fatalf("BeginSession failed: %v", err)
	}

	if biometricCalls != 1 {
		t.Fatalf("expected 1 biometric verification call, got %d", biometricCalls)
	}
	if !masterGrant.IsMaster {
		t.Fatal("expected IsMaster to be true")
	}
	if masterGrant.Environment["FABRIAL_SESSION_ID"] != string(masterGrant.ID) {
		t.Fatalf("session ID mismatch in environment: %v", masterGrant.Environment)
	}
	if masterGrant.Environment["HTTP_PROXY"] != "http://127.0.0.1:8443" {
		t.Fatalf("proxy mismatch in environment: %v", masterGrant.Environment["HTTP_PROXY"])
	}

	// 2. Derive Child Session (MUST NOT prompt biometrics)
	childGrant, err := sm.DeriveChildSession(ctx, masterGrant.ID, "task_backend_1", []string{"read", "test"})
	if err != nil {
		t.Fatalf("DeriveChildSession failed: %v", err)
	}

	if biometricCalls != 1 {
		t.Fatalf("biometric verification prompted during child derivation! calls=%d", biometricCalls)
	}
	if childGrant.IsMaster {
		t.Fatal("expected child grant to have IsMaster=false")
	}
	if childGrant.ParentID != masterGrant.ID {
		t.Fatalf("expected child ParentID to match master ID, got %s", childGrant.ParentID)
	}
	if childGrant.Environment["FABRIAL_PARENT_SESSION_ID"] != string(masterGrant.ID) {
		t.Fatalf("parent session ID not propagated to child environment")
	}

	// 3. Format Shell Export
	exportStr := FormatShellExport(childGrant.Environment)
	if !strings.Contains(exportStr, "export FABRIAL_SESSION_ID=") {
		t.Fatalf("export string missing FABRIAL_SESSION_ID: %s", exportStr)
	}
	if !strings.Contains(exportStr, "export HTTP_PROXY='http://127.0.0.1:8443'") {
		t.Fatalf("export string missing HTTP_PROXY: %s", exportStr)
	}
}

func TestAdversarial_ChildSessionScopeEscalation(t *testing.T) {
	ctx := context.Background()
	sm := NewSessionManager()

	masterGrant, err := sm.BeginSession(ctx, SessionConfig{
		AllowedScopes: []string{"read", "test"},
	})
	if err != nil {
		t.Fatalf("failed to create master session: %v", err)
	}

	// Attempt to derive child session requesting 'admin' or 'deploy' scope not held by parent
	_, err = sm.DeriveChildSession(ctx, masterGrant.ID, "task_escalate", []string{"read", "admin"})
	if err == nil {
		t.Fatal("expected error when child session requests ungranted parent scope, but succeeded")
	}
	if !errors.Is(err, ErrScopeEscalation) {
		t.Fatalf("expected ErrScopeEscalation, got: %v", err)
	}
}

func TestAdversarial_ChildSessionExpiredParent(t *testing.T) {
	ctx := context.Background()
	sm := NewSessionManager()

	// Master session with 10ms TTL
	masterGrant, err := sm.BeginSession(ctx, SessionConfig{
		TTL: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create master session: %v", err)
	}

	time.Sleep(25 * time.Millisecond)

	// Attempt derivation on expired parent
	_, err = sm.DeriveChildSession(ctx, masterGrant.ID, "task_expired", []string{"read"})
	if err == nil {
		t.Fatal("expected derivation from expired parent to fail, but succeeded")
	}
	if !errors.Is(err, ErrSessionNotFound) && !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired or ErrSessionNotFound, got: %v", err)
	}
}

func TestAdversarial_ForgedParentSession(t *testing.T) {
	ctx := context.Background()
	sm := NewSessionManager()

	// Attempt to derive from forged/non-existent parent
	forgedID := SessionID("master_0123456789abcdef01234567")
	_, err := sm.DeriveChildSession(ctx, forgedID, "task_fake", []string{"read"})
	if err == nil {
		t.Fatal("expected derivation from forged parent ID to fail, but succeeded")
	}
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got: %v", err)
	}
}

func TestAdversarial_CrossSessionIsolation(t *testing.T) {
	ctx := context.Background()
	sm := NewSessionManager()

	// Create Session A and Session B
	grantA, err := sm.BeginSession(ctx, SessionConfig{AllowedScopes: []string{"read"}})
	if err != nil {
		t.Fatalf("failed to create Session A: %v", err)
	}

	grantB, err := sm.BeginSession(ctx, SessionConfig{AllowedScopes: []string{"read"}})
	if err != nil {
		t.Fatalf("failed to create Session B: %v", err)
	}

	// Invalidate Session A
	if err := sm.InvalidateSession(ctx, grantA.ID); err != nil {
		t.Fatalf("failed to invalidate Session A: %v", err)
	}

	// Assert Session A is deleted
	_, err = sm.GetSession(grantA.ID)
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected Session A to be not found, got %v", err)
	}

	// Assert Session B is untouched and active
	retrievedB, err := sm.GetSession(grantB.ID)
	if err != nil {
		t.Fatalf("Session B should remain unaffected, got error: %v", err)
	}
	if retrievedB.ID != grantB.ID {
		t.Fatalf("Session B ID corrupted: %v", retrievedB.ID)
	}
}

func TestAdversarial_SessionIDInjection(t *testing.T) {
	injectionPayloads := []string{
		"../../etc/passwd",
		"sess\nLD_PRELOAD=/evil.so",
		"sess; rm -rf /",
		"sess\x00hidden",
		"short",
		strings.Repeat("a", 200), // > 128 characters
	}

	for _, payload := range injectionPayloads {
		if ValidateSessionID(payload) {
			t.Errorf("ValidateSessionID accepted injection payload: %q", payload)
		}
	}

	// Valid session ID
	validID := "master_a1b2c3d4e5f60718"
	if !ValidateSessionID(validID) {
		t.Errorf("ValidateSessionID rejected valid ID: %q", validID)
	}
}

func TestAdversarial_BiometricPreflightFailure(t *testing.T) {
	ctx := context.Background()
	failingVerifier := func(ctx context.Context, reason string) error {
		return errors.New("Touch ID canceled by user")
	}

	sm := NewSessionManager(WithBiometricVerifier(failingVerifier))

	_, err := sm.BeginSession(ctx, SessionConfig{
		BiometricPreflight: true,
	})
	if err == nil {
		t.Fatal("expected BeginSession to fail when biometrics fail, but succeeded")
	}
	if !errors.Is(err, ErrBiometricFailed) {
		t.Fatalf("expected ErrBiometricFailed, got: %v", err)
	}
}

func TestSession_Persistence(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	sessionFile := tmpDir + "/sessions.json"

	sm1 := NewSessionManager()
	grant, err := sm1.BeginSession(ctx, SessionConfig{
		TTL:           10 * time.Minute,
		AllowedScopes: []string{"read", "build"},
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	if err := sm1.SaveToFile(sessionFile); err != nil {
		t.Fatalf("failed to save session to file: %v", err)
	}

	// Load into second manager
	sm2 := NewSessionManager()
	if err := sm2.LoadFromFile(sessionFile); err != nil {
		t.Fatalf("failed to load session from file: %v", err)
	}

	retrieved, err := sm2.GetSession(grant.ID)
	if err != nil {
		t.Fatalf("failed to retrieve loaded session: %v", err)
	}
	if retrieved.ID != grant.ID {
		t.Fatalf("ID mismatch: got %s, want %s", retrieved.ID, grant.ID)
	}
	if len(retrieved.Scopes) != 2 {
		t.Fatalf("scopes mismatch: %v", retrieved.Scopes)
	}
}
