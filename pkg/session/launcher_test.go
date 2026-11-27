package session

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/bonjoski/fabrial/pkg/pillars"
	"github.com/bonjoski/fabrial/pkg/ux"
)

func TestLauncher_SessionLaunch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping session launch test on windows: requires /bin/sh")
	}
	t.Setenv("HOME", t.TempDir())
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

func TestLauncher_OptionalPillars_3StateContract(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping session launch test on windows: requires /bin/sh")
	}

	t.Run("State1_NoShield_NoDeadHTTPProxyInjected", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		emptyBin := t.TempDir()
		workDir := t.TempDir()
		resolver := &pillars.Resolver{Lookup: pillars.LookupInPATH(emptyBin)}
		sm := NewSessionManager(WithPillarResolver(resolver))

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		cfg := LaunchConfig{
			Profile:       "test-agent",
			TargetCommand: "/bin/sh",
			TargetArgs: []string{
				"-c",
				"if [ -n \"$HTTP_PROXY\" ] || [ -n \"$SOVEREIGN_SHIELD_ACTIVE\" ]; then exit 2; fi; if [ \"$FABRIAL_SESSION_ACTIVE\" != \"1\" ]; then exit 1; fi",
			},
			TTL:            10 * time.Minute,
			UseAirlock:     false,
			Biometric:      false,
			WorkDir:        workDir,
			PillarResolver: resolver,
		}
		if err := LaunchSession(ctx, sm, cfg); err != nil {
			t.Fatalf("State 1 LaunchSession failed (dead proxy may have been injected): %v", err)
		}
		sessions := sm.ActiveSessions()
		if len(sessions) != 1 {
			t.Fatalf("expected 1 active session, got %d", len(sessions))
		}
		if sessions[0].Environment["HTTP_PROXY"] != "" || sessions[0].Environment["SOVEREIGN_SHIELD_ACTIVE"] != "" {
			t.Fatalf("State 1: unexpected Shield proxy env injected: %+v", sessions[0].Environment)
		}
	})

	t.Run("State2_ShieldInstalled_AutoWired", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		resolver := &pillars.Resolver{
			Lookup:            pillars.StaticLookup(map[string]string{"shield": "/opt/homebrew/Cellar/shield/0.4.0/bin/shield"}),
			DisableTrustStore: true,
		}
		sm := NewSessionManager(WithPillarResolver(resolver))

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		cfg := LaunchConfig{
			Profile:       "test-agent",
			TargetCommand: "/bin/sh",
			TargetArgs: []string{
				"-c",
				"if [ \"$SOVEREIGN_SHIELD_ACTIVE\" != \"1\" ] || [ -z \"$HTTP_PROXY\" ]; then exit 3; fi",
			},
			TTL:            10 * time.Minute,
			UseAirlock:     false,
			Biometric:      false,
			WorkDir:        t.TempDir(),
			PillarResolver: resolver,
		}
		if err := LaunchSession(ctx, sm, cfg); err != nil {
			t.Fatalf("State 2 LaunchSession failed: %v", err)
		}
	})

	t.Run("State3_RequireShieldOrStormcageMissing_FailClosedExit126", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		emptyBin := t.TempDir()
		workDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(workDir, "fabrial.yaml"), []byte("version: \"1\"\nrequire_shield: true\n"), 0644); err != nil {
			t.Fatalf("write fabrial.yaml: %v", err)
		}
		resolver := &pillars.Resolver{Lookup: pillars.LookupInPATH(emptyBin)}
		sm := NewSessionManager(WithPillarResolver(resolver))

		err := LaunchSession(context.Background(), sm, LaunchConfig{
			TargetCommand:  "/bin/sh",
			TargetArgs:     []string{"-c", "exit 0"},
			UseAirlock:     false,
			WorkDir:        workDir,
			PillarResolver: resolver,
		})
		if err == nil {
			t.Fatal("FAIL-OPEN: expected LaunchSession to fail closed when require_shield: true and shield is missing")
		}
		var ffe *ux.FixForwardError
		if !errors.As(err, &ffe) || ffe.ExitCode != pillars.ExitCodeRequiredMissing {
			t.Fatalf("expected FixForwardError exit 126, got %v", err)
		}

		// Also verify BeginSession fails closed directly when RequireStormcage is true
		_, beginErr := sm.BeginSession(context.Background(), SessionConfig{
			RequireStormcage: true,
			PillarResolver:   resolver,
		})
		if !errors.As(beginErr, &ffe) || ffe.ExitCode != pillars.ExitCodeRequiredMissing {
			t.Fatalf("expected BeginSession FixForwardError exit 126 for missing required Stormcage, got %v", beginErr)
		}
	})
}
