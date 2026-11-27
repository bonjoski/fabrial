package doctor

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/fabrial/pkg/pillars"
)

func createFakeBin(t *testing.T, dir, name string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if runtime.GOOS == "windows" {
		p += ".exe"
	}
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write fake binary %s: %v", name, err)
	}
}

func TestDoctor_InspectAll_CanonicalOrdering(t *testing.T) {
	ctx := context.Background()

	inspector := NewInspector(1 * time.Second)
	inspector.Resolver = &pillars.Resolver{
		Lookup: pillars.StaticLookup(map[string]string{
			"halfshard": "/opt/homebrew/Cellar/halfshard/0.4.0/bin/halfshard",
			"stormcage": "/opt/homebrew/Cellar/stormcage/0.4.0/bin/stormcage",
		}),
		DisableTrustStore: true,
	}
	inspector.Requirements = &pillars.Requirements{}

	results := inspector.InspectAll(ctx, t.TempDir())

	if len(results) != len(CanonicalOrder) {
		t.Fatalf("expected %d pillar reports in State 2 (all installed), got %d", len(CanonicalOrder), len(results))
	}

	for i, pid := range CanonicalOrder {
		if results[i].Pillar != pid {
			t.Errorf("at index %d: expected pillar %s, got %s", i, pid, results[i].Pillar)
		}
	}
}

func TestDoctor_OptionalPillars_3StateContract(t *testing.T) {
	ctx := context.Background()

	t.Run("State1_AbsentAndUnrequired_Invisible", func(t *testing.T) {
		emptyBin := t.TempDir()
		workDir := t.TempDir()

		inspector := NewInspector(500 * time.Millisecond)
		inspector.Resolver = &pillars.Resolver{Lookup: pillars.LookupInPATH(emptyBin)}
		results := inspector.InspectAll(ctx, workDir)

		if len(results) != len(CoreCanonicalOrder) {
			t.Fatalf("State 1: expected %d core pillars only, got %d (%+v)", len(CoreCanonicalOrder), len(results), results)
		}
		for i, pid := range CoreCanonicalOrder {
			if results[i].Pillar != pid {
				t.Errorf("at index %d: expected %s, got %s", i, pid, results[i].Pillar)
			}
		}

		tbl := FormatTable(results)
		if strings.Contains(tbl, "Halfshard") || strings.Contains(tbl, "Stormcage") {
			t.Fatalf("State 1: FormatTable leaked absent optional pillars:\n%s", tbl)
		}
		jsonBytes, err := FormatJSON(results)
		if err != nil {
			t.Fatalf("FormatJSON failed: %v", err)
		}
		if strings.Contains(string(jsonBytes), "Halfshard") || strings.Contains(string(jsonBytes), "Stormcage") {
			t.Fatalf("State 1: FormatJSON leaked absent optional pillars:\n%s", string(jsonBytes))
		}
		if ffe := CheckRequiredHealth(results); ffe != nil {
			t.Fatalf("State 1: unexpected required health error: %v", ffe)
		}
	})

	t.Run("State2_Installed_AutoDiscovered", func(t *testing.T) {
		inspector := NewInspector(500 * time.Millisecond)
		inspector.Resolver = &pillars.Resolver{
			Lookup: pillars.StaticLookup(map[string]string{
				"halfshard": "/opt/homebrew/Cellar/halfshard/0.4.0/bin/halfshard",
				"stormcage": "/opt/homebrew/Cellar/stormcage/0.4.0/bin/stormcage",
			}),
			DisableTrustStore: true,
		}
		results := inspector.InspectAll(ctx, t.TempDir())

		if len(results) != len(CanonicalOrder) {
			t.Fatalf("State 2: expected %d pillars, got %d", len(CanonicalOrder), len(results))
		}
		tbl := FormatTable(results)
		if !strings.Contains(tbl, "Halfshard") || !strings.Contains(tbl, "Stormcage") {
			t.Fatalf("State 2: expected Halfshard and Stormcage in FormatTable:\n%s", tbl)
		}
		if ffe := CheckRequiredHealth(results); ffe != nil {
			t.Fatalf("State 2 (unrequired): unexpected required health failure: %v", ffe)
		}
	})

	t.Run("State3_RequiredMissing_FailClosedExit126", func(t *testing.T) {
		emptyBin := t.TempDir()
		workDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(workDir, "fabrial.yaml"), []byte("version: \"1\"\nrequire_halfshard: true\nrequire_stormcage: true\n"), 0644); err != nil {
			t.Fatalf("write fabrial.yaml: %v", err)
		}

		inspector := NewInspector(500 * time.Millisecond)
		inspector.Resolver = &pillars.Resolver{Lookup: pillars.LookupInPATH(emptyBin)}
		results := inspector.InspectAll(ctx, workDir)

		var sawHalfshard, sawStormcage bool
		for _, r := range results {
			if r.Pillar == PillarHalfshard {
				sawHalfshard = true
				if r.Status != StatusOffline || !r.Required {
					t.Fatalf("State 3: expected Halfshard OFFLINE+Required, got %+v", r)
				}
			}
			if r.Pillar == PillarStormcage {
				sawStormcage = true
				if r.Status != StatusOffline || !r.Required {
					t.Fatalf("State 3: expected Stormcage OFFLINE+Required, got %+v", r)
				}
			}
		}
		if !sawHalfshard || !sawStormcage {
			t.Fatalf("State 3: expected both required missing pillars in report, sawHalfshard=%v sawStormcage=%v", sawHalfshard, sawStormcage)
		}

		ffe := CheckRequiredHealth(results)
		if ffe == nil {
			t.Fatal("FAIL-OPEN: expected CheckRequiredHealth to return FixForwardError in State 3")
		}
		if ffe.ExitCode != pillars.ExitCodeRequiredMissing {
			t.Fatalf("expected ExitCode 126, got %d", ffe.ExitCode)
		}
	})
}

func TestDoctor_FormatTableAndJSON(t *testing.T) {
	ctx := context.Background()

	inspector := NewInspector(500 * time.Millisecond)
	inspector.Resolver = &pillars.Resolver{
		Lookup: pillars.StaticLookup(map[string]string{
			"halfshard": "/opt/homebrew/Cellar/halfshard/0.4.0/bin/halfshard",
			"stormcage": "/opt/homebrew/Cellar/stormcage/0.4.0/bin/stormcage",
		}),
		DisableTrustStore: true,
	}

	results := inspector.InspectAll(ctx, t.TempDir())
	tbl := FormatTable(results)

	if !strings.Contains(tbl, "Fabrial Universal Security Fabric Diagnostic Suite") {
		t.Fatalf("table missing header: %s", tbl)
	}

	for _, pid := range CanonicalOrder {
		if !strings.Contains(tbl, string(pid)) {
			t.Errorf("table output missing pillar %s", pid)
		}
	}

	jsonBytes, err := FormatJSON(results)
	if err != nil {
		t.Fatalf("FormatJSON failed: %v", err)
	}
	jsonStr := string(jsonBytes)
	for _, pid := range CanonicalOrder {
		if !strings.Contains(jsonStr, string(pid)) {
			t.Errorf("json output missing pillar %s", pid)
		}
	}
}

func TestDoctor_SocketSecurityVerification(t *testing.T) {
	// Use short path in os.TempDir() to avoid Darwin sockaddr_un 104-byte overflow
	sockPath := filepath.Join(os.TempDir(), fmt.Sprintf("doc-%d.sock", time.Now().UnixNano()))
	defer func() { _ = os.Remove(sockPath) }()

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen on test socket: %v", err)
	}
	defer ln.Close()

	// Default secure 0600
	_ = os.Chmod(sockPath, 0600)
	ok, reason := VerifySocketSecurity(sockPath)
	if !ok {
		t.Fatalf("expected 0600 socket to pass security check, failed: %s", reason)
	}

	// Insecure permissions 0666 (group/world writable)
	if runtime.GOOS != "windows" {
		_ = os.Chmod(sockPath, 0666)
		ok, reason = VerifySocketSecurity(sockPath)
		if ok {
			t.Fatalf("expected 0666 socket to fail security check")
		}
		if !strings.Contains(reason, "insecure permissions") {
			t.Errorf("expected insecure permissions reason, got: %s", reason)
		}
	}
}
