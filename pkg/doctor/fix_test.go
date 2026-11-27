package doctor

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/fabrial/pkg/pillars"
)

type mockDaemonManager struct {
	started map[string]bool
	stopped map[string]bool
}

func newMockDaemonManager() *mockDaemonManager {
	return &mockDaemonManager{
		started: make(map[string]bool),
		stopped: make(map[string]bool),
	}
}

func (m *mockDaemonManager) Start(_ context.Context, name string) error {
	m.started[strings.ToLower(name)] = true
	return nil
}

func (m *mockDaemonManager) Stop(_ context.Context, name string) error {
	m.stopped[strings.ToLower(name)] = true
	return nil
}

func (m *mockDaemonManager) Status(_ context.Context, name string) (bool, string) {
	if m.started[strings.ToLower(name)] {
		return true, "running"
	}
	return false, "stopped"
}

func TestFixer_SocketSecurityAndSymlinkRemediation(t *testing.T) {
	// Use short path in os.TempDir() to prevent Darwin sockaddr_un 104-byte limit
	id := time.Now().UnixNano()
	sockDaemon := filepath.Join(os.TempDir(), fmt.Sprintf("fxd-%d.sock", id))
	sockSymlink := filepath.Join(os.TempDir(), fmt.Sprintf("fxs-%d.sock", id))

	defer func() {
		_ = os.Remove(sockDaemon)
		_ = os.Remove(sockSymlink)
	}()

	ln, err := net.Listen("unix", sockDaemon)
	if err != nil {
		t.Fatalf("failed to create test socket: %v", err)
	}
	defer ln.Close()

	// Create symlink test.sock -> testd.sock
	if err := os.Symlink(sockDaemon, sockSymlink); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	// Symlink must fail VerifySocketSecurity
	if ok, _ := VerifySocketSecurity(sockSymlink); ok {
		t.Fatalf("expected symlink to fail security check")
	}

	// Simulate remediation logic
	if lfi, err := os.Lstat(sockSymlink); err == nil && (lfi.Mode()&os.ModeSymlink != 0) {
		if dfi, err := os.Stat(sockDaemon); err == nil && (dfi.Mode()&os.ModeSocket != 0) {
			_ = os.Remove(sockSymlink)
			if err := os.Link(sockDaemon, sockSymlink); err != nil {
				t.Fatalf("failed to link socket: %v", err)
			}
			_ = os.Chmod(sockSymlink, 0600)
		}
	}

	// Verify that test.sock is now a verified non-symlinked socket
	fi, err := os.Lstat(sockSymlink)
	if err != nil {
		t.Fatalf("expected remediated socket to exist: %v", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("remediated socket must not be a symlink")
	}
	if ok, reason := VerifySocketSecurity(sockSymlink); !ok {
		t.Fatalf("remediated socket must pass VerifySocketSecurity: %s", reason)
	}
}

func TestFixer_FormatFixTable(t *testing.T) {
	actions := []FixAction{
		{
			Pillar:      PillarLocksmith,
			Description: "Replaced symlink with hardlink (mode 0600)",
			Success:     true,
			Details:     "/path/to/sock",
		},
		{
			Pillar:      PillarHalfshard,
			Description: "Started wire guard proxy daemon",
			Success:     true,
			Details:     "127.0.0.1:8443",
		},
	}

	tbl := FormatFixTable(actions)
	if !strings.Contains(tbl, "Fabrial Sovereign Security Fabric — Remediation Actions") {
		t.Fatalf("missing table header: %s", tbl)
	}
	if !strings.Contains(tbl, "Locksmith") || !strings.Contains(tbl, "Halfshard") {
		t.Fatalf("missing expected pillars in fix table: %s", tbl)
	}

	emptyTbl := FormatFixTable(nil)
	if !strings.Contains(emptyTbl, "No remediations required") {
		t.Fatalf("expected clean summary for empty actions: %s", emptyTbl)
	}
}

func TestFixer_DaemonManagerInteraction(t *testing.T) {
	ctx := context.Background()
	dm := newMockDaemonManager()
	inspector := NewInspector(100 * time.Millisecond)
	fixer := NewFixer(inspector, dm, ".")

	// Fix individual pillar
	actions, report := fixer.FixPillar(ctx, PillarAirlock)
	if report.Pillar != PillarAirlock {
		t.Fatalf("expected Airlock report, got: %s", report.Pillar)
	}
	_ = actions
}

func TestFixer_OptionalPillars_State1AndState3(t *testing.T) {
	ctx := context.Background()
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)

	// State 1: halfshard absent & unrequired -> FixPillar("Halfshard") skips cleanly without creating ~/.halfshard
	emptyBin := t.TempDir()
	workDir := t.TempDir()
	inspector := NewInspector(100 * time.Millisecond)
	inspector.Resolver = &pillars.Resolver{Lookup: pillars.LookupInPATH(emptyBin)}
	dm := newMockDaemonManager()
	fixer := NewFixer(inspector, dm, workDir)

	actions, rep := fixer.FixPillar(ctx, PillarHalfshard)
	if rep.Status != StatusOptional {
		t.Fatalf("State 1: expected StatusOptional for explicit FixPillar(Halfshard), got %+v", rep)
	}
	if len(actions) != 1 || !actions[0].Success {
		t.Fatalf("State 1: expected single clean skip action, got %+v", actions)
	}
	if _, err := os.Stat(filepath.Join(homeDir, ".halfshard")); !os.IsNotExist(err) {
		t.Fatalf("State 1: FixPillar must not create ~/.halfshard when Halfshard is absent")
	}
	if dm.started["halfshard"] {
		t.Fatalf("State 1: FixPillar must not attempt to start Halfshard daemon")
	}

	// State 3: require_halfshard: true & missing binary -> FixPillar fails closed with Required=true
	if err := os.WriteFile(filepath.Join(workDir, "fabrial.yaml"), []byte("version: \"1\"\nrequire_halfshard: true\n"), 0644); err != nil {
		t.Fatalf("write fabrial.yaml: %v", err)
	}
	actions3, rep3 := fixer.FixPillar(ctx, PillarHalfshard)
	if rep3.Status != StatusOffline || !rep3.Required {
		t.Fatalf("State 3: expected StatusOffline+Required, got %+v", rep3)
	}
	if len(actions3) == 0 || actions3[0].Success {
		t.Fatalf("State 3: expected failing action, got %+v", actions3)
	}
	ffe := CheckRequiredHealth([]PillarHealth{rep3})
	if ffe == nil || ffe.ExitCode != pillars.ExitCodeRequiredMissing {
		t.Fatalf("State 3: expected CheckRequiredHealth exit 126, got %v", ffe)
	}
}
