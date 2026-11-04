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
			Pillar:      PillarShield,
			Description: "Started wire guard proxy daemon",
			Success:     true,
			Details:     "127.0.0.1:8443",
		},
	}

	tbl := FormatFixTable(actions)
	if !strings.Contains(tbl, "Fabrial Sovereign Security Fabric — Remediation Actions") {
		t.Fatalf("missing table header: %s", tbl)
	}
	if !strings.Contains(tbl, "Locksmith") || !strings.Contains(tbl, "Shield") {
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
	actions, report := fixer.FixPillar(ctx, PillarSpanreed)
	if report.Pillar != PillarSpanreed {
		t.Fatalf("expected Spanreed report, got: %s", report.Pillar)
	}
	_ = actions
}
