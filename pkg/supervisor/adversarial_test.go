package supervisor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestAdversarial_PIDFileTampering_PID1(t *testing.T) {
	tempDir := t.TempDir()
	pidFile := filepath.Join(tempDir, "malicious.pid")

	// Adversary injects PID 1 (init/launchd) into PID file
	if err := os.WriteFile(pidFile, []byte("1\n"), 0600); err != nil {
		t.Fatalf("failed to write test pid file: %v", err)
	}

	sup := &Supervisor{}
	def := ServiceDef{
		Name:    "MaliciousService",
		PIDFile: pidFile,
	}

	status := sup.StopService(context.Background(), def)
	if status.State != StateError {
		t.Fatalf("expected StopService to fail with StateError on PID 1, got state: %s", status.State)
	}

	// Verify PID file was NOT removed and PID 1 was not targeted
	if _, err := os.Stat(pidFile); err != nil {
		t.Fatalf("expected malicious PID file to be preserved for inspection: %v", err)
	}
}

func TestAdversarial_PIDFileTampering_SelfAndParent(t *testing.T) {
	tempDir := t.TempDir()

	for _, targetPID := range []int{os.Getpid(), os.Getppid()} {
		pidFile := filepath.Join(tempDir, fmt.Sprintf("target_%d.pid", targetPID))
		if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", targetPID)), 0600); err != nil {
			t.Fatalf("failed to write pid file: %v", err)
		}

		sup := &Supervisor{}
		def := ServiceDef{
			Name:    "SelfTargetService",
			PIDFile: pidFile,
		}

		status := sup.StopService(context.Background(), def)
		if status.State != StateError {
			t.Fatalf("expected StopService to reject self/parent PID %d with StateError, got: %s", targetPID, status.State)
		}
	}
}

func TestAdversarial_PIDFileTampering_Symlink(t *testing.T) {
	tempDir := t.TempDir()
	targetFile := filepath.Join(tempDir, "real_target.txt")
	if err := os.WriteFile(targetFile, []byte("99999\n"), 0600); err != nil {
		t.Fatalf("failed to write target: %v", err)
	}

	symlinkPID := filepath.Join(tempDir, "symlink.pid")
	if err := os.Symlink(targetFile, symlinkPID); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	sup := &Supervisor{}
	def := ServiceDef{
		Name:    "SymlinkService",
		PIDFile: symlinkPID,
	}

	status := sup.StopService(context.Background(), def)
	if status.State != StateError {
		t.Fatalf("expected StopService to reject symlinked PID file with StateError, got: %s", status.State)
	}
}

func TestAdversarial_PIDFileTampering_InsecurePermissions(t *testing.T) {
	tempDir := t.TempDir()
	pidFile := filepath.Join(tempDir, "insecure.pid")
	if err := os.WriteFile(pidFile, []byte("99999\n"), 0777); err != nil {
		t.Fatalf("failed to write pid file: %v", err)
	}
	_ = os.Chmod(pidFile, 0777)

	sup := &Supervisor{}
	def := ServiceDef{
		Name:    "InsecurePermService",
		PIDFile: pidFile,
	}

	status := sup.StopService(context.Background(), def)
	if status.State != StateError {
		t.Fatalf("expected StopService to reject world-writable PID file (0777) with StateError, got: %s", status.State)
	}
}

func TestAdversarial_FAB06_SupervisorPIDRecyclingGuard(t *testing.T) {
	tempDir := t.TempDir()
	pidFile := filepath.Join(tempDir, "recycled.pid")

	// Spawn a live unrelated process and write its PID with a mismatched historical start timestamp
	cmd := os.Getpid() // Wait: self is rejected by self-check; spawn a real sleep child
	_ = cmd
	childEngine := osExecEngine{}
	pid, actualStartNs, err := childEngine.StartProcess("sleep", []string{"30"}, "")
	if err != nil {
		t.Skipf("sleep unavailable: %v", err)
	}
	defer func() {
		_ = signalDaemonGroup(pid, true)
	}()

	if actualStartNs <= 0 {
		t.Skip("kernel start timestamp unsupported on this OS")
	}

	staleStartNs := actualStartNs + 1000 // mismatch (clock ticks or nanoseconds)
	record := fmt.Sprintf("%d:%d\n", pid, staleStartNs)
	if err := os.WriteFile(pidFile, []byte(record), 0600); err != nil {
		t.Fatalf("write pid file: %v", err)
	}

	sup := &Supervisor{Engine: childEngine}
	status := sup.StopService(context.Background(), ServiceDef{
		Name:    "RecycledService",
		PIDFile: pidFile,
	})
	if status.State != StateStopped {
		t.Fatalf("expected StateStopped for stale recycled PID file, got %s (%s)", status.State, status.Message)
	}

	// Unrelated live process occupying that PID MUST still be alive!
	if !isProcessAlive(pid) {
		t.Fatalf("FAIL-OPEN (FAB-06): StopService killed unrelated live process %d after PID recycling!", pid)
	}
}
