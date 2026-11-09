package doctor

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestAdversarial_FAB07_DoctorFixRefusesSymlinkChmod verifies that SecureSocket0600 and
// SecureDir0700 use os.Lstat and refuse symlinked targets without altering target file modes.
func TestAdversarial_FAB07_DoctorFixRefusesSymlinkChmod(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix symlink chmod test")
	}

	tmpDir := t.TempDir()
	victimFile := filepath.Join(tmpDir, "victim_file.txt")
	if err := os.WriteFile(victimFile, []byte("sensitive"), 0644); err != nil {
		t.Fatalf("write victim file: %v", err)
	}
	if err := os.Chmod(victimFile, 0644); err != nil {
		t.Fatalf("chmod victim file: %v", err)
	}

	symlinkSock := filepath.Join(tmpDir, "argus.sock")
	if err := os.Symlink(victimFile, symlinkSock); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	act, err := SecureSocket0600(PillarArgus, symlinkSock, "Fix socket")
	if err == nil {
		t.Fatal("FAIL-OPEN (FAB-07): SecureSocket0600 succeeded on symlinked socket!")
	}
	if act == nil || act.Success {
		t.Fatalf("expected unsuccessful FixAction for symlinked socket, got: %+v", act)
	}

	// Verify victimFile mode remained 0644 (not modified through symlink!)
	fi, statErr := os.Stat(victimFile)
	if statErr != nil {
		t.Fatalf("stat victim: %v", statErr)
	}
	if fi.Mode().Perm() != 0644 {
		t.Fatalf("FAIL-OPEN (FAB-07): symlink target permissions altered to %04o!", fi.Mode().Perm())
	}

	victimDir := filepath.Join(tmpDir, "real_dir")
	if err := os.MkdirAll(victimDir, 0755); err != nil {
		t.Fatalf("mkdir victim: %v", err)
	}
	_ = os.Chmod(victimDir, 0755)
	symlinkDir := filepath.Join(tmpDir, "symlink_dir")
	if err := os.Symlink(victimDir, symlinkDir); err != nil {
		t.Fatalf("symlink dir: %v", err)
	}
	if _, dirErr := SecureDir0700(symlinkDir); dirErr == nil {
		t.Fatal("FAIL-OPEN (FAB-07): SecureDir0700 accepted symlinked directory!")
	}
	dfi, _ := os.Stat(victimDir)
	if dfi.Mode().Perm() != 0755 {
		t.Fatalf("FAIL-OPEN (FAB-07): symlinked dir target mode altered to %04o!", dfi.Mode().Perm())
	}
}
