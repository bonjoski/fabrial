package pillars

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/bonjoski/fabrial/pkg/ux"
)

// TestAdversarial_ShellScriptTrojanRejected verifies Layer 1 (zero-execution debug/buildinfo):
// an executable 0755 shell script named `shield` or `stormcage` on PATH MUST NEVER be treated
// as our application or executed.
func TestAdversarial_ShellScriptTrojanRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell script test")
	}

	binDir := t.TempDir()
	for _, name := range []string{"shield", "stormcage"} {
		p := filepath.Join(binDir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\necho PWNED\nexit 0\n"), 0755); err != nil {
			t.Fatalf("write trojan script %s: %v", name, err)
		}
	}

	r := &Resolver{Lookup: LookupInPATH(binDir), DisableTrustStore: true}

	if res := r.ResolveShield(Requirements{}); res.State != StateAbsent {
		t.Fatalf("FAIL-OPEN: 0755 shell script trojan named shield accepted as %s", res.State)
	}
	if res := r.ResolveStormcage(Requirements{}); res.State != StateAbsent {
		t.Fatalf("FAIL-OPEN: 0755 shell script trojan named stormcage accepted as %s", res.State)
	}
	if res := r.ResolveShield(Requirements{RequireShield: true}); res.State != StateRequiredMissing {
		t.Fatalf("FAIL-OPEN: required shield accepted 0755 shell script trojan: %s", res.State)
	}
}

// TestAdversarial_ThirdPartyGoBinaryCollisionRejected verifies Layer 1 defeats benign name
// collisions (e.g. Stark & Wayne Cloud Foundry `shield` CLI or any unrelated Go binary named `shield`).
func TestAdversarial_ThirdPartyGoBinaryCollisionRejected(t *testing.T) {
	ensureCompiledFixtures(t)

	binDir := t.TempDir()
	installFixtureCopy(t, evilCollisionBin, binDir, "shield")

	r := &Resolver{Lookup: LookupInPATH(binDir), DisableTrustStore: true}

	if res := r.ResolveShield(Requirements{}); res.State != StateAbsent {
		t.Fatalf("FAIL-OPEN: unrelated Go binary (github.com/evil/shield) accepted as %s", res.State)
	}
	res := r.ResolveShield(Requirements{RequireShield: true})
	if res.State != StateRequiredMissing {
		t.Fatalf("FAIL-OPEN: required shield accepted colliding third-party Go binary: %s", res.State)
	}
	var ffe *ux.FixForwardError
	if !errors.As(res.Err, &ffe) || ffe.ExitCode != ExitCodeRequiredMissing {
		t.Fatalf("expected FixForwardError exit 126, got %v", res.Err)
	}
}

// TestAdversarial_ForgedModuleDigestMismatchFailsClosed verifies Layer 3 cryptographic SHA-256
// pinning defeats an active adversary who compiles a forged Go binary declaring
// `module github.com/bonjoski/shield`!
func TestAdversarial_ForgedModuleDigestMismatchFailsClosed(t *testing.T) {
	ensureCompiledFixtures(t)

	// 1. Pin the genuine binary's SHA-256 in the trust store.
	genuineDir := t.TempDir()
	installFixtureCopy(t, genuineShieldBin, genuineDir, "shield")
	storePath := filepath.Join(t.TempDir(), ".fabrial", "trusted-pillars.json")

	pinned, err := TrustPillar("shield", storePath, LookupInPATH(genuineDir))
	if err != nil {
		t.Fatalf("TrustPillar genuine shield: %v", err)
	}

	// 2. Attacker swaps the binary with a forged Go binary claiming module github.com/bonjoski/shield.
	forgedDir := t.TempDir()
	installFixtureCopy(t, forgedShieldBin, forgedDir, "shield")

	r := &Resolver{Lookup: LookupInPATH(forgedDir), TrustStorePath: storePath}

	// Even when RequireShield is false, a pinned binary whose SHA-256 mismatches MUST FAIL CLOSED!
	res := r.ResolveShield(Requirements{RequireShield: false})
	if res.State != StateRequiredMissing || res.Err == nil {
		t.Fatalf("FAIL-OPEN: forged Go binary with mismatched SHA-256 was not blocked (state=%s err=%v)", res.State, res.Err)
	}
	var ffe *ux.FixForwardError
	if !errors.As(res.Err, &ffe) || ffe.Code != "FABRIAL_PILLAR_DIGEST_MISMATCH" || ffe.ExitCode != ExitCodeRequiredMissing {
		t.Fatalf("expected FABRIAL_PILLAR_DIGEST_MISMATCH exit 126, got %+v", res.Err)
	}

	// Also verify EnforceRequired catches the forged binary immediately.
	if err := r.EnforceRequired(Requirements{RequireShield: false}); err == nil {
		t.Fatal("FAIL-OPEN: EnforceRequired allowed forged Go binary with digest mismatch")
	}

	// Also verify fabrial.yaml pillar_digests catches the forged binary even without trust store.
	rPolicy := &Resolver{Lookup: LookupInPATH(forgedDir), DisableTrustStore: true}
	resPolicy := rPolicy.ResolveShield(Requirements{
		PillarDigests: map[string]string{"shield": pinned.SHA256},
	})
	if resPolicy.State != StateRequiredMissing || resPolicy.Err == nil {
		t.Fatalf("FAIL-OPEN: fabrial.yaml pillar_digests did not reject forged binary: %+v", resPolicy)
	}
}

// TestAdversarial_StrictPillarPinningRejectsUnpinnedForgedBinary verifies strict_pillar_pinning: true
// refuses to auto-load any binary that lacks an explicit SHA-256 pin.
func TestAdversarial_StrictPillarPinningRejectsUnpinnedForgedBinary(t *testing.T) {
	ensureCompiledFixtures(t)

	binDir := t.TempDir()
	installFixtureCopy(t, forgedShieldBin, binDir, "shield")

	r := &Resolver{Lookup: LookupInPATH(binDir), DisableTrustStore: true}

	// Optional + strict_pillar_pinning: never auto-loads unpinned binary.
	if res := r.ResolveShield(Requirements{StrictPillarPinning: true}); res.State != StateAbsent {
		t.Fatalf("FAIL-OPEN: strict_pillar_pinning auto-loaded unpinned binary as %s", res.State)
	}

	// Required + strict_pillar_pinning: fails closed exit 126 with FABRIAL_PILLAR_UNPINNED.
	res := r.ResolveShield(Requirements{RequireShield: true, StrictPillarPinning: true})
	if res.State != StateRequiredMissing || res.Err == nil {
		t.Fatalf("FAIL-OPEN: required+strict_pillar_pinning allowed unpinned binary: %+v", res)
	}
	var ffe *ux.FixForwardError
	if !errors.As(res.Err, &ffe) || ffe.Code != "FABRIAL_PILLAR_UNPINNED" || ffe.ExitCode != ExitCodeRequiredMissing {
		t.Fatalf("expected FABRIAL_PILLAR_UNPINNED exit 126, got %+v", res.Err)
	}
}

// TestAdversarial_ConflictingPolicyAndTrustStorePinsFailClosed ensures disagreement between
// fabrial.yaml pillar_digests and ~/.fabrial/trusted-pillars.json fails closed.
func TestAdversarial_ConflictingPolicyAndTrustStorePinsFailClosed(t *testing.T) {
	ensureCompiledFixtures(t)

	binDir := t.TempDir()
	installFixtureCopy(t, genuineShieldBin, binDir, "shield")
	storePath := filepath.Join(t.TempDir(), ".fabrial", "trusted-pillars.json")

	if _, err := TrustPillar("shield", storePath, LookupInPATH(binDir)); err != nil {
		t.Fatalf("TrustPillar failed: %v", err)
	}

	r := &Resolver{Lookup: LookupInPATH(binDir), TrustStorePath: storePath}
	res := r.ResolveShield(Requirements{
		PillarDigests: map[string]string{"shield": strings.Repeat("b", 64)},
	})
	if res.State != StateRequiredMissing || res.Err == nil {
		t.Fatalf("FAIL-OPEN: conflicting pins between policy and trust store did not fail closed: %+v", res)
	}
}

// TestAdversarial_SymlinkedOrWorldWritableTrustStoreRejected prevents trust-store tampering.
func TestAdversarial_SymlinkedOrWorldWritableTrustStoreRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission/symlink test")
	}

	dir := t.TempDir()
	realFile := filepath.Join(dir, "real.json")
	if err := os.WriteFile(realFile, []byte(`{"version":1,"digests":{}}`), 0600); err != nil {
		t.Fatalf("write real: %v", err)
	}
	link := filepath.Join(dir, "trusted-pillars.json")
	if err := os.Symlink(realFile, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := LoadTrustStore(link); err == nil {
		t.Fatal("FAIL-OPEN: LoadTrustStore accepted symlinked trust store")
	}

	wwFile := filepath.Join(dir, "ww-trust.json")
	if err := os.WriteFile(wwFile, []byte(`{"version":1,"digests":{}}`), 0666); err != nil {
		t.Fatalf("write ww: %v", err)
	}
	_ = os.Chmod(wwFile, 0666)
	if _, err := LoadTrustStore(wwFile); err == nil {
		t.Fatal("FAIL-OPEN: LoadTrustStore accepted world-writable trust store")
	}
}

// TestAdversarial_RegularFileInWorldWritableDirRejected closes the Layer 2 regular-file
// parent-directory world-writability gap (e.g., genuine binary dropped in /tmp or 0777 dir).
func TestAdversarial_RegularFileInWorldWritableDirRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions test")
	}
	ensureCompiledFixtures(t)

	worldDir := t.TempDir()
	installFixtureCopy(t, genuineShieldBin, worldDir, "shield")
	if err := os.Chmod(worldDir, 0777); err != nil {
		t.Fatalf("chmod worldDir: %v", err)
	}

	r := &Resolver{Lookup: LookupInPATH(worldDir), DisableTrustStore: true}
	if res := r.ResolveShield(Requirements{}); res.State != StateAbsent {
		t.Fatalf("FAIL-OPEN: regular binary inside 0777 world-writable dir accepted as %s", res.State)
	}
	if res := r.ResolveShield(Requirements{RequireShield: true}); res.State != StateRequiredMissing {
		t.Fatalf("FAIL-OPEN: required shield accepted regular binary in 0777 dir: %s", res.State)
	}
}

func TestAdversarial_NonExecutableFileNotTreatedAsInstalled(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX execute permission bit test")
	}
	ensureCompiledFixtures(t)

	binDir := t.TempDir()
	shieldPath := installFixtureCopy(t, genuineShieldBin, binDir, "shield")
	stormPath := installFixtureCopy(t, genuineStormBin, binDir, "stormcage")
	_ = os.Chmod(shieldPath, 0644)
	_ = os.Chmod(stormPath, 0644)

	r := &Resolver{Lookup: LookupInPATH(binDir), DisableTrustStore: true}

	if res := r.ResolveShield(Requirements{}); res.State != StateAbsent {
		t.Fatalf("FAIL-OPEN: non-executable shield treated as %s", res.State)
	}
	if res := r.ResolveStormcage(Requirements{}); res.State != StateAbsent {
		t.Fatalf("FAIL-OPEN: non-executable stormcage treated as %s", res.State)
	}
	res := r.ResolveShield(Requirements{RequireShield: true})
	if res.State != StateRequiredMissing {
		t.Fatalf("FAIL-OPEN: required non-executable shield returned %s", res.State)
	}
	var ffe *ux.FixForwardError
	if !errors.As(res.Err, &ffe) || ffe.ExitCode != ExitCodeRequiredMissing {
		t.Fatalf("expected FixForwardError exit 126, got %v", res.Err)
	}
}

func TestAdversarial_SymlinkAttacksRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX symlink test")
	}
	ensureCompiledFixtures(t)

	cases := []struct {
		name  string
		setup func(t *testing.T, binDir string)
	}{
		{
			name: "DanglingSymlink",
			setup: func(t *testing.T, binDir string) {
				if err := os.Symlink("/nonexistent/path/shield", filepath.Join(binDir, "shield")); err != nil {
					t.Fatalf("symlink: %v", err)
				}
			},
		},
		{
			name: "SymlinkToUnrelatedBinaryDecoy",
			setup: func(t *testing.T, binDir string) {
				if err := os.Symlink("/bin/sh", filepath.Join(binDir, "shield")); err != nil {
					t.Fatalf("symlink: %v", err)
				}
			},
		},
		{
			name: "SymlinkToDifferentBonjoskiBinaryDecoy",
			setup: func(t *testing.T, binDir string) {
				// Point `shield` symlink to genuine `stormcage` binary
				targetDir := t.TempDir()
				target := installFixtureCopy(t, genuineStormBin, targetDir, "stormcage")
				if err := os.Symlink(target, filepath.Join(binDir, "shield")); err != nil {
					t.Fatalf("symlink: %v", err)
				}
			},
		},
		{
			name: "SymlinkToNonExecutableFile",
			setup: func(t *testing.T, binDir string) {
				targetDir := t.TempDir()
				target := installFixtureCopy(t, genuineShieldBin, targetDir, "shield")
				_ = os.Chmod(target, 0644)
				if err := os.Symlink(target, filepath.Join(binDir, "shield")); err != nil {
					t.Fatalf("symlink: %v", err)
				}
			},
		},
		{
			name: "SymlinkToDirectory",
			setup: func(t *testing.T, binDir string) {
				targetDir := filepath.Join(t.TempDir(), "shield")
				if err := os.MkdirAll(targetDir, 0755); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				if err := os.Symlink(targetDir, filepath.Join(binDir, "shield")); err != nil {
					t.Fatalf("symlink: %v", err)
				}
			},
		},
		{
			name: "SymlinkToWorldWritableTarget",
			setup: func(t *testing.T, binDir string) {
				targetDir := t.TempDir()
				target := installFixtureCopy(t, genuineShieldBin, targetDir, "shield")
				_ = os.Chmod(target, 0777)
				if err := os.Symlink(target, filepath.Join(binDir, "shield")); err != nil {
					t.Fatalf("symlink: %v", err)
				}
			},
		},
		{
			name: "SymlinkToTargetInWorldWritableDir",
			setup: func(t *testing.T, binDir string) {
				worldDir := t.TempDir()
				target := installFixtureCopy(t, genuineShieldBin, worldDir, "shield")
				if err := os.Chmod(worldDir, 0777); err != nil {
					t.Fatalf("chmod worldDir: %v", err)
				}
				if err := os.Symlink(target, filepath.Join(binDir, "shield")); err != nil {
					t.Fatalf("symlink: %v", err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			binDir := t.TempDir()
			tc.setup(t, binDir)
			r := &Resolver{Lookup: LookupInPATH(binDir), DisableTrustStore: true}

			if res := r.ResolveShield(Requirements{}); res.State != StateAbsent {
				t.Fatalf("FAIL-OPEN (%s): treated untrusted symlink as %s", tc.name, res.State)
			}
			if res := r.ResolveShield(Requirements{RequireShield: true}); res.State != StateRequiredMissing {
				t.Fatalf("FAIL-OPEN (%s): required untrusted symlink did not fail closed (got %s)", tc.name, res.State)
			}
		})
	}
}

// TestAdversarial_HomebrewStyleCellarSymlinkAcceptedAndCanonicalized verifies legitimate
// Homebrew Cellar symlinks resolve cleanly AND return the canonical EvalSymlinks target path
// (eliminating raw-symlink TOCTOU).
func TestAdversarial_HomebrewStyleCellarSymlinkAcceptedAndCanonicalized(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX symlink test")
	}
	ensureCompiledFixtures(t)

	root := t.TempDir()
	cellarBin := filepath.Join(root, "Cellar", "shield", "0.4.0", "bin")
	linkBin := filepath.Join(root, "bin")
	if err := os.MkdirAll(cellarBin, 0755); err != nil {
		t.Fatalf("mkdir cellar: %v", err)
	}
	if err := os.MkdirAll(linkBin, 0755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}

	realBin := installFixtureCopy(t, genuineShieldBin, cellarBin, "shield")
	linkPath := filepath.Join(linkBin, "shield")
	if err := os.Symlink(filepath.Join("..", "Cellar", "shield", "0.4.0", "bin", "shield"), linkPath); err != nil {
		t.Fatalf("create homebrew-style symlink: %v", err)
	}

	r := &Resolver{Lookup: LookupInPATH(linkBin), DisableTrustStore: true}
	res := r.ResolveShield(Requirements{})
	if res.State != StateInstalled {
		t.Fatalf("expected legitimate Homebrew-style symlink to resolve as StateInstalled, got %s (err=%v)", res.State, res.Err)
	}
	if res.BinaryPath != realBin {
		t.Fatalf("expected canonical resolved path %q (not raw symlink %q), got %q", realBin, linkPath, res.BinaryPath)
	}
}

func TestAdversarial_WorldWritableBinaryAndRelativePATHRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions test")
	}
	ensureCompiledFixtures(t)

	// 1. World-writable binary
	binDir := t.TempDir()
	ww := installFixtureCopy(t, genuineShieldBin, binDir, "shield")
	_ = os.Chmod(ww, 0777)

	r := &Resolver{Lookup: LookupInPATH(binDir), DisableTrustStore: true}
	if res := r.ResolveShield(Requirements{}); res.State != StateAbsent {
		t.Fatalf("FAIL-OPEN: world-writable shield accepted as %s", res.State)
	}

	// 2. Directory named shield
	dirTrap := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dirTrap, "shield"), 0755); err != nil {
		t.Fatalf("mkdir trap: %v", err)
	}
	rDir := &Resolver{Lookup: LookupInPATH(dirTrap), DisableTrustStore: true}
	if res := rDir.ResolveShield(Requirements{}); res.State != StateAbsent {
		t.Fatalf("FAIL-OPEN: directory named shield accepted as %s", res.State)
	}

	// 3. Relative PATH entry "."
	relDir := t.TempDir()
	installFixtureCopy(t, genuineShieldBin, relDir, "shield")
	t.Chdir(relDir)
	rRel := &Resolver{Lookup: LookupInPATH(".:./bin"), DisableTrustStore: true}
	if res := rRel.ResolveShield(Requirements{}); res.State != StateAbsent {
		t.Fatalf("FAIL-OPEN: relative PATH entry resolved shield as %s", res.State)
	}

	// 4. Path traversal in lookup name
	lookup := LookupInPATH(relDir)
	for _, bad := range []string{"", ".", "..", "../shield", "/bin/sh", "shield\x00"} {
		if _, err := lookup(bad); err == nil {
			t.Fatalf("FAIL-OPEN: LookupInPATH accepted invalid binary name %q", bad)
		}
	}
}

func TestAdversarial_ConcurrentEightSubagentResolution(t *testing.T) {
	ensureCompiledFixtures(t)
	binDir := t.TempDir()
	installFixtureCopy(t, genuineShieldBin, binDir, "shield")
	storePath := filepath.Join(t.TempDir(), ".fabrial", "trusted-pillars.json")

	if _, err := TrustPillar("shield", storePath, LookupInPATH(binDir)); err != nil {
		t.Fatalf("TrustPillar failed: %v", err)
	}

	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := &Resolver{Lookup: LookupInPATH(binDir), TrustStorePath: storePath}
			s := res.ResolveShield(Requirements{RequireShield: true, StrictPillarPinning: true})
			if s.State != StateInstalled {
				errs <- errors.New("expected Shield StateInstalled under concurrency")
				return
			}
			sc := res.ResolveStormcage(Requirements{RequireStormcage: false})
			if sc.State != StateAbsent {
				errs <- errors.New("expected Stormcage StateAbsent under concurrency")
				return
			}
			scReq := res.ResolveStormcage(Requirements{RequireStormcage: true})
			if scReq.State != StateRequiredMissing {
				errs <- errors.New("expected Stormcage StateRequiredMissing under concurrency")
				return
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}
