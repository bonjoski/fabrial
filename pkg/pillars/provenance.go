package pillars

import (
	"debug/buildinfo"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// BinaryIdentity defines the authoritative Go module provenance expected inside a
// bonjoski ecosystem binary's embedded debug/buildinfo table.
type BinaryIdentity struct {
	BinaryName     string
	AllowedModules []string
}

// knownBonjoskiBinaries maps canonical bonjoski CLI/daemon binary names to their
// authoritative Go module paths. Reading debug/buildinfo never executes the binary.
var knownBonjoskiBinaries = map[string]BinaryIdentity{
	"shield": {
		BinaryName:     "shield",
		AllowedModules: []string{"github.com/bonjoski/shield"},
	},
	"stormcage": {
		BinaryName:     "stormcage",
		AllowedModules: []string{"github.com/bonjoski/stormcage"},
	},
	"fabrial": {
		BinaryName:     "fabrial",
		AllowedModules: []string{"github.com/bonjoski/fabrial"},
	},
	"airlock": {
		BinaryName:     "airlock",
		AllowedModules: []string{"github.com/bonjoski/airlock"},
	},
	"aegisbox": {
		BinaryName:     "aegisbox",
		AllowedModules: []string{"github.com/bonjoski/aegisbox"},
	},
	"aegisboxd": {
		BinaryName:     "aegisboxd",
		AllowedModules: []string{"github.com/bonjoski/aegisbox"},
	},
	"argus": {
		BinaryName:     "argus",
		AllowedModules: []string{"bonjoski/argus", "github.com/bonjoski/argus"},
	},
	"locksmith": {
		BinaryName:     "locksmith",
		AllowedModules: []string{"github.com/bonjoski/locksmith/v2", "github.com/bonjoski/locksmith"},
	},
	"conjoiner": {
		BinaryName:     "conjoiner",
		AllowedModules: []string{"github.com/bonjoski/conjoiner"},
	},
	"soulcaster": {
		BinaryName:     "soulcaster",
		AllowedModules: []string{"github.com/bonjoski/soulcaster"},
	},
	"bomhound": {
		BinaryName:     "bomhound",
		AllowedModules: []string{"github.com/bonjoski/bomhound"},
	},
	"coppermind": {
		BinaryName:     "coppermind",
		AllowedModules: []string{"github.com/bonjoski/coppermind"},
	},
	"stoneward": {
		BinaryName:     "stoneward",
		AllowedModules: []string{"github.com/bonjoski/stoneward"},
	},
}

// KnownBinaryIdentity returns the expected Go module provenance for a bonjoski binary.
func KnownBinaryIdentity(name string) (BinaryIdentity, bool) {
	id, ok := knownBonjoskiBinaries[strings.ToLower(strings.TrimSpace(name))]
	return id, ok
}

// VerifyGoBuildInfo reads Go debug/buildinfo directly from resolvedPath WITHOUT executing
// the binary, asserting that its embedded Main.Path and package Path match the authoritative
// bonjoski module for expectedName.
//
// This eliminates benign name collisions (e.g. third-party tools named `shield`), shell scripts,
// and non-bonjoski binaries in <0.4ms with zero subprocess execution.
func VerifyGoBuildInfo(resolvedPath, expectedName string) (string, error) {
	ident, known := KnownBinaryIdentity(expectedName)
	if !known {
		return "", nil
	}

	bi, err := buildinfo.ReadFile(resolvedPath)
	if err != nil {
		return "", fmt.Errorf("binary %q failed Go buildinfo verification (not a bonjoski Go binary): %w", resolvedPath, err)
	}
	if bi == nil {
		return "", fmt.Errorf("binary %q has nil Go buildinfo", resolvedPath)
	}

	mainMod := strings.TrimSpace(bi.Main.Path)
	pkgPath := strings.TrimSpace(bi.Path)

	for _, allowed := range ident.AllowedModules {
		modMatch := mainMod == allowed
		pkgMatch := pkgPath == allowed || strings.HasPrefix(pkgPath, allowed+"/")
		if modMatch && pkgMatch {
			return mainMod, nil
		}
	}

	return "", fmt.Errorf(
		"binary %q module identity mismatch for %s: got main=%q pkg=%q, want one of %v",
		resolvedPath, expectedName, mainMod, pkgPath, ident.AllowedModules,
	)
}

// verifyExecutableWithProvenance enforces Layers 1 & 2 on a candidate path:
//   - Layer 2 (Filesystem & Ownership Hygiene):
//     * Rejects directories, sockets, FIFOs, device nodes, setuid/setgid, non-exec, world-writable files.
//     * Rejects world-writable parent directories on BOTH regular files and resolved symlink targets.
//     * Verifies Unix UID ownership (current EUID or root) on target binary and its parent directory.
//     * Resolves symlinks via EvalSymlinks and validates basename == expectedName (preserving Homebrew Cellar).
//     * Returns the canonical resolved path (eliminating symlink-swap TOCTOU).
//   - Layer 1 (Zero-Execution Go BuildInfo Provenance):
//     * For all known bonjoski binaries, verifies embedded Go debug/buildinfo module & package path
//       without executing the binary.
func verifyExecutableWithProvenance(cand, expectedName string) (string, string, bool) {
	lfi, err := os.Lstat(cand)
	if err != nil {
		return "", "", false
	}

	// Verify candidate's own parent directory is not world-writable and is owned by current user or root.
	if !verifyDirectoryHygiene(filepath.Dir(cand)) {
		return "", "", false
	}

	var resolved string
	var tfi os.FileInfo

	if lfi.Mode()&os.ModeSymlink != 0 {
		res, err := filepath.EvalSymlinks(cand)
		if err != nil || res == "" {
			return "", "", false
		}
		info, err := os.Stat(res)
		if err != nil {
			return "", "", false
		}
		base := strings.TrimSuffix(filepath.Base(res), ".exe")
		if !strings.EqualFold(base, expectedName) {
			return "", "", false
		}
		resolved = res
		tfi = info
	} else {
		res, err := filepath.EvalSymlinks(cand)
		if err != nil || res == "" {
			res = filepath.Clean(cand)
		}
		resolved = res
		tfi = lfi
	}

	if !tfi.Mode().IsRegular() {
		return "", "", false
	}

	if runtime.GOOS != "windows" {
		if tfi.Mode()&0111 == 0 {
			return "", "", false
		}
		if tfi.Mode().Perm()&0002 != 0 {
			return "", "", false
		}
		// Reject setuid/setgid binaries as unexpected privilege-escalation traps.
		if tfi.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
			return "", "", false
		}
		if !isOwnedByCurrentUserOrRoot(tfi) {
			return "", "", false
		}
		// Verify resolved target's parent directory is also non-world-writable and owned by user/root.
		if !verifyDirectoryHygiene(filepath.Dir(resolved)) {
			return "", "", false
		}
	}

	modPath, err := VerifyGoBuildInfo(resolved, expectedName)
	if err != nil {
		return "", "", false
	}

	return resolved, modPath, true
}

func verifyDirectoryHygiene(dir string) bool {
	if runtime.GOOS == "windows" {
		return true
	}
	dfi, err := os.Stat(dir)
	if err != nil || !dfi.IsDir() {
		return false
	}
	if dfi.Mode().Perm()&0002 != 0 {
		return false
	}
	if !isOwnedByCurrentUserOrRoot(dfi) {
		return false
	}
	return true
}
