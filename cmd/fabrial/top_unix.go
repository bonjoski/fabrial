//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/bonjoski/fabrial/pkg/ux"
)

// handleTop delegates `fabrial top` directly to the decoupled `fabrial-top` companion binary
// via syscall.Exec so cmd/fabrial never links TUI or SQLite dependencies (0.00ms Hop Tax).
func handleTop(args []string) {
	binPath, err := resolveFabrialTopBinary()
	if err != nil {
		ffe := &ux.FixForwardError{
			Tool:           "fabrial",
			Code:           "FABRIAL_TOP_NOT_INSTALLED",
			Summary:        "Decoupled companion binary `fabrial-top` was not found",
			RemediationCmd: "brew upgrade bonjoski/tap/fabrial",
			WhyOneLiner:    "fabrial-top is built as a separate binary to keep fabrial CLI cold-start at 0.00ms overhead.",
			DeepWhy:        "Install both binaries via `brew upgrade bonjoski/tap/fabrial` or build locally with `make build` (`bin/fabrial-top`).",
			ExitCode:       127,
		}
		_ = ffe.Render(os.Stderr, false, false)
		os.Exit(ffe.ExitCode)
	}
	argv := append([]string{"fabrial-top"}, args...)
	if execErr := syscall.Exec(binPath, argv, os.Environ()); execErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "fabrial top: exec %s failed: %v\n", binPath, execErr)
		os.Exit(1)
	}
}

func resolveFabrialTopBinary() (string, error) {
	if exe, err := os.Executable(); err == nil {
		sibling := filepath.Join(filepath.Dir(exe), "fabrial-top")
		if fi, sErr := os.Lstat(sibling); sErr == nil && fi.Mode()&os.ModeSymlink == 0 && fi.Mode().IsRegular() {
			return sibling, nil
		}
	}
	return exec.LookPath("fabrial-top")
}
