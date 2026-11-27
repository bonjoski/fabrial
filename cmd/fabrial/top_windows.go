//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/bonjoski/fabrial/pkg/ux"
)

// handleTop delegates `fabrial top` to the decoupled `fabrial-top.exe` companion binary
// so cmd/fabrial never links TUI or SQLite dependencies.
func handleTop(args []string) {
	binPath, err := resolveFabrialTopBinary()
	if err != nil {
		ffe := &ux.FixForwardError{
			Tool:           "fabrial",
			Code:           "FABRIAL_TOP_NOT_INSTALLED",
			Summary:        "Decoupled companion binary `fabrial-top` was not found",
			RemediationCmd: "make build",
			WhyOneLiner:    "fabrial-top is built as a separate binary to keep fabrial CLI cold-start at 0.00ms overhead.",
			DeepWhy:        "Build both binaries with `make build` or ensure `fabrial-top.exe` is on PATH.",
			ExitCode:       127,
		}
		_ = ffe.Render(os.Stderr, false, false)
		os.Exit(ffe.ExitCode)
	}
	cmd := exec.Command(binPath, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if runErr := cmd.Run(); runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		_, _ = fmt.Fprintf(os.Stderr, "fabrial top: exec %s failed: %v\n", binPath, runErr)
		os.Exit(1)
	}
}

func resolveFabrialTopBinary() (string, error) {
	if exe, err := os.Executable(); err == nil {
		sibling := filepath.Join(filepath.Dir(exe), "fabrial-top.exe")
		if fi, sErr := os.Lstat(sibling); sErr == nil && fi.Mode()&os.ModeSymlink == 0 && fi.Mode().IsRegular() {
			return sibling, nil
		}
	}
	return exec.LookPath("fabrial-top")
}
