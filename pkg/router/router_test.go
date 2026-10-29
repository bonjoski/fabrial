package router

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bonjoski/fabrial/pkg/policy"
)

func TestParseArgs(t *testing.T) {
	// Case 1: Standard flags with "--"
	args := []string{"--profile", "agent", "--airgap", "--", "npm", "test"}
	opts, cmdArgs, err := ParseArgs(args)
	if err != nil {
		t.Fatalf("ParseArgs error: %v", err)
	}
	if opts.Profile != "agent" {
		t.Errorf("expected profile agent, got %q", opts.Profile)
	}
	if !opts.Airgap {
		t.Errorf("expected airgap to be true")
	}
	if len(cmdArgs) != 2 || cmdArgs[0] != "npm" || cmdArgs[1] != "test" {
		t.Errorf("expected cmdArgs [npm test], got %v", cmdArgs)
	}

	// Case 2: Shorthand execution without "--"
	args = []string{"--microvm", "python", "script.py"}
	opts, cmdArgs, err = ParseArgs(args)
	if err != nil {
		t.Fatalf("ParseArgs error: %v", err)
	}
	if opts.TierOverride != policy.Tier2 {
		t.Errorf("expected Tier2 override for --microvm, got %v", opts.TierOverride)
	}
	if len(cmdArgs) != 2 || cmdArgs[0] != "python" || cmdArgs[1] != "script.py" {
		t.Errorf("expected cmdArgs [python script.py], got %v", cmdArgs)
	}

	// Case 3: Explicit tier override --tier 1
	args = []string{"--tier", "1", "npm", "install"}
	opts, cmdArgs, err = ParseArgs(args)
	if err != nil {
		t.Fatalf("ParseArgs error: %v", err)
	}
	if opts.TierOverride != policy.Tier1 {
		t.Errorf("expected Tier1 override, got %v", opts.TierOverride)
	}
	if len(cmdArgs) != 2 || cmdArgs[0] != "npm" || cmdArgs[1] != "install" {
		t.Errorf("expected cmdArgs [npm install], got %v", cmdArgs)
	}
}

func TestRoute_DynamicRouting(t *testing.T) {
	// Airlock Tier 1 for benign linting / formatting
	opts := &ExecutionOptions{
		Quiet: true,
	}
	dec, err := Route(opts, []string{"eslint", "src/"})
	if err != nil {
		t.Fatalf("Route error: %v", err)
	}
	if dec.Tier != policy.Tier1 {
		t.Errorf("expected Tier 1 for eslint, got %v", dec.Tier)
	}
	if dec.Engine != "airlock" {
		t.Errorf("expected airlock engine, got %s", dec.Engine)
	}
	if dec.ExecArgs[0] != "run" {
		t.Errorf("expected airlock run subcommand, got %s", dec.ExecArgs[0])
	}

	// Aegisbox Tier 2 for sensitive package management / network
	dec, err = Route(opts, []string{"npm", "install", "lodash"})
	if err != nil {
		t.Fatalf("Route error: %v", err)
	}
	if dec.Tier != policy.Tier2 {
		t.Errorf("expected Tier 2 for npm install, got %v", dec.Tier)
	}
	if dec.Engine != "aegisbox" {
		t.Errorf("expected aegisbox engine, got %s", dec.Engine)
	}
	if dec.ExecArgs[0] != "exec" || dec.ExecArgs[1] != "-engine" || dec.ExecArgs[2] != "microvm" {
		t.Errorf("expected aegisbox exec -engine microvm, got %v", dec.ExecArgs[:3])
	}
}

func TestRoute_WithFabrialYAML(t *testing.T) {
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "fabrial.yaml")
	content := `
version: "1"
default_tier: 1
tier1:
  tools:
    - quick-linter
tier2:
  tools:
    - custom-compiler
`
	if err := os.WriteFile(yamlPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test yaml: %v", err)
	}

	opts := &ExecutionOptions{
		PolicyPath: yamlPath,
		Quiet:      true,
	}

	// Custom tier 1 tool
	dec, err := Route(opts, []string{"quick-linter", "file.go"})
	if err != nil {
		t.Fatalf("Route error: %v", err)
	}
	if dec.Tier != policy.Tier1 {
		t.Errorf("expected Tier 1 for quick-linter, got %v", dec.Tier)
	}

	// Custom tier 2 tool
	dec, err = Route(opts, []string{"custom-compiler", "--build"})
	if err != nil {
		t.Fatalf("Route error: %v", err)
	}
	if dec.Tier != policy.Tier2 {
		t.Errorf("expected Tier 2 for custom-compiler, got %v", dec.Tier)
	}
}

func TestExecute_DryRun(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	opts := &ExecutionOptions{
		DryRun: true,
		Stdout: &stdout,
		Stderr: &stderr,
	}

	dec, err := Route(opts, []string{"gofmt", "-w", "."})
	if err != nil {
		t.Fatalf("Route error: %v", err)
	}

	exitCode, err := Execute(context.Background(), dec)
	if err != nil {
		t.Fatalf("Execute dry-run failed: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	out := stdout.String()
	if !strings.Contains(out, "Dry-run:") || !strings.Contains(out, "airlock") {
		t.Errorf("expected dry-run output containing airlock, got: %s", out)
	}

	errOut := stderr.String()
	if !strings.Contains(errOut, "Fabrial Multi-Tier Router") || !strings.Contains(errOut, "Tier 1") {
		t.Errorf("expected routing notice on stderr, got: %s", errOut)
	}
}

func TestRoute_Airgap_ExplicitTier2_FailsClosed(t *testing.T) {
	opts := &ExecutionOptions{
		TierOverride: policy.Tier2,
		Airgap:       true,
	}
	_, err := Route(opts, []string{"curl", "https://example.com"})
	if err == nil {
		t.Fatal("expected error when routing explicit Tier 2 with --airgap, got nil")
	}
	if !strings.Contains(err.Error(), "does not support verified network airgap") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestRoute_Airgap_DowngradesPolicyTier2ToTier1(t *testing.T) {
	// npm install would normally route to Tier 2 by default policy
	opts := &ExecutionOptions{
		Airgap: true,
		Quiet:  true,
	}
	dec, err := Route(opts, []string{"npm", "install", "axios"})
	if err != nil {
		t.Fatalf("Route error: %v", err)
	}
	// Under airgap, must route to Tier 1 to guarantee offline network isolation
	if dec.Tier != policy.Tier1 {
		t.Errorf("expected Tier 1 routing under --airgap, got %v", dec.Tier)
	}
	if dec.Engine != "airlock" {
		t.Errorf("expected airlock engine under --airgap, got %s", dec.Engine)
	}
	if !strings.Contains(dec.Reason, "airgap requested") {
		t.Errorf("expected reason to mention airgap requirement, got: %s", dec.Reason)
	}
}

func setupMockAegisbox(t *testing.T) {
	t.Helper()
	tmpBinDir := t.TempDir()
	mockBin := filepath.Join(tmpBinDir, "aegisbox")
	if runtime.GOOS == "windows" {
		mockBin += ".bat"
		_ = os.WriteFile(mockBin, []byte("@echo off\r\n"), 0755)
	} else {
		_ = os.WriteFile(mockBin, []byte("#!/bin/sh\nexit 0\n"), 0755)
	}
	origPath := os.Getenv("PATH")
	_ = os.Setenv("PATH", tmpBinDir+string(os.PathListSeparator)+origPath)
	t.Cleanup(func() {
		_ = os.Setenv("PATH", origPath)
	})
}

func TestExecute_Tier2_FailsClosedWhenDaemonOffline(t *testing.T) {
	setupMockAegisbox(t)
	origEnv := os.Getenv("AEGISBOX_SOCKET")
	defer func() {
		if origEnv != "" {
			_ = os.Setenv("AEGISBOX_SOCKET", origEnv)
		} else {
			_ = os.Unsetenv("AEGISBOX_SOCKET")
		}
	}()

	nonExistentSock := filepath.Join(os.TempDir(), "nonexistent_aegisbox_exec.sock")
	_ = os.Remove(nonExistentSock)
	_ = os.Setenv("AEGISBOX_SOCKET", nonExistentSock)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	opts := &ExecutionOptions{
		TierOverride: policy.Tier2,
		Stdout:       &stdout,
		Stderr:       &stderr,
	}

	dec, err := Route(opts, []string{"python3", "script.py"})
	if err != nil {
		t.Fatalf("Route error: %v", err)
	}

	exitCode, err := Execute(context.Background(), dec)
	if err == nil {
		t.Fatal("expected Execute to fail closed when microvm daemon is offline, got nil")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if !strings.Contains(err.Error(), "offline") || !strings.Contains(err.Error(), "fail-closed") {
		t.Errorf("expected error to explain offline daemon and fail-closed invariant, got: %v", err)
	}

	// Crucial check: make sure the banner falsely claiming hardware isolation was NOT emitted
	if strings.Contains(stderr.String(), "hardware isolation") {
		t.Errorf("false assurance banner was emitted even though daemon was offline: %s", stderr.String())
	}
}

func TestExecute_Tier2_SucceedsWhenDaemonOnline(t *testing.T) {
	setupMockAegisbox(t)
	sockPath := filepath.Join(os.TempDir(), "agb_online_test.sock")
	_ = os.Remove(sockPath)

	origEnv := os.Getenv("AEGISBOX_SOCKET")
	defer func() {
		if origEnv != "" {
			_ = os.Setenv("AEGISBOX_SOCKET", origEnv)
		} else {
			_ = os.Unsetenv("AEGISBOX_SOCKET")
		}
		_ = os.Remove(sockPath)
	}()

	_ = os.Setenv("AEGISBOX_SOCKET", sockPath)

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen on test socket: %v", err)
	}
	defer ln.Close()
	_ = os.Chmod(sockPath, 0600)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	opts := &ExecutionOptions{
		TierOverride: policy.Tier2,
		DryRun:       true,
		Stdout:       &stdout,
		Stderr:       &stderr,
	}

	dec, err := Route(opts, []string{"python3", "script.py"})
	if err != nil {
		t.Fatalf("Route error: %v", err)
	}

	exitCode, err := Execute(context.Background(), dec)
	if err != nil {
		t.Fatalf("Execute dry-run failed with active socket: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	// In online dry-run, the banner is printed on stderr
	if !strings.Contains(stderr.String(), "Tier 2 (Aegisbox MicroVM)") {
		t.Errorf("expected Tier 2 routing banner on stderr, got: %s", stderr.String())
	}
}
