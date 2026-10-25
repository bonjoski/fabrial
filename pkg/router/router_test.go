package router

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
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
