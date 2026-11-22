package integration

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestInitMCP_RejectsSymlinkAndPreservesUserConfig verifies ADV-BOOT-01:
//  1. Symlinked IDE config files and symlinked parent directories fail closed with
//     ErrMCPSymlinkDetected and write 0 bytes to the symlink target.
//  2. Unrelated user MCP servers and top-level IDE configuration keys are strictly preserved.
func TestInitMCP_RejectsSymlinkAndPreservesUserConfig(t *testing.T) {
	// Case 1: Symlinked config file (.mcp.json -> outsideFile)
	worktree1 := t.TempDir()
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "sensitive.json")
	sentinel := `{"do_not_touch": "secret"}`
	if err := os.WriteFile(outsideFile, []byte(sentinel), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideFile, filepath.Join(worktree1, ".mcp.json")); err != nil {
		t.Fatal(err)
	}

	_, err := PlanAndApplyMCP(MCPInitOptions{
		WorktreeDir: worktree1,
		Apply:       true,
		Targets:     []string{TargetClaude},
	})
	if !errors.Is(err, ErrMCPSymlinkDetected) {
		t.Fatalf("ADV-BOOT-01 FAIL-OPEN: expected ErrMCPSymlinkDetected on symlinked .mcp.json, got: %v", err)
	}
	gotOutside, err := os.ReadFile(outsideFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotOutside) != sentinel {
		t.Fatalf("ADV-BOOT-01 FAIL-OPEN: symlink target was modified! got %q", string(gotOutside))
	}

	// Case 2: Symlinked parent directory (.cursor -> outsideDir)
	worktree2 := t.TempDir()
	if err := os.Symlink(outsideDir, filepath.Join(worktree2, ".cursor")); err != nil {
		t.Fatal(err)
	}
	_, err = PlanAndApplyMCP(MCPInitOptions{
		WorktreeDir: worktree2,
		Apply:       true,
		Targets:     []string{TargetCursor},
	})
	if !errors.Is(err, ErrMCPSymlinkDetected) {
		t.Fatalf("ADV-BOOT-01 FAIL-OPEN: expected ErrMCPSymlinkDetected on symlinked .cursor dir, got: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(outsideDir, "mcp.json")); !os.IsNotExist(statErr) {
		t.Fatal("ADV-BOOT-01 FAIL-OPEN: mcp.json was written through symlinked .cursor directory!")
	}

	// Case 3: Preserves unrelated user MCP servers and top-level fields on legitimate target
	worktree3 := t.TempDir()
	agentsDir := filepath.Join(worktree3, ".agents")
	if err := os.MkdirAll(agentsDir, 0700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(agentsDir, "mcp_config.json")
	existing := `{
  "theme": "dark",
  "mcpServers": {
    "postgres-local": {
      "command": "pg-mcp",
      "args": ["--readonly"],
      "env": {"PGHOST": "127.0.0.1"}
    }
  }
}
`
	if err := os.WriteFile(configPath, []byte(existing), 0600); err != nil {
		t.Fatal(err)
	}

	report, err := PlanAndApplyMCP(MCPInitOptions{
		WorktreeDir: worktree3,
		Apply:       true,
		Targets:     []string{TargetAntigravity},
		Now:         func() time.Time { return time.Unix(1795289000, 0) },
	})
	if err != nil {
		t.Fatalf("unexpected error on legitimate config: %v", err)
	}
	if len(report.Plans) != 1 || len(report.Plans[0].UserServersPreserved) != 1 || report.Plans[0].UserServersPreserved[0] != "postgres-local" {
		t.Fatalf("expected postgres-local preserved, got plan: %+v", report.Plans)
	}

	merged, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(merged, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["theme"] != "dark" {
		t.Fatalf("top-level key 'theme' was clobbered: %+v", parsed)
	}
	servers := parsed["mcpServers"].(map[string]interface{})
	pg, ok := servers["postgres-local"].(map[string]interface{})
	if !ok || pg["command"] != "pg-mcp" {
		t.Fatalf("user server postgres-local was clobbered or corrupted: %+v", servers)
	}
	for _, canonicalName := range CanonicalMCPServerOrder {
		if _, ok := servers[canonicalName]; !ok {
			t.Fatalf("expected canonical server %s to be added", canonicalName)
		}
	}
}
