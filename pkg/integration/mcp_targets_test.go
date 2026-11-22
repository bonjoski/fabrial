package integration

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestInitMCP_DryRunBackupAndAtomicMerge(t *testing.T) {
	worktree := t.TempDir()
	fakeHome := t.TempDir()

	// Seed an existing local Claude Code .mcp.json with an unrelated user MCP server & extra top-level key
	claudePath := filepath.Join(worktree, ".mcp.json")
	seedContent := `{
  "customTopLevel": true,
  "mcpServers": {
    "my-custom-db": {
      "command": "npx",
      "args": ["-y", "custom-db-mcp"]
    }
  }
}
`
	if err := os.WriteFile(claudePath, []byte(seedContent), 0600); err != nil {
		t.Fatal(err)
	}

	fixedTime := func() time.Time { return time.Unix(1795288800, 0) }

	// 1. Dry-run (Apply=false) MUST write 0 bytes and not create backups or new files
	dryReport, err := PlanAndApplyMCP(MCPInitOptions{
		WorktreeDir: worktree,
		HomeDir:     fakeHome,
		Global:      false,
		Apply:       false,
		Targets:     []string{TargetAll},
		Now:         fixedTime,
	})
	if err != nil {
		t.Fatalf("dry-run PlanAndApplyMCP failed: %v", err)
	}
	if dryReport.Mode != "dry-run" {
		t.Fatalf("expected dry-run mode, got %q", dryReport.Mode)
	}
	if len(dryReport.Plans) != 4 {
		t.Fatalf("expected 4 IDE target plans, got %d", len(dryReport.Plans))
	}
	if _, err := os.Stat(filepath.Join(worktree, ".agents", "mcp_config.json")); !os.IsNotExist(err) {
		t.Fatal("dry-run created .agents/mcp_config.json")
	}
	if _, err := os.Stat(filepath.Join(worktree, ".cursor", "mcp.json")); !os.IsNotExist(err) {
		t.Fatal("dry-run created .cursor/mcp.json")
	}
	afterDryClaude, err := os.ReadFile(claudePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterDryClaude) != seedContent {
		t.Fatal("dry-run mutated existing .mcp.json")
	}

	// 2. Apply with --conjoiner-wrap enabled and mock LookPath finding mcp-conjoiner-proxy
	applyReport, err := PlanAndApplyMCP(MCPInitOptions{
		WorktreeDir:   worktree,
		HomeDir:       fakeHome,
		Global:        false,
		Apply:         true,
		ConjoinerWrap: true,
		Targets:       []string{TargetAll},
		LookPath: func(bin string) (string, error) {
			if bin == conjoinerProxyBinary {
				return "/usr/local/bin/mcp-conjoiner-proxy", nil
			}
			return "", errors.New("not found")
		},
		Now: fixedTime,
	})
	if err != nil {
		t.Fatalf("apply PlanAndApplyMCP failed: %v", err)
	}
	if applyReport.Mode != "applied" || !applyReport.ConjoinerWrapped {
		t.Fatalf("unexpected apply report: %+v", applyReport)
	}

	// Verify Claude Code backup was created with 0600 and exact original bytes
	expectedBackup := claudePath + ".bak.1795288800"
	bakData, err := os.ReadFile(expectedBackup)
	if err != nil {
		t.Fatalf("expected backup %s to exist: %v", expectedBackup, err)
	}
	if string(bakData) != seedContent {
		t.Fatalf("backup content mismatch: got %q", string(bakData))
	}
	bakInfo, err := os.Stat(expectedBackup)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && bakInfo.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions on backup, got %04o", bakInfo.Mode().Perm())
	}

	// Verify merged Claude Code config preserves user server, top-level key, and wraps canonical servers
	mergedBytes, err := os.ReadFile(claudePath)
	if err != nil {
		t.Fatal(err)
	}
	mergedInfo, err := os.Stat(claudePath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && mergedInfo.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions on merged config, got %04o", mergedInfo.Mode().Perm())
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(mergedBytes, &parsed); err != nil {
		t.Fatalf("invalid merged JSON: %v", err)
	}
	if parsed["customTopLevel"] != true {
		t.Fatalf("customTopLevel lost during merge: %+v", parsed)
	}
	servers := parsed["mcpServers"].(map[string]interface{})
	if _, ok := servers["my-custom-db"]; !ok {
		t.Fatalf("user MCP server my-custom-db was clobbered!")
	}
	for _, name := range CanonicalMCPServerOrder {
		entry, ok := servers[name].(map[string]interface{})
		if !ok {
			t.Fatalf("canonical server %s missing from merged config", name)
		}
		if entry["command"] != conjoinerProxyBinary {
			t.Fatalf("expected %s wrapped with %s, got %v", name, conjoinerProxyBinary, entry["command"])
		}
	}

	// 3. Global apply into fakeHome verifies ~/.gemini/config/mcp_config.json, ~/.claude.json, ~/.cursor/mcp.json
	globalReport, err := PlanAndApplyMCP(MCPInitOptions{
		WorktreeDir: worktree,
		HomeDir:     fakeHome,
		Global:      true,
		Apply:       true,
		Targets:     []string{TargetAntigravity, TargetClaude, TargetCursor},
		Now:         fixedTime,
	})
	if err != nil {
		t.Fatalf("global PlanAndApplyMCP failed: %v", err)
	}
	wantGlobalPaths := []string{
		filepath.Join(fakeHome, ".gemini", "config", "mcp_config.json"),
		filepath.Join(fakeHome, ".claude.json"),
		filepath.Join(fakeHome, ".cursor", "mcp.json"),
	}
	for i, want := range wantGlobalPaths {
		if globalReport.Plans[i].ConfigPath != want {
			t.Fatalf("global plan[%d] path = %q, want %q", i, globalReport.Plans[i].ConfigPath, want)
		}
		data, rErr := os.ReadFile(want)
		if rErr != nil {
			t.Fatalf("expected global config %s to be written: %v", want, rErr)
		}
		if !strings.Contains(string(data), `"coppermind"`) || !strings.Contains(string(data), `"argus"`) {
			t.Fatalf("global config %s missing canonical servers", want)
		}
	}
}
