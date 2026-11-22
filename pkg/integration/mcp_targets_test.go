package integration

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/fabrial/pkg/ux"
)

func TestInitMCP_DryRunBackupAndAtomicMerge(t *testing.T) {
	worktree := t.TempDir()
	fakeHome := t.TempDir()
	fakeConfigDir := t.TempDir()

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
		ConfigDir:   fakeConfigDir,
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
	if len(dryReport.Plans) != 7 {
		t.Fatalf("expected 7 IDE target plans, got %d", len(dryReport.Plans))
	}
	for i, wantTarget := range CanonicalMCPTargetOrder {
		if dryReport.Plans[i].Target != wantTarget {
			t.Fatalf("dry plan[%d].Target = %q, want %q", i, dryReport.Plans[i].Target, wantTarget)
		}
		if dryReport.Plans[i].Applied {
			t.Fatalf("dry plan[%d] unexpectedly marked Applied=true", i)
		}
	}
	for _, untouchedRel := range []string{
		filepath.Join(".agents", "mcp_config.json"),
		filepath.Join(".codex", "config.toml"),
		filepath.Join(".cursor", "mcp.json"),
		filepath.Join(".gemini", "settings.json"),
		filepath.Join(".super.engineering", "config.json"),
		filepath.Join(".vscode", "mcp.json"),
	} {
		if _, err := os.Stat(filepath.Join(worktree, untouchedRel)); !os.IsNotExist(err) {
			t.Fatalf("dry-run unexpectedly created %s", untouchedRel)
		}
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
		ConfigDir:     fakeConfigDir,
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
	if len(applyReport.Plans) != 7 {
		t.Fatalf("expected 7 applied plans, got %d", len(applyReport.Plans))
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

	// Verify Codex TOML, Gemini settings.json, and VS Code mcp.json were all written locally with 0600
	codexLocalBytes, err := os.ReadFile(filepath.Join(worktree, ".codex", "config.toml"))
	if err != nil {
		t.Fatalf("expected local .codex/config.toml: %v", err)
	}
	if err := ValidateCodexTOML(codexLocalBytes); err != nil {
		t.Fatalf("generated local .codex/config.toml invalid: %v", err)
	}
	if !strings.Contains(string(codexLocalBytes), "[mcp_servers.coppermind]") ||
		!strings.Contains(string(codexLocalBytes), conjoinerProxyBinary) {
		t.Fatalf("local .codex/config.toml missing wrapped canonical servers:\n%s", string(codexLocalBytes))
	}

	// 3. Global apply across all 7 targets into fakeHome + fakeConfigDir
	globalReport, err := PlanAndApplyMCP(MCPInitOptions{
		WorktreeDir: worktree,
		HomeDir:     fakeHome,
		ConfigDir:   fakeConfigDir,
		Global:      true,
		Apply:       true,
		Targets:     []string{TargetAll},
		Now:         fixedTime,
	})
	if err != nil {
		t.Fatalf("global PlanAndApplyMCP failed: %v", err)
	}
	wantGlobalPaths := []string{
		filepath.Join(fakeHome, ".gemini", "config", "mcp_config.json"),
		filepath.Join(fakeHome, ".claude.json"),
		filepath.Join(fakeHome, ".codex", "config.toml"),
		filepath.Join(fakeHome, ".cursor", "mcp.json"),
		filepath.Join(fakeHome, ".gemini", "settings.json"),
		filepath.Join(fakeHome, ".super.engineering", "config.json"),
		filepath.Join(fakeConfigDir, "Code", "User", "mcp.json"),
	}
	if len(globalReport.Plans) != len(wantGlobalPaths) {
		t.Fatalf("global plans count = %d, want %d", len(globalReport.Plans), len(wantGlobalPaths))
	}
	for i, want := range wantGlobalPaths {
		if globalReport.Plans[i].ConfigPath != want {
			t.Fatalf("global plan[%d] (%s) path = %q, want %q", i, globalReport.Plans[i].Target, globalReport.Plans[i].ConfigPath, want)
		}
		data, rErr := os.ReadFile(want)
		if rErr != nil {
			t.Fatalf("expected global config %s to be written: %v", want, rErr)
		}
		if globalReport.Plans[i].Target == TargetCodex {
			if err := ValidateCodexTOML(data); err != nil {
				t.Fatalf("global codex config invalid TOML: %v", err)
			}
			if !strings.Contains(string(data), "[mcp_servers.coppermind]") || !strings.Contains(string(data), "[mcp_servers.argus]") {
				t.Fatalf("global codex config %s missing canonical servers", want)
			}
		} else {
			if !strings.Contains(string(data), `"coppermind"`) || !strings.Contains(string(data), `"argus"`) {
				t.Fatalf("global config %s missing canonical servers", want)
			}
		}
	}

	// 4. Verify global VS Code fallback when HomeDir is set without ConfigDir
	fallbackHome := t.TempDir()
	vsFallbackReport, err := PlanAndApplyMCP(MCPInitOptions{
		WorktreeDir: worktree,
		HomeDir:     fallbackHome,
		Global:      true,
		Apply:       true,
		Targets:     []string{TargetVSCode},
		Now:         fixedTime,
	})
	if err != nil {
		t.Fatalf("global vscode fallback failed: %v", err)
	}
	wantVSFallback := filepath.Join(fallbackHome, ".config", "Code", "User", "mcp.json")
	if vsFallbackReport.Plans[0].ConfigPath != wantVSFallback {
		t.Fatalf("global vscode fallback path = %q, want %q", vsFallbackReport.Plans[0].ConfigPath, wantVSFallback)
	}
}

func TestNormalizeMCPTargets_AllSevenAndAliases(t *testing.T) {
	wantAll := []string{
		TargetAntigravity,
		TargetClaude,
		TargetCodex,
		TargetCursor,
		TargetGemini,
		TargetSuperEngineering,
		TargetVSCode,
	}

	gotDefault, err := NormalizeMCPTargets(nil)
	if err != nil {
		t.Fatalf("NormalizeMCPTargets(nil) error: %v", err)
	}
	if !reflect.DeepEqual(gotDefault, wantAll) {
		t.Fatalf("NormalizeMCPTargets(nil) = %v, want %v", gotDefault, wantAll)
	}

	gotAll, err := NormalizeMCPTargets([]string{"all"})
	if err != nil {
		t.Fatalf("NormalizeMCPTargets(all) error: %v", err)
	}
	if !reflect.DeepEqual(gotAll, wantAll) {
		t.Fatalf("NormalizeMCPTargets(all) = %v, want %v", gotAll, wantAll)
	}

	gotAliases, err := NormalizeMCPTargets([]string{"openai-codex,gemini-cli,copilot", "codex-cli,vs-code,github-copilot,agy,claude-code,se"})
	if err != nil {
		t.Fatalf("NormalizeMCPTargets(aliases) error: %v", err)
	}
	wantAliases := []string{TargetCodex, TargetGemini, TargetVSCode, TargetAntigravity, TargetClaude, TargetSuperEngineering}
	if !reflect.DeepEqual(gotAliases, wantAliases) {
		t.Fatalf("NormalizeMCPTargets(aliases) = %v, want %v", gotAliases, wantAliases)
	}

	_, err = NormalizeMCPTargets([]string{"unknown-ide"})
	if err == nil {
		t.Fatal("expected error for unknown target")
	}
	var ff *ux.FixForwardError
	if !errors.As(err, &ff) {
		t.Fatalf("expected FixForwardError, got %T: %v", err, err)
	}
	if ff.Code != "FABRIAL_INIT_MCP_UNKNOWN_TARGET" {
		t.Fatalf("expected FABRIAL_INIT_MCP_UNKNOWN_TARGET, got %q", ff.Code)
	}
	for _, targetName := range wantAll {
		if !strings.Contains(ff.WhyOneLiner, targetName) {
			t.Fatalf("WhyOneLiner %q missing target %q", ff.WhyOneLiner, targetName)
		}
	}
}

func TestInitMCP_ConvenienceHelpers_CodexGeminiVSCode(t *testing.T) {
	worktree := t.TempDir()

	// Codex helper: dry-run then apply then idempotent apply
	codexDry, err := Codex(worktree, false, false, false)
	if err != nil {
		t.Fatalf("Codex dry-run error: %v", err)
	}
	if codexDry.Applied || len(codexDry.ServersAdded) != 5 {
		t.Fatalf("unexpected Codex dry-run plan: %+v", codexDry)
	}
	codexApply, err := Codex(worktree, false, true, false)
	if err != nil {
		t.Fatalf("Codex apply error: %v", err)
	}
	if !codexApply.Applied || len(codexApply.ServersAdded) != 5 {
		t.Fatalf("unexpected Codex apply plan: %+v", codexApply)
	}
	codexIdem, err := Codex(worktree, false, false, false)
	if err != nil {
		t.Fatalf("Codex second dry-run error: %v", err)
	}
	if len(codexIdem.ServersUnchanged) != 5 || len(codexIdem.ServersAdded) != 0 || len(codexIdem.ServersUpdated) != 0 {
		t.Fatalf("expected Codex idempotency, got: %+v", codexIdem)
	}

	// Gemini helper
	geminiApply, err := Gemini(worktree, false, true, false)
	if err != nil {
		t.Fatalf("Gemini apply error: %v", err)
	}
	if !geminiApply.Applied || geminiApply.ConfigPath != filepath.Join(worktree, ".gemini", "settings.json") {
		t.Fatalf("unexpected Gemini apply plan: %+v", geminiApply)
	}

	// VSCode helper
	vsApply, err := VSCode(worktree, false, true, false)
	if err != nil {
		t.Fatalf("VSCode apply error: %v", err)
	}
	if !vsApply.Applied || vsApply.ConfigPath != filepath.Join(worktree, ".vscode", "mcp.json") {
		t.Fatalf("unexpected VSCode apply plan: %+v", vsApply)
	}
	vsIdem, err := VSCode(worktree, false, false, false)
	if err != nil {
		t.Fatalf("VSCode second dry-run error: %v", err)
	}
	if len(vsIdem.ServersUnchanged) != 5 {
		t.Fatalf("expected VSCode idempotency, got: %+v", vsIdem)
	}
}
