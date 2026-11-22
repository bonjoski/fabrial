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

	"github.com/bonjoski/fabrial/pkg/ux"
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

// TestInitMCP_CodexTOML_PreservesCommentsAndRejectsSymlinkAndInjection verifies:
//  1. Surgical comment-preserving TOML merging preserves comments, blank lines,
//     top-level keys, inline tables, multi-line arrays, and user [mcp_servers.*] tables.
//  2. Dry-run writes 0 bytes; --apply writes 0600 config & 0600 .bak.<ts> backup.
//  3. Symlinked .codex/config.toml and symlinked .codex/ directories fail closed.
//  4. Malformed TOML fails closed with FABRIAL_INIT_MCP_INVALID_TOML.
//  5. Newline / control-char / bidi / key-name TOML injection payloads fail closed.
func TestInitMCP_CodexTOML_PreservesCommentsAndRejectsSymlinkAndInjection(t *testing.T) {
	fixedTime := func() time.Time { return time.Unix(1795291000, 0) }

	t.Run("preserves_comments_and_user_tables_with_backup", func(t *testing.T) {
		worktree := t.TempDir()
		codexDir := filepath.Join(worktree, ".codex")
		if err := os.MkdirAll(codexDir, 0700); err != nil {
			t.Fatal(err)
		}
		configPath := filepath.Join(codexDir, "config.toml")
		seedTOML := `# Codex Workstation Configuration
# Keep this header comment verbatim!
model = "o3" # inline comment
approval_policy = "on-request"
sandbox_mode = 'workspace-write'
max_tokens = 8_192
temperature = 0.25
telemetry = false
extra_settings = { retries = 3, strict = true }

# User-owned custom MCP server (must stay untouched!)
[mcp_servers.my-custom-db]
command = "npx"
args = [
  "-y", # inline array comment
  "custom-db-mcp",
]
env = { PGHOST = "127.0.0.1", PGPORT = "5432" }

# Outdated coppermind definition (should be surgically updated)
[mcp_servers.coppermind]
command = "old-coppermind"
args = ["legacy-serve"]
# Trailing comment before next table must survive!

[mcp_servers.argus]
command = "argus"
args = ["mcp"]
`
		if err := os.WriteFile(configPath, []byte(seedTOML), 0600); err != nil {
			t.Fatal(err)
		}

		// Dry-run writes 0 bytes
		dryReport, err := PlanAndApplyMCP(MCPInitOptions{
			WorktreeDir: worktree,
			Apply:       false,
			Targets:     []string{TargetCodex},
			Now:         fixedTime,
		})
		if err != nil {
			t.Fatalf("codex dry-run failed: %v", err)
		}
		if len(dryReport.Plans) != 1 || dryReport.Plans[0].Applied {
			t.Fatalf("unexpected codex dry-run plan: %+v", dryReport.Plans)
		}
		afterDry, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(afterDry) != seedTOML {
			t.Fatal("dry-run mutated .codex/config.toml")
		}

		// Apply
		applyReport, err := PlanAndApplyMCP(MCPInitOptions{
			WorktreeDir: worktree,
			Apply:       true,
			Targets:     []string{TargetCodex},
			Now:         fixedTime,
		})
		if err != nil {
			t.Fatalf("codex apply failed: %v", err)
		}
		plan := applyReport.Plans[0]
		if !plan.Applied {
			t.Fatal("expected plan.Applied == true")
		}
		if len(plan.ServersUpdated) != 1 || plan.ServersUpdated[0] != "coppermind" {
			t.Fatalf("expected only coppermind updated, got %v", plan.ServersUpdated)
		}
		if len(plan.ServersUnchanged) != 1 || plan.ServersUnchanged[0] != "argus" {
			t.Fatalf("expected only argus unchanged, got %v", plan.ServersUnchanged)
		}
		if len(plan.ServersAdded) != 3 {
			t.Fatalf("expected 3 servers added (airlock, aegisbox, locksmith), got %v", plan.ServersAdded)
		}
		if len(plan.UserServersPreserved) != 1 || plan.UserServersPreserved[0] != "my-custom-db" {
			t.Fatalf("expected my-custom-db preserved, got %v", plan.UserServersPreserved)
		}

		// Verify 0600 backup contains exact original bytes
		wantBackup := configPath + ".bak.1795291000"
		if plan.BackupPath != wantBackup {
			t.Fatalf("backup path = %q, want %q", plan.BackupPath, wantBackup)
		}
		bakBytes, err := os.ReadFile(wantBackup)
		if err != nil {
			t.Fatalf("read backup: %v", err)
		}
		if string(bakBytes) != seedTOML {
			t.Fatal("backup bytes do not match original config.toml")
		}
		if runtime.GOOS != "windows" {
			bakInfo, _ := os.Stat(wantBackup)
			if bakInfo.Mode().Perm() != 0600 {
				t.Fatalf("expected 0600 backup perm, got %04o", bakInfo.Mode().Perm())
			}
			cfgInfo, _ := os.Stat(configPath)
			if cfgInfo.Mode().Perm() != 0600 {
				t.Fatalf("expected 0600 config perm, got %04o", cfgInfo.Mode().Perm())
			}
		}

		// Verify merged output preserves every comment, top-level key, and custom table
		mergedBytes, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatal(err)
		}
		mergedStr := string(mergedBytes)
		if err := ValidateCodexTOML(mergedBytes); err != nil {
			t.Fatalf("merged TOML failed validation: %v\n%s", err, mergedStr)
		}
		for _, mustKeep := range []string{
			"# Codex Workstation Configuration",
			"# Keep this header comment verbatim!",
			`model = "o3" # inline comment`,
			`approval_policy = "on-request"`,
			`sandbox_mode = 'workspace-write'`,
			`extra_settings = { retries = 3, strict = true }`,
			"# User-owned custom MCP server (must stay untouched!)",
			"[mcp_servers.my-custom-db]",
			`  "-y", # inline array comment`,
			`env = { PGHOST = "127.0.0.1", PGPORT = "5432" }`,
			"# Outdated coppermind definition (should be surgically updated)",
			"# Trailing comment before next table must survive!",
			"[mcp_servers.coppermind]",
			`command = "coppermind"`,
			`args = ["mcp"]`,
			"[mcp_servers.argus]",
			"[mcp_servers.airlock]",
			"[mcp_servers.aegisbox]",
			"[mcp_servers.locksmith]",
		} {
			if !strings.Contains(mergedStr, mustKeep) {
				t.Fatalf("merged config.toml missing expected content %q:\n%s", mustKeep, mergedStr)
			}
		}
		if strings.Contains(mergedStr, "old-coppermind") || strings.Contains(mergedStr, "legacy-serve") {
			t.Fatalf("outdated coppermind settings were not replaced:\n%s", mergedStr)
		}
	})

	t.Run("rejects_symlinked_file_and_dir", func(t *testing.T) {
		outsideDir := t.TempDir()
		outsideFile := filepath.Join(outsideDir, "zshrc")
		sentinel := "# DO NOT OVERWRITE\n"
		if err := os.WriteFile(outsideFile, []byte(sentinel), 0600); err != nil {
			t.Fatal(err)
		}

		// Case A: symlinked .codex/config.toml
		wt1 := t.TempDir()
		if err := os.MkdirAll(filepath.Join(wt1, ".codex"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outsideFile, filepath.Join(wt1, ".codex", "config.toml")); err != nil {
			t.Fatal(err)
		}
		_, err := PlanAndApplyMCP(MCPInitOptions{
			WorktreeDir: wt1,
			Apply:       true,
			Targets:     []string{TargetCodex},
		})
		if !errors.Is(err, ErrMCPSymlinkDetected) {
			t.Fatalf("FAIL-OPEN: expected ErrMCPSymlinkDetected on symlinked config.toml, got: %v", err)
		}
		gotOutside, _ := os.ReadFile(outsideFile)
		if string(gotOutside) != sentinel {
			t.Fatalf("FAIL-OPEN: symlink target mutated: %q", string(gotOutside))
		}

		// Case B: symlinked .codex directory
		wt2 := t.TempDir()
		if err := os.Symlink(outsideDir, filepath.Join(wt2, ".codex")); err != nil {
			t.Fatal(err)
		}
		_, err = PlanAndApplyMCP(MCPInitOptions{
			WorktreeDir: wt2,
			Apply:       true,
			Targets:     []string{TargetCodex},
		})
		if !errors.Is(err, ErrMCPSymlinkDetected) {
			t.Fatalf("FAIL-OPEN: expected ErrMCPSymlinkDetected on symlinked .codex dir, got: %v", err)
		}
		if _, statErr := os.Stat(filepath.Join(outsideDir, "config.toml")); !os.IsNotExist(statErr) {
			t.Fatal("FAIL-OPEN: wrote config.toml through symlinked .codex directory")
		}
	})

	t.Run("fails_closed_on_malformed_toml", func(t *testing.T) {
		cases := []struct {
			name string
			body string
		}{
			{"unclosed_quote", "model = \"o3\n"},
			{"unclosed_array", "[mcp_servers.foo]\ncommand = \"x\"\nargs = [\"a\", \"b\"\n"},
			{"unclosed_header", "[mcp_servers.foo\ncommand = \"x\"\n"},
			{"duplicate_header", "[mcp_servers.coppermind]\ncommand = \"a\"\n[mcp_servers.coppermind]\ncommand = \"b\"\n"},
			{"duplicate_quoted_header", "[mcp_servers.coppermind]\ncommand = \"a\"\n[mcp_servers.\"coppermind\"]\ncommand = \"b\"\n"},
			{"missing_equals", "model \"o3\"\n"},
			{"non_table_mcp_servers", "mcp_servers = \"broken\"\n"},
			{"unclosed_inline_table", "opts = { a = 1\n"},
			{"duplicate_key", "model = \"o3\"\nmodel = \"o4\"\n"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				wt := t.TempDir()
				codexDir := filepath.Join(wt, ".codex")
				if err := os.MkdirAll(codexDir, 0700); err != nil {
					t.Fatal(err)
				}
				cfgPath := filepath.Join(codexDir, "config.toml")
				if err := os.WriteFile(cfgPath, []byte(tc.body), 0600); err != nil {
					t.Fatal(err)
				}
				_, err := PlanAndApplyMCP(MCPInitOptions{
					WorktreeDir: wt,
					Apply:       true,
					Targets:     []string{TargetCodex},
				})
				if err == nil {
					t.Fatalf("FAIL-OPEN: malformed TOML (%s) was accepted", tc.name)
				}
				var ff *ux.FixForwardError
				if !errors.As(err, &ff) || ff.Code != "FABRIAL_INIT_MCP_INVALID_TOML" {
					t.Fatalf("expected FABRIAL_INIT_MCP_INVALID_TOML for %s, got: %v", tc.name, err)
				}
				after, _ := os.ReadFile(cfgPath)
				if string(after) != tc.body {
					t.Fatalf("malformed file %s was modified on disk", tc.name)
				}
			})
		}
	})

	t.Run("rejects_toml_injection_payloads", func(t *testing.T) {
		injectionCases := []struct {
			name      string
			canonical map[string]MCPServerSpec
		}{
			{
				name: "newline_table_injection_in_command",
				canonical: map[string]MCPServerSpec{
					"coppermind": {Command: "coppermind\"\n[mcp_servers.evil]\ncommand = \"pwn", Args: []string{"mcp"}},
				},
			},
			{
				name: "carriage_return_in_args",
				canonical: map[string]MCPServerSpec{
					"coppermind": {Command: "coppermind", Args: []string{"mcp\r[mcp_servers.evil]"}},
				},
			},
			{
				name: "nul_byte_in_args",
				canonical: map[string]MCPServerSpec{
					"coppermind": {Command: "coppermind", Args: []string{"mcp\x00evil"}},
				},
			},
			{
				name: "ansi_escape_in_command",
				canonical: map[string]MCPServerSpec{
					"coppermind": {Command: "coppermind\x1b[31m", Args: []string{"mcp"}},
				},
			},
			{
				name: "bidi_override_in_args",
				canonical: map[string]MCPServerSpec{
					"coppermind": {Command: "coppermind", Args: []string{"mcp\u202eevil"}},
				},
			},
		}

		for _, tc := range injectionCases {
			t.Run(tc.name, func(t *testing.T) {
				_, _, err := MergeCodexTOML(nil, tc.canonical, "/tmp/config.toml", TargetCodex)
				if !errors.Is(err, ErrMCPTOMLInjection) {
					t.Fatalf("FAIL-OPEN: expected ErrMCPTOMLInjection for %s, got: %v", tc.name, err)
				}
			})
		}

		// Verify key segment validator blocks bracket/newline injection directly
		if _, err := formatCodexMCPServerBlock("evil]\n[mcp_servers.pwn", MCPServerSpec{Command: "x", Args: []string{"y"}}); !errors.Is(err, ErrMCPTOMLInjection) {
			t.Fatalf("FAIL-OPEN: expected ErrMCPTOMLInjection on crafted table key, got: %v", err)
		}

		// Verify legitimate quotes/backslashes are safely escaped and round-trip cleanly
		safeWithQuotes := map[string]MCPServerSpec{
			"coppermind": {Command: `C:\bin\coppermind.exe`, Args: []string{`--label="safe"`}},
			"argus":      {Command: "argus", Args: []string{"mcp"}},
			"airlock":    {Command: "airlock", Args: []string{"mcp"}},
			"aegisbox":   {Command: "aegisbox", Args: []string{"mcp"}},
			"locksmith":  {Command: "locksmith", Args: []string{"mcp"}},
		}
		out, _, err := MergeCodexTOML(nil, safeWithQuotes, "/tmp/config.toml", TargetCodex)
		if err != nil {
			t.Fatalf("expected safely escaped quotes/backslashes to succeed, got: %v", err)
		}
		if err := ValidateCodexTOML(out); err != nil {
			t.Fatalf("escaped TOML failed round-trip validation: %v\n%s", err, string(out))
		}
	})
}

// TestInitMCP_VSCodeServersSchemaAndGeminiSettingsPreservation verifies:
//  1. VS Code uses top-level "servers" (never "mcpServers") with explicit "type": "stdio",
//     preserving "inputs" and user servers, rejecting symlinks and malformed JSON.
//  2. Gemini CLI uses top-level "mcpServers" inside settings.json while preserving
//     "general", "theme", "selectedAuthType", "hooks", and user servers, rejecting
//     symlinks and malformed JSON.
func TestInitMCP_VSCodeServersSchemaAndGeminiSettingsPreservation(t *testing.T) {
	fixedTime := func() time.Time { return time.Unix(1795292000, 0) }

	t.Run("vscode_servers_schema_and_inputs_preservation", func(t *testing.T) {
		wt := t.TempDir()
		vsDir := filepath.Join(wt, ".vscode")
		if err := os.MkdirAll(vsDir, 0700); err != nil {
			t.Fatal(err)
		}
		vsPath := filepath.Join(vsDir, "mcp.json")
		seedVS := `{
  "inputs": [
    {
      "type": "promptString",
      "id": "pg-pass",
      "description": "Local Postgres password",
      "password": true
    }
  ],
  "servers": {
    "my-github": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"]
    },
    "coppermind": {
      "command": "coppermind",
      "args": ["mcp"]
    }
  }
}
`
		if err := os.WriteFile(vsPath, []byte(seedVS), 0600); err != nil {
			t.Fatal(err)
		}

		// Dry-run writes 0 bytes; coppermind missing "type": "stdio" must be flagged as updated
		dryReport, err := PlanAndApplyMCP(MCPInitOptions{
			WorktreeDir: wt,
			Apply:       false,
			Targets:     []string{TargetVSCode},
			Now:         fixedTime,
		})
		if err != nil {
			t.Fatalf("vscode dry-run failed: %v", err)
		}
		if len(dryReport.Plans[0].ServersUpdated) != 1 || dryReport.Plans[0].ServersUpdated[0] != "coppermind" {
			t.Fatalf("expected coppermind updated (missing type:stdio), got %+v", dryReport.Plans[0])
		}
		if afterDry, _ := os.ReadFile(vsPath); string(afterDry) != seedVS {
			t.Fatal("dry-run mutated .vscode/mcp.json")
		}

		// Apply
		applyReport, err := PlanAndApplyMCP(MCPInitOptions{
			WorktreeDir: wt,
			Apply:       true,
			Targets:     []string{TargetVSCode},
			Now:         fixedTime,
		})
		if err != nil {
			t.Fatalf("vscode apply failed: %v", err)
		}
		plan := applyReport.Plans[0]
		if !plan.Applied || plan.BackupPath != vsPath+".bak.1795292000" {
			t.Fatalf("unexpected vscode apply plan: %+v", plan)
		}
		if len(plan.UserServersPreserved) != 1 || plan.UserServersPreserved[0] != "my-github" {
			t.Fatalf("expected my-github preserved, got %v", plan.UserServersPreserved)
		}
		if runtime.GOOS != "windows" {
			bakInfo, _ := os.Stat(plan.BackupPath)
			if bakInfo.Mode().Perm() != 0600 {
				t.Fatalf("expected 0600 backup perm, got %04o", bakInfo.Mode().Perm())
			}
		}

		mergedBytes, err := os.ReadFile(vsPath)
		if err != nil {
			t.Fatal(err)
		}
		var parsed map[string]interface{}
		if err := json.Unmarshal(mergedBytes, &parsed); err != nil {
			t.Fatalf("invalid merged vscode json: %v", err)
		}
		if _, hasMCPServers := parsed["mcpServers"]; hasMCPServers {
			t.Fatalf("VS Code mcp.json MUST NOT contain top-level mcpServers key: %+v", parsed)
		}
		inputs, ok := parsed["inputs"].([]interface{})
		if !ok || len(inputs) != 1 {
			t.Fatalf("VS Code inputs array was lost or corrupted: %+v", parsed["inputs"])
		}
		servers, ok := parsed["servers"].(map[string]interface{})
		if !ok {
			t.Fatalf("VS Code top-level servers map missing: %+v", parsed)
		}
		if _, ok := servers["my-github"]; !ok {
			t.Fatalf("user server my-github was lost: %+v", servers)
		}
		for _, name := range CanonicalMCPServerOrder {
			entry, ok := servers[name].(map[string]interface{})
			if !ok {
				t.Fatalf("canonical server %s missing in VS Code servers", name)
			}
			if entry["type"] != "stdio" {
				t.Fatalf("canonical VS Code server %s missing type=stdio: %+v", name, entry)
			}
			if entry["command"] != name {
				t.Fatalf("canonical VS Code server %s command = %v, want %q", name, entry["command"], name)
			}
		}

		// Symlink rejection on .vscode/mcp.json
		outsideFile := filepath.Join(t.TempDir(), "secret.json")
		_ = os.WriteFile(outsideFile, []byte(`{"keep":true}`), 0600)
		wtSym := t.TempDir()
		_ = os.MkdirAll(filepath.Join(wtSym, ".vscode"), 0700)
		_ = os.Symlink(outsideFile, filepath.Join(wtSym, ".vscode", "mcp.json"))
		if _, err := PlanAndApplyMCP(MCPInitOptions{WorktreeDir: wtSym, Apply: true, Targets: []string{TargetVSCode}}); !errors.Is(err, ErrMCPSymlinkDetected) {
			t.Fatalf("FAIL-OPEN: expected ErrMCPSymlinkDetected for symlinked .vscode/mcp.json, got: %v", err)
		}

		// Non-object "servers" fails closed with FABRIAL_INIT_MCP_INVALID_JSON
		wtBad := t.TempDir()
		_ = os.MkdirAll(filepath.Join(wtBad, ".vscode"), 0700)
		badVS := filepath.Join(wtBad, ".vscode", "mcp.json")
		_ = os.WriteFile(badVS, []byte(`{"servers": ["not-an-object"]}`), 0600)
		_, err = PlanAndApplyMCP(MCPInitOptions{WorktreeDir: wtBad, Apply: true, Targets: []string{TargetVSCode}})
		var ff *ux.FixForwardError
		if !errors.As(err, &ff) || ff.Code != "FABRIAL_INIT_MCP_INVALID_JSON" {
			t.Fatalf("expected FABRIAL_INIT_MCP_INVALID_JSON on non-object servers, got: %v", err)
		}
	})

	t.Run("gemini_settings_preserves_general_theme_auth_hooks_and_user_servers", func(t *testing.T) {
		wt := t.TempDir()
		gemDir := filepath.Join(wt, ".gemini")
		if err := os.MkdirAll(gemDir, 0700); err != nil {
			t.Fatal(err)
		}
		gemPath := filepath.Join(gemDir, "settings.json")
		seedGemini := `{
  "general": {
    "vimMode": true,
    "preferredEditor": "code"
  },
  "theme": "GitHub Dark",
  "selectedAuthType": "oauth-personal",
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "run_shell_command",
        "hooks": [
          {
            "type": "command",
            "command": "fabrial hook eval --client gemini --event pre-tool"
          }
        ]
      }
    ]
  },
  "mcpServers": {
    "local-docs": {
      "command": "docs-mcp",
      "args": ["--port", "0"]
    }
  }
}
`
		if err := os.WriteFile(gemPath, []byte(seedGemini), 0600); err != nil {
			t.Fatal(err)
		}

		// Dry-run writes 0 bytes
		if _, err := PlanAndApplyMCP(MCPInitOptions{WorktreeDir: wt, Apply: false, Targets: []string{TargetGemini}, Now: fixedTime}); err != nil {
			t.Fatalf("gemini dry-run failed: %v", err)
		}
		if afterDry, _ := os.ReadFile(gemPath); string(afterDry) != seedGemini {
			t.Fatal("dry-run mutated .gemini/settings.json")
		}

		// Apply
		applyReport, err := PlanAndApplyMCP(MCPInitOptions{
			WorktreeDir: wt,
			Apply:       true,
			Targets:     []string{TargetGemini},
			Now:         fixedTime,
		})
		if err != nil {
			t.Fatalf("gemini apply failed: %v", err)
		}
		plan := applyReport.Plans[0]
		if !plan.Applied || plan.BackupPath != gemPath+".bak.1795292000" {
			t.Fatalf("unexpected gemini apply plan: %+v", plan)
		}
		if len(plan.UserServersPreserved) != 1 || plan.UserServersPreserved[0] != "local-docs" {
			t.Fatalf("expected local-docs preserved, got %v", plan.UserServersPreserved)
		}

		mergedBytes, err := os.ReadFile(gemPath)
		if err != nil {
			t.Fatal(err)
		}
		var parsed map[string]interface{}
		if err := json.Unmarshal(mergedBytes, &parsed); err != nil {
			t.Fatalf("invalid merged gemini settings.json: %v", err)
		}
		if parsed["theme"] != "GitHub Dark" {
			t.Fatalf("theme clobbered: %+v", parsed["theme"])
		}
		if parsed["selectedAuthType"] != "oauth-personal" {
			t.Fatalf("selectedAuthType clobbered: %+v", parsed["selectedAuthType"])
		}
		general, ok := parsed["general"].(map[string]interface{})
		if !ok || general["vimMode"] != true {
			t.Fatalf("general settings clobbered: %+v", parsed["general"])
		}
		hooksMap, ok := parsed["hooks"].(map[string]interface{})
		if !ok || hooksMap["BeforeTool"] == nil {
			t.Fatalf("hooks settings clobbered: %+v", parsed["hooks"])
		}
		servers, ok := parsed["mcpServers"].(map[string]interface{})
		if !ok {
			t.Fatalf("mcpServers missing in gemini settings.json")
		}
		if _, ok := servers["local-docs"]; !ok {
			t.Fatalf("user server local-docs lost in gemini settings.json")
		}
		for _, name := range CanonicalMCPServerOrder {
			if _, ok := servers[name]; !ok {
				t.Fatalf("canonical server %s missing in gemini settings.json", name)
			}
		}

		// Symlinked .gemini directory fails closed
		wtSym := t.TempDir()
		_ = os.Symlink(t.TempDir(), filepath.Join(wtSym, ".gemini"))
		if _, err := PlanAndApplyMCP(MCPInitOptions{WorktreeDir: wtSym, Apply: true, Targets: []string{TargetGemini}}); !errors.Is(err, ErrMCPSymlinkDetected) {
			t.Fatalf("FAIL-OPEN: expected ErrMCPSymlinkDetected on symlinked .gemini dir, got: %v", err)
		}

		// Malformed JSON fails closed
		wtBad := t.TempDir()
		_ = os.MkdirAll(filepath.Join(wtBad, ".gemini"), 0700)
		badGem := filepath.Join(wtBad, ".gemini", "settings.json")
		_ = os.WriteFile(badGem, []byte(`{"theme": "dark",`), 0600)
		_, err = PlanAndApplyMCP(MCPInitOptions{WorktreeDir: wtBad, Apply: true, Targets: []string{TargetGemini}})
		var ff *ux.FixForwardError
		if !errors.As(err, &ff) || ff.Code != "FABRIAL_INIT_MCP_INVALID_JSON" {
			t.Fatalf("expected FABRIAL_INIT_MCP_INVALID_JSON on malformed settings.json, got: %v", err)
		}
	})
}
