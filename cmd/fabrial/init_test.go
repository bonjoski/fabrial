package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bonjoski/fabrial/pkg/initscan"
	"github.com/bonjoski/fabrial/pkg/ux"
)

func TestFabrialCLI_InitReadOnlyAndFlags(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"dependencies":{"openai":"^4.0.0","@modelcontextprotocol/sdk":"^1.0.0"}}`), 0644); err != nil {
		t.Fatal(err)
	}

	// Default <=3 lines
	var out, errBuf bytes.Buffer
	code := runInit([]string{"--dir", dir}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("runInit exited %d, stderr: %s", code, errBuf.String())
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) > 3 {
		t.Fatalf("expected <=3 lines for default fabrial init, got %d:\n%s", len(lines), out.String())
	}
	if !strings.Contains(out.String(), "openai") || !strings.Contains(out.String(), "0 YAML written") {
		t.Fatalf("unexpected default init output:\n%s", out.String())
	}

	// --json
	out.Reset()
	errBuf.Reset()
	code = runInit([]string{"--dir", dir, "--json"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("runInit --json exited %d, stderr: %s", code, errBuf.String())
	}
	var res initscan.ScanResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("invalid init --json output: %v (raw: %s)", err, out.String())
	}
	if !res.ReadOnly || res.YAMLWritten {
		t.Fatalf("expected read-only zero-YAML scan, got: %+v", res)
	}

	// --why
	out.Reset()
	errBuf.Reset()
	code = runInit([]string{"--dir", dir, "--why"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("runInit --why exited %d", code)
	}
	if !strings.Contains(out.String(), "Deep Dive (--why):") || !strings.Contains(out.String(), "ai-app-and-rag-safety.capsule") {
		t.Fatalf("expected --why breakdown with AI safety tip, got:\n%s", out.String())
	}

	// Unknown flag returns UB-CLI-v2 FixForwardError JSON
	out.Reset()
	errBuf.Reset()
	code = runInit([]string{"--bogus-flag", "--json"}, &out, &errBuf)
	if code == 0 {
		t.Fatalf("expected non-zero exit for unknown flag")
	}
	var ffe ux.FixForwardError
	if err := json.Unmarshal(errBuf.Bytes(), &ffe); err != nil {
		t.Fatalf("expected FixForwardError JSON on stderr, got: %v (raw: %s)", err, errBuf.String())
	}
	if ffe.Code == "" || ffe.RemediationCmd == "" || ffe.WhyOneLiner == "" {
		t.Fatalf("FixForwardError missing required fields: %+v", ffe)
	}
}

func TestFabrialCLI_Explain(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runExplain([]string{"sandbox"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("runExplain sandbox failed: %d %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "Deep Dive (--why):") || !strings.Contains(out.String(), "Airlock") {
		t.Fatalf("unexpected explain output:\n%s", out.String())
	}
}

func TestFabrialCLI_InitMCPDryRunApplyAndSymlinkReject(t *testing.T) {
	dir := t.TempDir()

	// 1. Dry-run writes 0 files
	var out, errBuf bytes.Buffer
	code := runInit([]string{"--dir", dir, "--mcp", "--target", "claude,cursor", "--json"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("init --mcp dry-run exited %d, stderr: %s", code, errBuf.String())
	}
	if _, err := os.Stat(filepath.Join(dir, ".mcp.json")); !os.IsNotExist(err) {
		t.Fatal("dry-run wrote .mcp.json")
	}

	// 2. --apply writes files atomically
	out.Reset()
	errBuf.Reset()
	code = runInit([]string{"--dir", dir, "--mcp", "--apply", "--target", "claude,cursor", "--json"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("init --mcp --apply exited %d, stderr: %s", code, errBuf.String())
	}
	if _, err := os.Stat(filepath.Join(dir, ".mcp.json")); err != nil {
		t.Fatalf("expected .mcp.json written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".cursor", "mcp.json")); err != nil {
		t.Fatalf("expected .cursor/mcp.json written: %v", err)
	}

	// 3. Symlinked IDE config fails closed with exit code 10
	symDir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "escape.json")
	if err := os.WriteFile(outside, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(symDir, ".mcp.json")); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errBuf.Reset()
	code = runInit([]string{"--dir", symDir, "--mcp", "--apply", "--target", "claude", "--json"}, &out, &errBuf)
	if code != 10 {
		t.Fatalf("expected exit code 10 on symlinked IDE config, got %d (stderr: %s)", code, errBuf.String())
	}
	var ffe ux.FixForwardError
	if err := json.Unmarshal(errBuf.Bytes(), &ffe); err != nil {
		t.Fatalf("expected FixForwardError JSON on stderr, got: %v", err)
	}
	if ffe.Code != "FABRIAL_INIT_MCP_SYMLINK_REJECTED" {
		t.Fatalf("unexpected error code %q", ffe.Code)
	}
}

func TestFabrialCLI_InitMCP_NewTargetsCodexGeminiVSCode(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runInit([]string{"--dir", dir, "--mcp", "--apply", "--target", "codex,gemini,vscode", "--json"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("init --mcp --apply codex,gemini,vscode exited %d, stderr: %s", code, errBuf.String())
	}
	for _, rel := range []string{
		filepath.Join(".codex", "config.toml"),
		filepath.Join(".gemini", "settings.json"),
		filepath.Join(".vscode", "mcp.json"),
	} {
		if _, err := os.Stat(filepath.Join(dir, rel)); err != nil {
			t.Fatalf("expected %s to be written: %v", rel, err)
		}
	}
}

func TestFabrialCLI_InitHooks_DryRunApplyAndMutuallyExclusive(t *testing.T) {
	dir := t.TempDir()

	// Mutually exclusive --mcp --hooks fails cleanly with FixForwardError JSON
	var out, errBuf bytes.Buffer
	code := runInit([]string{"--dir", dir, "--mcp", "--hooks", "--json"}, &out, &errBuf)
	if code == 0 {
		t.Fatal("expected non-zero exit when combining --mcp and --hooks")
	}
	var ffe ux.FixForwardError
	if err := json.Unmarshal(errBuf.Bytes(), &ffe); err != nil {
		t.Fatalf("expected FixForwardError JSON: %v (raw: %s)", err, errBuf.String())
	}
	if ffe.Code != "FABRIAL_INIT_MUTUALLY_EXCLUSIVE_MODES" {
		t.Fatalf("unexpected error code %q", ffe.Code)
	}

	// Dry-run writes 0 files
	out.Reset()
	errBuf.Reset()
	code = runInit([]string{"--dir", dir, "--hooks", "--target", "claude,cursor,gemini", "--json"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("init --hooks dry-run exited %d, stderr: %s", code, errBuf.String())
	}
	if _, err := os.Stat(filepath.Join(dir, ".claude", "settings.json")); !os.IsNotExist(err) {
		t.Fatal("dry-run wrote .claude/settings.json")
	}

	// --apply writes all 3 native hook configs
	out.Reset()
	errBuf.Reset()
	code = runInit([]string{"--dir", dir, "--hooks", "--apply", "--target", "claude,cursor,gemini", "--json"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("init --hooks --apply exited %d, stderr: %s", code, errBuf.String())
	}
	for _, rel := range []string{
		filepath.Join(".claude", "settings.json"),
		filepath.Join(".cursor", "hooks.json"),
		filepath.Join(".gemini", "settings.json"),
	} {
		if _, err := os.Stat(filepath.Join(dir, rel)); err != nil {
			t.Fatalf("expected %s to be written: %v", rel, err)
		}
	}
}
