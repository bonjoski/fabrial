package integration

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/bonjoski/fabrial/pkg/ux"
)

const (
	TargetAll              = "all"
	TargetAntigravity      = "antigravity"
	TargetClaude           = "claude"
	TargetCodex            = "codex"
	TargetCursor           = "cursor"
	TargetGemini           = "gemini"
	TargetSuperEngineering = "superengineering"
	TargetVSCode           = "vscode"

	conjoinerProxyBinary = "mcp-conjoiner-proxy"
)

// CanonicalMCPTargetOrder lists all 7 first-class IDE MCP targets in deterministic order.
var CanonicalMCPTargetOrder = []string{
	TargetAntigravity,
	TargetClaude,
	TargetCodex,
	TargetCursor,
	TargetGemini,
	TargetSuperEngineering,
	TargetVSCode,
}

// ErrMCPSymlinkDetected is returned fail-closed when any IDE MCP config file or
// intermediate config directory is a symbolic link.
var ErrMCPSymlinkDetected = errors.New("symlink detected in IDE MCP config path (fail-closed)")

// CanonicalMCPServerOrder lists the 5 canonical UB-MCP-v1 servers in deterministic order.
var CanonicalMCPServerOrder = []string{
	"coppermind",
	"argus",
	"airlock",
	"aegisbox",
	"locksmith",
}

// MCPServerSpec represents a standard STDIO MCP server entry in IDE JSON configs.
type MCPServerSpec struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

// MCPInitOptions configures safe multi-IDE MCP dry-run planning or atomic apply.
type MCPInitOptions struct {
	WorktreeDir string
	HomeDir     string
	// ConfigDir optionally overrides os.UserConfigDir() for global targets that
	// store configuration in the OS user config directory (e.g., VS Code's
	// Code/User/mcp.json). When ConfigDir is empty and HomeDir is explicitly
	// provided (such as in hermetic tests), global VS Code falls back to
	// filepath.Join(HomeDir, ".config", "Code", "User", "mcp.json"). When both
	// ConfigDir and HomeDir are empty, os.UserConfigDir() is queried.
	ConfigDir     string
	Global        bool
	Apply         bool
	ConjoinerWrap bool
	Targets       []string
	LookPath      func(string) (string, error)
	Now           func() time.Time
}

// MCPTargetPlan summarizes planned or applied MCP changes for one IDE target.
type MCPTargetPlan struct {
	Target               string   `json:"target"`
	ConfigPath           string   `json:"config_path"`
	Exists               bool     `json:"exists"`
	BackupPath           string   `json:"backup_path,omitempty"`
	Applied              bool     `json:"applied"`
	ConjoinerWrapped     bool     `json:"conjoiner_wrapped"`
	ServersAdded         []string `json:"servers_added,omitempty"`
	ServersUpdated       []string `json:"servers_updated,omitempty"`
	ServersUnchanged     []string `json:"servers_unchanged,omitempty"`
	UserServersPreserved []string `json:"user_servers_preserved,omitempty"`
	Diff                 string   `json:"diff"`
}

// MCPInitReport aggregates results across all requested IDE targets.
type MCPInitReport struct {
	Tool                   string          `json:"tool"`
	Mode                   string          `json:"mode"` // "dry-run" or "applied"
	Global                 bool            `json:"global"`
	ConjoinerWrapRequested bool            `json:"conjoiner_wrap_requested"`
	ConjoinerWrapped       bool            `json:"conjoiner_wrapped"`
	Plans                  []MCPTargetPlan `json:"plans"`
}

// CanonicalMCPServers returns the 5 canonical Bonjoski MCP servers.
// When conjoinerWrap is true and mcp-conjoiner-proxy is available on PATH,
// each server is routed through mcp-conjoiner-proxy for DPoP & scope attenuation.
func CanonicalMCPServers(conjoinerWrap bool, lookPath func(string) (string, error)) (map[string]MCPServerSpec, bool) {
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	wrapped := false
	if conjoinerWrap {
		if _, err := lookPath(conjoinerProxyBinary); err == nil {
			wrapped = true
		}
	}

	specs := make(map[string]MCPServerSpec, len(CanonicalMCPServerOrder))
	for _, name := range CanonicalMCPServerOrder {
		if wrapped {
			specs[name] = MCPServerSpec{
				Command: conjoinerProxyBinary,
				Args:    []string{"--", name, "mcp"},
			}
		} else {
			specs[name] = MCPServerSpec{
				Command: name,
				Args:    []string{"mcp"},
			}
		}
	}
	return specs, wrapped
}

// NormalizeMCPTargets validates and expands target names ("all", "antigravity",
// "claude", "codex", "cursor", "gemini", "superengineering", "vscode") in
// canonical deterministic order.
func NormalizeMCPTargets(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return append([]string(nil), CanonicalMCPTargetOrder...), nil
	}

	seen := make(map[string]bool)
	var out []string
	add := func(t string) {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}

	for _, item := range raw {
		for _, tok := range strings.Split(item, ",") {
			switch strings.ToLower(strings.TrimSpace(tok)) {
			case "", TargetAll:
				for _, t := range CanonicalMCPTargetOrder {
					add(t)
				}
			case TargetAntigravity, "agy":
				add(TargetAntigravity)
			case TargetClaude, "claude-code", "claudecode":
				add(TargetClaude)
			case TargetCodex, "openai-codex", "codex-cli":
				add(TargetCodex)
			case TargetCursor:
				add(TargetCursor)
			case TargetGemini, "gemini-cli":
				add(TargetGemini)
			case TargetSuperEngineering, "super.engineering", "se":
				add(TargetSuperEngineering)
			case TargetVSCode, "copilot", "vs-code", "github-copilot":
				add(TargetVSCode)
			default:
				return nil, &ux.FixForwardError{
					Tool:           "fabrial",
					Code:           "FABRIAL_INIT_MCP_UNKNOWN_TARGET",
					Summary:        fmt.Sprintf("Unknown MCP IDE target %q", tok),
					RemediationCmd: "fabrial init --mcp --target all",
					WhyOneLiner:    "Supported targets are: all, antigravity, claude, codex, cursor, gemini, superengineering, vscode.",
					DeepWhy:        "Specify --target with one or more comma-separated IDE names, or use --target all to preview/apply all supported local IDE MCP configurations.",
					ExitCode:       1,
				}
			}
		}
	}
	return out, nil
}

// PlanAndApplyMCP performs a strictly read-only dry-run diff by default (Apply=false).
// When Apply=true, it enforces Lstat non-symlink guards on every path component,
// backs up existing files to <config>.bak.<ts> (0600), preserves unrelated user
// MCP servers and top-level keys, validates JSON round-trip, and atomically renames (0600).
func PlanAndApplyMCP(opts MCPInitOptions) (*MCPInitReport, error) {
	targets, err := NormalizeMCPTargets(opts.Targets)
	if err != nil {
		return nil, err
	}

	worktreeDir := strings.TrimSpace(opts.WorktreeDir)
	if worktreeDir == "" {
		worktreeDir = "."
	}
	absWorktree, err := filepath.Abs(worktreeDir)
	if err != nil {
		return nil, fmt.Errorf("resolve worktree dir: %w", err)
	}

	explicitHome := strings.TrimSpace(opts.HomeDir) != ""
	homeDir := strings.TrimSpace(opts.HomeDir)
	if homeDir == "" {
		homeDir, err = os.UserHomeDir()
		if err != nil && opts.Global {
			return nil, fmt.Errorf("determine home directory: %w", err)
		}
	}
	configDir := strings.TrimSpace(opts.ConfigDir)

	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	servers, wrapped := CanonicalMCPServers(opts.ConjoinerWrap, opts.LookPath)

	mode := "dry-run"
	if opts.Apply {
		mode = "applied"
	}

	report := &MCPInitReport{
		Tool:                   "fabrial",
		Mode:                   mode,
		Global:                 opts.Global,
		ConjoinerWrapRequested: opts.ConjoinerWrap,
		ConjoinerWrapped:       wrapped,
		Plans:                  make([]MCPTargetPlan, 0, len(targets)),
	}

	for _, target := range targets {
		baseDir, relPath, err := resolveMCPTargetPath(target, absWorktree, homeDir, configDir, explicitHome, opts.Global)
		if err != nil {
			return nil, err
		}

		plan, err := processMCPTarget(target, baseDir, relPath, servers, wrapped, opts.Apply, nowFn)
		if err != nil {
			return nil, err
		}
		report.Plans = append(report.Plans, *plan)
	}

	return report, nil
}

func resolveMCPTargetPath(target, absWorktree, homeDir, configDir string, explicitHome, isGlobal bool) (baseDir string, relPath string, err error) {
	if isGlobal {
		if target == TargetVSCode {
			if configDir != "" {
				return configDir, filepath.Join("Code", "User", "mcp.json"), nil
			}
			if explicitHome {
				return homeDir, filepath.Join(".config", "Code", "User", "mcp.json"), nil
			}
			ucd, uErr := os.UserConfigDir()
			if uErr != nil || strings.TrimSpace(ucd) == "" {
				if homeDir != "" {
					return homeDir, filepath.Join(".config", "Code", "User", "mcp.json"), nil
				}
				return "", "", fmt.Errorf("determine user config directory for --global vscode integration: %w", uErr)
			}
			return ucd, filepath.Join("Code", "User", "mcp.json"), nil
		}

		if homeDir == "" {
			return "", "", errors.New("home directory unavailable for --global MCP integration")
		}
		switch target {
		case TargetAntigravity:
			return homeDir, filepath.Join(".gemini", "config", "mcp_config.json"), nil
		case TargetClaude:
			return homeDir, ".claude.json", nil
		case TargetCodex:
			return homeDir, filepath.Join(".codex", "config.toml"), nil
		case TargetCursor:
			return homeDir, filepath.Join(".cursor", "mcp.json"), nil
		case TargetGemini:
			return homeDir, filepath.Join(".gemini", "settings.json"), nil
		case TargetSuperEngineering:
			return homeDir, filepath.Join(".super.engineering", "config.json"), nil
		}
	} else {
		switch target {
		case TargetAntigravity:
			return absWorktree, filepath.Join(".agents", "mcp_config.json"), nil
		case TargetClaude:
			return absWorktree, ".mcp.json", nil
		case TargetCodex:
			return absWorktree, filepath.Join(".codex", "config.toml"), nil
		case TargetCursor:
			return absWorktree, filepath.Join(".cursor", "mcp.json"), nil
		case TargetGemini:
			return absWorktree, filepath.Join(".gemini", "settings.json"), nil
		case TargetSuperEngineering:
			return absWorktree, filepath.Join(".super.engineering", "config.json"), nil
		case TargetVSCode:
			return absWorktree, filepath.Join(".vscode", "mcp.json"), nil
		}
	}
	return "", "", fmt.Errorf("unsupported MCP target %q", target)
}

func processMCPTarget(
	target string,
	baseDir string,
	relPath string,
	canonical map[string]MCPServerSpec,
	conjoinerWrapped bool,
	apply bool,
	nowFn func() time.Time,
) (*MCPTargetPlan, error) {
	if target == TargetCodex {
		return processCodexTOMLTarget(target, baseDir, relPath, canonical, conjoinerWrapped, apply, nowFn)
	}

	fullPath := filepath.Join(baseDir, relPath)

	// Strictly reject any symlink along the relative path inside baseDir before reading or writing.
	if err := checkNoSymlinksAlongRel(baseDir, relPath); err != nil {
		return nil, err
	}

	plan := &MCPTargetPlan{
		Target:           target,
		ConfigPath:       fullPath,
		ConjoinerWrapped: conjoinerWrapped,
	}

	var originalBytes []byte
	var rawMap map[string]interface{}

	fi, lErr := os.Lstat(fullPath)
	if lErr == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, symlinkFixForwardError(fullPath)
		}
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("IDE config path %s is not a regular file", fullPath)
		}
		data, rErr := os.ReadFile(fullPath)
		if rErr != nil {
			return nil, fmt.Errorf("read existing %s: %w", fullPath, rErr)
		}
		originalBytes = data
		plan.Exists = true
		if len(strings.TrimSpace(string(data))) == 0 {
			rawMap = make(map[string]interface{})
		} else if err := json.Unmarshal(data, &rawMap); err != nil {
			return nil, &ux.FixForwardError{
				Tool:           "fabrial",
				Code:           "FABRIAL_INIT_MCP_INVALID_JSON",
				Summary:        fmt.Sprintf("Existing IDE config %s contains invalid JSON", filepath.Base(fullPath)),
				RemediationCmd: fmt.Sprintf("fabrial init --mcp --target %s", target),
				WhyOneLiner:    "Refusing to overwrite a malformed IDE config file; fix the JSON syntax first.",
				DeepWhy:        fmt.Sprintf("Failed to parse %s: %v", ux.SanitizeTerminalText(fullPath), err),
				ExitCode:       1,
			}
		}
		if rawMap == nil {
			rawMap = make(map[string]interface{})
		}
	} else if os.IsNotExist(lErr) {
		rawMap = make(map[string]interface{})
	} else {
		return nil, fmt.Errorf("lstat %s: %w", fullPath, lErr)
	}

	rootKey := "mcpServers"
	requireStdioType := false
	if target == TargetVSCode {
		rootKey = "servers"
		requireStdioType = true
	}

	var serversMap map[string]interface{}
	if existingRoot, exists := rawMap[rootKey]; exists && existingRoot != nil {
		m, ok := existingRoot.(map[string]interface{})
		if !ok {
			return nil, &ux.FixForwardError{
				Tool:           "fabrial",
				Code:           "FABRIAL_INIT_MCP_INVALID_JSON",
				Summary:        fmt.Sprintf("Existing IDE config %s has non-object %q field", filepath.Base(fullPath), rootKey),
				RemediationCmd: fmt.Sprintf("fabrial init --mcp --target %s", target),
				WhyOneLiner:    fmt.Sprintf("Refusing to overwrite %s because %q is not a JSON object.", filepath.Base(fullPath), rootKey),
				DeepWhy:        fmt.Sprintf("Expected %q in %s to be a JSON object mapping server names to configurations.", rootKey, ux.SanitizeTerminalText(fullPath)),
				ExitCode:       1,
			}
		}
		serversMap = m
	}
	if serversMap == nil {
		serversMap = make(map[string]interface{})
	}

	// Track preserved user-owned MCP servers (any key not in CanonicalMCPServerOrder)
	for existingKey := range serversMap {
		if _, isCanonical := canonical[existingKey]; !isCanonical {
			plan.UserServersPreserved = append(plan.UserServersPreserved, existingKey)
		}
	}
	sort.Strings(plan.UserServersPreserved)

	// Merge canonical servers in deterministic order
	var diffLines []string
	diffLines = append(diffLines, fmt.Sprintf("--- %s (target: %s)", fullPath, target))
	for _, name := range CanonicalMCPServerOrder {
		spec := canonical[name]
		desiredMap := map[string]interface{}{
			"command": spec.Command,
			"args":    toInterfaceSlice(spec.Args),
		}
		if requireStdioType {
			desiredMap["type"] = "stdio"
		}

		existingRaw, exists := serversMap[name]
		if !exists {
			serversMap[name] = desiredMap
			plan.ServersAdded = append(plan.ServersAdded, name)
			diffLines = append(diffLines, fmt.Sprintf("+ %s.%s: %s %s", rootKey, name, spec.Command, strings.Join(spec.Args, " ")))
			continue
		}

		existingMap, ok := existingRaw.(map[string]interface{})
		if !ok || !mcpSpecMatches(existingMap, spec, requireStdioType) {
			serversMap[name] = desiredMap
			plan.ServersUpdated = append(plan.ServersUpdated, name)
			diffLines = append(diffLines, fmt.Sprintf("~ %s.%s: %s %s", rootKey, name, spec.Command, strings.Join(spec.Args, " ")))
			continue
		}

		plan.ServersUnchanged = append(plan.ServersUnchanged, name)
		diffLines = append(diffLines, fmt.Sprintf("= %s.%s: unchanged", rootKey, name))
	}
	if len(plan.UserServersPreserved) > 0 {
		diffLines = append(diffLines, fmt.Sprintf("  preserved user servers: %s", strings.Join(plan.UserServersPreserved, ", ")))
	}
	plan.Diff = strings.Join(diffLines, "\n")

	rawMap[rootKey] = serversMap

	if !apply {
		return plan, nil
	}

	// Serialize and validate JSON round-trip BEFORE touching disk
	outData, err := json.MarshalIndent(rawMap, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal merged config %s: %w", fullPath, err)
	}
	outData = append(outData, '\n')

	var roundTrip map[string]interface{}
	if err := json.Unmarshal(outData, &roundTrip); err != nil {
		return nil, fmt.Errorf("post-merge JSON validation failed for %s: %w", fullPath, err)
	}
	if _, ok := roundTrip[rootKey].(map[string]interface{}); !ok {
		return nil, fmt.Errorf("post-merge JSON validation failed: missing %s map in %s", rootKey, fullPath)
	}

	// Ensure parent directories exist safely (no symlinks)
	if err := ensureSafeParentDirs(baseDir, filepath.Dir(relPath)); err != nil {
		return nil, err
	}

	// Backup existing file to <configPath>.bak.<ts> (0600) before replacing
	if plan.Exists {
		backupPath, bErr := writeAtomicBackup(fullPath, originalBytes, nowFn())
		if bErr != nil {
			return nil, bErr
		}
		plan.BackupPath = backupPath
	}

	// Re-verify no symlink was planted before atomic replace
	if err := checkNoSymlinksAlongRel(baseDir, relPath); err != nil {
		return nil, err
	}

	// Atomic write (O_CREAT|O_EXCL, 0600) + fsync + rename
	if err := atomicWriteConfig(fullPath, outData); err != nil {
		return nil, err
	}

	plan.Applied = true
	return plan, nil
}

func checkNoSymlinksAlongRel(baseDir, relPath string) error {
	cleanRel := filepath.Clean(relPath)
	parts := strings.Split(cleanRel, string(filepath.Separator))
	curr := baseDir
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		curr = filepath.Join(curr, part)
		fi, err := os.Lstat(curr)
		if err != nil {
			if os.IsNotExist(err) {
				// Remaining path components do not exist yet
				return nil
			}
			return fmt.Errorf("lstat %s: %w", curr, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return symlinkFixForwardError(curr)
		}
	}
	return nil
}

func ensureSafeParentDirs(baseDir, relDir string) error {
	if relDir == "." || relDir == "" {
		return nil
	}
	parts := strings.Split(filepath.Clean(relDir), string(filepath.Separator))
	curr := baseDir
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		curr = filepath.Join(curr, part)
		fi, err := os.Lstat(curr)
		if err != nil {
			if os.IsNotExist(err) {
				if mkErr := os.Mkdir(curr, 0700); mkErr != nil && !os.IsExist(mkErr) {
					return fmt.Errorf("mkdir %s: %w", curr, mkErr)
				}
				continue
			}
			return fmt.Errorf("lstat %s: %w", curr, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return symlinkFixForwardError(curr)
		}
		if !fi.IsDir() {
			return fmt.Errorf("expected directory at %s", curr)
		}
	}
	return nil
}

func writeAtomicBackup(configPath string, original []byte, ts time.Time) (string, error) {
	baseBackup := fmt.Sprintf("%s.bak.%d", configPath, ts.Unix())
	backupPath := baseBackup
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			nonce := make([]byte, 3)
			_, _ = rand.Read(nonce)
			backupPath = fmt.Sprintf("%s.%s", baseBackup, hex.EncodeToString(nonce))
		}
		f, err := os.OpenFile(backupPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			if os.IsExist(err) {
				continue
			}
			return "", fmt.Errorf("create backup %s: %w", backupPath, err)
		}
		if _, wErr := f.Write(original); wErr != nil {
			_ = f.Close()
			_ = os.Remove(backupPath)
			return "", fmt.Errorf("write backup %s: %w", backupPath, wErr)
		}
		if sErr := f.Sync(); sErr != nil {
			_ = f.Close()
			_ = os.Remove(backupPath)
			return "", fmt.Errorf("fsync backup %s: %w", backupPath, sErr)
		}
		if cErr := f.Close(); cErr != nil {
			_ = os.Remove(backupPath)
			return "", fmt.Errorf("close backup %s: %w", backupPath, cErr)
		}
		return backupPath, nil
	}
	return "", fmt.Errorf("unable to allocate unique backup path for %s", configPath)
}

func atomicWriteConfig(configPath string, data []byte) error {
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate temp nonce: %w", err)
	}
	tmpPath := fmt.Sprintf("%s.tmp.%s", configPath, hex.EncodeToString(nonce))
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create temp config %s: %w", tmpPath, err)
	}
	if _, wErr := f.Write(data); wErr != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write temp config %s: %w", tmpPath, wErr)
	}
	if sErr := f.Sync(); sErr != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("fsync temp config %s: %w", tmpPath, sErr)
	}
	if cErr := f.Close(); cErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp config %s: %w", tmpPath, cErr)
	}
	if fi, lErr := os.Lstat(configPath); lErr == nil && fi.Mode()&os.ModeSymlink != 0 {
		_ = os.Remove(tmpPath)
		return symlinkFixForwardError(configPath)
	}
	if err := os.Rename(tmpPath, configPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("atomic rename %s: %w", configPath, err)
	}
	return nil
}

func symlinkFixForwardError(path string) error {
	return fmt.Errorf("%w: %w", ErrMCPSymlinkDetected, &ux.FixForwardError{
		Tool:           "fabrial",
		Code:           "FABRIAL_INIT_MCP_SYMLINK_REJECTED",
		Summary:        fmt.Sprintf("Refused symlinked IDE MCP config path %s", filepath.Base(path)),
		RemediationCmd: "fabrial init --mcp --why",
		WhyOneLiner:    "Symlinked IDE config paths are blocked fail-closed to prevent arbitrary file overwrite outside your workspace.",
		DeepWhy:        fmt.Sprintf("Lstat detected a symbolic link at %s. Replace the symlink with a regular file/directory owned by your user before running `fabrial init --mcp --apply`.", ux.SanitizeTerminalText(path)),
		ExitCode:       10,
	})
}

func mcpSpecMatches(existing map[string]interface{}, desired MCPServerSpec, requireStdioType bool) bool {
	if requireStdioType {
		t, ok := existing["type"].(string)
		if !ok || t != "stdio" {
			return false
		}
	}
	cmd, ok := existing["command"].(string)
	if !ok || cmd != desired.Command {
		return false
	}
	var gotArgs []string
	switch rawArgs := existing["args"].(type) {
	case []interface{}:
		gotArgs = make([]string, 0, len(rawArgs))
		for _, a := range rawArgs {
			s, ok := a.(string)
			if !ok {
				return false
			}
			gotArgs = append(gotArgs, s)
		}
	case []string:
		gotArgs = rawArgs
	default:
		if len(desired.Args) == 0 && rawArgs == nil {
			return true
		}
		return false
	}
	return reflect.DeepEqual(gotArgs, desired.Args)
}

func toInterfaceSlice(in []string) []interface{} {
	out := make([]interface{}, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

// Render prints JSON (--json), calm <=3-line default summary, or full diff breakdown (--why).
func (r *MCPInitReport) Render(w io.Writer, asJSON bool, showWhy bool) error {
	if r == nil {
		return nil
	}
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		return enc.Encode(r)
	}

	added, updated, unchanged := 0, 0, 0
	for _, p := range r.Plans {
		added += len(p.ServersAdded)
		updated += len(p.ServersUpdated)
		unchanged += len(p.ServersUnchanged)
	}

	if r.Mode == "dry-run" {
		if _, err := fmt.Fprintf(w, "✓ fabrial: MCP dry-run across %d IDE target(s) (%d add, %d update, %d unchanged; 0 bytes written)\n",
			len(r.Plans), added, updated, unchanged); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  Next: fabrial init --mcp --apply\n"); err != nil {
			return err
		}
		whyLine := "Preview only; re-run with --apply to create .bak backups and atomically merge canonical MCP servers."
		if !showWhy {
			whyLine += " (re-run with --why for full diff)"
		}
		if _, err := fmt.Fprintf(w, "  Why:  %s\n", whyLine); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintf(w, "✓ fabrial: applied canonical MCP config to %d IDE target(s) (%d added, %d updated, %d unchanged)\n",
			len(r.Plans), added, updated, unchanged); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  Next: fabrial doctor\n"); err != nil {
			return err
		}
		whyLine := "Existing user MCP servers preserved and .bak backups written with 0600 permissions."
		if !showWhy {
			whyLine += " (re-run with --why for per-target diff)"
		}
		if _, err := fmt.Fprintf(w, "  Why:  %s\n", whyLine); err != nil {
			return err
		}
	}

	if showWhy {
		if _, err := fmt.Fprintf(w, "\n  Deep Dive (--why):\n"); err != nil {
			return err
		}
		for _, p := range r.Plans {
			for _, line := range strings.Split(ux.SanitizeTerminalText(p.Diff), "\n") {
				if _, err := fmt.Fprintf(w, "  %s\n", line); err != nil {
					return err
				}
			}
			if p.BackupPath != "" {
				if _, err := fmt.Fprintf(w, "  backup: %s\n", ux.SanitizeTerminalText(p.BackupPath)); err != nil {
					return err
				}
			}
		}
	}

	return nil
}
