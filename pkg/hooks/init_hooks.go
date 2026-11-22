package hooks

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/bonjoski/fabrial/pkg/ux"
)

// NormalizeHookTargets validates and expands target names ("all", "claude",
// "cursor", "gemini", plus aliases "claude-code", "gemini-cli") in canonical order.
func NormalizeHookTargets(raw []string) ([]ClientDialect, error) {
	if len(raw) == 0 {
		return []ClientDialect{ClientClaude, ClientCursor, ClientGemini}, nil
	}

	seen := make(map[ClientDialect]bool)
	var out []ClientDialect
	add := func(t ClientDialect) {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}

	for _, item := range raw {
		for _, tok := range strings.Split(item, ",") {
			switch strings.ToLower(strings.TrimSpace(tok)) {
			case "", "all":
				add(ClientClaude)
				add(ClientCursor)
				add(ClientGemini)
			case "claude", "claude-code", "claudecode":
				add(ClientClaude)
			case "cursor":
				add(ClientCursor)
			case "gemini", "gemini-cli", "geminicli":
				add(ClientGemini)
			default:
				return nil, &ux.FixForwardError{
					Tool:           "fabrial",
					Code:           "FABRIAL_INIT_HOOKS_UNKNOWN_TARGET",
					Summary:        fmt.Sprintf("Unknown IDE hooks target %q", tok),
					RemediationCmd: "fabrial init --hooks --target all",
					WhyOneLiner:    "Supported hook targets are: all, claude, cursor, gemini.",
					DeepWhy:        "Specify --target with one or more comma-separated IDE names (claude, cursor, gemini) or use --target all to preview/apply all native IDE hook configs.",
					ExitCode:       1,
				}
			}
		}
	}
	return out, nil
}

// PlanAndApplyHooks performs a strictly read-only dry-run diff by default (Apply=false).
// When Apply=true, it enforces Lstat non-symlink guards on every path component,
// backs up existing files to <config>.bak.<ts> (0600), preserves 100% of existing
// user hooks and unrelated keys, validates JSON round-trip, and atomically renames (0600).
func PlanAndApplyHooks(opts HooksInitOptions) (*HooksInitReport, error) {
	targets, err := NormalizeHookTargets(opts.Targets)
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

	homeDir := strings.TrimSpace(opts.HomeDir)
	if homeDir == "" {
		homeDir, err = os.UserHomeDir()
		if err != nil && opts.Global {
			return nil, fmt.Errorf("determine home directory: %w", err)
		}
	}

	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	mode := "dry-run"
	if opts.Apply {
		mode = "applied"
	}

	report := &HooksInitReport{
		Tool:   "fabrial",
		Mode:   mode,
		Global: opts.Global,
		Plans:  make([]HookTargetPlan, 0, len(targets)),
	}

	for _, target := range targets {
		baseDir, relPath, err := resolveHookTargetPath(target, absWorktree, homeDir, opts.Global)
		if err != nil {
			return nil, err
		}

		plan, err := processHookTarget(target, baseDir, relPath, opts.Apply, nowFn)
		if err != nil {
			return nil, err
		}
		report.Plans = append(report.Plans, *plan)
	}

	return report, nil
}

func resolveHookTargetPath(target ClientDialect, absWorktree, homeDir string, isGlobal bool) (string, string, error) {
	baseDir := absWorktree
	if isGlobal {
		if homeDir == "" {
			return "", "", errors.New("home directory unavailable for --global hooks integration")
		}
		baseDir = homeDir
	}

	switch target {
	case ClientClaude:
		return baseDir, filepath.Join(".claude", "settings.json"), nil
	case ClientCursor:
		return baseDir, filepath.Join(".cursor", "hooks.json"), nil
	case ClientGemini:
		return baseDir, filepath.Join(".gemini", "settings.json"), nil
	default:
		return "", "", fmt.Errorf("unsupported hooks target %q", target)
	}
}

func processHookTarget(
	target ClientDialect,
	baseDir string,
	relPath string,
	apply bool,
	nowFn func() time.Time,
) (*HookTargetPlan, error) {
	fullPath := filepath.Join(baseDir, relPath)

	// Fail-closed Lstat non-symlink check along every relative path component.
	if err := checkNoSymlinksAlongRel(baseDir, relPath); err != nil {
		return nil, err
	}

	plan := &HookTargetPlan{
		Target:     target,
		ConfigPath: fullPath,
	}

	var originalBytes []byte
	var rawMap map[string]interface{}

	fi, lErr := os.Lstat(fullPath)
	if lErr == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, hooksSymlinkFixForwardError(fullPath)
		}
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("IDE hooks config path %s is not a regular file", fullPath)
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
				Code:           "FABRIAL_INIT_HOOKS_INVALID_JSON",
				Summary:        fmt.Sprintf("Existing IDE config %s contains invalid JSON", filepath.Base(fullPath)),
				RemediationCmd: fmt.Sprintf("fabrial init --hooks --target %s", target),
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

	// Merge dialect-specific Fabrial hooks non-destructively and detect user hooks.
	var diffLines []string
	diffLines = append(diffLines, fmt.Sprintf("--- %s (target: %s)", fullPath, target))

	switch target {
	case ClientClaude:
		mergeClaudeHooks(rawMap, plan, &diffLines)
	case ClientCursor:
		mergeCursorHooks(rawMap, plan, &diffLines)
	case ClientGemini:
		mergeGeminiHooks(rawMap, plan, &diffLines)
	}

	sort.Strings(plan.UserHooksDetected)
	if len(plan.UserHooksDetected) > 0 {
		diffLines = append(diffLines, fmt.Sprintf("  ! pre-existing user hooks detected (%d): %s",
			len(plan.UserHooksDetected), strings.Join(plan.UserHooksDetected, " | ")))
	}
	plan.Diff = strings.Join(diffLines, "\n")

	if !apply {
		return plan, nil
	}

	// Serialize and validate JSON round-trip BEFORE touching disk.
	outData, err := json.MarshalIndent(rawMap, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal merged hooks config %s: %w", fullPath, err)
	}
	outData = append(outData, '\n')

	var roundTrip map[string]interface{}
	if err := json.Unmarshal(outData, &roundTrip); err != nil {
		return nil, fmt.Errorf("post-merge JSON validation failed for %s: %w", fullPath, err)
	}
	if _, ok := roundTrip["hooks"].(map[string]interface{}); !ok {
		return nil, fmt.Errorf("post-merge JSON validation failed: missing hooks map in %s", fullPath)
	}

	// Ensure parent directories exist safely (no symlinks).
	if err := ensureSafeParentDirs(baseDir, filepath.Dir(relPath)); err != nil {
		return nil, err
	}

	// Backup existing file to <configPath>.bak.<ts> (0600) before replacing.
	if plan.Exists {
		backupPath, bErr := writeAtomicBackup(fullPath, originalBytes, nowFn())
		if bErr != nil {
			return nil, bErr
		}
		plan.BackupPath = backupPath
	}

	// Re-verify no symlink was planted before atomic replace.
	if err := checkNoSymlinksAlongRel(baseDir, relPath); err != nil {
		return nil, err
	}

	// Atomic write (O_CREAT|O_EXCL, 0600) + fsync + rename.
	if err := atomicWriteConfig(fullPath, outData); err != nil {
		return nil, err
	}

	plan.Applied = true
	return plan, nil
}

// ============================================================================
// Dialect-Specific Non-Destructive Mergers
// ============================================================================

func getOrCreateHooksMap(rawMap map[string]interface{}) map[string]interface{} {
	hooksMap, ok := rawMap["hooks"].(map[string]interface{})
	if !ok || hooksMap == nil {
		hooksMap = make(map[string]interface{})
		rawMap["hooks"] = hooksMap
	}
	return hooksMap
}

func collectUserHooksFromMap(hooksMap map[string]interface{}, plan *HookTargetPlan) {
	seen := make(map[string]bool)
	record := func(eventName, cmd string) {
		cmd = strings.TrimSpace(cmd)
		if cmd == "" || strings.HasPrefix(cmd, ManagedCommandPrefix) {
			return
		}
		entry := fmt.Sprintf("%s: %s", eventName, cmd)
		if !seen[entry] {
			seen[entry] = true
			plan.UserHooksDetected = append(plan.UserHooksDetected, entry)
		}
	}

	for eventName, val := range hooksMap {
		arr, ok := val.([]interface{})
		if !ok {
			continue
		}
		for _, item := range arr {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			// Flat hook entry (Cursor or legacy format)
			if cmd, ok := m["command"].(string); ok {
				record(eventName, cmd)
			}
			// Nested matcher group (Claude Code & Gemini CLI)
			if nested, ok := m["hooks"].([]interface{}); ok {
				for _, sub := range nested {
					if sm, ok := sub.(map[string]interface{}); ok {
						if cmd, ok := sm["command"].(string); ok {
							record(eventName, cmd)
						}
					}
				}
			}
		}
	}
}

func mergeClaudeHooks(rawMap map[string]interface{}, plan *HookTargetPlan, diffLines *[]string) {
	hooksMap := getOrCreateHooksMap(rawMap)
	collectUserHooksFromMap(hooksMap, plan)

	preDesired := map[string]interface{}{
		"matcher": "Bash",
		"hooks": []interface{}{
			map[string]interface{}{
				"type":    "command",
				"command": "fabrial hook eval --client claude --event pre-tool",
				"timeout": float64(10),
			},
		},
	}
	postDesired := map[string]interface{}{
		"matcher": "Edit|Write",
		"hooks": []interface{}{
			map[string]interface{}{
				"type":    "command",
				"command": "fabrial hook eval --client claude --event post-tool",
				"async":   true,
				"timeout": float64(5),
			},
		},
	}

	mergeNestedMatcherEvent(hooksMap, "PreToolUse", preDesired, "hooks.PreToolUse", plan, diffLines)
	mergeNestedMatcherEvent(hooksMap, "PostToolUse", postDesired, "hooks.PostToolUse", plan, diffLines)
	rawMap["hooks"] = hooksMap
}

func mergeGeminiHooks(rawMap map[string]interface{}, plan *HookTargetPlan, diffLines *[]string) {
	hooksMap := getOrCreateHooksMap(rawMap)
	collectUserHooksFromMap(hooksMap, plan)

	preDesired := map[string]interface{}{
		"matcher": "run_shell_command|bash|sh",
		"hooks": []interface{}{
			map[string]interface{}{
				"name":    "fabrial-pre-tool",
				"type":    "command",
				"command": "fabrial hook eval --client gemini --event pre-tool",
			},
		},
	}
	postDesired := map[string]interface{}{
		"matcher": "write_file|replace|edit",
		"hooks": []interface{}{
			map[string]interface{}{
				"name":    "fabrial-post-tool",
				"type":    "command",
				"command": "fabrial hook eval --client gemini --event post-tool",
			},
		},
	}

	mergeNestedMatcherEvent(hooksMap, "BeforeTool", preDesired, "hooks.BeforeTool", plan, diffLines)
	mergeNestedMatcherEvent(hooksMap, "AfterTool", postDesired, "hooks.AfterTool", plan, diffLines)
	rawMap["hooks"] = hooksMap
}

func mergeCursorHooks(rawMap map[string]interface{}, plan *HookTargetPlan, diffLines *[]string) {
	if _, exists := rawMap["version"]; !exists {
		rawMap["version"] = float64(1)
	}
	hooksMap := getOrCreateHooksMap(rawMap)
	collectUserHooksFromMap(hooksMap, plan)

	preDesired := map[string]interface{}{
		"command":    "fabrial hook eval --client cursor --event pre-tool",
		"timeout":    float64(10),
		"failClosed": true,
	}
	postDesired := map[string]interface{}{
		"command": "fabrial hook eval --client cursor --event post-tool",
		"timeout": float64(5),
	}

	mergeFlatEvent(hooksMap, "beforeShellExecution", preDesired, "hooks.beforeShellExecution", plan, diffLines)
	mergeFlatEvent(hooksMap, "afterFileEdit", postDesired, "hooks.afterFileEdit", plan, diffLines)
	rawMap["hooks"] = hooksMap
}

func mergeFlatEvent(
	hooksMap map[string]interface{},
	eventKey string,
	desired map[string]interface{},
	label string,
	plan *HookTargetPlan,
	diffLines *[]string,
) {
	existing, _ := hooksMap[eventKey].([]interface{})
	desiredCmd, _ := desired["command"].(string)

	foundIdx := -1
	for i, item := range existing {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if cmd, ok := m["command"].(string); ok && strings.HasPrefix(strings.TrimSpace(cmd), ManagedCommandPrefix) {
			foundIdx = i
			break
		}
	}

	if foundIdx == -1 {
		existing = append(existing, desired)
		hooksMap[eventKey] = existing
		plan.HooksAdded = append(plan.HooksAdded, label)
		*diffLines = append(*diffLines, fmt.Sprintf("+ %s: %s", label, desiredCmd))
		return
	}

	if jsonMapEquals(existing[foundIdx], desired) {
		plan.HooksUnchanged = append(plan.HooksUnchanged, label)
		*diffLines = append(*diffLines, fmt.Sprintf("= %s: unchanged", label))
		return
	}

	existing[foundIdx] = desired
	hooksMap[eventKey] = existing
	plan.HooksUpdated = append(plan.HooksUpdated, label)
	*diffLines = append(*diffLines, fmt.Sprintf("~ %s: %s", label, desiredCmd))
}

func mergeNestedMatcherEvent(
	hooksMap map[string]interface{},
	eventKey string,
	desired map[string]interface{},
	label string,
	plan *HookTargetPlan,
	diffLines *[]string,
) {
	existing, _ := hooksMap[eventKey].([]interface{})
	desiredHooks := desired["hooks"].([]interface{})
	desiredLeaf := desiredHooks[0].(map[string]interface{})
	desiredCmd, _ := desiredLeaf["command"].(string)
	desiredMatcher, _ := desired["matcher"].(string)

	foundGroupIdx := -1
	foundHookIdx := -1
	for gi, item := range existing {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		subHooks, ok := m["hooks"].([]interface{})
		if !ok {
			continue
		}
		for hi, sub := range subHooks {
			sm, ok := sub.(map[string]interface{})
			if !ok {
				continue
			}
			if cmd, ok := sm["command"].(string); ok && strings.HasPrefix(strings.TrimSpace(cmd), ManagedCommandPrefix) {
				foundGroupIdx = gi
				foundHookIdx = hi
				break
			}
		}
		if foundGroupIdx != -1 {
			break
		}
	}

	if foundGroupIdx == -1 {
		existing = append(existing, desired)
		hooksMap[eventKey] = existing
		plan.HooksAdded = append(plan.HooksAdded, label)
		*diffLines = append(*diffLines, fmt.Sprintf("+ %s [%s]: %s", label, desiredMatcher, desiredCmd))
		return
	}

	groupMap := existing[foundGroupIdx].(map[string]interface{})
	subHooks := groupMap["hooks"].([]interface{})

	// If this group contains ONLY the Fabrial hook, compare/replace the whole matcher group cleanly.
	if len(subHooks) == 1 {
		if jsonMapEquals(groupMap, desired) {
			plan.HooksUnchanged = append(plan.HooksUnchanged, label)
			*diffLines = append(*diffLines, fmt.Sprintf("= %s [%s]: unchanged", label, desiredMatcher))
			return
		}
		existing[foundGroupIdx] = desired
		hooksMap[eventKey] = existing
		plan.HooksUpdated = append(plan.HooksUpdated, label)
		*diffLines = append(*diffLines, fmt.Sprintf("~ %s [%s]: %s", label, desiredMatcher, desiredCmd))
		return
	}

	// Shared group with user hooks: preserve user hooks untouched and update only the Fabrial leaf.
	if jsonMapEquals(subHooks[foundHookIdx], desiredLeaf) {
		plan.HooksUnchanged = append(plan.HooksUnchanged, label)
		*diffLines = append(*diffLines, fmt.Sprintf("= %s [%s]: unchanged", label, desiredMatcher))
		return
	}
	subHooks[foundHookIdx] = desiredLeaf
	groupMap["hooks"] = subHooks
	existing[foundGroupIdx] = groupMap
	hooksMap[eventKey] = existing
	plan.HooksUpdated = append(plan.HooksUpdated, label)
	*diffLines = append(*diffLines, fmt.Sprintf("~ %s [%s]: %s", label, desiredMatcher, desiredCmd))
}

func jsonMapEquals(a, b interface{}) bool {
	ab, errA := json.Marshal(a)
	bb, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return reflect.DeepEqual(a, b)
	}
	var am, bm interface{}
	if json.Unmarshal(ab, &am) != nil || json.Unmarshal(bb, &bm) != nil {
		return reflect.DeepEqual(a, b)
	}
	return reflect.DeepEqual(am, bm)
}

// ============================================================================
// Symlink Defense & Atomic File Operations (Hardened Parity with integration)
// ============================================================================

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
				return nil
			}
			return fmt.Errorf("lstat %s: %w", curr, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return hooksSymlinkFixForwardError(curr)
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
			return hooksSymlinkFixForwardError(curr)
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
		return hooksSymlinkFixForwardError(configPath)
	}
	if err := os.Rename(tmpPath, configPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("atomic rename %s: %w", configPath, err)
	}
	return nil
}

func hooksSymlinkFixForwardError(path string) error {
	return fmt.Errorf("%w: %w", ErrHooksSymlinkDetected, &ux.FixForwardError{
		Tool:           "fabrial",
		Code:           "FABRIAL_INIT_HOOKS_SYMLINK_REJECTED",
		Summary:        fmt.Sprintf("Refused symlinked IDE hooks config path %s", filepath.Base(path)),
		RemediationCmd: "fabrial init --hooks --why",
		WhyOneLiner:    "Symlinked IDE hook config paths are blocked fail-closed to prevent arbitrary file overwrite outside your workspace.",
		DeepWhy:        fmt.Sprintf("Lstat detected a symbolic link at %s. Replace the symlink with a regular file/directory owned by your user before running `fabrial init --hooks --apply`.", ux.SanitizeTerminalText(path)),
		ExitCode:       10,
	})
}

// Render prints JSON (--json), calm <=3-line UB-CLI-v2 default summary, or full
// progressive disclosure diff & user-hook audit breakdown (--why).
func (r *HooksInitReport) Render(w io.Writer, asJSON bool, showWhy bool) error {
	if r == nil {
		return nil
	}
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		return enc.Encode(r)
	}

	added, updated, unchanged, userHooks := 0, 0, 0, 0
	for _, p := range r.Plans {
		added += len(p.HooksAdded)
		updated += len(p.HooksUpdated)
		unchanged += len(p.HooksUnchanged)
		userHooks += len(p.UserHooksDetected)
	}

	userHookNote := ""
	if userHooks > 0 {
		userHookNote = fmt.Sprintf("; %d existing user hook(s) detected", userHooks)
	}

	if r.Mode == "dry-run" {
		if _, err := fmt.Fprintf(w, "✓ fabrial: hooks dry-run across %d IDE target(s) (%d add, %d update, %d unchanged%s; 0 bytes written)\n",
			len(r.Plans), added, updated, unchanged, userHookNote); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  Next: fabrial init --hooks --apply\n"); err != nil {
			return err
		}
		whyLine := "Preview only; re-run with --apply to create .bak backups and atomically wire native IDE hooks."
		if userHooks > 0 {
			whyLine = fmt.Sprintf("Detected %d pre-existing non-Fabrial hook(s) — inspect before trusting this repo.", userHooks)
		}
		if !showWhy {
			whyLine += " (re-run with --why for full diff)"
		}
		if _, err := fmt.Fprintf(w, "  Why:  %s\n", whyLine); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintf(w, "✓ fabrial: applied native IDE hooks to %d target(s) (%d added, %d updated, %d unchanged%s)\n",
			len(r.Plans), added, updated, unchanged, userHookNote); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  Next: fabrial doctor\n"); err != nil {
			return err
		}
		whyLine := "Existing user hooks and settings preserved; .bak backups written with 0600 permissions."
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
			if len(p.UserHooksDetected) > 0 {
				if _, err := fmt.Fprintf(w, "  warning: review pre-existing user hooks in %s before trusting untrusted repos\n", ux.SanitizeTerminalText(p.ConfigPath)); err != nil {
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
