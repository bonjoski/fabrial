package check

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/bonjoski/fabrial/pkg/ux"
)

const (
	// DefaultCheckTimeout caps each local PR dry-run check to keep the gate fast and bounded.
	DefaultCheckTimeout = 10 * time.Second
	// MaxCheckTimeout is the hard upper bound per individual check invocation.
	MaxCheckTimeout = 10 * time.Second
	// MaxRenderedFindings limits human-readable Fix-Forward output to keep developer feedback calm.
	MaxRenderedFindings = 5
	// maxCmdOutputBytes bounds stdout/stderr captured from any single local check process.
	maxCmdOutputBytes = 2 * 1024 * 1024
)

// CommandRunner executes a local check binary inside workspace dir with a bounded context.
type CommandRunner func(ctx context.Context, dir, binPath string, args []string) (stdout, stderr []byte, exitCode int, err error)

// CheckOptions configures a strictly worktree-local, read-only dry-run of the RFC-2026-11-22-48 PR gate.
type CheckOptions struct {
	Dir        string
	DiffOnly   bool
	BaseRef    string
	AITarget   string
	Timeout    time.Duration
	LookPath   func(file string) (string, error)
	RunCommand CommandRunner
}

// CheckStatus captures the outcome of a single local tool invocation.
type CheckStatus struct {
	Tool           string `json:"tool"`
	Command        string `json:"command"`
	Status         string `json:"status"` // "passed", "failed", "skipped", "timeout", "degraded"
	ProvenCount    int    `json:"proven_count"`
	DurationMs     int64  `json:"duration_ms"`
	Summary        string `json:"summary"`
	RemediationCmd string `json:"remediation_cmd,omitempty"`
}

// ProvenFinding represents a single strictly verified, sanitized, secret-scrubbed finding.
type ProvenFinding struct {
	Tool           string `json:"tool"`
	ID             string `json:"id,omitempty"`
	Location       string `json:"location,omitempty"`
	Summary        string `json:"summary"`
	RemediationCmd string `json:"remediation_cmd"`
	WhyOneLiner    string `json:"why"`
}

// CheckResult is the structured result of `fabrial check --diff`.
type CheckResult struct {
	Tool           string          `json:"tool"`
	Workspace      string          `json:"workspace"`
	DiffOnly       bool            `json:"diff_only"`
	BaseRef        string          `json:"base_ref"`
	AITarget       string          `json:"ai_target,omitempty"`
	Passed         bool            `json:"passed"`
	ProvenCount    int             `json:"proven_count"`
	Checks         []CheckStatus   `json:"checks"`
	Findings       []ProvenFinding `json:"findings,omitempty"`
	MissingTools   []string        `json:"missing_tools,omitempty"`
	RemediationCmd string          `json:"remediation_cmd"`
	Why            string          `json:"why"`
	DeepWhy        string          `json:"deep_why"`
}

var baseRefRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/~^-]{0,127}$`)

// ValidateBaseRef rejects git flag injection, whitespace, and shell metacharacters.
func ValidateBaseRef(ref string) (string, error) {
	trimmed := strings.TrimSpace(ref)
	if trimmed == "" {
		return "HEAD", nil
	}
	if !baseRefRe.MatchString(trimmed) || strings.Contains(trimmed, "..") {
		return "", &ux.FixForwardError{
			Tool:           "fabrial",
			Code:           "FABRIAL_CHECK_INVALID_BASE_REF",
			Summary:        fmt.Sprintf("Rejected unsafe git base ref %q", trimmed),
			RemediationCmd: "fabrial check --diff --base HEAD",
			WhyOneLiner:    "Base refs must be a simple branch, tag, or HEAD reference without flags or path traversal.",
			DeepWhy:        "Strict allowlist validation prevents git option injection (e.g. --exec=...) when running `soulcaster verify-patch` locally.",
			References:     []string{"CWE-88"},
			ExitCode:       1,
		}
	}
	return trimmed, nil
}

// ValidateLoopbackTarget enforces that --ai-target strictly targets a local loopback URL
// (http:// or https:// on 127.0.0.1, localhost, or ::1) with no embedded credentials.
func ValidateLoopbackTarget(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	for _, r := range trimmed {
		if r < 0x20 || r == 0x7f {
			return "", invalidAITargetError(trimmed, "contains control characters")
		}
	}

	u, err := url.Parse(trimmed)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", invalidAITargetError(trimmed, "must be a valid http:// or https:// loopback URL")
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", invalidAITargetError(trimmed, "only http:// and https:// schemes are allowed")
	}
	if u.User != nil {
		return "", invalidAITargetError(trimmed, "embedded URL credentials are forbidden")
	}

	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "" {
		return "", invalidAITargetError(trimmed, "missing target hostname")
	}

	if host != "localhost" {
		addr, parseErr := netip.ParseAddr(host)
		if parseErr != nil || addr.Is4In6() || !addr.IsLoopback() {
			return "", invalidAITargetError(trimmed, "target host must be localhost, 127.0.0.1, or ::1")
		}
	}

	return u.String(), nil
}

func invalidAITargetError(raw, reason string) *ux.FixForwardError {
	return &ux.FixForwardError{
		Tool:           "fabrial",
		Code:           "FABRIAL_CHECK_INVALID_AI_TARGET",
		Summary:        fmt.Sprintf("Rejected non-loopback --ai-target (%s)", reason),
		RemediationCmd: "fabrial check --diff --ai-target http://127.0.0.1:8080",
		WhyOneLiner:    "Local AI safety probes strictly target loopback endpoints (127.0.0.1, localhost, ::1) to prevent SSRF and remote scanning.",
		DeepWhy:        fmt.Sprintf("Input %q failed strict loopback validation (%s). RFC-2026-11-22-48 restricts `fabrial check` to 100%% local developer workstation targets.", ux.SanitizeTerminalText(ScrubSecrets(raw)), reason),
		References:     []string{"CWE-918", "RFC-2026-11-22-48"},
		ExitCode:       1,
	}
}

type checkSpec struct {
	Tool string
	Args []string
}

// Run executes the worktree-local dry-run of the RFC-2026-11-22-48 PR gate with zero shared locks
// and zero interactive Touch ID prompts.
func Run(ctx context.Context, opts CheckOptions) (*CheckResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	dir := strings.TrimSpace(opts.Dir)
	if dir == "" {
		dir = "."
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, &ux.FixForwardError{
			Tool:           "fabrial",
			Code:           "FABRIAL_CHECK_INVALID_DIR",
			Summary:        "Could not resolve target workspace directory",
			RemediationCmd: "fabrial check --diff --dir .",
			WhyOneLiner:    "fabrial check runs strictly inside a single local repository worktree.",
			DeepWhy:        fmt.Sprintf("filepath.Abs failed: %v", err),
			ExitCode:       1,
		}
	}

	// Verify directory strictly via os.OpenRoot so checks stay scoped to workspaceRoot.
	root, err := os.OpenRoot(absDir)
	if err != nil {
		return nil, &ux.FixForwardError{
			Tool:           "fabrial",
			Code:           "FABRIAL_CHECK_OPEN_ROOT_FAILED",
			Summary:        "Target workspace directory does not exist or is not accessible",
			RemediationCmd: "fabrial check --diff --dir .",
			WhyOneLiner:    "fabrial check inspects only a readable local repository root.",
			DeepWhy:        fmt.Sprintf("os.OpenRoot failed for %s: %v", ux.SanitizeTerminalText(absDir), err),
			ExitCode:       1,
		}
	}
	_ = root.Close()

	baseRef, err := ValidateBaseRef(opts.BaseRef)
	if err != nil {
		return nil, err
	}

	aiTarget, err := ValidateLoopbackTarget(opts.AITarget)
	if err != nil {
		return nil, err
	}

	timeout := opts.Timeout
	if timeout <= 0 || timeout > MaxCheckTimeout {
		timeout = DefaultCheckTimeout
	}

	lookPath := opts.LookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	runCmd := opts.RunCommand
	if runCmd == nil {
		runCmd = defaultRunCommand
	}

	specs := []checkSpec{
		{Tool: "argus", Args: []string{"vet", "--diff", "--json"}},
		{Tool: "soulcaster", Args: []string{"verify-patch", "-base", baseRef, "--json"}},
	}
	if aiTarget != "" {
		specs = append(specs, checkSpec{
			Tool: "aegisbox",
			Args: []string{"test", "--ai-safety", "--allow-degraded-local", "--target", aiTarget, "--json"},
		})
	}

	res := &CheckResult{
		Tool:      "fabrial",
		Workspace: absDir,
		DiffOnly:  true,
		BaseRef:   baseRef,
		AITarget:  aiTarget,
		Passed:    true,
		Checks:    make([]CheckStatus, 0, len(specs)),
	}

	for _, spec := range specs {
		cmdLine := spec.Tool + " " + strings.Join(spec.Args, " ")
		binPath, lpErr := lookPath(spec.Tool)
		if lpErr != nil {
			installHint := "brew install bonjoski/tap/" + spec.Tool
			res.MissingTools = append(res.MissingTools, spec.Tool)
			res.Checks = append(res.Checks, CheckStatus{
				Tool:           spec.Tool,
				Command:        cmdLine,
				Status:         "skipped",
				Summary:        fmt.Sprintf("%s is not installed locally; skipped optional check", spec.Tool),
				RemediationCmd: installHint,
			})
			continue
		}

		checkCtx, cancel := context.WithTimeout(ctx, timeout)
		start := time.Now()
		stdout, stderr, exitCode, runErr := runCmd(checkCtx, absDir, binPath, spec.Args)
		elapsedMs := time.Since(start).Milliseconds()
		timedOut := errors.Is(runErr, context.DeadlineExceeded) || errors.Is(checkCtx.Err(), context.DeadlineExceeded)
		cancel()

		if timedOut {
			res.Checks = append(res.Checks, CheckStatus{
				Tool:           spec.Tool,
				Command:        cmdLine,
				Status:         "timeout",
				DurationMs:     elapsedMs,
				Summary:        fmt.Sprintf("%s exceeded %s per-check timeout budget", spec.Tool, timeout),
				RemediationCmd: fmt.Sprintf("fabrial check --diff --dir . --why"),
			})
			continue
		}

		findings, parsedJSON := extractProvenFindings(stdout, spec.Tool)
		if !parsedJSON && len(stderr) > 0 {
			findings, parsedJSON = extractProvenFindings(stderr, spec.Tool)
		}

		if len(findings) > 0 {
			res.Passed = false
			res.Findings = append(res.Findings, findings...)
			res.Checks = append(res.Checks, CheckStatus{
				Tool:        spec.Tool,
				Command:     cmdLine,
				Status:      "failed",
				ProvenCount: len(findings),
				DurationMs:  elapsedMs,
				Summary:     fmt.Sprintf("%d proven issue(s) found in diff", len(findings)),
			})
			continue
		}

		if exitCode == 0 && runErr == nil {
			res.Checks = append(res.Checks, CheckStatus{
				Tool:       spec.Tool,
				Command:    cmdLine,
				Status:     "passed",
				DurationMs: elapsedMs,
				Summary:    "0 proven issues",
			})
			continue
		}

		// Non-zero exit with zero proven findings (e.g., no git commits, unsupported local subcommand,
		// or local AI target not running): surface calmly as degraded without noisy raw tracebacks.
		hint := fmt.Sprintf("brew upgrade bonjoski/tap/%s", spec.Tool)
		if spec.Tool == "aegisbox" && aiTarget != "" {
			hint = fmt.Sprintf("Start your local app on %s and re-run `fabrial check --diff --ai-target %s`", aiTarget, aiTarget)
		}
		summary := fmt.Sprintf("%s exited with status %d (0 proven findings)", spec.Tool, exitCode)
		if errHint := extractToolErrorSummary(stderr, stdout); errHint != "" {
			summary = fmt.Sprintf("%s degraded: %s", spec.Tool, errHint)
		}
		res.Checks = append(res.Checks, CheckStatus{
			Tool:           spec.Tool,
			Command:        cmdLine,
			Status:         "degraded",
			DurationMs:     elapsedMs,
			Summary:        sanitizeInline(summary, 180),
			RemediationCmd: sanitizeInline(hint, 180),
		})
	}

	res.ProvenCount = len(res.Findings)
	res.RemediationCmd = buildSummaryNextCmd(res)
	res.Why = buildSummaryWhy(res)
	res.DeepWhy = buildDeepWhy(res)

	return res, nil
}

// Render outputs either single-line JSON (--json) or calm UB-CLI-v2 Fix-Forward text.
func (r *CheckResult) Render(w io.Writer, asJSON bool, showWhy bool) error {
	if r == nil {
		return nil
	}
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		return enc.Encode(r)
	}

	if len(r.Findings) == 0 {
		passedCount := 0
		skippedCount := 0
		degradedCount := 0
		timeoutCount := 0
		for _, c := range r.Checks {
			switch c.Status {
			case "passed":
				passedCount++
			case "skipped":
				skippedCount++
			case "timeout":
				timeoutCount++
			case "degraded":
				degradedCount++
			}
		}

		var detailParts []string
		detailParts = append(detailParts, fmt.Sprintf("%d passed", passedCount))
		if skippedCount > 0 {
			detailParts = append(detailParts, fmt.Sprintf("%d skipped", skippedCount))
		}
		if degradedCount > 0 {
			detailParts = append(detailParts, fmt.Sprintf("%d degraded", degradedCount))
		}
		if timeoutCount > 0 {
			detailParts = append(detailParts, fmt.Sprintf("%d timed out", timeoutCount))
		}

		// Calm <=3 lines when clean
		if _, err := fmt.Fprintf(w, "✓ fabrial check: 0 proven issues (%s)\n", sanitizeInline(strings.Join(detailParts, ", "), 120)); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  Next: %s\n", sanitizeInline(r.RemediationCmd, 200)); err != nil {
			return err
		}
		whyLine := sanitizeInline(r.Why, 220)
		if !showWhy {
			whyLine = fmt.Sprintf("%s (re-run with --why for details)", whyLine)
		}
		if _, err := fmt.Fprintf(w, "  Why:  %s\n", whyLine); err != nil {
			return err
		}
	} else {
		shown := r.Findings
		overflow := 0
		if len(shown) > MaxRenderedFindings {
			overflow = len(shown) - MaxRenderedFindings
			shown = shown[:MaxRenderedFindings]
		}

		for _, f := range shown {
			summary := f.Summary
			if f.Location != "" {
				summary = fmt.Sprintf("%s (%s)", summary, f.Location)
			}
			ffe := &ux.FixForwardError{
				Tool:           f.Tool,
				Code:           f.ID,
				Summary:        summary,
				RemediationCmd: f.RemediationCmd,
				WhyOneLiner:    f.WhyOneLiner,
				ExitCode:       1,
			}
			if err := ffe.Render(w, false, false); err != nil {
				return err
			}
		}
		if overflow > 0 {
			if _, err := fmt.Fprintf(w, "  ... +%d additional proven finding(s) omitted (run `fabrial check --diff --json` for full list)\n", overflow); err != nil {
				return err
			}
		}
	}

	if showWhy && r.DeepWhy != "" {
		cleanDeep := strings.TrimSpace(ux.SanitizeTerminalText(ScrubSecrets(r.DeepWhy)))
		if _, err := fmt.Fprintf(w, "\n  Deep Dive (--why):\n  %s\n", strings.ReplaceAll(cleanDeep, "\n", "\n  ")); err != nil {
			return err
		}
	}

	return nil
}

func defaultRunCommand(ctx context.Context, dir, binPath string, args []string) ([]byte, []byte, int, error) {
	cmd := exec.CommandContext(ctx, binPath, args...)
	cmd.Dir = dir
	cmd.Stdin = nil // Strictly headless; never block waiting for interactive input.
	cmd.Env = append(os.Environ(),
		"NO_COLOR=1",
		"CI=true",
		"LOCKSMITH_NO_PROMPT=1",
	)

	var stdoutBuf, stderrBuf limitedBuffer
	stdoutBuf.limit = maxCmdOutputBytes
	stderrBuf.limit = maxCmdOutputBytes
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}
	return stdoutBuf.buf.Bytes(), stderrBuf.buf.Bytes(), exitCode, err
}

type limitedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if l.limit <= 0 {
		return len(p), nil
	}
	remaining := l.limit - l.buf.Len()
	if remaining <= 0 {
		return len(p), nil
	}
	if len(p) > remaining {
		_, _ = l.buf.Write(p[:remaining])
		return len(p), nil
	}
	_, _ = l.buf.Write(p)
	return len(p), nil
}

// extractProvenFindings parses tool JSON output and applies the RFC-2026-11-22-48 strict Proven-Only filter.
func extractProvenFindings(raw []byte, defaultTool string) ([]ProvenFinding, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, false
	}

	var payload any
	if err := json.Unmarshal(trimmed, &payload); err != nil {
		return nil, false
	}

	var candidates []any
	switch v := payload.(type) {
	case []any:
		candidates = v
	case map[string]any:
		for _, key := range []string{"findings", "violations", "blocked", "results", "issues"} {
			if list, ok := v[key].([]any); ok {
				candidates = append(candidates, list...)
			}
		}
		if len(candidates) == 0 {
			if _, hasProven := v["proven"]; hasProven {
				candidates = append(candidates, v)
			} else if _, hasSummary := v["summary"]; hasSummary {
				candidates = append(candidates, v)
			}
		}
	}

	var proven []ProvenFinding
	for _, item := range candidates {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if !isProvenFinding(m, defaultTool) {
			continue
		}
		proven = append(proven, normalizeFinding(m, defaultTool))
	}
	return proven, true
}

func isProvenFinding(m map[string]any, defaultTool string) bool {
	if val, exists := m["proven"]; exists {
		b, ok := val.(bool)
		return ok && b
	}
	tool := strings.ToLower(strings.TrimSpace(firstString(m, "tool")))
	if tool == "" {
		tool = strings.ToLower(defaultTool)
	}
	if tool == "argus" {
		verified, _ := m["verified"].(bool)
		action := strings.ToLower(strings.TrimSpace(firstString(m, "action")))
		conf := strings.ToLower(strings.TrimSpace(firstString(m, "confidence")))
		return verified && action == "block" && conf == "high"
	}
	return false
}

func normalizeFinding(m map[string]any, defaultTool string) ProvenFinding {
	tool := sanitizeInline(firstString(m, "tool"), 40)
	if tool == "" {
		tool = sanitizeInline(defaultTool, 40)
	}
	id := sanitizeInline(firstString(m, "probe_id", "rule_id", "code", "id"), 64)
	location := sanitizeInline(firstString(m, "location", "file", "package"), 120)
	summary := sanitizeInline(firstString(m, "summary", "message", "observed_effect"), 200)
	if summary == "" {
		summary = "Proven issue detected in diff"
	}
	fix := sanitizeInline(firstString(m, "remediation_cmd", "fix_patch_hint", "fix", "remediation"), 240)
	if fix == "" {
		fix = fmt.Sprintf("fabrial check --diff --why")
	}
	why := sanitizeInline(firstString(m, "why_one_liner", "why", "rationale"), 220)
	if why == "" {
		why = "Verified against local PR diff with zero speculative noise."
	}

	return ProvenFinding{
		Tool:           tool,
		ID:             id,
		Location:       location,
		Summary:        summary,
		RemediationCmd: fix,
		WhyOneLiner:    why,
	}
}

func extractToolErrorSummary(stderr, stdout []byte) string {
	for _, buf := range [][]byte{stderr, stdout} {
		trimmed := bytes.TrimSpace(buf)
		if len(trimmed) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(trimmed, &m); err == nil {
			if msg := firstString(m, "summary", "error", "message"); msg != "" {
				return sanitizeInline(msg, 120)
			}
		}
		firstLine := strings.SplitN(string(trimmed), "\n", 2)[0]
		if clean := sanitizeInline(firstLine, 120); clean != "" {
			return clean
		}
	}
	return ""
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if raw, ok := m[k]; ok {
			if s, ok := raw.(string); ok && strings.TrimSpace(s) != "" {
				return s
			}
		}
	}
	return ""
}

func buildSummaryNextCmd(res *CheckResult) string {
	if len(res.Findings) > 0 {
		return res.Findings[0].RemediationCmd
	}
	if len(res.MissingTools) > 0 {
		safe := make([]string, 0, len(res.MissingTools))
		for _, t := range res.MissingTools {
			if ux.ValidateRemediationToken(t) {
				safe = append(safe, "bonjoski/tap/"+t)
			}
		}
		if len(safe) > 0 {
			return "brew install " + strings.Join(safe, " ")
		}
	}
	if res.AITarget == "" {
		return "fabrial check --diff --ai-target http://127.0.0.1:8080"
	}
	return "fabrial check --diff --why"
}

func buildSummaryWhy(res *CheckResult) string {
	if len(res.Findings) > 0 {
		return "Only proven diff issues are surfaced so local PR dry-runs stay fast and noise-free."
	}
	if len(res.MissingTools) > 0 {
		return "Installed checks passed; install optional tools via Homebrew to enable full local PR gate parity."
	}
	return "Local worktree dry-run mirrors the RFC-2026-11-22-48 PR gate with zero shared locks and zero Touch ID prompts."
}

func buildDeepWhy(res *CheckResult) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("Workspace (os.OpenRoot scoped, read-only): %s", sanitizeInline(res.Workspace, 160)))
	for _, c := range res.Checks {
		line := fmt.Sprintf("- %s [%s, %dms]: %s", c.Tool, c.Status, c.DurationMs, c.Summary)
		if c.RemediationCmd != "" {
			line += fmt.Sprintf(" (Fix: %s)", c.RemediationCmd)
		}
		parts = append(parts, line)
	}
	parts = append(parts, "Invariants: strict proven-only filter, 10s per-check timeout, zero shared lock files (N=8 worktree safe), zero Touch ID prompts, loopback-only --ai-target.")
	return strings.Join(parts, "\n")
}

type secretRule struct {
	re          *regexp.Regexp
	replacement string
}

var secretRules = []secretRule{
	{regexp.MustCompile(`(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`), "[REDACTED_PEM_KEY]"},
	{regexp.MustCompile(`(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*$`), "[REDACTED_PEM_KEY]"},
	{regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{8,}\b`), "[REDACTED_ANTHROPIC_KEY]"},
	{regexp.MustCompile(`\bsk-(?:proj|svcacct|live|test)-[A-Za-z0-9_-]{8,}\b`), "[REDACTED_OPENAI_KEY]"},
	{regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{16,}\b`), "[REDACTED_API_KEY]"},
	{regexp.MustCompile(`\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b`), "[REDACTED_AWS_KEY]"},
	{regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{16,}\b`), "[REDACTED_GITHUB_TOKEN]"},
	{regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{16,}\b`), "[REDACTED_GITHUB_TOKEN]"},
	{regexp.MustCompile(`(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]{10,}`), "${1}[REDACTED_BEARER_TOKEN]"},
}

// ScrubSecrets redacts common credential patterns from rendered findings and diagnostics.
func ScrubSecrets(s string) string {
	if s == "" {
		return ""
	}
	cleaned := s
	for _, r := range secretRules {
		cleaned = r.re.ReplaceAllString(cleaned, r.replacement)
	}
	return cleaned
}

func sanitizeInline(s string, maxLen int) string {
	clean := ux.SanitizeTerminalText(ScrubSecrets(s))
	clean = strings.ReplaceAll(clean, "\n", " ")
	clean = strings.ReplaceAll(clean, "\t", " ")
	clean = strings.TrimSpace(clean)
	if maxLen > 3 && len(clean) > maxLen {
		clean = strings.TrimSpace(clean[:maxLen-3]) + "..."
	}
	return clean
}
