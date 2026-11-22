// Package hooks implements Pillar 2 of RFC-2026-11-22-50: push-based, sub-5ms
// native IDE lifecycle hooks (Claude Code, Cursor, Gemini CLI) and idempotent
// non-destructive hook wiring (`fabrial init --hooks`).
package hooks

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bonjoski/fabrial/pkg/ux"
)

// ClientDialect identifies a supported local IDE hook protocol dialect.
type ClientDialect string

const (
	ClientClaude ClientDialect = "claude"
	ClientCursor ClientDialect = "cursor"
	ClientGemini ClientDialect = "gemini"
)

// HookEvent identifies the normalized lifecycle phase of an IDE hook invocation.
type HookEvent string

const (
	EventPreTool  HookEvent = "pre-tool"
	EventPostTool HookEvent = "post-tool"
)

const (
	// DefaultMaxInputBytes is the hard 1 MiB stdin cap for hook evaluation.
	DefaultMaxInputBytes int64 = 1 << 20
	// DefaultReadTimeout is the non-blocking stdin read deadline.
	DefaultReadTimeout = 50 * time.Millisecond
	// DefaultArgusDialTimeout bounds UDS queries to ~/.argus/argus.sock.
	DefaultArgusDialTimeout = 200 * time.Millisecond
	// DefaultCoppermindTimeout bounds non-blocking post-tool index signals.
	DefaultCoppermindTimeout = 10 * time.Millisecond
	// ManagedCommandPrefix deterministically identifies Fabrial-managed IDE hooks.
	ManagedCommandPrefix = "fabrial hook eval "
)

var (
	// ErrHooksSymlinkDetected is returned fail-closed when any IDE hook config
	// path or intermediate directory is a symbolic link.
	ErrHooksSymlinkDetected = errors.New("symlink detected in IDE hooks config path (fail-closed)")
	// ErrInputTooLarge indicates stdin payload exceeded maxBytes.
	ErrInputTooLarge = errors.New("hook stdin payload exceeds maximum byte limit")
	// ErrInputTimeout indicates stdin did not complete within the read deadline.
	ErrInputTimeout = errors.New("hook stdin read deadline exceeded")
	// ErrEmptyInput indicates stdin contained no JSON payload.
	ErrEmptyInput = errors.New("hook stdin payload is empty")
)

// NormalizedHookInput abstracts Claude Code, Cursor, and Gemini CLI stdin JSON payloads.
type NormalizedHookInput struct {
	Client    ClientDialect `json:"client"`
	Event     HookEvent     `json:"event"`
	ToolName  string        `json:"tool_name"`
	Command   string        `json:"command,omitempty"`
	FilePath  string        `json:"file_path,omitempty"`
	SessionID string        `json:"session_id,omitempty"`
	CWD       string        `json:"cwd,omitempty"`
}

// Decision represents the deterministic evaluation outcome.
type Decision struct {
	Allow          bool   `json:"allow"`
	Code           string `json:"code,omitempty"`
	Summary        string `json:"summary,omitempty"`
	RemediationCmd string `json:"remediation_cmd,omitempty"`
	Why            string `json:"why,omitempty"`
	ReceiptID      string `json:"receipt_id,omitempty"`
	HardBlock      bool   `json:"hard_block,omitempty"`
}

// Evaluator executes sub-5ms local security checks without spawning shell wrappers.
type Evaluator interface {
	Evaluate(ctx context.Context, in *NormalizedHookInput) (*Decision, error)
}

// HooksInitOptions configures safe multi-IDE hook dry-run planning or atomic apply.
type HooksInitOptions struct {
	WorktreeDir string
	HomeDir     string
	Global      bool
	Apply       bool
	Targets     []string
	Now         func() time.Time
}

// HookTargetPlan summarizes planned or applied native hook changes for one IDE target.
type HookTargetPlan struct {
	Target            ClientDialect `json:"target"`
	ConfigPath        string        `json:"config_path"`
	Exists            bool          `json:"exists"`
	BackupPath        string        `json:"backup_path,omitempty"`
	Applied           bool          `json:"applied"`
	HooksAdded        []string      `json:"hooks_added,omitempty"`
	HooksUpdated      []string      `json:"hooks_updated,omitempty"`
	HooksUnchanged    []string      `json:"hooks_unchanged,omitempty"`
	UserHooksDetected []string      `json:"user_hooks_detected,omitempty"`
	Diff              string        `json:"diff"`
}

// HooksInitReport aggregates dry-run or applied hook plans across requested IDEs.
type HooksInitReport struct {
	Tool   string           `json:"tool"`
	Mode   string           `json:"mode"` // "dry-run" or "applied"
	Global bool             `json:"global"`
	Plans  []HookTargetPlan `json:"plans"`
}

// ParseClientDialect normalizes CLI client names and aliases to a canonical ClientDialect.
func ParseClientDialect(raw string) (ClientDialect, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "claude", "claude-code", "claudecode":
		return ClientClaude, nil
	case "cursor":
		return ClientCursor, nil
	case "gemini", "gemini-cli", "geminicli":
		return ClientGemini, nil
	default:
		return "", &ux.FixForwardError{
			Tool:           "fabrial",
			Code:           "FABRIAL_HOOK_UNKNOWN_CLIENT",
			Summary:        fmt.Sprintf("Unknown hook client dialect %q", raw),
			RemediationCmd: "fabrial hook eval --client claude --event pre-tool",
			WhyOneLiner:    "Supported hook clients are: claude, cursor, gemini.",
			DeepWhy:        "Specify --client claude, --client cursor, or --client gemini so Fabrial emits the exact native JSON schema expected by your IDE.",
			ExitCode:       1,
		}
	}
}

// ParseHookEvent normalizes CLI or native IDE event names to EventPreTool or EventPostTool.
func ParseHookEvent(raw string) (HookEvent, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "pre-tool", "pretool", "pre_tool", "pretooluse", "beforeshellexecution", "beforetool":
		return EventPreTool, nil
	case "post-tool", "posttool", "post_tool", "posttooluse", "afterfileedit", "aftertool":
		return EventPostTool, nil
	default:
		return "", &ux.FixForwardError{
			Tool:           "fabrial",
			Code:           "FABRIAL_HOOK_UNKNOWN_EVENT",
			Summary:        fmt.Sprintf("Unknown hook event %q", raw),
			RemediationCmd: "fabrial hook eval --client claude --event pre-tool",
			WhyOneLiner:    "Supported hook events are: pre-tool, post-tool.",
			DeepWhy:        "Use --event pre-tool for pre-execution policy gates and --event post-tool for async file-edit indexing.",
			ExitCode:       1,
		}
	}
}
