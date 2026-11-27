// Package topui implements the decoupled, read-only local multi-agent workstation
// mission control TUI engine for cmd/fabrial-top (RFC-2026-11-25-63).
//
// Architectural Invariant: cmd/fabrial MUST NEVER import pkg/topui so the main
// CLI retains 0.00ms cold-start regression and 0 extra binary bytes.
package topui

import (
	"context"
	"time"
)

// ProviderState describes the non-fatal operational state of a local data provider.
type ProviderState string

const (
	ProviderOK      ProviderState = "OK"
	ProviderOffline ProviderState = "OFFLINE"
	ProviderTimeout ProviderState = "TIMEOUT"
	ProviderBackoff ProviderState = "BACKOFF"
	ProviderError   ProviderState = "ERROR"
)

// WorkstationSnapshot aggregates one non-blocking poll cycle of local workstation state.
// Every string field is guaranteed sanitized (ANSI/OSC-52/Bidi stripped and secret-redacted)
// before rendering or JSON marshaling.
type WorkstationSnapshot struct {
	CollectedAt time.Time             `json:"collected_at"`
	Workdir     string                `json:"workdir"`
	PollMs      int64                 `json:"poll_ms"`
	Worktrees   []WorktreeStatus      `json:"worktrees"`
	Sessions    []AgentSessionStatus  `json:"sessions"`
	Leases      []LeaseMetaStatus     `json:"leases"`
	Inbox       []LensTicketSummary   `json:"inbox"`
	OpenHighObs int                   `json:"open_high_observations"`
	Traces      []TraceSummary        `json:"traces"`
	Checkpoints []CheckpointSummary   `json:"checkpoints"`
	Health      []PillarHealthSummary `json:"health"`
	Providers   []ProviderStatus      `json:"providers"`
}

// WorktreeStatus summarizes one local git worktree.
type WorktreeStatus struct {
	Path       string `json:"path"`
	Branch     string `json:"branch"`
	HeadSHA    string `json:"head_sha"`
	Bare       bool   `json:"bare,omitempty"`
	Detached   bool   `json:"detached,omitempty"`
	Locked     bool   `json:"locked,omitempty"`
	DirtyFiles int    `json:"dirty_files"`
}

// AgentSessionStatus represents non-secret metadata for a local Fabrial agent session.
// It intentionally omits MasterToken and raw Environment maps.
type AgentSessionStatus struct {
	SessionID    string    `json:"session_id"`
	ParentID     string    `json:"parent_id,omitempty"`
	SubtaskID    string    `json:"subtask_id,omitempty"`
	Workspace    string    `json:"workspace,omitempty"`
	Scopes       []string  `json:"scopes,omitempty"`
	IsMaster     bool      `json:"is_master"`
	PID          int       `json:"pid,omitempty"`
	StartTimeNs  int64     `json:"start_time_ns,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	RemainingSec int64     `json:"remaining_sec"`
	Revoked      bool      `json:"revoked"`
	ReceiptCount int       `json:"receipt_count,omitempty"`
}

// LeaseMetaStatus holds strictly non-secret metadata for an active Locksmith lease.
// It physically lacks any Value, Secret, or Token field to prevent accidental disclosure.
type LeaseMetaStatus struct {
	LeaseID          string    `json:"lease_id"`
	SecretName       string    `json:"secret_name"`
	ClientPID        int       `json:"client_pid"`
	ProcessStartTime int64     `json:"process_start_time,omitempty"`
	SpiffeID         string    `json:"spiffe_id,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	RemainingSec     int64     `json:"remaining_sec"`
	MaxUses          int       `json:"max_uses"`
	UsesCount        int       `json:"uses_count"`
	Revoked          bool      `json:"revoked"`
}

// LensTicketSummary summarizes a pending Coppermind commit-lens inbox ticket.
type LensTicketSummary struct {
	ID         string    `json:"id"`
	LensName   string    `json:"lens_name"`
	CommitSHA  string    `json:"commit_sha,omitempty"`
	MemoryID   string    `json:"memory_id,omitempty"`
	RepoName   string    `json:"repo_name,omitempty"`
	BranchName string    `json:"branch_name,omitempty"`
	Summary    string    `json:"summary"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	TriageCmd  string    `json:"triage_cmd"`
}

// TraceSummary summarizes a local Tinmind / Flightdeck forensic trace file.
type TraceSummary struct {
	TraceID       string    `json:"trace_id"`
	Source        string    `json:"source"` // "tinmind" or "flightdeck"
	Format        string    `json:"format"` // "jsonl" or "zstd"
	FilePath      string    `json:"file_path"`
	SizeBytes     int64     `json:"size_bytes"`
	ModTime       time.Time `json:"mod_time"`
	EventCount    int       `json:"event_count"`
	FailureCount  int       `json:"failure_count"`
	LastCommand   string    `json:"last_command,omitempty"`
	ReplayCommand string    `json:"replay_command"`
}

// CheckpointSummary summarizes a local Oathgate copy-on-write snapshot checkpoint.
type CheckpointSummary struct {
	ID             string    `json:"id"`
	ParentID       string    `json:"parent_id,omitempty"`
	RepoRoot       string    `json:"repo_root"`
	WorktreeID     string    `json:"worktree_id"`
	Label          string    `json:"label,omitempty"`
	Trigger        string    `json:"trigger"`
	GitHead        string    `json:"git_head,omitempty"`
	GitBranch      string    `json:"git_branch,omitempty"`
	CowBackend     string    `json:"cow_backend"`
	DurationMs     int64     `json:"duration_ms"`
	EntriesCloned  int64     `json:"entries_cloned"`
	BytesLogical   int64     `json:"bytes_logical"`
	Pinned         bool      `json:"pinned"`
	TinmindTraceID string    `json:"tinmind_trace_id,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// PillarHealthSummary mirrors fabrial/pkg/doctor.PillarHealth in sanitized form.
type PillarHealthSummary struct {
	Pillar     string `json:"pillar"`
	Role       string `json:"role"`
	Status     string `json:"status"`
	Details    string `json:"details"`
	BinaryPath string `json:"binary_path,omitempty"`
	SocketPath string `json:"socket_path,omitempty"`
	LatencyMs  int64  `json:"latency_ms,omitempty"`
	Required   bool   `json:"required,omitempty"`
}

// ProviderStatus reports the health, latency, and degradation hint for one data provider.
type ProviderStatus struct {
	Name      string        `json:"name"`
	State     ProviderState `json:"state"`
	Detail    string        `json:"detail,omitempty"`
	Hint      string        `json:"hint,omitempty"`
	LatencyMs int64         `json:"latency_ms"`
}

// Provider fetches one domain slice with a strict per-call deadline.
type Provider interface {
	Name() string
	Collect(ctx context.Context) error
}

// SessionAction executes an explicitly confirmed, session-scoped local action.
type SessionAction interface {
	StopSession(ctx context.Context, sessionID string, pid int, startTime int64) error
	LaunchReplay(traceID string) error
	TriggerRewind(worktree, snapID string) error
}
