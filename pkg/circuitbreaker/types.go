package circuitbreaker

import (
	"encoding/json"
	"time"
)

// MatchedEvent represents an atomic telemetry event reported in a Quarry alert.
type MatchedEvent struct {
	Layer       string    `json:"layer"`
	Action      string    `json:"action"`
	Path        string    `json:"path,omitempty"`
	Destination string    `json:"destination,omitempty"`
	Tool        string    `json:"tool,omitempty"`
	Command     string    `json:"command,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// Alert represents an alert payload emitted by Argus Project Quarry runtime engine.
type Alert struct {
	RuleName      string         `json:"rule_name"`
	RuleVersion   string         `json:"rule_version,omitempty"`
	Severity      string         `json:"severity"`
	Action        string         `json:"action"` // "kill", "freeze", "alert"
	AgentPID      int            `json:"agent_pid"`
	SessionID     string         `json:"session_id,omitempty"`
	SessionTicket string         `json:"session_ticket,omitempty"`
	TriggeredAt   time.Time      `json:"triggered_at"`
	SequenceSteps []string       `json:"sequence_steps"`
	MatchedEvents []MatchedEvent `json:"matched_events"`
	Details       map[string]any `json:"details,omitempty"`
	LatencyNs     int64          `json:"latency_ns,omitempty"`
}

// TripResult contains metrics and status of the automated circuit breaker tripwire action.
type TripResult struct {
	IncidentID        string        `json:"incident_id"`
	Alert             *Alert        `json:"alert"`
	TargetPID         int           `json:"target_pid"`
	FreezeLatency     time.Duration `json:"freeze_latency"`
	Frozen            bool          `json:"frozen"`
	FreezeMethod      string        `json:"freeze_method"` // "sigstop", "cgroup_v2", "suspended"
	RevokedLocksmith  bool          `json:"revoked_locksmith"`
	RevokedConjoiner  bool          `json:"revoked_conjoiner"`
	RevocationDetails string        `json:"revocation_details,omitempty"`
	Error             string        `json:"error,omitempty"`
	Timestamp         time.Time     `json:"timestamp"`
}

// JSON returns serialized JSON representation of TripResult.
func (tr *TripResult) JSON() ([]byte, error) {
	return json.Marshal(tr)
}
