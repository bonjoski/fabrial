package session

import (
	"errors"
	"time"
)

// Standard error definitions for session management.
var (
	ErrSessionNotFound     = errors.New("session not found")
	ErrSessionExpired      = errors.New("session has expired")
	ErrScopeEscalation     = errors.New("child session requested scope not granted to parent (monotonic attenuation violation)")
	ErrInvalidSessionID    = errors.New("invalid session ID format")
	ErrParentNotMaster     = errors.New("child session must be derived from a valid master session")
	ErrBiometricFailed     = errors.New("biometric hardware pre-flight verification failed")
	ErrMaxConcurrencyLimit = errors.New("maximum concurrent sessions limit exceeded")
)

// SessionID uniquely identifies an active session or subagent run.
type SessionID string

// SessionConfig defines parameters for creating a master or child session.
type SessionConfig struct {
	WorkspacePath      string        `json:"workspace_path"`
	ParentID           SessionID     `json:"parent_id,omitempty"`
	SubtaskID          string        `json:"subtask_id,omitempty"`
	TTL                time.Duration `json:"ttl"`
	MaxVMs             int           `json:"max_vms,omitempty"`
	AllowedScopes      []string      `json:"allowed_scopes"`
	BiometricPreflight bool          `json:"biometric_preflight"`
	ShieldProxyAddr    string        `json:"shield_proxy_addr,omitempty"`
	ShieldCACertPath   string        `json:"shield_ca_cert_path,omitempty"`
}

// SessionGrant represents an authenticated session lease with ambient security context.
type SessionGrant struct {
	ID          SessionID         `json:"session_id"`
	ParentID    SessionID         `json:"parent_id,omitempty"`
	SubtaskID   string            `json:"subtask_id,omitempty"`
	MasterToken string            `json:"master_token,omitempty"`
	Scopes      []string          `json:"scopes"`
	CreatedAt   time.Time         `json:"created_at"`
	ExpiresAt   time.Time         `json:"expires_at"`
	Environment map[string]string `json:"environment"`
	IsMaster    bool              `json:"is_master"`
}

// IsExpired checks if the session lease has passed its TTL.
func (g *SessionGrant) IsExpired() bool {
	if g == nil {
		return true
	}
	return time.Now().After(g.ExpiresAt)
}
