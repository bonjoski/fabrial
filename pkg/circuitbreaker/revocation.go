package circuitbreaker

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RevokerOptions configures target sockets for credential revocation.
type RevokerOptions struct {
	LocksmithSocket string
	ConjoinerSocket string
	Timeout         time.Duration
}

// Revoker handles broadcasting session and token invalidations to Locksmith and Conjoiner.
type Revoker struct {
	opts RevokerOptions
}

// NewRevoker initializes a Revoker with options or system defaults.
func NewRevoker(opts ...RevokerOptions) *Revoker {
	opt := RevokerOptions{
		Timeout: 200 * time.Millisecond,
	}
	if len(opts) > 0 {
		opt = opts[0]
		if opt.Timeout == 0 {
			opt.Timeout = 200 * time.Millisecond
		}
	}

	if opt.LocksmithSocket == "" {
		opt.LocksmithSocket = resolveDefaultLocksmithSocket()
	}
	if opt.ConjoinerSocket == "" {
		opt.ConjoinerSocket = resolveDefaultConjoinerSocket()
	}

	return &Revoker{opts: opt}
}

// Revoke broadcasts token and session invalidations to both Locksmith and Conjoiner.
func (r *Revoker) Revoke(alert *Alert) (revokedLocksmith bool, revokedConjoiner bool, errs []error) {
	if alert == nil {
		return false, false, nil
	}

	// 1. Revoke in Locksmith
	if r.opts.LocksmithSocket != "" {
		if err := r.revokeLocksmith(alert); err != nil {
			errs = append(errs, fmt.Errorf("locksmith revocation error: %w", err))
		} else {
			revokedLocksmith = true
		}
	}

	// 2. Revoke in Conjoiner
	if r.opts.ConjoinerSocket != "" {
		if err := r.revokeConjoiner(alert); err != nil {
			errs = append(errs, fmt.Errorf("conjoiner revocation error: %w", err))
		} else {
			revokedConjoiner = true
		}
	}

	return revokedLocksmith, revokedConjoiner, errs
}

func (r *Revoker) revokeLocksmith(alert *Alert) error {
	conn, err := net.DialTimeout("unix", r.opts.LocksmithSocket, r.opts.Timeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(r.opts.Timeout))

	var encErr error
	if alert.SessionTicket != "" {
		payload := map[string]any{
			"action":    "revoke_session",
			"ticket_id": alert.SessionTicket,
		}
		if err := json.NewEncoder(conn).Encode(payload); err != nil {
			encErr = err
		}
	}

	if alert.AgentPID > 0 {
		payload := map[string]any{
			"action":     "revoke_lease",
			"client_pid": alert.AgentPID,
		}
		if err := json.NewEncoder(conn).Encode(payload); err != nil {
			encErr = err
		}
	}

	return encErr
}

func (r *Revoker) revokeConjoiner(alert *Alert) error {
	conn, err := net.DialTimeout("unix", r.opts.ConjoinerSocket, r.opts.Timeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(r.opts.Timeout))

	payload := map[string]any{
		"action":         "revoke_token",
		"session_id":     alert.SessionID,
		"session_ticket": alert.SessionTicket,
		"agent_pid":      alert.AgentPID,
		"rule":           alert.RuleName,
		"reason":         "quarry_circuit_breaker_tripped",
	}

	return json.NewEncoder(conn).Encode(payload)
}

func resolveDefaultLocksmithSocket() string {
	if s := os.Getenv("LOCKSMITH_SOCKET"); s != "" {
		return s
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		p := filepath.Join(home, ".locksmith", "locksmith.sock")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	tmpCandidate := filepath.Join(os.TempDir(), fmt.Sprintf("locksmith-%d.sock", os.Getuid()))
	if _, err := os.Stat(tmpCandidate); err == nil {
		return tmpCandidate
	}
	return filepath.Join(os.TempDir(), "locksmith.sock")
}

func resolveDefaultConjoinerSocket() string {
	if s := os.Getenv("CONJOINER_SOCKET"); s != "" {
		return s
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		p := filepath.Join(home, ".conjoiner", "conjoiner.sock")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	tmpCandidate := filepath.Join(os.TempDir(), fmt.Sprintf("conjoiner-%d.sock", os.Getuid()))
	if _, err := os.Stat(tmpCandidate); err == nil {
		return tmpCandidate
	}
	return filepath.Join(os.TempDir(), "conjoiner.sock")
}

// FormatErrors combines slice of errors into single string.
func FormatErrors(errs []error) string {
	if len(errs) == 0 {
		return ""
	}
	var sb strings.Builder
	for i, e := range errs {
		if i > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString(e.Error())
	}
	return sb.String()
}
