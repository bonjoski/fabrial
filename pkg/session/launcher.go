package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/bonjoski/fabrial/pkg/procident"
	"github.com/bonjoski/fabrial/pkg/router"
)

var resolveExecutable = router.FindExecutable

// LaunchConfig defines arguments for initializing an ambient agent workspace.
type LaunchConfig struct {
	Profile          string        `json:"profile"`
	TargetCommand    string        `json:"command"`
	TargetArgs       []string      `json:"args"`
	Scopes           []string      `json:"scopes"`
	TTL              time.Duration `json:"ttl"`
	ProxyAddr        string        `json:"proxy_addr"`
	UseAirlock       bool          `json:"use_airlock"`
	AllowUnsandboxed bool          `json:"allow_unsandboxed,omitempty"`
	Biometric        bool          `json:"biometric"`
}

// LaunchSession orchestrates ambient daemon environment and drops the agent into Airlock.
func LaunchSession(ctx context.Context, sm *SessionManager, cfg LaunchConfig) error {
	if cfg.TargetCommand == "" {
		return errors.New("missing target command to launch")
	}

	if cfg.TTL <= 0 {
		cfg.TTL = 30 * time.Minute
	}
	if cfg.ProxyAddr == "" {
		cfg.ProxyAddr = "127.0.0.1:8443"
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"read", "build", "test", "lint"}
	}
	if cfg.Profile == "" {
		cfg.Profile = "agent"
	}

	// 1. Check for existing active unexpired master session
	var activeGrant *SessionGrant
	for _, s := range sm.ActiveSessions() {
		if s.IsMaster && !s.Revoked && !s.IsExpired() {
			grantCopy := s
			activeGrant = &grantCopy
			break
		}
	}

	// 2. Begin new master session if none active
	if activeGrant == nil {
		sessCfg := SessionConfig{
			TTL:                cfg.TTL,
			AllowedScopes:      cfg.Scopes,
			ShieldProxyAddr:    cfg.ProxyAddr,
			BiometricPreflight: cfg.Biometric,
		}
		var err error
		activeGrant, err = sm.BeginSession(ctx, sessCfg)
		if err != nil {
			return fmt.Errorf("failed to begin ambient master session: %w", err)
		}
		if saveErr := sm.SaveToFile(DefaultSessionFilePath()); saveErr != nil {
			// Non-fatal in ephemeral test environments where ~/.fabrial may be read-only
			_ = saveErr
		}
	}

	// 3. Resolve execution command & airlock integration (Fail-Closed by default)
	var execBinary string
	var execArgs []string

	if cfg.UseAirlock {
		airlockPath, err := resolveExecutable("airlock")
		if err != nil || airlockPath == "" {
			if !cfg.AllowUnsandboxed {
				if err != nil {
					return fmt.Errorf("%w: %w", ErrAirlockUnavailable, err)
				}
				return ErrAirlockUnavailable
			}
			// Explicit operator --allow-degraded-local opt-in
			execBinary = cfg.TargetCommand
			execArgs = cfg.TargetArgs
		} else {
			execBinary = airlockPath
			execArgs = append([]string{"run", "--profile", cfg.Profile, "--", cfg.TargetCommand}, cfg.TargetArgs...)
		}
	} else {
		execBinary = cfg.TargetCommand
		execArgs = cfg.TargetArgs
	}

	// 4. Build process environment with ambient variables (never spoof AIRLOCK_ACTIVE=1 pre-confinement)
	cmd := exec.CommandContext(ctx, execBinary, execArgs...)
	procident.ConfigureChildProcGroup(cmd)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	env := os.Environ()
	for k, v := range activeGrant.Environment {
		if k == "AIRLOCK_ACTIVE" || k == "__AIRLOCK_ACTIVE" {
			continue
		}
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	env = append(env, fmt.Sprintf("FABRIAL_SESSION_ID=%s", activeGrant.ID))
	env = append(env, "FABRIAL_SESSION_ACTIVE=1")
	cmd.Env = env

	return cmd.Run()
}
