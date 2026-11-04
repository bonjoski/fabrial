// Package doctor implements automated remediation for degraded or offline fabric pillars.
package doctor

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bonjoski/airlock/pkg/secrets"
	"github.com/bonjoski/fabrial/pkg/router"
)

// DaemonManager abstracts daemon lifecycle management for remediation.
type DaemonManager interface {
	Start(ctx context.Context, name string) error
	Stop(ctx context.Context, name string) error
	Status(ctx context.Context, name string) (bool, string)
}

// FixAction records an individual remediation action taken by the Fixer.
type FixAction struct {
	Pillar      PillarID `json:"pillar"`
	Description string   `json:"description"`
	Success     bool     `json:"success"`
	Details     string   `json:"details,omitempty"`
}

// Fixer orchestrates automated remediation for degraded or offline fabric components.
type Fixer struct {
	inspector     *Inspector
	daemonManager DaemonManager
	projectDir    string
}

// NewFixer creates a Fixer instance.
func NewFixer(inspector *Inspector, dm DaemonManager, projectDir string) *Fixer {
	if inspector == nil {
		inspector = NewInspector(1 * time.Second)
	}
	if projectDir == "" {
		projectDir = "."
	}
	return &Fixer{
		inspector:     inspector,
		daemonManager: dm,
		projectDir:    projectDir,
	}
}

// FixAll diagnoses all 10 pillars, executes remediations on any degraded or offline component,
// and returns the actions taken alongside the re-evaluated diagnostic reports.
func (f *Fixer) FixAll(ctx context.Context) ([]FixAction, []PillarHealth) {
	initialReports := f.inspector.InspectAll(ctx, f.projectDir)
	var actions []FixAction

	for _, rep := range initialReports {
		if rep.Status == StatusDegraded || rep.Status == StatusOffline {
			pillarActions := f.fixPillarInternal(ctx, rep.Pillar)
			actions = append(actions, pillarActions...)
		}
	}

	// Always ensure shared fabric directories (~/.fabrial) are secure
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		fabDir := filepath.Join(home, ".fabrial")
		if err := os.MkdirAll(fabDir, 0700); err == nil {
			_ = os.Chmod(fabDir, 0700)
		}
	}

	// Re-evaluate diagnostics after remediation
	updatedReports := f.inspector.InspectAll(ctx, f.projectDir)
	return actions, updatedReports
}

// FixPillar remediates a specific named pillar and returns the actions taken with updated health.
func (f *Fixer) FixPillar(ctx context.Context, pillar PillarID) ([]FixAction, PillarHealth) {
	actions := f.fixPillarInternal(ctx, pillar)
	updatedReports := f.inspector.InspectAll(ctx, f.projectDir)
	for _, r := range updatedReports {
		if strings.EqualFold(string(r.Pillar), string(pillar)) {
			return actions, r
		}
	}
	return actions, PillarHealth{Pillar: pillar, Status: StatusOffline, Details: "Unknown pillar"}
}

func (f *Fixer) fixPillarInternal(ctx context.Context, pillar PillarID) []FixAction {
	switch PillarID(strings.ToLower(string(pillar))) {
	case "locksmith", PillarLocksmith:
		return f.fixLocksmith(ctx)
	case "aegisbox", PillarAegisbox:
		return f.fixAegisbox(ctx)
	case "argus", PillarArgus:
		return f.fixArgus(ctx)
	case "shield", PillarShield:
		return f.fixShield(ctx)
	case "stormcage", PillarStormcage:
		return f.fixStormcage(ctx)
	case "airlock", PillarAirlock:
		return f.fixAirlock(ctx)
	case "conjoiner", PillarConjoiner:
		return f.fixConjoiner(ctx)
	default:
		return []FixAction{
			{
				Pillar:      pillar,
				Description: fmt.Sprintf("No automated fix available for %s", pillar),
				Success:     false,
			},
		}
	}
}

func (f *Fixer) fixLocksmith(ctx context.Context) []FixAction {
	var actions []FixAction
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return actions
	}

	lockDir := filepath.Join(home, ".locksmith")
	if fi, err := os.Stat(lockDir); err == nil {
		if fi.Mode().Perm()&0077 != 0 {
			if err := os.Chmod(lockDir, 0700); err == nil {
				actions = append(actions, FixAction{
					Pillar:      PillarLocksmith,
					Description: "Secured directory permissions to 0700",
					Success:     true,
					Details:     lockDir,
				})
			}
		}
	} else {
		_ = os.MkdirAll(lockDir, 0700)
	}

	// Remediate symlink / socket permissions
	sockSymlink := filepath.Join(lockDir, "locksmith.sock")
	sockDaemon := filepath.Join(lockDir, "locksmithd.sock")

	// If locksmith.sock is a symlink pointing to locksmithd.sock in the same directory, replace with hardlink
	if lfi, err := os.Lstat(sockSymlink); err == nil && (lfi.Mode()&os.ModeSymlink != 0) {
		if dfi, err := os.Stat(sockDaemon); err == nil && (dfi.Mode()&os.ModeSocket != 0) {
			_ = os.Remove(sockSymlink)
			if err := os.Link(sockDaemon, sockSymlink); err == nil {
				_ = os.Chmod(sockSymlink, 0600)
				actions = append(actions, FixAction{
					Pillar:      PillarLocksmith,
					Description: "Replaced insecure symlinked socket with verified hardlink (mode 0600)",
					Success:     true,
					Details:     fmt.Sprintf("%s -> %s", sockSymlink, sockDaemon),
				})
			} else {
				actions = append(actions, FixAction{
					Pillar:      PillarLocksmith,
					Description: "Failed to replace symlinked socket with hardlink",
					Success:     false,
					Details:     err.Error(),
				})
			}
		}
	}

	// Ensure 0600 on daemon socket if it exists
	if dfi, err := os.Lstat(sockDaemon); err == nil {
		if dfi.Mode().Perm()&0077 != 0 {
			if err := os.Chmod(sockDaemon, 0600); err == nil {
				actions = append(actions, FixAction{
					Pillar:      PillarLocksmith,
					Description: "Fixed daemon socket permissions to 0600",
					Success:     true,
					Details:     sockDaemon,
				})
			}
		}
	}

	// Check daemon connectivity
	targetSock := ResolveLocksmithSocketPath()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", targetSock)
	if err == nil {
		_ = conn.Close()
		return actions
	}

	// Daemon is offline; start via DaemonManager if binary exists
	if _, err := router.FindExecutable("locksmith"); err == nil && f.daemonManager != nil {
		if err := f.daemonManager.Start(ctx, "Locksmith"); err == nil {
			// Wait for socket to become active
			if f.waitForSocket(ctx, targetSock, 3*time.Second) {
				actions = append(actions, FixAction{
					Pillar:      PillarLocksmith,
					Description: "Started resident Locksmith daemon and verified active socket",
					Success:     true,
					Details:     targetSock,
				})
			} else {
				actions = append(actions, FixAction{
					Pillar:      PillarLocksmith,
					Description: "Started Locksmith daemon but socket did not respond within timeout",
					Success:     false,
					Details:     targetSock,
				})
			}
		} else {
			actions = append(actions, FixAction{
				Pillar:      PillarLocksmith,
				Description: fmt.Sprintf("Failed to start Locksmith daemon: %v", err),
				Success:     false,
			})
		}
	}

	return actions
}

func (f *Fixer) fixAegisbox(ctx context.Context) []FixAction {
	var actions []FixAction
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return actions
	}

	aegisDir := filepath.Join(home, ".aegisbox")
	if err := os.MkdirAll(aegisDir, 0700); err == nil {
		_ = os.Chmod(aegisDir, 0700)
	}

	sock := router.ResolveAegisboxSocketPath()
	if fi, err := os.Lstat(sock); err == nil {
		if fi.Mode().Perm()&0077 != 0 {
			_ = os.Chmod(sock, 0600)
			actions = append(actions, FixAction{
				Pillar:      PillarAegisbox,
				Description: "Fixed daemon socket permissions to 0600",
				Success:     true,
				Details:     sock,
			})
		}
	}

	// Check if daemon is connectable
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", sock)
	if err == nil {
		_ = conn.Close()
		return actions
	}

	// If offline, start daemon via manager if binary exists
	if _, err := router.FindExecutable("aegisbox"); err == nil && f.daemonManager != nil {
		if err := f.daemonManager.Start(ctx, "Aegisbox"); err == nil {
			if f.waitForSocket(ctx, sock, 3*time.Second) {
				actions = append(actions, FixAction{
					Pillar:      PillarAegisbox,
					Description: "Started resident Aegisbox hypervisor daemon and verified active socket",
					Success:     true,
					Details:     sock,
				})
			} else {
				actions = append(actions, FixAction{
					Pillar:      PillarAegisbox,
					Description: "Started Aegisbox daemon but socket did not respond within timeout",
					Success:     false,
					Details:     sock,
				})
			}
		} else {
			actions = append(actions, FixAction{
				Pillar:      PillarAegisbox,
				Description: fmt.Sprintf("Failed to start Aegisbox daemon: %v", err),
				Success:     false,
			})
		}
	}

	return actions
}

func (f *Fixer) fixArgus(ctx context.Context) []FixAction {
	var actions []FixAction
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return actions
	}

	argusDir := filepath.Join(home, ".argus")
	if err := os.MkdirAll(argusDir, 0700); err == nil {
		_ = os.Chmod(argusDir, 0700)
	}

	sock := ResolveArgusSocketPath()
	if fi, err := os.Lstat(sock); err == nil {
		if fi.Mode().Perm()&0077 != 0 {
			_ = os.Chmod(sock, 0600)
			actions = append(actions, FixAction{
				Pillar:      PillarArgus,
				Description: "Fixed bus socket permissions to 0600",
				Success:     true,
				Details:     sock,
			})
		}
	}

	// Check if bus socket is connectable
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", sock)
	if err == nil {
		_ = conn.Close()
		return actions
	}

	if _, err := router.FindExecutable("argus"); err == nil && f.daemonManager != nil {
		if err := f.daemonManager.Start(ctx, "Argus"); err == nil {
			if f.waitForSocket(ctx, sock, 3*time.Second) {
				actions = append(actions, FixAction{
					Pillar:      PillarArgus,
					Description: "Started resident Argus SIEM killswitch bus daemon",
					Success:     true,
					Details:     sock,
				})
			} else {
				actions = append(actions, FixAction{
					Pillar:      PillarArgus,
					Description: "Started Argus daemon but socket did not respond within timeout",
					Success:     false,
					Details:     sock,
				})
			}
		} else {
			actions = append(actions, FixAction{
				Pillar:      PillarArgus,
				Description: fmt.Sprintf("Failed to start Argus daemon: %v", err),
				Success:     false,
			})
		}
	}

	return actions
}

func (f *Fixer) fixShield(ctx context.Context) []FixAction {
	var actions []FixAction
	home, _ := os.UserHomeDir()
	if home != "" {
		shieldDir := filepath.Join(home, ".shield")
		if err := os.MkdirAll(shieldDir, 0700); err == nil {
			_ = os.Chmod(shieldDir, 0700)
		}
	}

	// Check if proxy port 127.0.0.1:8443 is connectable
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", "127.0.0.1:8443")
	if err == nil {
		_ = conn.Close()
		return actions
	}

	if _, err := router.FindExecutable("shield"); err == nil && f.daemonManager != nil {
		if err := f.daemonManager.Start(ctx, "Shield"); err == nil {
			if f.waitForTCP(ctx, "127.0.0.1:8443", 3*time.Second) {
				actions = append(actions, FixAction{
					Pillar:      PillarShield,
					Description: "Started resident Shield wire guard proxy on 127.0.0.1:8443",
					Success:     true,
					Details:     "127.0.0.1:8443",
				})
			} else {
				actions = append(actions, FixAction{
					Pillar:      PillarShield,
					Description: "Started Shield proxy but port did not respond within timeout",
					Success:     false,
					Details:     "127.0.0.1:8443",
				})
			}
		} else {
			actions = append(actions, FixAction{
				Pillar:      PillarShield,
				Description: fmt.Sprintf("Failed to start Shield proxy: %v", err),
				Success:     false,
			})
		}
	}

	return actions
}

func (f *Fixer) fixStormcage(ctx context.Context) []FixAction {
	var actions []FixAction
	home, _ := os.UserHomeDir()
	if home != "" {
		scDir := filepath.Join(home, ".stormcage")
		if err := os.MkdirAll(scDir, 0700); err == nil {
			_ = os.Chmod(scDir, 0700)
		}
	}

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", "127.0.0.1:8088")
	if err == nil {
		_ = conn.Close()
		return actions
	}

	if _, err := router.FindExecutable("stormcage"); err == nil && f.daemonManager != nil {
		if err := f.daemonManager.Start(ctx, "Stormcage"); err == nil {
			if f.waitForTCP(ctx, "127.0.0.1:8088", 3*time.Second) {
				actions = append(actions, FixAction{
					Pillar:      PillarStormcage,
					Description: "Started resident Stormcage context firewall daemon on 127.0.0.1:8088",
					Success:     true,
					Details:     "127.0.0.1:8088",
				})
			} else {
				actions = append(actions, FixAction{
					Pillar:      PillarStormcage,
					Description: "Started Stormcage daemon but port did not respond within timeout",
					Success:     false,
					Details:     "127.0.0.1:8088",
				})
			}
		} else {
			actions = append(actions, FixAction{
				Pillar:      PillarStormcage,
				Description: fmt.Sprintf("Failed to start Stormcage daemon: %v", err),
				Success:     false,
			})
		}
	}

	return actions
}

func (f *Fixer) fixAirlock(_ context.Context) []FixAction {
	var actions []FixAction
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return actions
	}

	airDir := filepath.Join(home, ".airlock")
	sandboxesDir := filepath.Join(airDir, "sandboxes")
	if err := os.MkdirAll(sandboxesDir, 0700); err == nil {
		_ = os.Chmod(airDir, 0700)
		_ = os.Chmod(sandboxesDir, 0700)
		actions = append(actions, FixAction{
			Pillar:      PillarAirlock,
			Description: "Verified and secured ~/.airlock/sandboxes kernel sandbox boundaries (mode 0700)",
			Success:     true,
			Details:     sandboxesDir,
		})
	}

	return actions
}

func (f *Fixer) fixConjoiner(_ context.Context) []FixAction {
	var actions []FixAction
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return actions
	}

	conjDir := filepath.Join(home, ".conjoiner")
	if err := os.MkdirAll(conjDir, 0700); err == nil {
		_ = os.Chmod(conjDir, 0700)
	}

	sock := ResolveConjoinerSocketPath()
	if fi, err := os.Lstat(sock); err == nil {
		if fi.Mode().Perm()&0077 != 0 {
			_ = os.Chmod(sock, 0600)
			actions = append(actions, FixAction{
				Pillar:      PillarConjoiner,
				Description: "Fixed Conjoiner socket permissions to 0600",
				Success:     true,
				Details:     sock,
			})
		}
	}

	return actions
}

func (f *Fixer) waitForSocket(ctx context.Context, sockPath string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return false
		default:
			conn, err := (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
			if err == nil {
				_ = conn.Close()
				return true
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	return false
}

func (f *Fixer) waitForTCP(ctx context.Context, addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return false
		default:
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
			if err == nil {
				_ = conn.Close()
				return true
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	return false
}

// ResolveLocksmithSocketPath returns the canonical Locksmith daemon socket path.
// It prioritizes the official daemon socket (~/.locksmith/locksmithd.sock) before
// falling back to legacy symlinks or temporary socket locations.
func ResolveLocksmithSocketPath() string {
	if sock := os.Getenv("LOCKSMITH_SOCKET"); sock != "" {
		return sock
	}

	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		directSock := filepath.Join(home, ".locksmith", "locksmithd.sock")
		if _, err := os.Stat(directSock); err == nil {
			return directSock
		}
	}

	return secrets.ResolveLocksmithSocket()
}

// FormatFixTable outputs a formatted summary of remediation actions.
func FormatFixTable(actions []FixAction) string {
	var sb strings.Builder
	sb.WriteString("💎 Fabrial Sovereign Security Fabric — Remediation Actions\n")
	sb.WriteString(strings.Repeat("─", 75) + "\n")
	if len(actions) == 0 {
		sb.WriteString("✔ No remediations required; all components were already optimal.\n")
		sb.WriteString(strings.Repeat("─", 75))
		return sb.String()
	}

	for _, a := range actions {
		icon := "✔"
		if !a.Success {
			icon = "❌"
		}
		sb.WriteString(fmt.Sprintf("%s %-12s: %s\n", icon, a.Pillar, a.Description))
		if a.Details != "" {
			sb.WriteString(fmt.Sprintf("   Details: %s\n", a.Details))
		}
	}
	sb.WriteString(strings.Repeat("─", 75))
	return sb.String()
}
