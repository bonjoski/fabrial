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

// SecureDir0700 ensures dir exists as a real owned directory (never a symlink) with 0700 mode.
func SecureDir0700(dir string) (changed bool, err error) {
	fi, statErr := os.Lstat(dir)
	if statErr != nil {
		if !os.IsNotExist(statErr) {
			return false, fmt.Errorf("lstat %s: %w", dir, statErr)
		}
		if mkErr := os.MkdirAll(dir, 0700); mkErr != nil {
			return false, fmt.Errorf("mkdir %s: %w", dir, mkErr)
		}
		return true, nil
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("refusing symlinked directory %s", dir)
	}
	if !fi.IsDir() {
		return false, fmt.Errorf("path %s exists and is not a directory", dir)
	}
	if !isOwnedByCurrentUser(fi) {
		return false, fmt.Errorf("refusing foreign-UID directory %s", dir)
	}
	if fi.Mode().Perm()&0077 != 0 {
		if chErr := os.Chmod(dir, 0700); chErr != nil {
			return false, fmt.Errorf("chmod 0700 %s: %w", dir, chErr)
		}
		return true, nil
	}
	return false, nil
}

// SecureSocket0600 remediates socket permissions to 0600 ONLY after verifying via os.Lstat
// that sockPath is a real Unix domain socket (not a symlink) owned by the current UID.
func SecureSocket0600(pillar PillarID, sockPath, desc string) (*FixAction, error) {
	fi, err := os.Lstat(sockPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("lstat socket %s: %w", sockPath, err)
	}

	if fi.Mode()&os.ModeSymlink != 0 {
		act := &FixAction{
			Pillar:      pillar,
			Description: "Refused to chmod symlinked socket (symlink attack blocked)",
			Success:     false,
			Details:     sockPath,
		}
		return act, fmt.Errorf("refusing symlinked socket %s", sockPath)
	}

	if !isOwnedByCurrentUser(fi) {
		act := &FixAction{
			Pillar:      pillar,
			Description: "Refused to chmod socket owned by foreign UID",
			Success:     false,
			Details:     sockPath,
		}
		return act, fmt.Errorf("refusing foreign-UID socket %s", sockPath)
	}

	if fi.Mode()&os.ModeSocket == 0 {
		act := &FixAction{
			Pillar:      pillar,
			Description: "Refused to chmod non-socket path",
			Success:     false,
			Details:     sockPath,
		}
		return act, fmt.Errorf("refusing non-socket file %s", sockPath)
	}

	if fi.Mode().Perm()&0077 == 0 {
		return nil, nil
	}

	if chErr := os.Chmod(sockPath, 0600); chErr != nil {
		act := &FixAction{
			Pillar:      pillar,
			Description: "Failed to enforce 0600 permissions on socket",
			Success:     false,
			Details:     chErr.Error(),
		}
		return act, fmt.Errorf("chmod 0600 %s: %w", sockPath, chErr)
	}

	return &FixAction{
		Pillar:      pillar,
		Description: desc,
		Success:     true,
		Details:     sockPath,
	}, nil
}

// FixAll diagnoses all pillars, executes remediations on any degraded or offline component,
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

	// Ensure shared fabric directory (~/.fabrial) is secure without following symlinks
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		fabDir := filepath.Join(home, ".fabrial")
		if _, secErr := SecureDir0700(fabDir); secErr != nil {
			actions = append(actions, FixAction{
				Pillar:      PillarAirlock,
				Description: "Failed to secure ~/.fabrial directory",
				Success:     false,
				Details:     secErr.Error(),
			})
		}
	}

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
	if changed, dirErr := SecureDir0700(lockDir); dirErr != nil {
		actions = append(actions, FixAction{
			Pillar:      PillarLocksmith,
			Description: "Refused insecure ~/.locksmith directory",
			Success:     false,
			Details:     dirErr.Error(),
		})
		return actions
	} else if changed {
		actions = append(actions, FixAction{
			Pillar:      PillarLocksmith,
			Description: "Secured directory permissions to 0700",
			Success:     true,
			Details:     lockDir,
		})
	}

	sockSymlink := filepath.Join(lockDir, "locksmith.sock")
	sockDaemon := filepath.Join(lockDir, "locksmithd.sock")

	// If locksmith.sock is a symlink and locksmithd.sock is a verified owned non-symlink socket, replace safely
	if lfi, lErr := os.Lstat(sockSymlink); lErr == nil && (lfi.Mode()&os.ModeSymlink != 0) {
		if dfi, dErr := os.Lstat(sockDaemon); dErr == nil &&
			(dfi.Mode()&os.ModeSymlink == 0) &&
			(dfi.Mode()&os.ModeSocket != 0) &&
			isOwnedByCurrentUser(dfi) {
			if rmErr := os.Remove(sockSymlink); rmErr == nil {
				if linkErr := os.Link(sockDaemon, sockSymlink); linkErr == nil {
					if act, _ := SecureSocket0600(PillarLocksmith, sockSymlink, "Secured hardlinked socket to 0600"); act != nil && !act.Success {
						actions = append(actions, *act)
					} else {
						actions = append(actions, FixAction{
							Pillar:      PillarLocksmith,
							Description: "Replaced insecure symlinked socket with verified hardlink (mode 0600)",
							Success:     true,
							Details:     fmt.Sprintf("%s -> %s", sockSymlink, sockDaemon),
						})
					}
				} else {
					actions = append(actions, FixAction{
						Pillar:      PillarLocksmith,
						Description: "Failed to replace symlinked socket with hardlink",
						Success:     false,
						Details:     linkErr.Error(),
					})
				}
			}
		} else {
			actions = append(actions, FixAction{
				Pillar:      PillarLocksmith,
				Description: "Refused symlinked Locksmith socket targeting unverified destination",
				Success:     false,
				Details:     sockSymlink,
			})
		}
	}

	if act, _ := SecureSocket0600(PillarLocksmith, sockDaemon, "Fixed daemon socket permissions to 0600"); act != nil {
		actions = append(actions, *act)
	}

	targetSock := ResolveLocksmithSocketPath()
	if ok, _ := VerifySocketSecurity(targetSock); ok {
		conn, dialErr := (&net.Dialer{}).DialContext(ctx, "unix", targetSock)
		if dialErr == nil {
			_ = conn.Close()
			return actions
		}
	}

	if _, findErr := router.FindExecutable("locksmith"); findErr == nil && f.daemonManager != nil {
		if startErr := f.daemonManager.Start(ctx, "Locksmith"); startErr == nil {
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
				Description: fmt.Sprintf("Failed to start Locksmith daemon: %v", startErr),
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
	if _, dirErr := SecureDir0700(aegisDir); dirErr != nil {
		actions = append(actions, FixAction{
			Pillar:      PillarAegisbox,
			Description: "Refused insecure ~/.aegisbox directory",
			Success:     false,
			Details:     dirErr.Error(),
		})
		return actions
	}

	sock := router.ResolveAegisboxSocketPath()
	if act, secErr := SecureSocket0600(PillarAegisbox, sock, "Fixed daemon socket permissions to 0600"); act != nil {
		actions = append(actions, *act)
		if secErr != nil {
			return actions
		}
	}

	if ok, _ := VerifySocketSecurity(sock); ok {
		conn, dialErr := (&net.Dialer{}).DialContext(ctx, "unix", sock)
		if dialErr == nil {
			_ = conn.Close()
			return actions
		}
	}

	if _, findErr := router.FindExecutable("aegisbox"); findErr == nil && f.daemonManager != nil {
		if startErr := f.daemonManager.Start(ctx, "Aegisbox"); startErr == nil {
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
				Description: fmt.Sprintf("Failed to start Aegisbox daemon: %v", startErr),
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
	if _, dirErr := SecureDir0700(argusDir); dirErr != nil {
		actions = append(actions, FixAction{
			Pillar:      PillarArgus,
			Description: "Refused insecure ~/.argus directory",
			Success:     false,
			Details:     dirErr.Error(),
		})
		return actions
	}

	sock := ResolveArgusSocketPath()
	if act, secErr := SecureSocket0600(PillarArgus, sock, "Fixed bus socket permissions to 0600"); act != nil {
		actions = append(actions, *act)
		if secErr != nil {
			return actions
		}
	}

	if ok, _ := VerifySocketSecurity(sock); ok {
		conn, dialErr := (&net.Dialer{}).DialContext(ctx, "unix", sock)
		if dialErr == nil {
			_ = conn.Close()
			return actions
		}
	}

	if _, findErr := router.FindExecutable("argus"); findErr == nil && f.daemonManager != nil {
		if startErr := f.daemonManager.Start(ctx, "Argus"); startErr == nil {
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
				Description: fmt.Sprintf("Failed to start Argus daemon: %v", startErr),
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
		if _, dirErr := SecureDir0700(shieldDir); dirErr != nil {
			actions = append(actions, FixAction{
				Pillar:      PillarShield,
				Description: "Refused insecure ~/.shield directory",
				Success:     false,
				Details:     dirErr.Error(),
			})
			return actions
		}
	}

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", "127.0.0.1:8443")
	if err == nil {
		_ = conn.Close()
		return actions
	}

	if _, findErr := router.FindExecutable("shield"); findErr == nil && f.daemonManager != nil {
		if startErr := f.daemonManager.Start(ctx, "Shield"); startErr == nil {
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
				Description: fmt.Sprintf("Failed to start Shield proxy: %v", startErr),
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
		if _, dirErr := SecureDir0700(scDir); dirErr != nil {
			actions = append(actions, FixAction{
				Pillar:      PillarStormcage,
				Description: "Refused insecure ~/.stormcage directory",
				Success:     false,
				Details:     dirErr.Error(),
			})
			return actions
		}
	}

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", "127.0.0.1:8088")
	if err == nil {
		_ = conn.Close()
		return actions
	}

	if _, findErr := router.FindExecutable("stormcage"); findErr == nil && f.daemonManager != nil {
		if startErr := f.daemonManager.Start(ctx, "Stormcage"); startErr == nil {
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
				Description: fmt.Sprintf("Failed to start Stormcage daemon: %v", startErr),
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
	if _, dirErr := SecureDir0700(airDir); dirErr != nil {
		actions = append(actions, FixAction{
			Pillar:      PillarAirlock,
			Description: "Refused insecure ~/.airlock directory",
			Success:     false,
			Details:     dirErr.Error(),
		})
		return actions
	}

	sandboxesDir := filepath.Join(airDir, "sandboxes")
	if _, sbErr := SecureDir0700(sandboxesDir); sbErr != nil {
		actions = append(actions, FixAction{
			Pillar:      PillarAirlock,
			Description: "Refused insecure ~/.airlock/sandboxes directory",
			Success:     false,
			Details:     sbErr.Error(),
		})
		return actions
	}

	actions = append(actions, FixAction{
		Pillar:      PillarAirlock,
		Description: "Verified and secured ~/.airlock/sandboxes kernel sandbox boundaries (mode 0700)",
		Success:     true,
		Details:     sandboxesDir,
	})

	return actions
}

func (f *Fixer) fixConjoiner(_ context.Context) []FixAction {
	var actions []FixAction
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return actions
	}

	conjDir := filepath.Join(home, ".conjoiner")
	if _, dirErr := SecureDir0700(conjDir); dirErr != nil {
		actions = append(actions, FixAction{
			Pillar:      PillarConjoiner,
			Description: "Refused insecure ~/.conjoiner directory",
			Success:     false,
			Details:     dirErr.Error(),
		})
		return actions
	}

	sock := ResolveConjoinerSocketPath()
	if act, _ := SecureSocket0600(PillarConjoiner, sock, "Fixed Conjoiner socket permissions to 0600"); act != nil {
		actions = append(actions, *act)
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
			if ok, _ := VerifySocketSecurity(sockPath); ok {
				conn, err := (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
				if err == nil {
					_ = conn.Close()
					return true
				}
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
func ResolveLocksmithSocketPath() string {
	if sock := os.Getenv("LOCKSMITH_SOCKET"); sock != "" {
		return sock
	}

	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		directSock := filepath.Join(home, ".locksmith", "locksmithd.sock")
		if _, err := os.Lstat(directSock); err == nil {
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
