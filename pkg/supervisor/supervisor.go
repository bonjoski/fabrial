// Package supervisor provides lifecycle orchestration for all resident sovereign security daemons:
// Locksmith, Argus, Aegisbox, Shield, and Stormcage.
package supervisor

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bonjoski/airlock/pkg/secrets"
	"github.com/bonjoski/fabrial/pkg/doctor"
	"github.com/bonjoski/fabrial/pkg/router"
)

// ServiceState represents the operational condition of a daemon.
type ServiceState string

const (
	StateRunning ServiceState = "RUNNING"
	StateStopped ServiceState = "STOPPED"
	StateError   ServiceState = "ERROR"
)

// ServiceStatus reports the lifecycle status of a daemon.
type ServiceStatus struct {
	Name       string       `json:"name"`
	State      ServiceState `json:"state"`
	PID        int          `json:"pid,omitempty"`
	Target     string       `json:"target,omitempty"`
	Message    string       `json:"message"`
	BinaryPath string       `json:"binary_path,omitempty"`
}

// ServiceDef defines the command and endpoints for a resident daemon.
type ServiceDef struct {
	Name        string
	BinaryName  string
	StartArgs   []string
	StopArgs    []string
	PIDFile     string
	LogFile     string
	SocketPath  string
	TCPAddr     string
	HealthProbe func(ctx context.Context) bool
}

// Supervisor orchestrates start, stop, and status operations for resident security daemons.
type Supervisor struct {
	Services []ServiceDef
}

// NewDefaultSupervisor returns a Supervisor pre-configured with all sovereign fabric daemons.
func NewDefaultSupervisor() *Supervisor {
	home, _ := os.UserHomeDir()

	services := []ServiceDef{
		{
			Name:       "Locksmith",
			BinaryName: "locksmith",
			StartArgs:  []string{"daemon"},
			PIDFile:    filepath.Join(home, ".locksmith", "locksmith.pid"),
			LogFile:    filepath.Join(home, ".locksmith", "daemon.log"),
			SocketPath: secrets.ResolveLocksmithSocket(),
			HealthProbe: func(ctx context.Context) bool {
				sock := secrets.ResolveLocksmithSocket()
				conn, err := (&net.Dialer{}).DialContext(ctx, "unix", sock)
				if err == nil {
					_ = conn.Close()
					return true
				}
				return false
			},
		},
		{
			Name:       "Argus",
			BinaryName: "argus",
			StartArgs:  []string{"daemon", "start"},
			StopArgs:   []string{"daemon", "stop"},
			PIDFile:    filepath.Join(home, ".argus", "argus.pid"),
			SocketPath: doctor.ResolveArgusSocketPath(),
			HealthProbe: func(ctx context.Context) bool {
				sock := doctor.ResolveArgusSocketPath()
				conn, err := (&net.Dialer{}).DialContext(ctx, "unix", sock)
				if err == nil {
					_ = conn.Close()
					return true
				}
				return false
			},
		},
		{
			Name:       "Aegisbox",
			BinaryName: "aegisbox",
			StartArgs:  []string{"daemon", "start"},
			StopArgs:   []string{"daemon", "stop"},
			PIDFile:    filepath.Join(home, ".aegisbox", "aegisboxd.pid"),
			SocketPath: router.ResolveAegisboxSocketPath(),
			HealthProbe: func(ctx context.Context) bool {
				sock := router.ResolveAegisboxSocketPath()
				conn, err := (&net.Dialer{}).DialContext(ctx, "unix", sock)
				if err == nil {
					_ = conn.Close()
					return true
				}
				return false
			},
		},
		{
			Name:       "Shield",
			BinaryName: "shield",
			StartArgs:  []string{"proxy", "--addr", "127.0.0.1:8443", "--tls"},
			PIDFile:    filepath.Join(home, ".shield", "shield.pid"),
			LogFile:    filepath.Join(home, ".shield", "proxy.log"),
			TCPAddr:    "127.0.0.1:8443",
			HealthProbe: func(ctx context.Context) bool {
				_, ok := router.DetectShieldProxy()
				return ok
			},
		},
		{
			Name:       "Stormcage",
			BinaryName: "stormcage",
			StartArgs:  []string{"daemon", "--port", "8088"},
			PIDFile:    filepath.Join(home, ".stormcage", "stormcage.pid"),
			LogFile:    filepath.Join(home, ".stormcage", "daemon.log"),
			TCPAddr:    "127.0.0.1:8088",
			HealthProbe: func(ctx context.Context) bool {
				conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", "127.0.0.1:8088")
				if err == nil {
					_ = conn.Close()
					return true
				}
				return false
			},
		},
	}

	return &Supervisor{Services: services}
}

// StartAll starts all configured resident daemons that are not already online.
func (s *Supervisor) StartAll(ctx context.Context) []ServiceStatus {
	var statuses []ServiceStatus
	for _, def := range s.Services {
		st := s.StartService(ctx, def)
		statuses = append(statuses, st)
	}
	return statuses
}

// StopAll gracefully shuts down all configured resident daemons.
func (s *Supervisor) StopAll(ctx context.Context) []ServiceStatus {
	var statuses []ServiceStatus
	for _, def := range s.Services {
		st := s.StopService(ctx, def)
		statuses = append(statuses, st)
	}
	return statuses
}

// StatusAll returns the current state of all configured services.
func (s *Supervisor) StatusAll(ctx context.Context) []ServiceStatus {
	var statuses []ServiceStatus
	for _, def := range s.Services {
		st := s.QueryStatus(ctx, def)
		statuses = append(statuses, st)
	}
	return statuses
}

// StartService starts a single resident daemon service.
func (s *Supervisor) StartService(ctx context.Context, def ServiceDef) ServiceStatus {
	target := def.SocketPath
	if target == "" {
		target = def.TCPAddr
	}

	// 1. Check if already online
	if def.HealthProbe != nil && def.HealthProbe(ctx) {
		pid, _ := readPIDFile(def.PIDFile)
		return ServiceStatus{
			Name:    def.Name,
			State:   StateRunning,
			PID:     pid,
			Target:  target,
			Message: "Daemon is already active and responsive",
		}
	}

	// 2. Discover binary
	bin, err := router.FindExecutable(def.BinaryName)
	if err != nil {
		return ServiceStatus{
			Name:    def.Name,
			State:   StateError,
			Target:  target,
			Message: fmt.Sprintf("%s binary not found on PATH or standard install dirs", def.BinaryName),
		}
	}

	// 3. Prepare logging directory and process execution
	if def.LogFile != "" {
		_ = os.MkdirAll(filepath.Dir(def.LogFile), 0700)
	}
	if def.PIDFile != "" {
		_ = os.MkdirAll(filepath.Dir(def.PIDFile), 0700)
	}

	cmd := exec.Command(bin, def.StartArgs...)
	if def.LogFile != "" {
		logF, err := os.OpenFile(def.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err == nil {
			cmd.Stdout = logF
			cmd.Stderr = logF
		}
	}

	// Launch in separate process group so killing parent doesn't terminate background daemon
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return ServiceStatus{
			Name:       def.Name,
			State:      StateError,
			Target:     target,
			BinaryPath: bin,
			Message:    fmt.Sprintf("Failed to spawn process: %v", err),
		}
	}

	pid := cmd.Process.Pid
	if def.PIDFile != "" {
		_ = os.WriteFile(def.PIDFile, []byte(strconv.Itoa(pid)), 0600)
	}

	// 4. Poll for readiness up to 2 seconds
	ready := false
	for i := 0; i < 20; i++ {
		time.Sleep(100 * time.Millisecond)
		if def.HealthProbe != nil && def.HealthProbe(ctx) {
			ready = true
			break
		}
	}

	if ready {
		return ServiceStatus{
			Name:       def.Name,
			State:      StateRunning,
			PID:        pid,
			Target:     target,
			BinaryPath: bin,
			Message:    fmt.Sprintf("Daemon started successfully (PID %d)", pid),
		}
	}

	return ServiceStatus{
		Name:       def.Name,
		State:      StateRunning,
		PID:        pid,
		Target:     target,
		BinaryPath: bin,
		Message:    fmt.Sprintf("Daemon spawned (PID %d), waiting for readiness", pid),
	}
}

// StopService terminates a resident daemon service gracefully.
func (s *Supervisor) StopService(_ context.Context, def ServiceDef) ServiceStatus {
	target := def.SocketPath
	if target == "" {
		target = def.TCPAddr
	}

	stopped := false

	// 1. If explicit stop command is available, execute it first
	if len(def.StopArgs) > 0 {
		if bin, err := router.FindExecutable(def.BinaryName); err == nil {
			cmd := exec.Command(bin, def.StopArgs...)
			if runErr := cmd.Run(); runErr == nil {
				stopped = true
			}
		}
	}

	// 2. Read PID file securely and terminate process tree
	pid, err := readPIDFile(def.PIDFile)
	if err != nil {
		return ServiceStatus{
			Name:    def.Name,
			State:   StateError,
			Target:  target,
			Message: fmt.Sprintf("Failed to stop daemon: %v", err),
		}
	}

	if pid > 0 {
		if isProcessAlive(pid) {
			// Graceful SIGTERM first
			_ = syscall.Kill(pid, syscall.SIGTERM)

			// Wait up to 1.5 seconds for graceful shutdown
			for i := 0; i < 15; i++ {
				time.Sleep(100 * time.Millisecond)
				if !isProcessAlive(pid) {
					stopped = true
					break
				}
			}

			// Force SIGKILL if still hanging
			if !stopped {
				_ = syscall.Kill(pid, syscall.SIGKILL)
				time.Sleep(100 * time.Millisecond)
				stopped = !isProcessAlive(pid)
			}
		} else {
			stopped = true
		}
		if rmErr := os.Remove(def.PIDFile); rmErr != nil && !os.IsNotExist(rmErr) {
			// Cleaned or already unlinked
		}
	} else if len(def.StopArgs) == 0 {
		stopped = true
	}

	// Clean up socket file if present and not a symlink
	if def.SocketPath != "" {
		if fi, err := os.Lstat(def.SocketPath); err == nil {
			if fi.Mode()&os.ModeSymlink == 0 {
				if rmErr := os.Remove(def.SocketPath); rmErr != nil && !os.IsNotExist(rmErr) {
					// Cleaned or already unlinked
				}
			}
		}
	}

	state := StateStopped
	msg := "Daemon stopped"
	if !stopped && pid > 0 && isProcessAlive(pid) {
		state = StateError
		msg = fmt.Sprintf("Failed to terminate daemon process (PID %d)", pid)
	}

	return ServiceStatus{
		Name:    def.Name,
		State:   state,
		PID:     pid,
		Target:  target,
		Message: msg,
	}
}

// QueryStatus returns the current status of a service.
func (s *Supervisor) QueryStatus(ctx context.Context, def ServiceDef) ServiceStatus {
	target := def.SocketPath
	if target == "" {
		target = def.TCPAddr
	}

	online := false
	if def.HealthProbe != nil {
		online = def.HealthProbe(ctx)
	}

	pid, _ := readPIDFile(def.PIDFile)

	if online {
		return ServiceStatus{
			Name:    def.Name,
			State:   StateRunning,
			PID:     pid,
			Target:  target,
			Message: "Online and responsive",
		}
	}

	if pid > 0 && isProcessAlive(pid) {
		return ServiceStatus{
			Name:    def.Name,
			State:   StateRunning,
			PID:     pid,
			Target:  target,
			Message: "Process alive but health endpoint unresponsive",
		}
	}

	return ServiceStatus{
		Name:    def.Name,
		State:   StateStopped,
		Target:  target,
		Message: "Offline",
	}
}

// readPIDFile securely reads and validates a daemon PID file.
// Invariant: Symlinks, world-writable files, non-owned files, and system/self PIDs are rejected.
func readPIDFile(path string) (int, error) {
	if path == "" {
		return 0, nil
	}
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to stat PID file: %w", err)
	}

	// Invariant: Symlinked PID files are strictly forbidden (symlink attack prevention)
	if fi.Mode()&os.ModeSymlink != 0 {
		return 0, fmt.Errorf("insecure symlink detected for PID file %s", path)
	}

	// Invariant: Group or others must not have write permissions
	if fi.Mode().Perm()&0022 != 0 {
		return 0, fmt.Errorf("insecure permissions (%04o) on PID file %s: must not be group/other writable", fi.Mode().Perm(), path)
	}

	// Invariant: Ownership validation on Unix
	if err := verifyPIDFileOwnership(fi); err != nil {
		return 0, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("failed to read PID file: %w", err)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("malformed PID file contents: %w", err)
	}

	// Invariant: Refuse dangerous / system PIDs
	if pid <= 1 {
		return 0, fmt.Errorf("invalid PID %d in %s (system PIDs <= 1 rejected to prevent host disruption)", pid, path)
	}
	if pid == os.Getpid() || pid == os.Getppid() {
		return 0, fmt.Errorf("invalid PID %d in %s (cannot target caller or parent process)", pid, path)
	}

	return pid, nil
}

func verifyPIDFileOwnership(fi os.FileInfo) error {
	if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
		if stat.Uid != uint32(os.Getuid()) {
			return fmt.Errorf("PID file owned by UID %d, expected %d", stat.Uid, os.Getuid())
		}
	}
	return nil
}

func isProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	// Signal 0 tests process existence and permission
	err := syscall.Kill(pid, 0)
	return err == nil
}
