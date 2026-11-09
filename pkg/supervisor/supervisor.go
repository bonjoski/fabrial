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
	"time"

	"github.com/bonjoski/fabrial/pkg/doctor"
	"github.com/bonjoski/fabrial/pkg/procident"
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

// Engine abstracts process lifecycle execution so Supervisor respects DIP and supports deterministic testing.
type Engine interface {
	StartProcess(bin string, args []string, logFile string) (pid int, startTimeNs int64, err error)
	RunCommand(bin string, args []string) error
}

type osExecEngine struct{}

func (osExecEngine) StartProcess(bin string, args []string, logFile string) (int, int64, error) {
	cmd := exec.Command(bin, args...)
	var logF *os.File
	if logFile != "" {
		if err := os.MkdirAll(filepath.Dir(logFile), 0700); err != nil {
			return 0, 0, fmt.Errorf("create log directory: %w", err)
		}
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err == nil {
			logF = f
			cmd.Stdout = f
			cmd.Stderr = f
		}
	}

	// Isolate daemon in its own process group (Setpgid: true)
	procident.ConfigureChildProcGroup(cmd)

	if err := cmd.Start(); err != nil {
		if logF != nil {
			_ = logF.Close()
		}
		return 0, 0, err
	}
	if logF != nil {
		_ = logF.Close()
	}

	pid := cmd.Process.Pid
	startNs, _ := procident.GetProcessStartTimeNs(pid)
	return pid, startNs, nil
}

func (osExecEngine) RunCommand(bin string, args []string) error {
	cmd := exec.Command(bin, args...)
	procident.ConfigureChildProcGroup(cmd)
	return cmd.Run()
}

// Supervisor orchestrates start, stop, and status operations for resident security daemons.
type Supervisor struct {
	Services []ServiceDef
	Engine   Engine
}

func (s *Supervisor) engine() Engine {
	if s.Engine != nil {
		return s.Engine
	}
	return osExecEngine{}
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
			SocketPath: doctor.ResolveLocksmithSocketPath(),
			HealthProbe: func(ctx context.Context) bool {
				sock := doctor.ResolveLocksmithSocketPath()
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
			HealthProbe: func(_ context.Context) bool {
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

	return &Supervisor{
		Services: services,
		Engine:   osExecEngine{},
	}
}

// GetService returns the service definition matching name (case-insensitive).
func (s *Supervisor) GetService(name string) (ServiceDef, bool) {
	for _, def := range s.Services {
		if strings.EqualFold(def.Name, name) || strings.EqualFold(def.BinaryName, name) {
			return def, true
		}
	}
	return ServiceDef{}, false
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
		pid, _, _ := readPIDRecord(def.PIDFile)
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

	// 3. Prepare PID directory and spawn isolated process group via Engine
	if def.PIDFile != "" {
		if mkErr := os.MkdirAll(filepath.Dir(def.PIDFile), 0700); mkErr != nil {
			return ServiceStatus{
				Name:       def.Name,
				State:      StateError,
				Target:     target,
				BinaryPath: bin,
				Message:    fmt.Sprintf("Failed to create PID directory: %v", mkErr),
			}
		}
	}

	pid, startNs, err := s.engine().StartProcess(bin, def.StartArgs, def.LogFile)
	if err != nil {
		return ServiceStatus{
			Name:       def.Name,
			State:      StateError,
			Target:     target,
			BinaryPath: bin,
			Message:    fmt.Sprintf("Failed to spawn process: %v", err),
		}
	}

	if def.PIDFile != "" {
		record := strconv.Itoa(pid)
		if startNs > 0 {
			record = fmt.Sprintf("%d:%d", pid, startNs)
		}
		if fi, statErr := os.Lstat(def.PIDFile); statErr == nil && fi.Mode()&os.ModeSymlink != 0 {
			// Refuse writing through a symlinked PID file
		} else {
			_ = os.WriteFile(def.PIDFile, []byte(record), 0600)
		}
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

func isSameSupervisedProcess(pid int, expectedStartNs int64) bool {
	if !isProcessAlive(pid) {
		return false
	}
	if expectedStartNs <= 0 {
		return true
	}
	actualNs, err := procident.GetProcessStartTimeNs(pid)
	if err != nil {
		return false
	}
	return actualNs == expectedStartNs
}

// StopService terminates a resident daemon service gracefully, verifying kernel process start time
// to prevent terminating an unrelated process after PID recycling.
func (s *Supervisor) StopService(_ context.Context, def ServiceDef) ServiceStatus {
	target := def.SocketPath
	if target == "" {
		target = def.TCPAddr
	}

	stopped := false

	// 1. If explicit stop command is available, execute it first
	if len(def.StopArgs) > 0 {
		if bin, err := router.FindExecutable(def.BinaryName); err == nil {
			if runErr := s.engine().RunCommand(bin, def.StopArgs); runErr == nil {
				stopped = true
			}
		}
	}

	// 2. Read PID file securely and terminate process group only if start timestamp matches
	pid, startNs, err := readPIDRecord(def.PIDFile)
	if err != nil {
		return ServiceStatus{
			Name:    def.Name,
			State:   StateError,
			Target:  target,
			Message: fmt.Sprintf("Failed to stop daemon: %v", err),
		}
	}

	if pid > 0 {
		if isSameSupervisedProcess(pid, startNs) {
			_ = signalDaemonGroup(pid, false)

			for i := 0; i < 15; i++ {
				time.Sleep(100 * time.Millisecond)
				if !isSameSupervisedProcess(pid, startNs) {
					stopped = true
					break
				}
			}

			if !stopped && isSameSupervisedProcess(pid, startNs) {
				_ = signalDaemonGroup(pid, true)
				time.Sleep(100 * time.Millisecond)
				stopped = !isSameSupervisedProcess(pid, startNs)
			}
		} else {
			// Original daemon already exited (or PID was recycled by an unrelated process)
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
	if !stopped && pid > 0 && isSameSupervisedProcess(pid, startNs) {
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

	pid, startNs, _ := readPIDRecord(def.PIDFile)

	if online {
		return ServiceStatus{
			Name:    def.Name,
			State:   StateRunning,
			PID:     pid,
			Target:  target,
			Message: "Online and responsive",
		}
	}

	if pid > 0 && isSameSupervisedProcess(pid, startNs) {
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

func readPIDFile(path string) (int, error) {
	pid, _, err := readPIDRecord(path)
	return pid, err
}

// readPIDRecord securely reads and validates a daemon PID file (<pid> or <pid>:<startTimeNs>).
// Invariant: Symlinks, world-writable files, non-owned files, and system/self PIDs are rejected.
func readPIDRecord(path string) (int, int64, error) {
	if path == "" {
		return 0, 0, nil
	}
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, 0, nil
		}
		return 0, 0, fmt.Errorf("failed to stat PID file: %w", err)
	}

	if fi.Mode()&os.ModeSymlink != 0 {
		return 0, 0, fmt.Errorf("insecure symlink detected for PID file %s", path)
	}

	if fi.Mode().Perm()&0022 != 0 {
		return 0, 0, fmt.Errorf("insecure permissions (%04o) on PID file %s: must not be group/other writable", fi.Mode().Perm(), path)
	}

	if err := verifyPIDFileOwnership(fi); err != nil {
		return 0, 0, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read PID file: %w", err)
	}

	raw := strings.TrimSpace(string(data))
	pidPart := raw
	var startNs int64
	if before, after, ok := strings.Cut(raw, ":"); ok {
		pidPart = before
		parsedNs, nsErr := strconv.ParseInt(after, 10, 64)
		if nsErr != nil {
			return 0, 0, fmt.Errorf("malformed PID start timestamp: %w", nsErr)
		}
		startNs = parsedNs
	}

	pid, err := strconv.Atoi(pidPart)
	if err != nil {
		return 0, 0, fmt.Errorf("malformed PID file contents: %w", err)
	}

	if pid <= 1 {
		return 0, 0, fmt.Errorf("invalid PID %d in %s (system PIDs <= 1 rejected to prevent host disruption)", pid, path)
	}
	if pid == os.Getpid() || pid == os.Getppid() {
		return 0, 0, fmt.Errorf("invalid PID %d in %s (cannot target caller or parent process)", pid, path)
	}

	return pid, startNs, nil
}

// Start launches a service by name and implements doctor.DaemonManager.
func (s *Supervisor) Start(ctx context.Context, name string) error {
	def, ok := s.GetService(name)
	if !ok {
		return fmt.Errorf("unknown service: %s", name)
	}
	res := s.StartService(ctx, def)
	if res.State == StateError {
		return fmt.Errorf("%s", res.Message)
	}
	return nil
}

// Stop terminates a service by name and implements doctor.DaemonManager.
func (s *Supervisor) Stop(ctx context.Context, name string) error {
	def, ok := s.GetService(name)
	if !ok {
		return fmt.Errorf("unknown service: %s", name)
	}
	res := s.StopService(ctx, def)
	if res.State == StateError {
		return fmt.Errorf("%s", res.Message)
	}
	return nil
}

// Status queries a service by name and implements doctor.DaemonManager.
func (s *Supervisor) Status(ctx context.Context, name string) (bool, string) {
	def, ok := s.GetService(name)
	if !ok {
		return false, fmt.Sprintf("unknown service: %s", name)
	}
	st := s.QueryStatus(ctx, def)
	return st.State == StateRunning, st.Message
}
