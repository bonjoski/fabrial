package circuitbreaker

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bonjoski/fabrial/pkg/doctor"
	"github.com/bonjoski/fabrial/pkg/procident"
)

const maxAlertFrameBytes = 64 << 10 // 64 KiB maximum JSONL alert frame size

// TripHook is a callback function invoked whenever the circuit breaker trips.
type TripHook func(result *TripResult)

// SessionInvalidator abstracts session teardown when a circuit breaker trips.
type SessionInvalidator interface {
	InvalidateSession(ctx context.Context, sessionID string) error
}

// TripwireOptions configures the circuit breaker tripwire listener.
type TripwireOptions struct {
	SocketPath      string
	LocksmithSocket string
	ConjoinerSocket string
	ForensicDir     string
	SessionManager  SessionInvalidator
	OnTrip          TripHook
}

type registeredProc struct {
	pid         int
	startTimeNs int64
}

// Tripwire represents the Fabrial circuit breaker monitoring Argus alerts and
// enforcing sub-3ms process freezes and credential revocations.
type Tripwire struct {
	mu           sync.RWMutex
	opts         TripwireOptions
	revoker      *Revoker
	listener     net.Listener
	clientConn   net.Conn
	active       bool
	stopCh       chan struct{}
	trippedCount atomic.Int64
	lastResult   *TripResult
	hooks        []TripHook
	sessionPIDs  map[string][]registeredProc
}

// NewTripwire creates a new circuit breaker tripwire instance.
func NewTripwire(opts ...TripwireOptions) *Tripwire {
	opt := TripwireOptions{
		SocketPath: resolveArgusSocketPath(),
	}
	if len(opts) > 0 {
		if opts[0].SocketPath != "" {
			opt.SocketPath = opts[0].SocketPath
		}
		opt.LocksmithSocket = opts[0].LocksmithSocket
		opt.ConjoinerSocket = opts[0].ConjoinerSocket
		opt.ForensicDir = opts[0].ForensicDir
		opt.SessionManager = opts[0].SessionManager
		opt.OnTrip = opts[0].OnTrip
	}

	tw := &Tripwire{
		opts: opt,
		revoker: NewRevoker(RevokerOptions{
			LocksmithSocket: opt.LocksmithSocket,
			ConjoinerSocket: opt.ConjoinerSocket,
		}),
		stopCh:      make(chan struct{}),
		hooks:       make([]TripHook, 0, 4),
		sessionPIDs: make(map[string][]registeredProc),
	}

	if opt.OnTrip != nil {
		tw.hooks = append(tw.hooks, opt.OnTrip)
	}

	return tw
}

// AddHook registers a callback to be notified when the circuit breaker trips.
func (tw *Tripwire) AddHook(hook TripHook) {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	tw.hooks = append(tw.hooks, hook)
}

// RegisterSessionPID binds a child process PID (plus its kernel start timestamp)
// to a specific SessionID for targeted blast-radius isolation.
func (tw *Tripwire) RegisterSessionPID(sessionID string, pid int) {
	if sessionID == "" || pid <= 1 {
		return
	}
	startNs, _ := procident.GetProcessStartTimeNs(pid)
	tw.RegisterSessionPIDWithStartTime(sessionID, pid, startNs)
}

// RegisterSessionPIDWithStartTime binds a child process PID with an explicit start timestamp.
func (tw *Tripwire) RegisterSessionPIDWithStartTime(sessionID string, pid int, startTimeNs int64) {
	if sessionID == "" || pid <= 1 {
		return
	}
	tw.mu.Lock()
	defer tw.mu.Unlock()
	for i, existing := range tw.sessionPIDs[sessionID] {
		if existing.pid == pid {
			tw.sessionPIDs[sessionID][i].startTimeNs = startTimeNs
			return
		}
	}
	tw.sessionPIDs[sessionID] = append(tw.sessionPIDs[sessionID], registeredProc{
		pid:         pid,
		startTimeNs: startTimeNs,
	})
}

// UnregisterSessionPID removes a terminated PID from the session binding.
func (tw *Tripwire) UnregisterSessionPID(sessionID string, pid int) {
	if sessionID == "" || pid <= 1 {
		return
	}
	tw.mu.Lock()
	defer tw.mu.Unlock()
	procs, exists := tw.sessionPIDs[sessionID]
	if !exists {
		return
	}
	for i, p := range procs {
		if p.pid == pid {
			tw.sessionPIDs[sessionID] = append(procs[:i], procs[i+1:]...)
			break
		}
	}
	if len(tw.sessionPIDs[sessionID]) == 0 {
		delete(tw.sessionPIDs, sessionID)
	}
}

// Start begins listening on or connecting to a verified 0600 argus.sock.
func (tw *Tripwire) Start(_ context.Context) error {
	tw.mu.Lock()
	if tw.active {
		tw.mu.Unlock()
		return nil
	}
	tw.active = true
	tw.stopCh = make(chan struct{})
	sockPath := tw.opts.SocketPath
	tw.mu.Unlock()

	failStart := func(err error) error {
		tw.mu.Lock()
		tw.active = false
		tw.mu.Unlock()
		return err
	}

	// If socket path already exists, verify strict socket security BEFORE attempting to dial or unlink
	if fi, statErr := os.Lstat(sockPath); statErr == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return failStart(fmt.Errorf("refusing symlinked tripwire socket %s", sockPath))
		}
		if ok, reason := doctor.VerifySocketSecurity(sockPath); ok {
			conn, dialErr := net.DialTimeout("unix", sockPath, 200*time.Millisecond)
			if dialErr == nil {
				if peerErr := procident.VerifyUnixPeerUID(conn); peerErr != nil {
					_ = conn.Close()
					return failStart(fmt.Errorf("tripwire peer UID verification failed on %s: %w", sockPath, peerErr))
				}
				tw.mu.Lock()
				tw.clientConn = conn
				tw.mu.Unlock()
				go tw.readLoop(conn)
				return nil
			}
		} else if fi.Mode()&os.ModeSocket == 0 {
			return failStart(fmt.Errorf("refusing insecure non-socket path %s: %s", sockPath, reason))
		} else {
			return failStart(fmt.Errorf("refusing insecure tripwire socket %s: %s", sockPath, reason))
		}

		if rmErr := os.Remove(sockPath); rmErr != nil && !os.IsNotExist(rmErr) {
			return failStart(fmt.Errorf("failed to remove stale socket %s: %w", sockPath, rmErr))
		}
	}

	// Bind as Unix listener with 0700 parent directory and 0600 socket mode
	sockDir := filepath.Dir(sockPath)
	if err := os.MkdirAll(sockDir, 0700); err != nil {
		return failStart(fmt.Errorf("failed to create tripwire socket directory %s: %w", sockDir, err))
	}

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		return failStart(fmt.Errorf("failed to bind circuit breaker tripwire socket %s: %w", sockPath, err))
	}
	if err := os.Chmod(sockPath, 0600); err != nil {
		_ = l.Close()
		return failStart(fmt.Errorf("failed to enforce 0600 mode on tripwire socket %s: %w", sockPath, err))
	}

	tw.mu.Lock()
	tw.listener = l
	tw.mu.Unlock()

	go tw.acceptLoop(l)

	return nil
}

func (tw *Tripwire) acceptLoop(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-tw.stopCh:
				return
			default:
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
		}

		if err := procident.VerifyUnixPeerUID(conn); err != nil {
			_ = conn.Close()
			continue
		}

		go tw.readLoop(conn)
	}
}

func (tw *Tripwire) readLoop(conn net.Conn) {
	defer conn.Close()

	lr := io.LimitReader(conn, maxAlertFrameBytes).(*io.LimitedReader)
	reader := bufio.NewReaderSize(lr, 4096)

	for {
		lr.N = maxAlertFrameBytes
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if errors.Is(err, io.EOF) && lr.N == 0 && (len(line) == 0 || line[len(line)-1] != '\n') {
				// Frame exceeded 64 KiB cap; drop connection to prevent memory exhaustion
				return
			}
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			return
		}

		if len(line) == 0 || len(line) > maxAlertFrameBytes {
			continue
		}

		var alert Alert
		if err := json.Unmarshal(line, &alert); err != nil {
			continue
		}

		// Enforce circuit breaker on valid alert
		_ = tw.Trip(&alert)
	}
}

// Trip executes the instant process freeze and session revocation for an alert.
// Signaling is strictly restricted to PIDs explicitly registered in tw.sessionPIDs.
func (tw *Tripwire) Trip(alert *Alert) *TripResult {
	start := time.Now()
	incidentID := generateIncidentID()

	if alert == nil {
		alert = &Alert{}
	}

	res := &TripResult{
		IncidentID: incidentID,
		Alert:      alert,
		TargetPID:  alert.AgentPID,
		Timestamp:  start,
	}

	// 1. Instant Process Freeze (<3ms target) - STRICTLY restricted to registered tw.sessionPIDs
	var targets []registeredProc
	tw.mu.Lock()
	if alert.SessionID != "" {
		if procs, ok := tw.sessionPIDs[alert.SessionID]; ok {
			targets = append(targets, procs...)
			delete(tw.sessionPIDs, alert.SessionID)
		}
	} else if alert.AgentPID > 1 {
		for sessID, procs := range tw.sessionPIDs {
			for i, p := range procs {
				if p.pid == alert.AgentPID {
					targets = append(targets, p)
					tw.sessionPIDs[sessID] = append(procs[:i], procs[i+1:]...)
					if len(tw.sessionPIDs[sessID]) == 0 {
						delete(tw.sessionPIDs, sessID)
					}
					break
				}
			}
		}
	}
	tw.mu.Unlock()

	if len(targets) == 0 && alert.AgentPID > 0 {
		res.Error = fmt.Sprintf("refusing to signal unregistered PID %d", alert.AgentPID)
	}

	for _, proc := range targets {
		fr, err := FreezeVerified(proc.pid, proc.startTimeNs)
		res.FreezeLatency = time.Since(start)
		if err != nil {
			if res.Error == "" {
				res.Error = fmt.Sprintf("freeze pid %d failed: %v", proc.pid, err)
			}
		} else {
			res.Frozen = true
			res.FreezeMethod = fr.Method
			if res.TargetPID == 0 {
				res.TargetPID = proc.pid
			}
		}
	}

	// 2. Session Invalidation Hook (Local SessionManager)
	if alert.SessionID != "" && tw.opts.SessionManager != nil {
		_ = tw.opts.SessionManager.InvalidateSession(context.Background(), alert.SessionID)
	}

	// 3. Remote Session Revocation Hook (Locksmith & Conjoiner)
	revLocksmith, revConjoiner, errs := tw.revoker.Revoke(alert)
	res.RevokedLocksmith = revLocksmith
	res.RevokedConjoiner = revConjoiner
	if len(errs) > 0 {
		res.RevocationDetails = FormatErrors(errs)
	}

	// 4. Persist forensic log
	tw.writeForensicLog(res)

	// 5. Update metrics and notify hooks
	tw.trippedCount.Add(1)

	tw.mu.Lock()
	tw.lastResult = res
	hooks := append([]TripHook(nil), tw.hooks...)
	tw.mu.Unlock()

	for _, h := range hooks {
		h(res)
	}

	return res
}

func (tw *Tripwire) writeForensicLog(res *TripResult) {
	dir := tw.opts.ForensicDir
	if dir == "" {
		home, err := os.UserHomeDir()
		if err == nil && home != "" {
			dir = filepath.Join(home, ".fabrial", "forensics")
		} else {
			dir = filepath.Join(os.TempDir(), fmt.Sprintf("fabrial-forensics-%d", os.Getuid()))
		}
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return
	}
	logFile := filepath.Join(dir, fmt.Sprintf("incident-%s.json", res.IncidentID))

	data, err := json.MarshalIndent(res, "", "  ")
	if err == nil {
		_ = os.WriteFile(logFile, data, 0600)
	}
}

// Stop cleanly terminates the tripwire listener or client connection.
func (tw *Tripwire) Stop() error {
	tw.mu.Lock()
	if !tw.active {
		tw.mu.Unlock()
		return nil
	}
	tw.active = false
	close(tw.stopCh)

	if tw.clientConn != nil {
		_ = tw.clientConn.Close()
		tw.clientConn = nil
	}
	if tw.listener != nil {
		_ = tw.listener.Close()
		tw.listener = nil
		if fi, err := os.Lstat(tw.opts.SocketPath); err == nil && fi.Mode()&os.ModeSymlink == 0 {
			if rmErr := os.Remove(tw.opts.SocketPath); rmErr != nil && !os.IsNotExist(rmErr) {
				tw.mu.Unlock()
				return fmt.Errorf("failed to remove tripwire socket %s: %w", tw.opts.SocketPath, rmErr)
			}
		}
	}
	tw.mu.Unlock()
	return nil
}

// IsActive reports whether the tripwire is currently running.
func (tw *Tripwire) IsActive() bool {
	tw.mu.RLock()
	defer tw.mu.RUnlock()
	return tw.active
}

// TrippedCount returns the total number of circuit breaker trips executed.
func (tw *Tripwire) TrippedCount() int64 {
	return tw.trippedCount.Load()
}

// LastResult returns the most recent TripResult.
func (tw *Tripwire) LastResult() *TripResult {
	tw.mu.RLock()
	defer tw.mu.RUnlock()
	return tw.lastResult
}

func generateIncidentID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func resolveArgusSocketPath() string {
	return doctor.ResolveArgusSocketPath()
}
