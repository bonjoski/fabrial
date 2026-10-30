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
)

// TripHook is a callback function invoked whenever the circuit breaker trips.
type TripHook func(result *TripResult)

// TripwireOptions configures the circuit breaker tripwire listener.
type TripwireOptions struct {
	SocketPath      string
	LocksmithSocket string
	ConjoinerSocket string
	ForensicDir     string
	OnTrip          TripHook
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
		opt.OnTrip = opts[0].OnTrip
	}

	tw := &Tripwire{
		opts:    opt,
		revoker: NewRevoker(RevokerOptions{
			LocksmithSocket: opt.LocksmithSocket,
			ConjoinerSocket: opt.ConjoinerSocket,
		}),
		stopCh: make(chan struct{}),
		hooks:  make([]TripHook, 0, 4),
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

// Start begins listening on or connecting to argus.sock.
func (tw *Tripwire) Start(ctx context.Context) error {
	tw.mu.Lock()
	if tw.active {
		tw.mu.Unlock()
		return nil
	}
	tw.active = true
	tw.stopCh = make(chan struct{})
	sockPath := tw.opts.SocketPath
	tw.mu.Unlock()

	// Try connecting to existing Argus daemon socket
	conn, err := net.DialTimeout("unix", sockPath, 200*time.Millisecond)
	if err == nil {
		tw.mu.Lock()
		tw.clientConn = conn
		tw.mu.Unlock()
		go tw.readLoop(conn)
		return nil
	}

	// If connecting fails, bind as Unix listener so Argus can push directly to us
	_ = os.MkdirAll(filepath.Dir(sockPath), 0755)
	_ = os.Remove(sockPath)

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		tw.mu.Lock()
		tw.active = false
		tw.mu.Unlock()
		return fmt.Errorf("failed to bind circuit breaker tripwire socket %s: %w", sockPath, err)
	}
	_ = os.Chmod(sockPath, 0600)

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

		go tw.readLoop(conn)
	}
}

func (tw *Tripwire) readLoop(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			return
		}

		if len(line) == 0 {
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
func (tw *Tripwire) Trip(alert *Alert) *TripResult {
	start := time.Now()
	incidentID := generateIncidentID()

	res := &TripResult{
		IncidentID: incidentID,
		Alert:      alert,
		TargetPID:  alert.AgentPID,
		Timestamp:  start,
	}

	// 1. Instant Process Freeze (<3ms target)
	if alert.AgentPID > 1 {
		fr, err := Freeze(alert.AgentPID)
		res.FreezeLatency = time.Since(start)
		if err != nil {
			res.Error = fmt.Sprintf("freeze failed: %v", err)
		} else {
			res.Frozen = true
			res.FreezeMethod = fr.Method
		}
	}

	// 2. Session Revocation Hook (Locksmith & Conjoiner)
	revLocksmith, revConjoiner, errs := tw.revoker.Revoke(alert)
	res.RevokedLocksmith = revLocksmith
	res.RevokedConjoiner = revConjoiner
	if len(errs) > 0 {
		res.RevocationDetails = FormatErrors(errs)
	}

	// 3. Persist forensic log
	tw.writeForensicLog(res)

	// 4. Update metrics and notify hooks
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
			dir = filepath.Join(os.TempDir(), "fabrial-forensics")
		}
	}

	_ = os.MkdirAll(dir, 0700)
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
		_ = os.Remove(tw.opts.SocketPath)
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
	if s := os.Getenv("ARGUS_SOCKET"); s != "" {
		return s
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		p := fmt.Sprintf("%s/.argus/argus.sock", home)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	tmpCandidate := fmt.Sprintf("%s/argus-%d.sock", os.TempDir(), os.Getuid())
	if _, err := os.Stat(tmpCandidate); err == nil {
		return tmpCandidate
	}
	return fmt.Sprintf("%s/argus.sock", os.TempDir())
}
