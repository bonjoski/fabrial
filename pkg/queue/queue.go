package queue

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrQueueTimeout       = errors.New("timeout waiting for microVM execution slot in queue")
	ErrQueueSaturated     = errors.New("microVM queue is fully saturated")
	ErrPerSessionQuota    = errors.New("maximum per-session concurrent microVM quota exceeded")
	ErrInvalidWorkloadReq = errors.New("invalid workload request")
	ErrLeaseNotFound      = errors.New("workload lease not found")
)

// WorkloadRequest specifies requirements for executing a task inside a Tier 2 microVM.
type WorkloadRequest struct {
	SessionID string        `json:"session_id"`
	SubtaskID string        `json:"subtask_id,omitempty"`
	Command   []string      `json:"command"`
	MemoryMB  int           `json:"memory_mb,omitempty"`
	Timeout   time.Duration `json:"timeout,omitempty"`
}

// WorkloadLease represents a granted execution slot in the microVM pool.
type WorkloadLease struct {
	LeaseID     string    `json:"lease_id"`
	SessionID   string    `json:"session_id"`
	SlotIndex   int       `json:"slot_index"`
	AcquiredAt  time.Time `json:"acquired_at"`
	Release     func()    `json:"-"`
	released    atomic.Bool
	slotFile    *os.File
	sessionFile *os.File
}

// QueueStatus reports current utilization of the microVM pool.
type QueueStatus struct {
	ActiveSlots      int `json:"active_slots"`
	MaxSlots         int `json:"max_slots"`
	QueuedRequests   int `json:"queued_requests"`
	MaxQueueCapacity int `json:"max_queue_capacity"`
}

// MicroVMQueue manages bounded concurrent execution of Tier 2 microVMs.
// When lockDir is configured, slots are coordinated cross-process via kernel flock(2).
type MicroVMQueue struct {
	mu                 sync.Mutex
	maxSlots           int
	maxQueueCapacity   int
	perSessionLimit    int
	defaultWaitTimeout time.Duration
	lockDir            string

	activeSlots        int
	sessionActiveCount map[string]int
	leases             map[string]*WorkloadLease

	// Wait queue via channels
	waitQueue []chan struct{}
}

// QueueOption configures the MicroVMQueue.
type QueueOption func(*MicroVMQueue)

// WithMaxSlots sets the maximum concurrent active microVMs.
func WithMaxSlots(max int) QueueOption {
	return func(q *MicroVMQueue) {
		if max > 0 {
			q.maxSlots = max
		}
	}
}

// WithMaxQueueCapacity sets the maximum waiting requests allowed in queue.
func WithMaxQueueCapacity(cap int) QueueOption {
	return func(q *MicroVMQueue) {
		if cap > 0 {
			q.maxQueueCapacity = cap
		}
	}
}

// WithPerSessionLimit sets the maximum concurrent microVMs a single session can occupy.
func WithPerSessionLimit(limit int) QueueOption {
	return func(q *MicroVMQueue) {
		if limit > 0 {
			q.perSessionLimit = limit
		}
	}
}

// WithDefaultWaitTimeout sets the default timeout when waiting in queue.
func WithDefaultWaitTimeout(timeout time.Duration) QueueOption {
	return func(q *MicroVMQueue) {
		if timeout > 0 {
			q.defaultWaitTimeout = timeout
		}
	}
}

// WithLockDir enables cross-process kernel flock(2) coordination in dir.
func WithLockDir(dir string) QueueOption {
	return func(q *MicroVMQueue) {
		q.lockDir = dir
	}
}

// DefaultQueueLockDir returns the host lock directory used for cross-process microVM pooling.
func DefaultQueueLockDir() string {
	if env := os.Getenv("FABRIAL_QUEUE_LOCK_DIR"); env != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return filepath.Join(home, ".fabrial", "queue-locks")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("fabrial-queue-%d", os.Getuid()))
}

// NewMicroVMQueue initializes a bounded queue for Tier 2 execution slots.
func NewMicroVMQueue(opts ...QueueOption) *MicroVMQueue {
	maxSlots := 2
	if envSlots := os.Getenv("FABRIAL_MAX_MICROVM_SLOTS"); envSlots != "" {
		if parsed, err := strconv.Atoi(envSlots); err == nil && parsed > 0 {
			maxSlots = parsed
		}
	}

	q := &MicroVMQueue{
		maxSlots:           maxSlots, // Conservative default: 2 concurrent microVMs prevents host memory collapse
		maxQueueCapacity:   16,
		perSessionLimit:    1, // Fair-share: 1 microVM per session by default
		defaultWaitTimeout: 30 * time.Second,
		sessionActiveCount: make(map[string]int),
		leases:             make(map[string]*WorkloadLease),
		waitQueue:          make([]chan struct{}, 0, 16),
	}

	for _, opt := range opts {
		opt(q)
	}

	return q
}

// NewCrossProcessMicroVMQueue creates a flock-backed MicroVMQueue suitable for coordinating
// N parallel autonomous subagents across distinct OS processes and git worktrees.
func NewCrossProcessMicroVMQueue(lockDir string, opts ...QueueOption) *MicroVMQueue {
	if lockDir == "" {
		lockDir = DefaultQueueLockDir()
	}
	allOpts := make([]QueueOption, 0, len(opts)+1)
	allOpts = append(allOpts, WithLockDir(lockDir))
	allOpts = append(allOpts, opts...)
	return NewMicroVMQueue(allOpts...)
}

func (q *MicroVMQueue) ensureLockDir() error {
	if q.lockDir == "" {
		return nil
	}
	if fi, err := os.Lstat(q.lockDir); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("queue lock directory %s must not be a symlink", q.lockDir)
		}
		if !fi.IsDir() {
			return fmt.Errorf("queue lock path %s is not a directory", q.lockDir)
		}
		return nil
	}
	if err := os.MkdirAll(q.lockDir, 0700); err != nil {
		return fmt.Errorf("create queue lock directory %s: %w", q.lockDir, err)
	}
	return nil
}

func (q *MicroVMQueue) tryAcquireFlockSlot(sessionID string) (int, *os.File, *os.File, error) {
	if err := q.ensureLockDir(); err != nil {
		return -1, nil, nil, err
	}

	// 1. Cross-process per-session quota check
	sum := sha256.Sum256([]byte(sessionID))
	sessPrefix := hex.EncodeToString(sum[:8])
	var sessFile *os.File
	for i := 0; i < q.perSessionLimit; i++ {
		p := filepath.Join(q.lockDir, fmt.Sprintf("sess-%s-%d.lock", sessPrefix, i))
		f, ok, err := tryLockSlotFile(p)
		if err != nil {
			return -1, nil, nil, err
		}
		if ok {
			sessFile = f
			break
		}
	}
	if sessFile == nil {
		return -1, nil, nil, fmt.Errorf("%w: session '%s' exceeded cross-process limit (%d)", ErrPerSessionQuota, sessionID, q.perSessionLimit)
	}

	// 2. Try global host microVM slots [0..maxSlots)
	for idx := 0; idx < q.maxSlots; idx++ {
		p := filepath.Join(q.lockDir, fmt.Sprintf("slot-%d.lock", idx))
		f, ok, err := tryLockSlotFile(p)
		if err != nil {
			unlockSlotFile(sessFile)
			return -1, nil, nil, err
		}
		if ok {
			return idx, f, sessFile, nil
		}
	}

	unlockSlotFile(sessFile)
	return -1, nil, nil, nil
}

// AcquireSlot requests an execution slot, queueing if all slots are active.
func (q *MicroVMQueue) AcquireSlot(ctx context.Context, req WorkloadRequest) (*WorkloadLease, error) {
	if req.SessionID == "" {
		return nil, fmt.Errorf("%w: missing session_id", ErrInvalidWorkloadReq)
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = q.defaultWaitTimeout
	}

	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		q.mu.Lock()

		// 1. Check In-Process Per-Session Quota
		activeForSession := q.sessionActiveCount[req.SessionID]
		if activeForSession >= q.perSessionLimit {
			q.mu.Unlock()
			return nil, fmt.Errorf("%w: session '%s' currently holds %d slots (limit %d)", ErrPerSessionQuota, req.SessionID, activeForSession, q.perSessionLimit)
		}

		// 2. Check if Slot Available (in-process AND optional cross-process flock)
		if q.activeSlots < q.maxSlots {
			if q.lockDir == "" {
				slotIdx := q.activeSlots
				q.activeSlots++
				q.sessionActiveCount[req.SessionID]++
				lease := q.registerLeaseLocked(req.SessionID, slotIdx, nil, nil)
				q.mu.Unlock()
				return lease, nil
			}

			slotIdx, slotFile, sessFile, err := q.tryAcquireFlockSlot(req.SessionID)
			if err != nil {
				q.mu.Unlock()
				return nil, err
			}
			if slotFile != nil {
				q.activeSlots++
				q.sessionActiveCount[req.SessionID]++
				lease := q.registerLeaseLocked(req.SessionID, slotIdx, slotFile, sessFile)
				q.mu.Unlock()
				return lease, nil
			}
		}

		// 3. Queue Saturated Check
		if len(q.waitQueue) >= q.maxQueueCapacity {
			q.mu.Unlock()
			return nil, ErrQueueSaturated
		}

		// 4. Enqueue Waiter
		waitCh := make(chan struct{}, 1)
		q.waitQueue = append(q.waitQueue, waitCh)
		hasCrossProc := q.lockDir != ""
		q.mu.Unlock()

		var pollCh <-chan time.Time
		var ticker *time.Ticker
		if hasCrossProc {
			ticker = time.NewTicker(10 * time.Millisecond)
			pollCh = ticker.C
		}

		removeWaiter := func() {
			if ticker != nil {
				ticker.Stop()
			}
			q.mu.Lock()
			for i, ch := range q.waitQueue {
				if ch == waitCh {
					q.waitQueue = append(q.waitQueue[:i], q.waitQueue[i+1:]...)
					break
				}
			}
			q.mu.Unlock()
		}

		// 5. Wait for in-process release signal, cross-process flock poll, or timeout/cancellation
		select {
		case <-waitCh:
			if ticker != nil {
				ticker.Stop()
			}
			continue
		case <-pollCh:
			removeWaiter()
			continue
		case <-waitCtx.Done():
			removeWaiter()
			if errors.Is(waitCtx.Err(), context.DeadlineExceeded) {
				return nil, ErrQueueTimeout
			}
			return nil, waitCtx.Err()
		}
	}
}

func (q *MicroVMQueue) registerLeaseLocked(sessionID string, slotIdx int, slotFile, sessFile *os.File) *WorkloadLease {
	leaseID := generateLeaseID()
	lease := &WorkloadLease{
		LeaseID:     leaseID,
		SessionID:   sessionID,
		SlotIndex:   slotIdx,
		AcquiredAt:  time.Now(),
		slotFile:    slotFile,
		sessionFile: sessFile,
	}
	lease.Release = func() {
		_ = q.release(leaseID)
	}
	q.leases[leaseID] = lease
	return lease
}

// Release manually releases a granted lease by ID.
func (q *MicroVMQueue) Release(leaseID string) error {
	return q.release(leaseID)
}

func (q *MicroVMQueue) release(leaseID string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	lease, exists := q.leases[leaseID]
	if !exists {
		return ErrLeaseNotFound
	}

	if lease.released.Swap(true) {
		return nil // already released
	}

	unlockSlotFile(lease.slotFile)
	lease.slotFile = nil
	unlockSlotFile(lease.sessionFile)
	lease.sessionFile = nil

	delete(q.leases, leaseID)
	q.activeSlots--
	if q.sessionActiveCount[lease.SessionID] > 0 {
		q.sessionActiveCount[lease.SessionID]--
		if q.sessionActiveCount[lease.SessionID] == 0 {
			delete(q.sessionActiveCount, lease.SessionID)
		}
	}

	// Wake up first waiter in queue
	if len(q.waitQueue) > 0 {
		waiter := q.waitQueue[0]
		q.waitQueue = q.waitQueue[1:]
		select {
		case waiter <- struct{}{}:
		default:
		}
	}

	return nil
}

// Status returns current queue metrics, probing cross-process flock slots if configured.
func (q *MicroVMQueue) Status() QueueStatus {
	q.mu.Lock()
	defer q.mu.Unlock()

	active := q.activeSlots
	if q.lockDir != "" {
		if err := q.ensureLockDir(); err == nil {
			crossActive := 0
			// Count slots owned by OTHER processes plus our own held slot files
			heldBySelf := make(map[int]bool, len(q.leases))
			for _, l := range q.leases {
				heldBySelf[l.SlotIndex] = true
			}
			for idx := 0; idx < q.maxSlots; idx++ {
				if heldBySelf[idx] {
					crossActive++
					continue
				}
				p := filepath.Join(q.lockDir, fmt.Sprintf("slot-%d.lock", idx))
				f, ok, err := tryLockSlotFile(p)
				if err == nil {
					if ok {
						unlockSlotFile(f)
					} else {
						crossActive++
					}
				}
			}
			active = crossActive
		}
	}

	return QueueStatus{
		ActiveSlots:      active,
		MaxSlots:         q.maxSlots,
		QueuedRequests:   len(q.waitQueue),
		MaxQueueCapacity: q.maxQueueCapacity,
	}
}

func generateLeaseID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "lease_" + hex.EncodeToString(b)
}
