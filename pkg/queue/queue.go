package queue

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
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
	SessionID   string        `json:"session_id"`
	SubtaskID   string        `json:"subtask_id,omitempty"`
	Command     []string      `json:"command"`
	MemoryMB    int           `json:"memory_mb,omitempty"`
	Timeout     time.Duration `json:"timeout,omitempty"`
}

// WorkloadLease represents a granted execution slot in the microVM pool.
type WorkloadLease struct {
	LeaseID     string    `json:"lease_id"`
	SessionID   string    `json:"session_id"`
	SlotIndex   int       `json:"slot_index"`
	AcquiredAt  time.Time `json:"acquired_at"`
	Release     func()    `json:"-"`
	released    atomic.Bool
}

// QueueStatus reports current utilization of the microVM pool.
type QueueStatus struct {
	ActiveSlots      int `json:"active_slots"`
	MaxSlots         int `json:"max_slots"`
	QueuedRequests   int `json:"queued_requests"`
	MaxQueueCapacity int `json:"max_queue_capacity"`
}

// MicroVMQueue manages bounded concurrent execution of Tier 2 microVMs.
type MicroVMQueue struct {
	mu                 sync.Mutex
	maxSlots           int
	maxQueueCapacity   int
	perSessionLimit    int
	defaultWaitTimeout time.Duration

	activeSlots        int
	sessionActiveCount map[string]int
	leases             map[string]*WorkloadLease

	// Wait queue via channels
	waitQueue          []chan struct{}
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

// NewMicroVMQueue initializes a bounded queue for Tier 2 execution slots.
func NewMicroVMQueue(opts ...QueueOption) *MicroVMQueue {
	q := &MicroVMQueue{
		maxSlots:           2, // Conservative default: 2 concurrent microVMs prevents host memory collapse
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

		// 1. Check Per-Session Quota
		activeForSession := q.sessionActiveCount[req.SessionID]
		if activeForSession >= q.perSessionLimit {
			q.mu.Unlock()
			return nil, fmt.Errorf("%w: session '%s' currently holds %d slots (limit %d)", ErrPerSessionQuota, req.SessionID, activeForSession, q.perSessionLimit)
		}

		// 2. Check if Slot Available
		if q.activeSlots < q.maxSlots {
			slotIdx := q.activeSlots
			q.activeSlots++
			q.sessionActiveCount[req.SessionID]++

			leaseID := generateLeaseID()
			lease := &WorkloadLease{
				LeaseID:    leaseID,
				SessionID:  req.SessionID,
				SlotIndex:  slotIdx,
				AcquiredAt: time.Now(),
			}

			lease.Release = func() {
				q.release(leaseID)
			}

			q.leases[leaseID] = lease
			q.mu.Unlock()
			return lease, nil
		}

		// 3. Queue Saturated Check
		if len(q.waitQueue) >= q.maxQueueCapacity {
			q.mu.Unlock()
			return nil, ErrQueueSaturated
		}

		// 4. Enqueue Waiter
		waitCh := make(chan struct{}, 1)
		q.waitQueue = append(q.waitQueue, waitCh)
		q.mu.Unlock()

		// 5. Wait for signal or timeout/cancellation
		select {
		case <-waitCh:
			// Notified of freed slot; loop back to re-attempt acquisition
			continue
		case <-waitCtx.Done():
			// Clean up waiter channel from queue
			q.mu.Lock()
			for i, ch := range q.waitQueue {
				if ch == waitCh {
					q.waitQueue = append(q.waitQueue[:i], q.waitQueue[i+1:]...)
					break
				}
			}
			q.mu.Unlock()

			if errors.Is(waitCtx.Err(), context.DeadlineExceeded) {
				return nil, ErrQueueTimeout
			}
			return nil, waitCtx.Err()
		}
	}
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

// Status returns current queue metrics.
func (q *MicroVMQueue) Status() QueueStatus {
	q.mu.Lock()
	defer q.mu.Unlock()

	return QueueStatus{
		ActiveSlots:      q.activeSlots,
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
