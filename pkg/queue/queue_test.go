package queue

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestQueue_BoundedConcurrency(t *testing.T) {
	ctx := context.Background()
	maxSlots := 2
	q := NewMicroVMQueue(
		WithMaxSlots(maxSlots),
		WithPerSessionLimit(2),
		WithDefaultWaitTimeout(2*time.Second),
	)

	// Acquire slot 1
	lease1, err := q.AcquireSlot(ctx, WorkloadRequest{SessionID: "sess_1"})
	if err != nil {
		t.Fatalf("failed to acquire slot 1: %v", err)
	}

	// Acquire slot 2
	lease2, err := q.AcquireSlot(ctx, WorkloadRequest{SessionID: "sess_2"})
	if err != nil {
		t.Fatalf("failed to acquire slot 2: %v", err)
	}

	status := q.Status()
	if status.ActiveSlots != 2 {
		t.Fatalf("expected 2 active slots, got %d", status.ActiveSlots)
	}

	// Slot 3 from sess_3 should block and queue
	var lease3Acquired atomic.Bool
	go func() {
		lease3, err := q.AcquireSlot(ctx, WorkloadRequest{SessionID: "sess_3"})
		if err == nil && lease3 != nil {
			lease3Acquired.Store(true)
			lease3.Release()
		}
	}()

	time.Sleep(20 * time.Millisecond)
	status = q.Status()
	if status.QueuedRequests != 1 {
		t.Fatalf("expected 1 queued request, got %d", status.QueuedRequests)
	}
	if lease3Acquired.Load() {
		t.Fatal("lease 3 acquired before release of slot 1 or 2!")
	}

	// Release slot 1
	lease1.Release()

	// Wait for slot 3 to be acquired
	time.Sleep(30 * time.Millisecond)
	if !lease3Acquired.Load() {
		t.Fatal("expected lease 3 to be acquired after slot 1 was released")
	}

	lease2.Release()
	status = q.Status()
	if status.ActiveSlots != 0 {
		t.Fatalf("expected 0 active slots after all released, got %d", status.ActiveSlots)
	}
}

func TestQueue_FairnessAndPerSessionQuota(t *testing.T) {
	ctx := context.Background()
	q := NewMicroVMQueue(
		WithMaxSlots(4),
		WithPerSessionLimit(1), // Fair-share: 1 VM per session
	)

	// Sess 1 acquires its 1 allowed slot
	lease1, err := q.AcquireSlot(ctx, WorkloadRequest{SessionID: "sess_hog"})
	if err != nil {
		t.Fatalf("failed to acquire first slot: %v", err)
	}
	defer lease1.Release()

	// Sess 1 immediately tries to acquire another slot -> rejected immediately with ErrPerSessionQuota
	_, err = q.AcquireSlot(ctx, WorkloadRequest{SessionID: "sess_hog"})
	if err == nil {
		t.Fatal("expected second slot request from same session to be rejected by quota, but succeeded")
	}
	if !errors.Is(err, ErrPerSessionQuota) {
		t.Fatalf("expected ErrPerSessionQuota, got: %v", err)
	}

	// Another session can still acquire a slot concurrently
	leasePeer, err := q.AcquireSlot(ctx, WorkloadRequest{SessionID: "sess_peer"})
	if err != nil {
		t.Fatalf("peer session should have succeeded, got error: %v", err)
	}
	defer leasePeer.Release()
}

func TestQueue_TimeoutAndCancellation(t *testing.T) {
	ctx := context.Background()
	q := NewMicroVMQueue(
		WithMaxSlots(1),
		WithPerSessionLimit(1),
		WithDefaultWaitTimeout(50*time.Millisecond),
	)

	lease1, err := q.AcquireSlot(ctx, WorkloadRequest{SessionID: "sess_hold"})
	if err != nil {
		t.Fatalf("failed to acquire slot: %v", err)
	}
	defer lease1.Release()

	// Session 2 requests with a 30ms timeout
	_, err = q.AcquireSlot(ctx, WorkloadRequest{
		SessionID: "sess_waiter",
		Timeout:   30 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("expected timeout waiting for slot, but succeeded")
	}
	if !errors.Is(err, ErrQueueTimeout) {
		t.Fatalf("expected ErrQueueTimeout, got: %v", err)
	}

	// Ensure waiter cleaned up from queue
	status := q.Status()
	if status.QueuedRequests != 0 {
		t.Fatalf("expected 0 queued requests after timeout, got %d", status.QueuedRequests)
	}
}

func TestAdversarial_MicroVM_QueueExhaustionDoS(t *testing.T) {
	ctx := context.Background()
	maxQueueCapacity := 4
	q := NewMicroVMQueue(
		WithMaxSlots(1),
		WithMaxQueueCapacity(maxQueueCapacity),
		WithPerSessionLimit(1),
	)

	// Occupy the only slot
	leaseHolder, err := q.AcquireSlot(ctx, WorkloadRequest{SessionID: "sess_holder"})
	if err != nil {
		t.Fatalf("failed to acquire slot: %v", err)
	}
	defer leaseHolder.Release()

	// Fill queue to capacity (4 distinct sessions waiting)
	var wg sync.WaitGroup
	for i := 0; i < maxQueueCapacity; i++ {
		sessID := "sess_waiter_" + string(rune('a'+i))
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			_, _ = q.AcquireSlot(ctx, WorkloadRequest{
				SessionID: id,
				Timeout:   100 * time.Millisecond,
			})
		}(sessID)
	}

	time.Sleep(20 * time.Millisecond)

	// 5th waiter tries to enqueue when capacity is 4 -> should fail immediately with ErrQueueSaturated
	_, err = q.AcquireSlot(ctx, WorkloadRequest{
		SessionID: "sess_overflow",
		Timeout:   100 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("expected queue saturation error, but succeeded")
	}
	if !errors.Is(err, ErrQueueSaturated) {
		t.Fatalf("expected ErrQueueSaturated, got: %v", err)
	}

	wg.Wait()
}
