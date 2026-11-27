package topui

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

const (
	backoffThreshold = 3
	backoffSkipTicks = 5
)

type providerBackoff struct {
	consecutiveTimeouts int
	skipRemaining       int
}

// Collector orchestrates all bounded, read-only local workstation providers concurrently.
// Slow or hung providers trip a local UI-only backoff badge without blocking frames.
type Collector struct {
	cfg CollectorConfig

	mu      sync.Mutex
	backoff map[string]*providerBackoff
}

// NewCollector initializes a Collector with bounded 500ms per-provider defaults.
func NewCollector(cfg CollectorConfig) *Collector {
	if cfg.ProviderTimeout <= 0 {
		cfg.ProviderTimeout = DefaultProviderTimeout
	}
	if cfg.Workdir == "" {
		cfg.Workdir = "."
	}
	return &Collector{
		cfg:     cfg,
		backoff: make(map[string]*providerBackoff),
	}
}

func (c *Collector) shouldSkip(name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, ok := c.backoff[name]
	if !ok || b.skipRemaining <= 0 {
		return false
	}
	b.skipRemaining--
	return true
}

func (c *Collector) recordOutcome(name string, state ProviderState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, ok := c.backoff[name]
	if !ok {
		b = &providerBackoff{}
		c.backoff[name] = b
	}
	if state == ProviderTimeout {
		b.consecutiveTimeouts++
		if b.consecutiveTimeouts >= backoffThreshold {
			b.skipRemaining = backoffSkipTicks
		}
		return
	}
	b.consecutiveTimeouts = 0
	b.skipRemaining = 0
}

// Collect runs all local providers concurrently under strict per-provider timeouts
// and returns a fully sanitized, secret-redacted WorkstationSnapshot.
func (c *Collector) Collect(ctx context.Context) WorkstationSnapshot {
	pollStart := time.Now()
	snap := WorkstationSnapshot{
		CollectedAt: pollStart.UTC(),
		Workdir:     c.cfg.Workdir,
		Worktrees:   []WorktreeStatus{},
		Sessions:    []AgentSessionStatus{},
		Leases:      []LeaseMetaStatus{},
		Inbox:       []LensTicketSummary{},
		Traces:      []TraceSummary{},
		Checkpoints: []CheckpointSummary{},
		Health:      []PillarHealthSummary{},
		Providers:   make([]ProviderStatus, 0, 7),
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	run := func(name string, fn func(pCtx context.Context) ProviderStatus) {
		if c.shouldSkip(name) {
			mu.Lock()
			snap.Providers = append(snap.Providers, ProviderStatus{
				Name:   name,
				State:  ProviderBackoff,
				Detail: "temporarily backed off after repeated timeouts",
				Hint:   "Press R to force an immediate refresh",
			})
			mu.Unlock()
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			pCtx, cancel := context.WithTimeout(ctx, c.cfg.ProviderTimeout)
			defer cancel()

			pStart := time.Now()
			var st ProviderStatus
			func() {
				defer func() {
					if r := recover(); r != nil {
						st = ProviderStatus{
							Name:   name,
							State:  ProviderError,
							Detail: fmt.Sprintf("provider recovered panic: %v", r),
						}
					}
				}()
				st = fn(pCtx)
			}()
			st.LatencyMs = time.Since(pStart).Milliseconds()

			c.recordOutcome(name, st.State)
			mu.Lock()
			snap.Providers = append(snap.Providers, st)
			mu.Unlock()
		}()
	}

	run("git-worktrees", func(pCtx context.Context) ProviderStatus {
		wts, st := collectWorktrees(pCtx, c.cfg.Workdir)
		mu.Lock()
		if wts != nil {
			snap.Worktrees = wts
		}
		mu.Unlock()
		return st
	})

	run("fabrial-sessions", func(pCtx context.Context) ProviderStatus {
		sess, st := collectSessions(pCtx, c.cfg.SessionsFile, c.cfg.FabrialSock, c.cfg.ReceiptsDir)
		mu.Lock()
		if sess != nil {
			snap.Sessions = sess
		}
		mu.Unlock()
		return st
	})

	run("locksmith-leases", func(pCtx context.Context) ProviderStatus {
		leases, st := collectLocksmithLeases(pCtx, c.cfg.LocksmithSock)
		mu.Lock()
		if leases != nil {
			snap.Leases = leases
		}
		mu.Unlock()
		return st
	})

	run("coppermind-inbox", func(pCtx context.Context) ProviderStatus {
		inbox, openHigh, st := collectCoppermindInbox(pCtx, c.cfg.CoppermindDBs)
		mu.Lock()
		if inbox != nil {
			snap.Inbox = inbox
		}
		snap.OpenHighObs = openHigh
		mu.Unlock()
		return st
	})

	run("tinmind-traces", func(pCtx context.Context) ProviderStatus {
		traces, st := collectTraces(pCtx, c.cfg.TinmindDir, c.cfg.FlightdeckDir)
		mu.Lock()
		if traces != nil {
			snap.Traces = traces
		}
		mu.Unlock()
		return st
	})

	run("oathgate-checkpoints", func(pCtx context.Context) ProviderStatus {
		snaps, st := collectOathgateCheckpoints(pCtx, c.cfg.OathgateDB)
		mu.Lock()
		if snaps != nil {
			snap.Checkpoints = snaps
		}
		mu.Unlock()
		return st
	})

	if !c.cfg.SkipDoctor {
		run("fabrial-doctor", func(pCtx context.Context) ProviderStatus {
			health, st := collectDoctorHealth(pCtx, c.cfg.DoctorInspector, c.cfg.Workdir)
			mu.Lock()
			if health != nil {
				snap.Health = health
			}
			mu.Unlock()
			return st
		})
	}

	wg.Wait()

	sort.Slice(snap.Providers, func(i, j int) bool {
		return snap.Providers[i].Name < snap.Providers[j].Name
	})
	snap.PollMs = time.Since(pollStart).Milliseconds()

	// Mandatory defense-in-depth sanitization gate before leaving pkg/topui.
	SanitizeSnapshot(&snap)
	return snap
}
