# ADR-0001: Ambient Session Broker & Multi-Agent Resilience

- **Status:** Accepted
- **Date:** 2026-11-04
- **Component:** `pkg/session`, `pkg/engine`
- **Deciders:** Lead Systems Architect & Platform Engineer

---

## 1. Context & Problem Statement

Early designs wrapped every shell command in a synchronous proxy (`fabrial run -- <cmd>`), destroying Airlock's sub-10ms latency SLA and introducing significant process inception overhead ("Hop Tax").
- Global circuit breakers caused host-wide denial of service when a single exploratory agent triggered a tripwire.
- Unmanaged microVM dispatches across $N=8$ parallel subagents saturated host RAM.

---

## 2. Decision Outcome

We pivoted Fabrial to an **Ambient Session Broker**:

1. **Ambient Environment Provisioning:**
   - Fabrial initializes session context, network filters, and security profiles once at session startup (`fabrial session launch`). Inside the session, tools execute directly via Airlock jails with **0ms wrapper hop tax**.
2. **Process Group & Session Scoped Blast Radius:**
   - Processes are registered by PGID and session ID. When a tripwire trips, `fabrial kill` targets only the offending subagent process tree, leaving peer subagents unharmed.
3. **Bounded MicroVM Concurrency Semaphore:**
   - Hard semaphore limits concurrent Aegisbox microVMs (default: max 2–4 VMs) to prevent host memory exhaustion.

---

## 3. Consequences

- **Positive:** Zero latency overhead on execution hot paths; isolated circuit breaker tripwires.
- **Negative:** Requires processes to execute inside the initialized ambient session environment.
