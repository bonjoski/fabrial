# Fabrial Architectural Decision Records (ADRs)

This directory documents the key architectural decisions, multi-tier isolation fabric, and session broker invariants governing [`bonjoski/fabrial`](https://github.com/bonjoski/fabrial).

## ADR Index

| ADR ID | Title | Status | Date | Scope |
| :--- | :--- | :--- | :--- | :--- |
| **[ADR-0001](0001-ambient-session-broker-multi-agent-resilience.md)** | **Ambient Session Broker & Multi-Agent Resilience** | `Accepted` | 2026-11-04 | `pkg/session`, `pkg/engine` |
| **[ADR-0002](0002-decoupled-security-fabric-epvp-policy.md)** | **Decoupled Security Fabric & Delegated Policy Architecture (EPVP)** | `Accepted` | 2026-11-16 | `pkg/policy`, `cmd/fabrial` |

---

## Architectural Principles

1. **Ambient Session Inception:** Tier 1 kernel sandboxing executes with 0ms wrapper hop tax; the session broker configures environment variables and kernel parameters once at launch.
2. **Multi-Agent Isolation:** Sessions are strictly isolated by Process Group ID (PGID) and workspace worktree; a circuit breaker tripped by one subagent terminates only that subagent tree.
3. **Delegated Policy Validation:** Policy validation delegates to individual tool binaries via standard IPC (`<tool> policy validate --stdin`), eliminating hardcoded tool schemas.
