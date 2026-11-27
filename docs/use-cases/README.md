# 💡 Fabrial End-User Use Cases & Recipes

> **Repository:** [`github.com/bonjoski/fabrial`](https://github.com/bonjoski/fabrial)  
> **Classification:** Developer Recipes & Task-Oriented Guides  
> **Source of Truth:** Authoritative Standard  

---

## Overview

**Fabrial** unifies kernel sandboxing, hardware microVM isolation, biometric credential injection, and real-time SIEM killswitches into a seamless security fabric for developers and autonomous AI coding agents (Claude Code, Cursor, Antigravity, OpenCode, Aider, Devin).

This directory provides concrete, task-oriented recipes for common developer workflows.

---

## 📚 Recipe Catalog

| Recipe | Problem Addressed | Primary CLI Commands | Isolation Tier |
| :--- | :--- | :--- | :--- |
| **[01a. 60-Second Paved-Road Onboarding](01-sixty-second-paved-road-onboarding.md)** | Zero-config repo & AI SDK detection (`0 YAML written`), calm Fix-Forward errors, and `--why` progressive disclosure. | `fabrial init`<br/>`fabrial init --why`<br/>`fabrial explain sandbox` | Local Workstation (Read-Only) |
| **[02a. Inter-Tool `BLPR-v1` Receipts & 7-Client MCP](02-inter-tool-receipts-and-mcp-golden-path.md)** | Atomic backup-safe MCP wiring across 7 AI clients (Antigravity, Claude Code, Codex CLI TOML, Cursor, Gemini CLI, Super.Engineering, VS Code/Copilot) plus Ed25519 DSSE receipt verification. | `fabrial init --mcp --target all --apply`<br/>`fabrial receipt verify`<br/>`fabrial receipt status` | Local Workstation (DSSE / `0600`) |
| **[03a. Native IDE Lifecycle Hooks & 7-Client Bootstrap](03-native-ide-hooks-and-7-client-bootstrap.md)** | Push-based `<5ms` `PreToolUse`/`beforeShellExecution`/`BeforeTool` guardrails and `<1ms` async `coppermind` indexing across Claude Code, Cursor & Gemini CLI, plus Codex/Gemini/VS Code MCP wiring. | `fabrial init --hooks --apply`<br/>`fabrial hook eval --client claude --event pre-tool`<br/>`fabrial init --mcp --target codex,gemini,vscode --apply` | Local Workstation (`<5ms` In-Process) |
| **[01. Transparent Command Routing](01-transparent-command-routing.md)** | Automatically route linters to <15ms kernel sandboxes and untrusted builds/package managers to hardware microVMs without changing agent prompts. | `fabrial run <cmd>`<br/>`fabrial exec --profile agent -- <cmd>` | Tier 1 (Airlock) /<br/>Tier 2 (Aegisbox) |
| **[02. Ambient Session Brokerage](02-ambient-session-broker.md)** | Start an autonomous dev session where environment variables, proxy configurations, and credentials are set up with zero Hop Tax. | `fabrial session begin --ttl 30m`<br/>`fabrial session env` | Ambient Shell |
| **[03. Multi-Agent Sub-Sessions ($N=8$)](03-multi-agent-subsessions.md)** | Concurrently run up to 8 parallel subagents across distinct git worktrees without port collisions, biometric stalls, or file lock contention. | `fabrial session child --parent <id>` | Scoped Worktree |
| **[04. Emergency Circuit Breaker Killswitch](04-circuit-breaker-killswitch.md)** | Instantly terminate rogue process trees and revoke all credentials upon threat detection from Argus. | `fabrial circuit-breaker status`<br/>`fabrial circuit-breaker trip` | Host SIEM Bus |
| **[05. IDE & AI Coding Agent Integration](05-ide-sidecar-integration.md)** | Seamlessly hook Fabrial into Claude Code CLI, Cursor, and Antigravity terminal sessions. | `fabrial integrate antigravity`<br/>`fabrial doctor` | Agent IDE |
| **[06. Dynamic Tier Escalation](06-dynamic-tier-escalation.md)** | Automatically escalate ambiguous tool parameters, subshells, and differential fuzzing payloads to Tier 2 microVMs. | `fabrial run -- <cmd>` | Tier 2 (Aegisbox) |
| **[07. Optional Pillar Discovery & Fail-Closed Enforcement](07-optional-pillar-discovery.md)** | 3-State smart discovery for optional local pillars (`shield`, `stormcage`) with zero noise when absent and fail-closed `exit 126` enforcement via `require_shield` / `require_stormcage`. | `fabrial doctor`<br/>`fabrial session launch`<br/>`fabrial run -- <cmd>` | Local Workstation (3-State) |
