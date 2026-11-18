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
| **[01. Transparent Command Routing](01-transparent-command-routing.md)** | Automatically route linters to <15ms kernel sandboxes and untrusted builds/package managers to hardware microVMs without changing agent prompts. | `fabrial run <cmd>`<br/>`fabrial exec --profile agent -- <cmd>` | Tier 1 (Airlock) /<br/>Tier 2 (Aegisbox) |
| **[02. Ambient Session Brokerage](02-ambient-session-broker.md)** | Start an autonomous dev session where environment variables, proxy configurations, and credentials are set up with zero Hop Tax. | `fabrial session begin --ttl 30m`<br/>`fabrial session env` | Ambient Shell |
| **[03. Multi-Agent Sub-Sessions ($N=8$)](03-multi-agent-subsessions.md)** | Concurrently run up to 8 parallel subagents across distinct git worktrees without port collisions, biometric stalls, or file lock contention. | `fabrial session child --parent <id>` | Scoped Worktree |
| **[04. Emergency Circuit Breaker Killswitch](04-circuit-breaker-killswitch.md)** | Instantly terminate rogue process trees and revoke all credentials upon threat detection from Argus. | `fabrial circuit-breaker status`<br/>`fabrial circuit-breaker trip` | Host SIEM Bus |
| **[05. IDE & AI Coding Agent Integration](05-ide-sidecar-integration.md)** | Seamlessly hook Fabrial into Claude Code CLI, Cursor, and Antigravity terminal sessions. | `fabrial integrate antigravity`<br/>`fabrial doctor` | Agent IDE |
