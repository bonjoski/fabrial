<div align="center">

# 💎 Fabrial

### The Sovereign AI Agent Security Fabric
**Give autonomous coding agents the freedom to build without giving them the keys to your kingdom.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/go-1.27%2B-00ADD8.svg?logo=go)](https://golang.org)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey.svg)](https://github.com/bonjoski/fabrial)
[![Zero-SaaS](https://img.shields.io/badge/SaaS-Zero%20(100%25%20Local)-blueviolet.svg)](#-zero-saas-self-sovereignty)
[![Overhead](https://img.shields.io/badge/latency-%3C15ms%20Tier%201-success.svg)](#-two-isolation-tiers)

---

**Fabrial** unifies four specialized, developer-owned security engines—**Airlock**, **Locksmith**, **Aegisbox**, and **Argus**—into an integrated zero-trust runtime designed specifically for autonomous AI coding agents (Claude Code, Cursor, OpenCode, Aider, Devin).

</div>

---

## ⚡ The 60-Second Quickstart

### 1. Install
```bash
# Via Homebrew (macOS / Linux)
brew tap bonjoski/tap
brew install fabrial

# Or build from source
git clone https://github.com/bonjoski/fabrial.git
cd fabrial && make install
```

### 2. Verify Your Security Fabric
Ensure all local security engines are operating and kernel hooks/sockets are available:
```bash
fabrial doctor
```
```text
💎 Fabrial Multi-Pillar Diagnostic Suite
─────────────────────────────────────────────────────────────────
✅ Airlock      [READY   ] Tier 1 Kernel Sandbox Engine
   Details: Native kernel boundary active
✅ Locksmith    [ONLINE  ] Ephemeral Secret Lease Daemon
   Details: Active on /Users/user/.locksmith/locksmith.sock
✅ Aegisbox     [ONLINE  ] Tier 2 MicroVM Isolation Engine
   Details: Daemon active on /Users/user/.aegisbox/aegisboxd.sock
✅ Argus        [ONLINE  ] SIEM Telemetry & Killswitch Bus
   Details: Listening on /Users/user/.argus/argus.sock
─────────────────────────────────────────────────────────────────
```

### 3. Run Sandboxed Agent Commands with Dynamic Multi-Tier Routing
Fabrial automatically maps commands to the optimal isolation tier using `fabrial.yaml`:
```bash
# Dynamic routing: Benign linter routed to Tier 1 Airlock (<15ms cold start)
fabrial run eslint src/

# Dynamic routing: Sensitive package manager routed to Tier 2 Aegisbox MicroVM (~100ms hardware isolation)
fabrial run npm install lodash

# Explicit CLI overrides:
fabrial exec --profile agent -- npm test
fabrial exec --profile agent --microvm -- python3 untrusted_script.py
```

---

## 🚨 The Agent Security Dilemma

Autonomous AI coding agents need shell execution to run tests, compile code, and install dependencies. However, granting an LLM raw subshell access creates severe attack vectors:

| Attack Vector | What Happens Without Fabrial | How Fabrial Defends |
| :--- | :--- | :--- |
| **Credential Theft** | Agent or malicious sub-script reads `~/.ssh`, `~/.aws`, `~/.kube`, or `.env`. | **Denied by Default**: Blocked at the kernel VFS layer via Seatbelt / Landlock. |
| **Data Exfiltration** | Malicious script curls sensitive source code to an external server. | **Pinned Network Egress**: Strict allowlist (OpenAI, Anthropic, npm, PyPI, Crates, Go proxy). All other outbound traffic dropped. |
| **Prompt Injection Hijack** | A poisoned README or dependency forces terminal queue injection (`TIOCSTI`). | **PTY Sanitization**: Terminal input queue manipulation neutralized via stdin detachment and kernel filtering. |
| **Long-Lived Secret Exposure** | Ambient API keys dumped in environment variables remain exposed. | **Ephemeral ETX Leases**: Checked out dynamically in-memory via Locksmith; automatically revoked and zeroed upon command exit. |
| **Supply Chain Host Compromise** | Malicious postinstall script modifies system files or launches daemon. | **Tier 2 MicroVM**: Completely isolated hardware virtualization boundary with rollback on exit. |

---

## 🏛️ The Four Pillars of Fabrial

Fabrial orchestrates four purpose-built security engines operating locally on your workstation:

```
                      ┌────────────────────────────────────────┐
                      │  🤖 Autonomous AI Agent (Claude/Cursor)│
                      └──────────────────┬─────────────────────┘
                                         │ 1. Invocation (fabrial exec)
                                         ▼
                      ┌────────────────────────────────────────┐
                      │          💎 FABRIAL ORCHESTRATOR        │
                      └────┬─────────────────┬─────────────┬───┘
                           │                 │             │
        2. Lease Secret    │   3. Stream     │             │ 4. Enforce Boundary
        via Kernel IPC     │   Telemetry     │             │
              ▼            ▼                 ▼             ▼
      ┌───────────────┐ ┌───────────────┐ ┌─────────────┐ ┌─────────────┐
      │  🔐 Locksmith │ │   👁️ Argus    │ │ 🛡️ Airlock   │ │ 📦 Aegisbox │
      │ Ephemeral ETX │ │  Audit Ring   │ │ Tier 1      │ │ Tier 2      │
      │ Secret Vault  │ │  Buffer & SIEM│ │ Kernel SB   │ │ MicroVM     │
      └───────┬───────┘ └───────┬───────┘ └──────┬──────┘ └──────┬──────┘
              │                 │                │               │
              │                 ▼                │               │
              │         [⚡ Killswitch]          │               │
              │          Triggered on Anomaly    │               │
              └─────────────── (Revoke) ◄────────┴───────────────┘
```

1. **[Airlock](https://github.com/bonjoski/airlock) — Tier 1 Kernel Sandbox Engine**
   - Native macOS Apple Seatbelt (`sandbox_init`) and Linux Landlock / Seccomp confinement.
   - Sub-15ms startup overhead—imperceptible in interactive developer workflows.
   - Built-in `agent` profile enforcing credential blacklists and pinned network allowlists.

2. **[Locksmith](https://github.com/bonjoski/locksmith) — Biometric Secret Vault & Lease Daemon**
   - Stores master keys in developer-owned hardware keyrings (macOS Keychain, Touch ID, Windows Hello).
   - Kernel-attested local UNIX socket IPC (`LOCAL_PEERPID` on Darwin, `SO_PEERCRED` on Linux) with process start-time verification to defeat PID recycling attacks.
   - Leases ephemeral credentials directly into process memory; wipes memory on exit with active zombie scavenging.

3. **[Aegisbox](https://github.com/bonjoski/aegisbox) — Tier 2 Hypervisor MicroVM Engine**
   - Hardware-assisted microVM isolation powered by Apple Virtualization Framework (macOS) and Linux KVM.
   - Ephemeral copy-on-write guest rootfs: every execution runs in a pristine sandbox that vanishes upon exit.

4. **[Argus](https://github.com/bonjoski/argus) — Non-Blocking Telemetry Bus & Active Killswitch**
   - Zero-lock ring buffer telemetry sink (<308µs overhead) ensuring the agent runtime never deadlocks or lags.
   - Normalized Common Event Format (CEF) and OpenTelemetry output.
   - Active cascading killswitch: upon tripwire breach, instantly issues `SIGKILL` to target processes and triggers emergency lease revocation in Locksmith.

---

## 🛡️ Two Isolation Tiers

Choose the appropriate boundary based on risk profile:

| Feature | Tier 1 (Airlock Kernel Confinement) | Tier 2 (Aegisbox MicroVM Confinement) |
| :--- | :--- | :--- |
| **Startup Overhead** | **< 15 ms** | **~ 100 ms** |
| **Mechanism** | Apple Seatbelt / Linux Landlock | Apple Virtualization (VZ) / Linux KVM |
| **Filesystem** | Local VFS with path restriction rules | Ephemeral copy-on-write virtual disk |
| **Kernel Sharing** | Shared host OS kernel | Isolated guest Linux microkernel |
| **Best For** | Test runners, linters, git workflows, compilers | Untrusted scripts, arbitrary npm/pip installs |
| **Invocation** | `fabrial exec --profile agent -- <cmd>` | `fabrial exec --profile agent --microvm -- <cmd>` |

---

## 🤖 Real-World Agent Integrations

### Claude Code
Run Claude Code with automated permissions without worrying about hostile prompt injections or unintended data leaks:
```bash
fabrial exec --profile agent \
  --lease-secret ANTHROPIC_API_KEY \
  -- claude --dangerously-skip-permissions
```

### Cursor & Windsurf Terminal
Configure your project's `.cursorrules` or terminal settings to wrap agent tasks through Fabrial:
```json
{
  "terminal.integrated.profiles.osx": {
    "Fabrial Sandbox": {
      "path": "fabrial",
      "args": ["exec", "--profile", "agent", "--", "zsh"]
    }
  }
}
```

### Aider & OpenCode
Allow autonomous pair-programming tools to execute tests and edits with zero ambient credential access:
```bash
fabrial exec --profile agent \
  --lease-secret OPENAI_API_KEY,GITHUB_TOKEN \
  -- aider
```

---

## 🔐 Ephemeral Secret Leases (No Raw Env Dumps)

Instead of leaving plaintext tokens in `.env` files or exporting them across your entire shell session, store them in your OS hardware keychain via Locksmith:

```bash
# 1. Store secret securely in hardware keychain
locksmith set GITHUB_TOKEN

# 2. Check out an ephemeral, time-bounded lease during execution
fabrial exec --profile agent --lease-secret GITHUB_TOKEN -- npm run release
```
Inside the sandbox, `GITHUB_TOKEN` is injected strictly into the target process environment. The moment the process exits (or if it is terminated by Argus), the lease is immediately revoked and memory zeroed.

---

## 📖 Standardized `fabrial.yaml` Policy Schema

Place a `fabrial.yaml` in your repository root to configure multi-tier routing rules. Fabrial automatically maps sensitive tools to Aegisbox Tier 2 and benign linting/formatting to Airlock Tier 1:

```yaml
version: "1"
name: "my-agent-sandbox-policy"
default_tier: 1

# Tier 1: Fast Kernel Confinement via Airlock (<15ms cold start)
tier1:
  description: "Benign linters, formatters, and inspection"
  tools:
    - eslint
    - prettier
    - gofmt
    - golangci-lint
    - black
    - ruff
    - git diff
    - git status
  patterns:
    - "*lint*"
    - "*format*"

# Tier 2: Deep Hardware Isolation via Aegisbox MicroVM (~100ms cold start)
tier2:
  description: "Sensitive tools, package managers, and arbitrary scripts"
  tools:
    - npm
    - pip
    - cargo
    - python
    - node
    - bash
    - curl
    - wget
  patterns:
    - "*install*"
    - "*.sh"
    - "*.py"
```

---

## 📖 CLI Reference

### `fabrial run` / `fabrial exec`
Executes a command inside the sovereign security runtime with dynamic multi-tier routing:

```text
Usage:
  fabrial run [flags] [--] <command> [args...]
  fabrial exec [flags] [--] <command> [args...]

Flags:
  --profile <name>         Security profile: agent (default), strict, airgap
  --tier <1|2>             Explicit execution tier override (1: Airlock, 2: Aegisbox)
  --microvm                Escalate to Tier 2 Aegisbox Hypervisor MicroVM (alias for --tier 2)
  --policy <path>, -c      Explicit path to fabrial.yaml policy file
  --lease-secret <keys>    Comma-separated list of secrets to lease via Locksmith
  --session-ticket <tk>    Autonomous agent session ticket for batch loops
  --airgap                 Block 100% of network traffic (offline mode)
  --net                    Allow unconstrained outbound network access
  --dry-run                Preview routing decision and command without executing
  -q, --quiet              Suppress routing decision banner
```

### `fabrial doctor`
Inspects system prerequisites, kernel sandbox support, resident daemons, and daemon sockets (including `~/.aegisbox/aegisboxd.sock`):

```bash
fabrial doctor [--json]
```

### `fabrial daemon`
Manages resident fabric daemons (Locksmith, Argus, Aegisbox):

```bash
fabrial daemon [status|start|stop|restart]
```

### `fabrial version`
Prints version and status of the unified security fabric.

---

## 🛡️ Invariants & Security Guarantees

1. **Zero-SaaS Self-Sovereignty**: No telemetry, tokens, or execution data ever leave your machine. Zero cloud dependencies.
2. **Fail-Closed by Design**: If peer attestation fails, if a socket permission is insecure (non-`0600`), or if microVM initialization encounters an error, execution halts immediately.
3. **Anti-PID Recycling**: Peer attestation checks verify both PID and process start-time ticks via the kernel (`LOCAL_PEERPID` / proc status), defeating PID recycling attacks.
4. **Active Scavenging**: If an agent process crashes or is killed with `SIGKILL`, Locksmith’s resident scavenger actively detects the dead PID and revokes its credentials.

---

## 📜 Name Origin
In Brandon Sanderson’s *The Stormlight Archive*, **fabrials** are scientific-magical mechanisms created by infusing gemstones with elemental stormlight to sense approaching threats, project force fields, and harness raw power cleanly and safely.

---

## 📄 License
Apache-2.0 License. See [LICENSE](LICENSE) for details.  
Copyright © 2026 Ben Skolmoski.
