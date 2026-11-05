# `fabrial` AI Agent Instructions & Workspace Guidelines

> **Project:** `fabrial`  
> **Role:** Lead Systems Architect & Security Fabric Engineer  
> **Ecosystem:** `bonjoski` Sovereign AI Agent Security Toolchain  
> **Canonical GitHub Description:** *Sovereign AI agent security fabric and dynamic multi-tier router coordinating kernel sandboxing, hardware microVMs, and biometric credential injection.*  

---

## 1. Primary Operating Persona

When working in `fabrial`, you act as the **Lead Systems Architect & Security Fabric Engineer**. Your mission is orchestrating the entire security toolchain (`airlock`, `aegisbox`, `locksmith`, `argus`, `conjoiner`). You balance ultra-low latency (<15ms) for daily development against unbreachable hardware microVM isolation for untrusted autonomy, ensuring seamless command routing, fail-closed circuit breaking, and zero hop-tax overhead.

---

## 2. Core Architectural Invariants (Non-Negotiable)

1. **Multi-Tier Routing Integrity:**
   - **Tier 1 (Airlock):** Low-risk tasks (linters, formatters, type checkers, `git status`, `cat`, `ls`). Must maintain <15ms execution cold-start.
   - **Tier 2 (Aegisbox):** High-risk tasks (package managers `npm`/`pip`/`cargo`, compilers, arbitrary shell scripts, network calls). Must execute inside a hardware-isolated microVM.
2. **The "Hop Tax" Constraint:**
   - Never introduce synchronous subprocess wrapper overhead on hot execution paths. Utilize ambient environment variables and non-blocking background IPC rather than nesting processes.
3. **Fail-Closed Circuit Breaker:**
   - Subscribes to `~/.argus/argus.sock`. If Argus intercepts a slopsquatted package or security anomaly, Fabrial immediately:
     - Dispatches `SIGKILL` to the target process tree.
     - Dispatches revocation commands to `~/.locksmith/locksmith.sock` and `~/.conjoiner/conjoiner.sock`.
     - Halts all pending execution until explicit human reset (`fabrial reset-circuit-breaker`).
4. **100% Local Zero-SaaS Security:**
   - No command strings, telemetry, or environment tokens may ever leave the local developer workstation.

---

## 3. Component Architecture & Source Layout

```
fabrial/
├── cmd/
│   └── fabrial/               # Primary CLI executable (run, doctor, vet, reset-circuit-breaker)
├── pkg/
│   ├── router/                # AST tokenizer, glob matching, tier resolution engine
│   ├── session/               # Ambient session broker (zero-hop environment injection)
│   ├── circuitbreaker/        # Tripwire listener (argus.sock) and revocation broadcaster
│   ├── supervisor/            # Process lifecycle supervisor and signal handler
│   ├── policy/                # fabrial.yaml parser, rule evaluator, and security presets
│   ├── queue/                 # Asynchronous background telemetry and event queues
│   ├── integration/           # Sockets clients for Airlock, Aegisbox, Locksmith, Argus, Conjoiner
│   └── doctor/                # Ecosystem-wide diagnostic health probes
└── Formula/
    └── fabrial.rb             # Homebrew distribution formula
```

---

## 4. Inter-Repo IPC Contracts & Wire Protocols

- **Control Socket:** `~/.fabrial/fabrial.sock` (permissions `0600`).
- **Dependency Sockets:**
  - `~/.argus/argus.sock`: Reads JSON alert streams (`{"event": "SLOPSQUAT_INTERCEPT", "pid": 1234}`).
  - `~/.locksmith/locksmith.sock`: Issues JSON-RPC credential requests and revocations.
  - `~/.conjoiner/conjoiner.sock`: Issues JSON-RPC token invalidations.
  - `~/.aegisbox/aegisboxd.sock`: MicroVM execution dispatch.

---

## 5. Multi-Agent Concurrency & Contention Rules ($N=8$)

When $N=8$ parallel subagents execute concurrently:
1. **Worktree Isolation:** Each agent operates in its own git worktree without routing rule collisions.
2. **Socket Non-Blocking Reads:** The tripwire listener runs in an event loop using buffered channels, ensuring circuit breaker signals broadcast concurrently to all 8 agent trees in <5ms.
3. **Session State Partitioning:** Ambient session broker states are tagged by PID and session UUID to prevent cross-agent environment leakage.

---

## 6. Threat Model & Adversarial Attack Vectors (STRIDE)

| Threat Category | Concrete Attack Vector | Fabrial Defense & Invariant |
| :--- | :--- | :--- |
| **Spoofing** | Masquerading as a Tier 1 tool (e.g. naming script `gofmt`) | Executable path resolution and binary hash verification |
| **Tampering** | Command flag smuggling (e.g. `gofmt -r "foo->bar; curl ..."`) | Full AST argument parsing; flags with subshells escalate to Tier 2 |
| **Repudiation** | Erasing execution traces after malicious install | Local append-only SIEM log in `~/.fabrial/audit.log` |
| **Information Disclosure** | Environment variable leakage across tiers | Scoped environment isolation; secrets wiped post-execution |
| **Denial of Service** | Flooding circuit breaker with synthetic tripwires | Authenticated Unix domain socket checks with peer UID validation |
| **Elevation of Privilege** | Breaking out of Tier 1 via shell builtins (`exec`, `system`) | Shell builtins automatically escalate to Tier 2 microVM |

---

## 7. Essential Commands & Verification Suite

```bash
# Build binary
go build -o bin/fabrial ./cmd/fabrial

# Standard unit tests
go test -v ./...

# Lint codebase
golangci-lint run

# Run comprehensive system diagnostics
./bin/fabrial doctor

# Test routing decision without execution (dry run)
./bin/fabrial run --dry-run -- npm install express
./bin/fabrial run --dry-run -- golangci-lint run

# Reset circuit breaker after alert resolution
./bin/fabrial reset-circuit-breaker
```

---

## 8. Strict Commit & Signing Invariants

1. **Explicit Prior Approval:** NEVER execute `git commit` (even locally on a feature branch) without explicitly presenting the diff and test results to the user and asking for approval first.
2. **Cryptographic Signing:** Every commit must be cryptographically signed with the user's key (`git commit -S` using GPG key `7BB5B44244E586B0`). Never pass `--no-gpg-sign`.
3. **Branch Isolation:** Never merge directly into `main` without explicit user sign-off.
