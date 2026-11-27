# 07. Optional Pillar Discovery & Fail-Closed Enforcement

> **Scope:** Local single-developer workstation (`fabrial.yaml` + local `PATH` binaries)  
> **Exit Code on State 3 Violation:** `126` (Fail-Closed `FixForwardError`)

---

## 🎯 Problem

Fabrial orchestrates core public security pillars (**Airlock**, **Locksmith**, **Aegisbox**, **Argus**, **Conjoiner**, **Soulcaster**, **Bomhound**) out of the box, and also integrates seamlessly with optional local pillars (**Shield** wire-guard proxy and **Stormcage** context firewall) when installed on a developer workstation.

Without deterministic 3-state discovery:
- Users who have not installed optional pillars see degraded `fabrial doctor` noise or dead `HTTP_PROXY=http://127.0.0.1:8443` session variables.
- Conversely, repositories that *rely* on optional pillars risk silently downgrading protection if a binary is removed or tampered with on `PATH`.

---

## 🔄 The 3-State Optional Discovery Contract

Fabrial evaluates `shield` and `stormcage` using a strict 3-state contract:

| State | Condition | Behavior |
| :--- | :--- | :--- |
| **State 1: Absent & Unrequired** | Binary is not on `PATH` and `fabrial.yaml` does not set `require_shield: true` / `require_stormcage: true`. | **Completely invisible.** Omitted from `fabrial doctor`, `fabrial doctor --fix`, `fabrial daemon`, `fabrial version`, `fabrial integrate`, and session proxy injection. Health status is never degraded. |
| **State 2: Installed on `PATH`** | Valid, executable, non-world-writable binary is found on a trusted absolute `PATH` (or standard local prefix). | **Auto-discovered & fully integrated.** Automatically probed by `fabrial doctor`, managed by `fabrial daemon`, wired into `fabrial session launch` / `fabrial integrate superengineering`, and displayed in CLI summaries. |
| **State 3: Required & Missing/Unhealthy** | `fabrial.yaml` explicitly sets `require_shield: true` and/or `require_stormcage: true`, and the binary is missing, unexecutable, spoofed via symlink, or its required daemon is offline. | **Fail-Closed (`exit 126`).** `fabrial doctor`, `fabrial doctor --fix`, `fabrial run`, `fabrial session begin/launch`, `fabrial daemon`, and `fabrial policy` immediately halt with a calm `FixForwardError`. |

---

## ⚙️ Configuring Fail-Closed Enforcement in `fabrial.yaml`

By default, `require_shield` and `require_stormcage` default to `false` so every existing repository remains backward compatible.

To mandate fail-closed presence in a repository's `fabrial.yaml`:

```yaml
version: "1"
name: "strict-local-workspace"
default_tier: 1

# Fail closed (exit 126) if optional local pillars are missing or tampered with:
require_shield: true
require_stormcage: true
```

---

## 🧪 Verification Recipes

### 1. Public / Default Workstation (State 1)
```bash
# Clean health check with zero optional-pillar noise
fabrial doctor

# Ambient session starts without dead HTTP_PROXY injection
fabrial session begin --ttl 30m
eval $(fabrial session env)
```

### 2. Local Workstation with Optional Pillars Installed (State 2)
```bash
# Automatically discovers installed binaries on trusted PATH
fabrial doctor
fabrial daemon status
fabrial integrate superengineering .
```

### 3. Fail-Closed Enforcement Check (State 3)
```bash
# With require_shield: true in fabrial.yaml and shield absent from PATH:
fabrial doctor
# ⚠ fabrial: Required pillar Shield (shield) not found on PATH while require_shield: true is set
#   Fix:  Install shield on a trusted PATH directory or set require_shield: false in fabrial.yaml
#   Why:  fabrial.yaml requires Shield (require_shield: true), so Fabrial fails closed instead of silently downgrading protection.
echo $? # 126
```

---

## 🛡️ 3-Layer Binary Provenance & Anti-Spoofing Verification

Fabrial **never executes** an untrusted binary (e.g., `shield --version`) to identify it, and never relies on filename alone:

1. **Layer 1 — Zero-Execution Go `debug/buildinfo` Identity:** Reads embedded Mach-O/ELF Go module metadata directly from disk (`<0.4ms`) and asserts exact `Main.Path` + package path match (`github.com/bonjoski/shield`, `github.com/bonjoski/stormcage`, `airlock`, `aegisbox`, `argus`, `locksmith`, `conjoiner`, `soulcaster`, `bomhound`, `coppermind`, `stoneward`). Shell scripts (`#!/bin/sh`) and unrelated third-party binaries named `shield` are rejected without executing a single byte.
2. **Layer 2 — Filesystem, UID & Canonical Path Hygiene:**
   - Searches trusted Homebrew/system prefixes (`/opt/homebrew/bin`, `/usr/local/bin`) **before** mutable `PATH` entries
   - Rejects relative `PATH` entries (`.`, `./bin`), non-executable files (`0644`), setuid/setgid traps, directories, and world-writable binaries (`0777`) **or** world-writable parent directories on both regular files and symlink targets
   - Enforces Unix UID ownership (`euid` or `root`) on both binary and parent directory
   - Rejects dangling symlinks and mismatched symlink basenames (`ln -s /bin/sh shield`), while resolving legitimate Homebrew Cellar symlinks to their canonical `EvalSymlinks` path to close symlink-swap TOCTOU
3. **Layer 3 — Cryptographic SHA-256 Digest Pinning (`fabrial trust`):** Defeats active adversaries compiling forged Go binaries claiming our module path:

```bash
# Pin the verified local binary's SHA-256 into ~/.fabrial/trusted-pillars.json (0600)
fabrial trust pillar shield
fabrial trust pillar stormcage
fabrial trust list
```

You can also enforce strict pinning or pin digests directly in `fabrial.yaml`:

```yaml
version: "1"
require_shield: true
strict_pillar_pinning: true
pillar_digests:
  shield: "<64-char-lowercase-sha256>"
```

If any pinned binary's on-disk SHA-256 mismatches (or conflicts between `fabrial.yaml` and `~/.fabrial/trusted-pillars.json`), Fabrial **fails closed (`exit 126`, `FABRIAL_PILLAR_DIGEST_MISMATCH`)** regardless of whether `require_shield` is `true` or `false`.
