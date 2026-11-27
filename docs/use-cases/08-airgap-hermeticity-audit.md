# 08. Air-Gap Hermeticity Audit (`fabrial doctor --airgap`)

> **Repository:** [`github.com/bonjoski/fabrial`](https://github.com/bonjoski/fabrial)  
> **Primary Command:** `fabrial doctor --airgap [--json]`  
> **Isolation Tier:** Kernel Network-Denied Confinement (`airlock run --airgap`)  
> **Hot-Path Overhead:** `0.00ms` (on-demand diagnostic & CI gate)

---

## 🎯 Problem Addressed

High-assurance developer workstations and sovereign AI coding environments must prove empirically—not just assume—that their local security toolchain executes **100% offline** with **zero hidden cloud telemetry, license phone-homes, or silent DNS/TCP egress attempts**.

`fabrial doctor --airgap` probes every installed local toolchain binary inside a kernel-enforced, network-denied sandbox (`airlock run --airgap`) with proxy environment variables cleared (`HTTP_PROXY=""`, `HTTPS_PROXY=""`, `ALL_PROXY=""`, `NO_PROXY="*"`, `FABRIAL_AIRGAP=1`) and verifies:
1. Every probed tool exits `0` within its strict `5s` per-probe deadline.
2. Zero outbound DNS or TCP/UDP socket attempts occur (any `EPERM` denial, dial failure, or network-error signature marks `attempted_egress: true` and fails the audit with a non-zero exit code).
3. All stdout/stderr capture is bounded at `2 MiB` per probe and hung subprocess groups are terminated cleanly via `PGID` kill.
4. Optional local pillars follow Fabrial's **3-State Optional Discovery Contract** (invisible when absent & unrequired, probed when installed, and fail-closed `exit 126` when explicitly mandated in `fabrial.yaml` and missing).

---

## 🚀 Developer Workflow

### 1. Run a Human-Readable Air-Gap Audit
```bash
fabrial doctor --airgap
```

Example output:
```text
💎 Fabrial Air-Gap Hermeticity Audit
──────────────────────────────────────────────────────────────────────────────
Confinement: 🔒 Airlock Kernel Air-Gap (/opt/homebrew/bin/airlock)
──────────────────────────────────────────────────────────────────────────────
✅ airlock      [PASS   ] (28ms) 0 egress attempts (airlock-airgap) — Airlock version 0.12.3
✅ aegisbox     [PASS   ] (31ms) 0 egress attempts (airlock-airgap) — aegisbox version 0.8.1
✅ argus        [PASS   ] (26ms) 0 egress attempts (airlock-airgap) — argus version v0.11.5
✅ bomhound     [PASS   ] (24ms) 0 egress attempts (airlock-airgap) — bomhound v0.3.0
✅ conjoiner    [PASS   ] (25ms) 0 egress attempts (airlock-airgap) — conjoiner version v0.4.2
✅ coppermind   [PASS   ] (29ms) 0 egress attempts (airlock-airgap) — coppermind version 0.9.4
✅ locksmith    [PASS   ] (27ms) 0 egress attempts (airlock-airgap) — locksmith version 3.4.0
✅ soulcaster   [PASS   ] (22ms) 0 egress attempts (airlock-airgap) — Soulcaster v0.4.1
──────────────────────────────────────────────────────────────────────────────
✅ Air-Gap Hermeticity PROVEN (8/8 probes passed, 0 outbound egress attempts).
```

### 2. Emit Structured JSON for CI Gates & Automation
```bash
fabrial doctor --airgap --json
```

```json
{
  "timestamp": "2026-11-27T21:00:00Z",
  "airlock_enforced": true,
  "airlock_binary": "/opt/homebrew/bin/airlock",
  "all_passed": true,
  "egress_detected": false,
  "probes_run": 8,
  "probes_passed": 8,
  "results": [
    {
      "tool": "airlock",
      "binary_path": "/opt/homebrew/bin/airlock",
      "offline_args": ["version"],
      "confinement": "airlock-airgap",
      "passed": true,
      "attempted_egress": false,
      "duration_ms": 28,
      "exit_code": 0,
      "detail": "0 egress attempts (airlock-airgap) — Airlock version 0.12.3"
    }
  ]
}
```

### 3. Enforce Fail-Closed Optional Pillars in `fabrial.yaml`
If your repository declares `require_halfshard: true` or `require_stormcage: true` in `fabrial.yaml` and the verified binary is absent, `fabrial doctor --airgap` fails closed immediately with **exit code `126`** and a calm Fix-Forward remediation diagnostic on `stderr`.

---

## 🛡️ Security Guarantees

| Threat | Mitigation |
| :--- | :--- |
| **Silent cloud fallback** | Every probe runs under kernel-enforced `airlock run --airgap` (`WAN=DENY`) with all proxy environment variables cleared. |
| **Swallowed dial errors (exit 0)** | Output inspection flags `dial tcp`, `dial udp`, `operation not permitted`, and DNS/network error signals even if a binary catches the error and exits `0`. |
| **Hung probe DoS** | Strict `5s` per-probe context timeout kills the entire child process group (`PGID`). |
| **Output flooding / OOM** | Per-probe stdout/stderr capture is strictly capped at `2 MiB`. |
| **Multi-agent contention ($N=8$)** | Probes are 100% read-only with bounded concurrency (`c=4`) and zero interactive biometric prompts. |
