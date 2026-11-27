# 09. Local Multi-Agent Mission Control TUI (`fabrial-top`)

> **Classification:** End-User Developer Recipe (`RFC-2026-11-25-63`)  
> **Binaries:** `fabrial-top` (or `fabrial top` zero-wrapper `exec` passthrough)  
> **Hot-Path Hop Tax:** `0.00ms` (decoupled binary never imported by `cmd/fabrial`)  
> **Network Footprint:** Zero network listeners, zero cloud telemetry (100% Local Safe Harbor)

---

## 🎯 The Developer Problem

When running up to $N=8$ parallel autonomous coding agents across separate git worktrees, critical local workstation state is spread across six independent tools:

1. **Git Worktrees** — Which branches are active and how many uncommitted files exist per worktree?
2. **Fabrial Sessions & Receipts** — Which ambient master/child sessions are active, what scopes do they hold, and how many `BLPR-v1` receipts have been recorded?
3. **Locksmith Leases** — How much TTL remains on ephemeral secret leases before an agent session expires *(without triggering Touch ID or reading secret values)*?
4. **Coppermind Pending Lens Inbox** — Are unreviewed `red-team` or `security-architect` commit-lens tickets or open high/critical observations waiting?
5. **Tinmind / Flightdeck Traces & Oathgate Checkpoints** — Which recent agent runs hit non-zero exits or findings, and what CoW snapshots are ready for instant `diff` or `rewind`?
6. **Doctor Pillar Health** — Are all installed security pillars healthy, or does a local socket need `fabrial doctor --fix`?

---

## ⚡ Quick Recipes

### 1. Launch Interactive 4-Pane Mission Control
```bash
# Direct companion binary
fabrial-top

# Or via fabrial exec passthrough (zero parent wrapper process)
fabrial top

# Inspect a specific repository root with a custom 3s poll cadence
fabrial-top --dir ~/code/my-project --interval 3s
```

### 2. Headless Single-Shot Snapshot (Scripting / CI / Agent Checks)
```bash
# Human-readable one-shot summary
fabrial-top --snapshot

# Machine-readable sanitized JSON snapshot (zero ANSI, zero secrets)
fabrial-top --snapshot --json --dir .
```

### 3. Progressive Disclosure Rationale
```bash
fabrial-top --why
```

---

## ⌨️ Keyboard Controls

| Key | Pane | Action |
| :--- | :--- | :--- |
| `Tab` / `Shift+Tab` / `1`–`4` | All | Switch between `[1] Worktrees & Sessions`, `[2] Coppermind Inbox`, `[3] Traces & Checkpoints`, `[4] Doctor Health` |
| `↑` / `↓` (or `p` / `n`) | All | Move selection cursor within the active pane |
| `k` | `[1] Sessions` | Open explicit `y/N` confirmation modal to terminate **only** the selected session after kernel `(PID, StartTime)` re-verification |
| `l` | `[2] Inbox` | Copy/display the validated, shell-safe `coppermind` lens triage command for the selected ticket |
| `t` | `[3] Traces/Snaps` | Toggle selection focus between Tinmind/Flightdeck traces and Oathgate checkpoints |
| `r` | `[3] Traces` | Hand TTY cleanly (`tea.ExecProcess`) to `tinmind replay --safe-ansi <trace_id>` (with `flightdeck` fallback) |
| `w` / `W` | `[3] Checkpoints` | Hand TTY cleanly to `oathgate diff <id>` (`w`) or `y/N`-confirmed `oathgate rewind <id>` (`W`) |
| `f` | `[4] Health` | Run scoped `fabrial doctor --fix` (or `fabrial fix <pillar>`) and return to the TUI |
| `Space` | All | Pause / resume background `2s` polling |
| `R` | All | Force immediate refresh |
| `?` / `h` | All | Toggle `--why` architecture & threat-model drawer |
| `q` / `Ctrl+C` | All | Quit cleanly restoring terminal state |

---

## 🛡️ Security & Multi-Agent Concurrency Guarantees

- **Zero Hop Tax on `fabrial`:** `cmd/fabrial` is strictly verified in CI (`TestFabrialBinaryZeroTUIDependency`) to never import `pkg/topui`, Bubble Tea, Lip Gloss, or `modernc.org/sqlite`.
- **Zero Lock Contention Under $N=8$ Parallel Writers:** Coppermind and Oathgate SQLite WAL databases are opened strictly in read-only mode (`?mode=ro&_busy_timeout=200`).
- **Zero Touch ID Stalls & Zero Secret Disclosure:** Queries Locksmith solely via the read-only `list_leases` IPC action. `LeaseMetaStatus` physically lacks any `Value` or `Secret` field, `sessions.json` strips `MasterToken` and raw `Environment` maps, and all strings pass through `RedactSecrets`.
- **Hostile Terminal & Repo Input Defense:** Every string entering `WorkstationSnapshot` is scrubbed by `SanitizeTUIString` (stripping ANSI CSI/OSC-52/DCS/C1 escapes, Unicode Bidi overrides, Unicode Tag cloaking, and forged newlines); read-only `git` calls disable `core.fsmonitor` and `core.hooksPath`.
- **Fail-Closed Path & PID Guards:** Refuses symlinked or foreign-UID sockets/DBs (`Lstat` + `SO_PEERCRED`/`LOCAL_PEERCRED`), caps directory scans at `50` newest entries with a `500ms` per-provider timeout + automatic backoff badge, and re-verifies kernel `(PID, ProcessStartTime)` via `pkg/procident` immediately before `SIGKILL`.

---

## 📋 Prerequisites & Expected Verification Output

- **Prerequisites:** `fabrial` and `fabrial-top` installed via `brew install bonjoski/tap/fabrial` (or `make build`). Optional local tools (`coppermind`, `oathgate`, `tinmind`, `locksmith`) degrade calmly to `OFFLINE` when not installed.
- **Verification:**
```bash
fabrial-top --snapshot --dir .
# fabrial-top v0.7.8 snapshot (42ms) — .
# Worktrees: 1 | Sessions: 4 | Leases: 0 | Inbox: 10 (Open High Obs: 0) | Traces: 1 | Checkpoints: 0 | Pillars: 9
```

---

## 🔧 Troubleshooting

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| `fabrial top` exits `127` | Companion binary `fabrial-top` not on `PATH` | Run `brew upgrade bonjoski/tap/fabrial` (or `make build`) |
| Provider shows `[BACKOFF]` | Local daemon socket timed out 3 consecutive times | Press `f` to run `fabrial doctor --fix`, then `R` to force refresh |
| Provider shows `[ERROR]` symlink/UID | Symlink or foreign-UID file planted at `~/.fabrial`, `~/.coppermind`, or `~/.oathgate` | Inspect path with `ls -la`, remove untrusted symlink, and restore `0700`/`0600` ownership |
