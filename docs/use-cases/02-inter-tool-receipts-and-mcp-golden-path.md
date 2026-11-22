# Use Case 02: Inter-Tool `BLPR-v1` Receipts & Multi-IDE MCP Golden Path

> **Workflow:** Fresh workstation → wire canonical `UB-MCP-v1` servers into Antigravity, Claude Code, Cursor, and Super.Engineering → run local tools with opaque `locksmith` secret leases → cryptographically verify signed `BLPR-v1` receipts with `fabrial receipt verify`.  
> **Scope:** 100% local single-developer workstation DevEx (zero Kubernetes control plane, zero cloud SaaS telemetry, PANW Safe Harbor compliant).

---

## 🎯 The Problem

When autonomous coding agents run across parallel worktrees ($N=8$), ad-hoc JSON logs collide on file locks, hand-edited IDE MCP configs get clobbered, and raw secrets leak into LLM context windows. **Fabrial** solves all three locally:

1. **Multi-IDE Safe MCP Bootstrap (`fabrial init --mcp`):** Previews a strictly read-only diff by default, enforces `Lstat` non-symlink guards, creates `0600` `.bak.<ts>` backups, preserves your existing custom MCP servers, and atomically registers `coppermind`, `argus`, `airlock`, `aegisbox`, and `locksmith` (optionally wrapped via `mcp-conjoiner-proxy`).
2. **Lock-Free Cryptographic Provenance (`BLPR-v1`):** Every local tool writes immutable, Ed25519-signed DSSE / in-toto Statement v1 receipts under `.fabrial/receipts/<session_id>/<unix_ms>-<tool>-<id>.dsse.json` (`0600`, auto-excluded in `.git/info/exclude`), signed via Locksmith's amortized session key (`0` extra Touch ID prompts).
3. **Fail-Closed Verification (`fabrial receipt verify`):** Verifies DSSE PAE Ed25519 signatures, SPIFFE session `keyid` binding, and `os.OpenRoot` non-symlink integrity—exiting with deterministic code `10` (`EXIT_POLICY_DENY`) and a calm `FixForwardError` if any byte is tampered or symlinked.

---

## ⚡ Step-by-Step Golden Path

### 1. Install the Local Paved-Road Suite (Once)
```bash
brew tap bonjoski/tap
brew install bonjoski/tap/paved-road
```

### 2. Preview & Apply Multi-IDE MCP Wiring (`fabrial init --mcp`)
Preview all 4 supported IDE targets (**Antigravity**, **Claude Code**, **Cursor**, **Super.Engineering**) with **zero bytes written**:
```bash
# Strictly read-only dry-run diff across all targets:
fabrial init --mcp --why

# Apply to workspace-local IDE configs (.agents/mcp_config.json, .mcp.json, .cursor/mcp.json, .super.engineering/config.json):
fabrial init --mcp --apply

# Or apply globally with Conjoiner DPoP proxy wrapping when mcp-conjoiner-proxy is installed:
fabrial init --mcp --apply --global --conjoiner-wrap --target antigravity,claude,cursor
```
* Existing files are backed up to `<config>.bak.<timestamp>` (`0600`) before atomic `rename`.
* Unrelated user MCP servers and top-level IDE settings are strictly preserved.
* Symlinked config files or parent directories fail closed immediately with exit code `10`.

### 3. Start an Ambient Local Session (Zero Wrapper Hop Tax)
```bash
fabrial session begin --ttl 30m --scopes read,build,test
eval "$(fabrial session env)"
```
This exports strictly local variables (`FABRIAL_SESSION_ID`, `FABRIAL_WORKTREE_ROOT`, `FABRIAL_RECEIPT_DIR`) with zero cloud control plane variables.

### 4. Execute Tools & Inspect Local `BLPR-v1` Receipts
As `coppermind`, `argus`, `airlock`, `locksmith`, `aegisbox`, `soulcaster`, and `bomhound` run in your session, each emits a signed `BLPR-v1` DSSE receipt under `$FABRIAL_RECEIPT_DIR` (automatically added to `.git/info/exclude` so `git status` stays clean):
```bash
# Read-only structural summary of session receipts:
fabrial receipt status --why

# Machine-readable JSON for AI coding agents:
fabrial receipt status --json
```

### 5. Cryptographically Verify the Receipt Chain (`fabrial receipt verify`)
Verify all DSSE Ed25519 signatures and SPIFFE `keyid` bindings via Locksmith's local UDS socket (`~/.locksmith/locksmith.sock`) or offline with `--pubkey-b64`:
```bash
# Online local verification via Locksmith UDS session key:
fabrial receipt verify --why

# Offline verification with explicit base64 Ed25519 session public key:
fabrial receipt verify --session sess_01JDX9J00... --pubkey-b64 <base64-ed25519-pubkey> --json
```

If any receipt has a 1-byte payload tamper, swapped `keyid`, missing signature, wrong `predicateType`, or symlinked receipt path, `fabrial receipt verify` fails closed with deterministic exit code `10` and a `FixForwardError`:
```text
⚠ fabrial: BLPR-v1 receipt signature or schema verification failed (fail-closed)
  Fix:  fabrial receipt verify --why
  Why:  A receipt was unsigned, tampered, or signed with a mismatched session SPIFFE keyID. (re-run with --why for details)
```
