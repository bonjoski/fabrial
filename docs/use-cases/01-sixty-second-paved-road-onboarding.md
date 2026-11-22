# Use Case 01: 60-Second Zero-Config Paved-Road Onboarding

> **Workflow:** Fresh repository → protected secrets + sandboxed package installs + safe AI coding in under 60 seconds with **zero YAML written**.  
> **Scope:** 100% local single-developer workstation DevEx (zero cloud control plane, zero SaaS telemetry).

---

## 🎯 The Problem

Most developers skip security setup because it feels like a tollbooth: ten separate config files, cryptic `EPERM` failures, and slow wrapper tax. With **UB-CLI-v2**, the secure path is faster than copy-pasting `.env` files or gambling on hallucinated packages.

---

## ⚡ 60-Second Walkthrough

### 1. Install the Local Toolchain (Once)
```bash
# Single-command paved-road meta-formula:
brew tap bonjoski/tap
brew install bonjoski/tap/paved-road

# Or via Brewfile bundle:
brew bundle --file=/path/to/homebrew-tap/Brewfile.paved-road
```

### 2. Inspect Your Repository with Zero Config (`fabrial init`)
Run `fabrial init` inside any Go, Node, Python, or Rust repo. It is **strictly read-only** (writes zero YAML files and never touches `~/.zshrc`), auto-detects your stack and AI SDKs (`openai`, `@anthropic-ai/sdk`, `@google/genai`, `langchain`, `langgraph`, `@modelcontextprotocol/sdk`, `mcp`), and gives you one copy-pasteable next step:

```bash
fabrial init
```
```text
✓ fabrial: detected go, node (AI SDKs: openai, @modelcontextprotocol/sdk); 7/7 local tools ready (0 YAML written)
  Next: locksmith migrate .env
  Why:  Plaintext .env detected; moving secrets to Touch ID keychain protects them from git and AI agents. (re-run with --why for details)
```

Want the full breakdown (manifests inspected, safety capsules, and local boundaries)? Pass `--why`:
```bash
fabrial init --why
```

Running inside an autonomous coding agent (Claude Code, Cursor, Antigravity)? Pass `--json` for deterministic single-line JSON:
```bash
fabrial init --json
```

### 3. Move `.env` Secrets Out of Plaintext Disk (`locksmith migrate .env`)
```bash
locksmith migrate .env
```
```text
✓ locksmith: imported 6 secrets from .env into Touch ID keychain (project/my-app) and shredded .env
  Next: locksmith run --project my-app -- npm run dev
  Why:  Secrets now live in hardware memory instead of plaintext disk where git or AI agents can read them.
```
* Acquires a single amortized session write.
* Rejects symlinked `.env` targets fail-closed via `os.OpenRoot` + `Lstat`.
* Appends `.env` and `.env.*` (preserving `!.env.example`) to `.gitignore`.
* Overwrites `.env` bytes in place with zeros, calls `Sync()`, and unlinks `.env`.

### 4. Spellcheck AI-Suggested Packages Before Installing (`argus`)
If an LLM suggests a plausible-sounding typo or hallucination:
```bash
argus explain reqeusts --ecosystem pypi
```
```text
⚠ argus: 'reqeusts' looks like a typo or slopsquat of 'requests'
  Fix:  pip install requests
  Why:  Typosquatted packages often hide install hooks that exfiltrate credentials. (re-run with --why or `argus explain argus_slopsquat_suspect` for details)
```

### 5. Run Tests & AI Agents Safely (`fabrial run`)
```bash
fabrial run -- npm test
```
* Benign linters & unit tests stay in Tier 1 (**Airlock**, <15ms kernel confinement).
* Package managers & untrusted scripts automatically escalate to Tier 2 (**Aegisbox**, hardware microVM).

### 6. Run the Local PR Gate Dry-Run Before Pushing (`fabrial check --diff`)
Mirror the RFC-2026-11-22-48 diff-only PR gate locally inside any git worktree with **zero shared lock files**, **zero Touch ID prompts**, and **strictly proven findings only**:
```bash
# Diff-only local check (argus vet --diff + soulcaster verify-patch)
fabrial check --diff

# Include loopback-only AI safety probes against your local dev server
fabrial check --diff --ai-target http://127.0.0.1:8080 --why

# Single-line machine JSON for autonomous coding agents
fabrial check --diff --json
```
* Missing optional tools degrade gracefully with a copy-pasteable `brew install bonjoski/tap/<tool>` Fix-Forward hint.
* Non-loopback `--ai-target` URLs are rejected fail-closed so local probes never hit remote or cloud metadata endpoints.
* Safe to run across $N=8$ parallel worktrees simultaneously with 10s bounded per-check timeouts.

---

## 🧠 Progressive Disclosure (`--why` & `explain`)

Every UB-CLI-v2 command keeps default output to **≤3 calm lines**:
1. What paused (or succeeded)
2. A validated, copy-pasteable `Fix:` / `Next:` command
3. A 1-line `Why:` micro-lesson

Whenever you want the deeper threat model, CWE/OWASP mapping, or sandbox boundary proof, add `--why` or run:
```bash
fabrial explain init
fabrial explain check
fabrial explain sandbox
fabrial explain secrets
```
