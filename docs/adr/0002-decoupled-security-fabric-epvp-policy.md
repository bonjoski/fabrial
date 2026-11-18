# ADR-0002: Decoupled Security Fabric & Delegated Policy Architecture (EPVP)

- **Status:** Accepted
- **Date:** 2026-11-16
- **Component:** `pkg/policy`, `cmd/fabrial`
- **Deciders:** Lead Systems Architect & Platform Engineer

---

## 1. Context & Problem Statement

Maintaining hardcoded Go policy structs for every downstream tool (`airlock`, `locksmith`, `argus`, `conjoiner`) inside Fabrial created high coupling:
- Adding a feature or flag to one tool required patching and releasing Fabrial.
- Monolithic policy files broke independent tool development.

---

## 2. Decision Outcome

We introduced the **Ecosystem Policy Validation Protocol (EPVP)**:

1. **Project Policy Manifest Specification (PPMS v1):**
   - Declarative `fabrial.yaml` containing independent tool policy blocks (`airlock:`, `locksmith:`, `conjoiner:`).
2. **Delegated Subcommand Validation (`<tool> policy validate --stdin`):**
   - Fabrial decouples validation by invoking each tool's native policy validator over stdin.
3. **Build-Time Schema Compilation & Cache:**
   - Schemas are verified at session startup or in `fabrial doctor` with SHA-256 indexed validation caching, eliminating redundant runtime checks.

---

## 3. Consequences

- **Positive:** Tools evolve independently; zero hardcoded struct coupling in Fabrial core.
- **Negative:** Downstream tools must implement the EPVP `policy validate --stdin` protocol contract.
