# Claude Code Guidelines for `fabrial`

> **Authoritative Ecosystem Runbook:** [`spanreed/docs/knowledge-base/01-fabrial.md`](file:///Users/benskolmoski/code/spanreed/docs/knowledge-base/01-fabrial.md)

## Build & Test Commands
- **Build Binary:** `go build -o bin/fabrial ./cmd/fabrial`
- **Unit Tests:** `go test -v ./...`
- **Linter:** `golangci-lint run`
- **Diagnostics:** `./bin/fabrial doctor`
- **Routing Dry Run:** `./bin/fabrial run --dry-run -- <cmd>`

## Code Style & Architectural Invariants
- Dynamic multi-tier routing: Tier 1 (<15ms Airlock) vs Tier 2 (Aegisbox microVM).
- Zero hop tax on hot paths: use ambient session broker environment variables rather than wrapping processes.
- Fail closed: on tripwire breach (`argus.sock`), immediately SIGKILL target process tree and revoke credentials over `locksmith.sock` and `conjoiner.sock`.
- 100% local zero-SaaS execution: no telemetry leaves the workstation.

## Commit Invariants
- Mandatory cryptographic signing with GPG key `7BB5B44244E586B0` (`git commit -S`).
- Present diff and test output for explicit user sign-off before committing.
