# Fabrial Cockpit (Desktop Companion)

`fabrial-cockpit` is the standalone, decoupled desktop companion and system tray cockpit for the **Fabrial Sovereign AI Agent Security Fabric**.

## Architecture & Guarantees

* **Zero CLI Latency Impact:** Fabrial's sub-15ms cold start for Tier 1 kernel confinement is completely isolated from GUI webview overhead. The cockpit runs as an optional external process communicating via local IPC.
* **Dual IPC Interface:**
  * Unix Domain Socket: `~/.fabrial/fabrial.sock` (mode `0600`)
  * Local HTTP API: `http://127.0.0.1:9191` (protected against DNS rebinding and cross-origin attacks)
* **Single Pane of Glass:**
  * **10-Pillar Matrix:** Live real-time inspection of Airlock, Locksmith, Aegisbox, Argus, Shield, Conjoiner, Stormcage, Soulcaster, Bomhound, and Spanreed.
  * **Daemon Switchboard:** One-click start/stop/restart for Locksmith, Argus, Aegisbox, Shield, and Stormcage.
  * **SIEM Telemetry:** Live SSE stream for circuit breaker trips and active secret leases.

## Development

```bash
# In apps/cockpit:
npm install
npm run dev

# Or build native desktop bundle via Tauri:
npm run tauri build
```
