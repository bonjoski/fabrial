// Command fabrial-top is the decoupled, zero-hop-tax local multi-agent workstation
// mission control TUI companion binary for Fabrial (RFC-2026-11-25-63).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bonjoski/fabrial/pkg/topui"
	"github.com/bonjoski/fabrial/pkg/version"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fabrial-top", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		dir         = fs.String("dir", ".", "Target workspace directory for git worktree & receipt inspection")
		snapshot    = fs.Bool("snapshot", false, "Collect one bounded snapshot and exit (non-interactive)")
		once        = fs.Bool("once", false, "Alias for --snapshot")
		asJSON      = fs.Bool("json", false, "Emit sanitized WorkstationSnapshot as JSON (implies --once)")
		interval    = fs.Duration("interval", 2*time.Second, "Background TUI refresh interval (min 500ms)")
		timeout     = fs.Duration("timeout", topui.DefaultProviderTimeout, "Per-provider poll timeout (max 5s)")
		skipDoctor  = fs.Bool("no-doctor", false, "Skip fabrial doctor pillar probes for ultra-fast snapshots")
		showWhy     = fs.Bool("why", false, "Show progressive-disclosure architecture rationale and threat model")
		showVersion = fs.Bool("version", false, "Print fabrial-top version")
		shortVer    = fs.Bool("v", false, "Print fabrial-top version")
	)

	fs.Usage = func() {
		_, _ = fmt.Fprintf(stderr, `fabrial-top — Local Multi-Agent Workstation Mission Control TUI (RFC-2026-11-25-63)

Usage:
  fabrial-top [--dir <path>] [--interval 2s] [--timeout 500ms]
  fabrial-top --snapshot [--json] [--dir <path>]
  fabrial-top --why | --version

Keybindings (interactive TUI):
  Tab / 1-4   Switch panes (Worktrees & Sessions, Coppermind Inbox, Traces & Checkpoints, Health)
  Up / Down   Move selection cursor (also p / n)
  k           Scoped terminate of selected session (y/N modal + kernel PID StartTime verification)
  l           Copy/show safe Coppermind lens triage command for selected ticket
  r           Hand off TTY to tinmind/flightdeck replay --safe-ansi <trace>
  w / W       Hand off TTY to oathgate diff / rewind (y/N confirmed)
  f           Run scoped fabrial doctor --fix
  Space / R   Pause polling / Force immediate refresh
  ? / q       Toggle --why drawer / Quit cleanly

Flags:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	if *showVersion || *shortVer {
		_, _ = fmt.Fprintf(stdout, "fabrial-top %s (commit %s)\n", version.Version, version.Commit)
		return 0
	}

	if *showWhy {
		_, _ = fmt.Fprintln(stdout, `fabrial-top — Why a Decoupled Companion TUI?
  • 0.00ms Hop Tax: compiled as a separate binary (cmd/fabrial-top) never imported by cmd/fabrial.
  • N=8 Concurrency Safe: SQLite WAL databases (Coppermind, Oathgate) opened strictly ?mode=ro; Locksmith queried via read-only list_leases (0 Touch ID prompts).
  • Fail-Closed Local Security: strips ANSI/OSC-52/Bidi escapes, redacts secret patterns, verifies Lstat+SO_PEERCRED ownership, and re-verifies kernel (PID, StartTime) before signaling.
  • 100% Local Safe Harbor: zero network listeners, zero cloud backends, zero fleet telemetry.`)
		return 0
	}

	t := *timeout
	if t <= 0 {
		t = topui.DefaultProviderTimeout
	}
	if t > 5*time.Second {
		t = 5 * time.Second
	}

	cfg := topui.DefaultCollectorConfig(*dir)
	cfg.ProviderTimeout = t
	cfg.SkipDoctor = *skipDoctor

	collector := topui.NewCollector(cfg)

	if *snapshot || *once || *asJSON {
		ctx, cancel := context.WithTimeout(context.Background(), t+1500*time.Millisecond)
		defer cancel()
		snap := collector.Collect(ctx)
		if *asJSON {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(snap); err != nil {
				_, _ = fmt.Fprintf(stderr, "fabrial-top: encode json: %v\n", err)
				return 1
			}
			return 0
		}
		renderPlainSnapshot(stdout, snap)
		return 0
	}

	actions := topui.NewLocalActionRunner(cfg.SessionsFile, cfg.Workdir)
	model := topui.NewModel(collector, actions, *interval)
	prog := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := prog.Run(); err != nil {
		_, _ = fmt.Fprintf(stderr, "fabrial-top: %v\n", err)
		return 1
	}
	return 0
}

func renderPlainSnapshot(w io.Writer, snap topui.WorkstationSnapshot) {
	_, _ = fmt.Fprintf(w, "fabrial-top v%s snapshot (%dms) — %s\n", version.Version, snap.PollMs, snap.Workdir)
	_, _ = fmt.Fprintf(w, "Worktrees: %d | Sessions: %d | Leases: %d | Inbox: %d (Open High Obs: %d) | Traces: %d | Checkpoints: %d | Pillars: %d\n",
		len(snap.Worktrees), len(snap.Sessions), len(snap.Leases),
		len(snap.Inbox), snap.OpenHighObs, len(snap.Traces), len(snap.Checkpoints), len(snap.Health))
	for _, p := range snap.Providers {
		_, _ = fmt.Fprintf(w, "  %-22s [%-7s] %3dms  %s\n", p.Name, p.State, p.LatencyMs, p.Detail)
	}
}
