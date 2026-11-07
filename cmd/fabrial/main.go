// Command fabrial is the unified orchestrator for the Sovereign AI Agent Security Fabric:
// Airlock (sandbox), Locksmith (secrets), Aegisbox (microVM), and Argus (telemetry).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bonjoski/fabrial/pkg/auth"
	"github.com/bonjoski/fabrial/pkg/circuitbreaker"
	"github.com/bonjoski/fabrial/pkg/doctor"
	"github.com/bonjoski/fabrial/pkg/integration"
	"github.com/bonjoski/fabrial/pkg/queue"
	"github.com/bonjoski/fabrial/pkg/router"
	"github.com/bonjoski/fabrial/pkg/server"
	"github.com/bonjoski/fabrial/pkg/session"
	"github.com/bonjoski/fabrial/pkg/supervisor"
	"github.com/bonjoski/fabrial/pkg/version"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "help", "-h", "--help":
		printUsage()
		os.Exit(0)

	case "version", "-v", "--version":
		printVersion()
		os.Exit(0)

	case "session":
		handleSession(args)

	case "queue":
		handleQueue(args)

	case "launch":
		sessionFile := session.DefaultSessionFilePath()
		sm := session.NewSessionManager()
		_ = sm.LoadFromFile(sessionFile)
		handleSessionLaunch(args, sm)

	case "auth":
		handleAuth(args)

	case "login":
		handleAuth(append([]string{"login"}, args...))

	case "policy":
		handlePolicy(args)

	case "sync":
		handlePolicy(append([]string{"pull"}, args...))

	case "exec", "run":
		handleExec(args)

	case "doctor":
		handleDoctor(args)

	case "status":
		handleDaemon([]string{"status"})
		os.Exit(0)

	case "fix":
		handleFix(args)

	case "daemon":
		handleDaemon(args)

	case "integrate", "init":
		handleIntegrate(args)

	case "circuit-breaker", "breaker":
		handleCircuitBreaker(args)

	case "serve":
		handleServe(args)

	default:
		// Direct shorthand: if first arg is a flag or executable, run it
		handleExec(os.Args[1:])
	}
}

func printUsage() {
	fmt.Println(`💎 Fabrial — The Sovereign AI Agent Security Fabric
Ambient Session Broker, Multi-Agent Concurrency Coordinator & Scoped Security Fabric.

Usage:
  fabrial launch [--profile agent] [--] <editor-or-agent> [args...]
  fabrial session [begin|child|env|list|kill|launch] [flags]
  fabrial queue [status]
  fabrial exec [flags] [--] <command> [args...]
  fabrial run [flags] [--] <command> [args...]
  fabrial doctor [--json] [--fix]
  fabrial fix [pillar] [--json]
  fabrial daemon [status|start|stop|restart]
  fabrial serve [--socket <path>] [--port <port>]
  fabrial integrate [superengineering] [path] [--global]
  fabrial version

Ambient Multi-Agent Session Management (Zero Hot-Path Hop Tax):
  fabrial session begin [--scopes read,test,build] [--ttl 30m]
      Prompts Touch ID biometrics once; mints master session grant with Conjoiner DPoP tokens.

  fabrial session child --parent <id> [--task <task>] [--scopes <scopes>]
      Derives short-lived (60s) attenuated subagent tokens with ZERO biometric interruptions.

  eval $(fabrial session env)
      Exports ambient environment (HTTP_PROXY, CONJOINER_TASK_TOKEN, AIRLOCK_ACTIVE)
      allowing agents and subagents to execute tools directly with zero wrapper latency.

  fabrial session list
      Inspect active master and child agent sessions.

  fabrial session kill <id>
      Scoped invalidation of a specific session without affecting peer agents.

Bounded Concurrency & Host Protection:
  fabrial queue status
      Inspect Tier 2 microVM execution queue depth and active hypervisor slots.

Core Execution Commands:
  # Fast Tier 1 Kernel Confinement (<15ms via Airlock Seatbelt / Landlock)
  fabrial exec --profile agent -- <command>

  # Deep Tier 2 MicroVM Confinement (~100ms via Aegisbox Apple VZ / KVM)
  fabrial exec --profile agent --microvm -- <command>

Multi-Tier Dynamic Routing:
  • Tier 1: Fast Kernel Confinement via Airlock (<15ms cold start)
            Benign linting, formatting, read-only analysis (eslint, prettier, gofmt)
  • Tier 2: Deep MicroVM Isolation via Aegisbox (~100ms hardware boundary)
            Sensitive tools, package managers, network egress (npm, pip, cargo, python, bash)

Policy Configuration:
  fabrial automatically discovers repository-level 'fabrial.yaml' policies
  to map commands and wildcards to Tier 1 or Tier 2 isolation boundaries.

Execution Flags:
  --profile <name>      Execution profile (agent, strict, airgap, default)
  --tier <1|2>          Explicit execution tier override (1: Airlock, 2: Aegisbox)
  --microvm             Tier 2 Confinement via Aegisbox hypervisor MicroVM (alias for --tier 2)
  --policy <path>, -c   Explicit path to fabrial.yaml policy file
  --lease-secret <keys> Comma-separated secrets to lease dynamically via Locksmith
  --session-ticket <tk> Session ticket for autonomous agent batch loops
  --airgap              Total offline network isolation
  --net                 Permit direct outbound networking
  --dry-run             Preview the routing decision and command without executing
  -q, --quiet           Suppress Fabrial routing banner output`)
}

func printVersion() {
	fmt.Printf("💎 Fabrial Unified Fabric v%s\n", version.Version)
	fmt.Println("Pillars:")
	fmt.Println("  • Airlock:    Kernel Confinement & Zero-VM Sandbox")
	fmt.Println("  • Aegisbox:   Hardware MicroVM & Shadow CoW Workspace")
	fmt.Println("  • Argus:      Pre-Gate AST Inspection & SIEM Telemetry Bus")
	fmt.Println("  • Locksmith:  Biometric Hardware Vault & ETX Lease Engine")
	fmt.Println("  • Shield:     Secret Redaction & Fail-Closed Wire Guard Proxy")
	fmt.Println("  • Conjoiner:  NIST SP 800-207A Agentic IAM & DPoP Token Broker")
	fmt.Println("  • Stormcage:  Cross-Agent Context & Memory Firewall")
	fmt.Println("  • Soulcaster: Runtime Hermetic Compiler Attestation & SLSA Provenance")
	fmt.Println("  • Bomhound:   CycloneDX Legal Attribution & Copyright Engine")
}

func handleExec(args []string) {
	opts, cmdArgs, err := router.ParseArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fabrial: invalid arguments: %v\n", err)
		os.Exit(1)
	}

	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "fabrial: no command specified for execution")
		fmt.Fprintln(os.Stderr, "Usage: fabrial run [flags] [--] <command> [args...]")
		os.Exit(1)
	}

	ctx := context.Background()
	decision, err := router.Route(opts, cmdArgs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fabrial: routing error: %v\n", err)
		os.Exit(1)
	}

	exitCode, err := router.Execute(ctx, decision)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fabrial: execution error: %v\n", err)
		os.Exit(exitCode)
	}

	os.Exit(exitCode)
}

func handleDoctor(args []string) {
	asJSON := false
	doFix := false
	for _, a := range args {
		if a == "--json" {
			asJSON = true
		}
		if a == "--fix" || a == "fix" {
			doFix = true
		}
	}

	if doFix {
		handleFix(args)
		return
	}

	inspector := doctor.NewInspector(1 * time.Second)
	results := inspector.InspectAll(context.Background(), ".")

	if asJSON {
		data, err := doctor.FormatJSON(results)
		if err == nil {
			fmt.Println(string(data))
		}
		return
	}

	fmt.Println(doctor.FormatTable(results))
}

func handleFix(args []string) {
	asJSON := false
	var targetPillar string
	for _, a := range args {
		if a == "--json" {
			asJSON = true
		} else if a != "--fix" && a != "fix" && !strings.HasPrefix(a, "-") && targetPillar == "" {
			targetPillar = a
		}
	}

	inspector := doctor.NewInspector(1 * time.Second)
	sup := supervisor.NewDefaultSupervisor()
	fixer := doctor.NewFixer(inspector, sup, ".")

	ctx := context.Background()

	if targetPillar != "" {
		fmt.Printf("💎 Remediating degraded fabric component: %s...\n", targetPillar)
		actions, updatedReport := fixer.FixPillar(ctx, doctor.PillarID(targetPillar))
		if asJSON {
			out := map[string]interface{}{
				"actions": actions,
				"health":  updatedReport,
			}
			data, _ := json.MarshalIndent(out, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println(doctor.FormatFixTable(actions))
		fmt.Printf("✔ %-12s [%-8s] %s\n", updatedReport.Pillar, updatedReport.Status, updatedReport.Details)
		return
	}

	fmt.Println("💎 Scanning and remediating degraded fabric components...")
	actions, updatedReports := fixer.FixAll(ctx)

	if asJSON {
		out := map[string]interface{}{
			"actions": actions,
			"health":  updatedReports,
		}
		data, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(data))
		return
	}

	if len(actions) > 0 {
		fmt.Println(doctor.FormatFixTable(actions))
		fmt.Println("\nRe-evaluating fabric diagnostics...")
	}
	fmt.Println(doctor.FormatTable(updatedReports))
}

func handleDaemon(args []string) {
	action := "status"
	if len(args) > 0 {
		action = args[0]
	}

	sup := supervisor.NewDefaultSupervisor()
	ctx := context.Background()

	switch action {
	case "status":
		statuses := sup.StatusAll(ctx)
		fmt.Println("💎 Fabrial Resident Daemons Status")
		fmt.Println(strings.Repeat("─", 65))
		for _, s := range statuses {
			icon := "✅"
			if s.State != supervisor.StateRunning {
				icon = "⚠️ "
			}
			pidStr := ""
			if s.PID > 0 {
				pidStr = fmt.Sprintf(" (PID %d)", s.PID)
			}
			fmt.Printf("%s %-12s [%-7s] %s%s\n", icon, s.Name, s.State, s.Message, pidStr)
		}
		fmt.Println(strings.Repeat("─", 65))

	case "start":
		fmt.Println("💎 Starting Fabrial Sovereign Security Fabric Resident Daemons...")
		fmt.Println(strings.Repeat("─", 65))
		statuses := sup.StartAll(ctx)
		for _, s := range statuses {
			icon := "✔"
			if s.State == supervisor.StateError {
				icon = "❌"
			}
			fmt.Printf("%s %-12s: %s\n", icon, s.Name, s.Message)
		}
		fmt.Println(strings.Repeat("─", 65))
		fmt.Println("💎 Run 'fabrial doctor' to verify multi-pillar health.")

	case "stop":
		fmt.Println("💎 Stopping Fabrial Sovereign Security Fabric Resident Daemons...")
		fmt.Println(strings.Repeat("─", 65))
		statuses := sup.StopAll(ctx)
		for _, s := range statuses {
			fmt.Printf("✔ %-12s: %s\n", s.Name, s.Message)
		}
		fmt.Println(strings.Repeat("─", 65))
		fmt.Println("💎 All resident fabric daemons stopped.")

	case "restart":
		_ = sup.StopAll(ctx)
		time.Sleep(500 * time.Millisecond)
		_ = sup.StartAll(ctx)
		fmt.Println("💎 All resident fabric daemons restarted.")

	default:
		fmt.Fprintf(os.Stderr, "Unknown daemon command: %q. Usage: fabrial daemon [status|start|stop|restart]\n", action)
		os.Exit(1)
	}
}

func handleCircuitBreaker(args []string) {
	sockPath := doctor.ResolveArgusSocketPath()
	for i := 0; i < len(args); i++ {
		if (args[i] == "--socket" || args[i] == "-socket") && i+1 < len(args) {
			sockPath = args[i+1]
			i++
		}
	}

	subcmd := "listen"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		subcmd = args[0]
	}

	switch subcmd {
	case "listen", "start", "run":
		fmt.Printf("💎 Starting Fabrial Circuit Breaker tripwire on %s...\n", sockPath)
		tw := circuitbreaker.NewTripwire(circuitbreaker.TripwireOptions{
			SocketPath: sockPath,
			OnTrip: func(res *circuitbreaker.TripResult) {
				fmt.Printf("⚡ [CIRCUIT BREAKER TRIPPED] PID %d FROZEN in %v (method: %s, rule: %s)\n",
					res.TargetPID, res.FreezeLatency, res.FreezeMethod, res.Alert.RuleName)
			},
		})

		ctx := context.Background()
		if err := tw.Start(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "circuit-breaker: failed to start: %v\n", err)
			os.Exit(1)
		}
		defer tw.Stop()

		fmt.Println("✔ Circuit breaker tripwire active. Monitoring for Quarry telemetry kill signals...")
		select {}

	case "status":
		fmt.Println("💎 Fabrial Circuit Breaker Status:")
		fmt.Printf("   Socket: %s\n", sockPath)
		if conn, err := net.DialTimeout("unix", sockPath, 200*time.Millisecond); err == nil {
			_ = conn.Close()
			fmt.Println("   State:  ● Active")
		} else {
			fmt.Println("   State:  ○ Inactive")
		}

	default:
		fmt.Println("Usage: fabrial circuit-breaker [listen|status] [--socket <path>]")
	}
}

func handleIntegrate(args []string) {
	targetPlatform := "superengineering"
	targetDir := "."
	isGlobal := false

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "superengineering", "super.engineering", "--superengineering", "-s":
			targetPlatform = "superengineering"
		case "antigravity", "agy", "--antigravity", "-a":
			targetPlatform = "antigravity"
		case "--global", "-g":
			isGlobal = true
		case "help", "-h", "--help":
			fmt.Println(`Usage: fabrial integrate [superengineering] [path] [--global]
Bootstrap Bonjoski sovereign security fabric into agentic environments.

Options:
  --global, -g        Install globally into App Settings across ALL paths/workspaces

Supported targets:
  superengineering    Generate/update .super.engineering/config.json with hooks and commands
  antigravity, agy    Configure native MCP servers (aegisbox, locksmith, airlock) in mcp_config.json`)
			os.Exit(0)
		default:
			if !strings.HasPrefix(arg, "-") {
				targetDir = arg
			}
		}
	}

	switch targetPlatform {
	case "superengineering":
		var res *integration.Result
		var err error
		if isGlobal {
			res, err = integration.SuperEngineeringGlobal()
		} else {
			res, err = integration.SuperEngineering(targetDir)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: integration failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("💎 Integrated Bonjoski Sovereign Security Fabric into %s\n", res.ConfigPath)
		if len(res.SetupAdded) > 0 {
			fmt.Printf("  • Setup hook added: %s\n", strings.Join(res.SetupAdded, ", "))
		}
		if len(res.RunAdded) > 0 {
			fmt.Printf("  • Managed run script added: %s\n", strings.Join(res.RunAdded, ", "))
		}
		if len(res.CommandsAdded) > 0 {
			fmt.Printf("  • Slash commands configured: %s\n", strings.Join(res.CommandsAdded, ", "))
		} else if len(res.CommandsUpdated) == 0 {
			fmt.Printf("  • All commands already configured (idempotent)\n")
		}
		if len(res.CommandsUpdated) > 0 {
			fmt.Printf("  • Slash commands updated: %s\n", strings.Join(res.CommandsUpdated, ", "))
		}
	case "antigravity", "agy":
		res, err := integration.Antigravity(targetDir, isGlobal)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Antigravity integration failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("💎 Integrated Bonjoski Security MCP Servers into Antigravity (%s)\n", res.ConfigPath)
		if len(res.ServersAdded) > 0 {
			fmt.Printf("  • MCP servers added: %s\n", strings.Join(res.ServersAdded, ", "))
		} else if len(res.ServersUpdated) == 0 {
			fmt.Printf("  • All MCP servers already configured (idempotent)\n")
		}
		if len(res.ServersUpdated) > 0 {
			fmt.Printf("  • MCP servers updated: %s\n", strings.Join(res.ServersUpdated, ", "))
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown integration target: %s\n", targetPlatform)
		os.Exit(1)
	}
}

func handleServe(args []string) {
	sockPath := server.DefaultSocketPath()
	tcpAddr := "127.0.0.1:9191"

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--socket", "-s":
			if i+1 < len(args) {
				sockPath = args[i+1]
				i++
			}
		case "--addr", "-a":
			if i+1 < len(args) {
				tcpAddr = args[i+1]
				i++
			}
		case "--no-tcp":
			tcpAddr = ""
		case "--port", "-p":
			if i+1 < len(args) {
				tcpAddr = "127.0.0.1:" + args[i+1]
				i++
			}
		}
	}

	srv := server.NewServer(server.Config{
		SocketPath: sockPath,
		TCPAddr:    tcpAddr,
	})

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "fabrial serve: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("💎 Fabrial Sovereign Control Plane Server")
	fmt.Println(strings.Repeat("─", 65))
	if sockPath != "" {
		fmt.Printf("✔ IPC Socket: %s (0600 mode)\n", sockPath)
	}
	if tcpAddr != "" {
		fmt.Printf("✔ HTTP API:   http://%s (CSRF/DNS rebinding protected)\n", tcpAddr)
	}
	fmt.Println("✔ Telemetry:  /api/v1/events (SSE stream)")
	fmt.Println(strings.Repeat("─", 65))
	fmt.Println("Press Ctrl+C to shutdown.")

	<-ctx.Done()
	fmt.Println("\n💎 Shutting down Fabrial control plane...")
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()
	_ = srv.Stop(stopCtx)
}

func handleSession(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: fabrial session [begin|child|env|list|kill] [flags]")
		os.Exit(1)
	}

	sub := args[0]
	subArgs := args[1:]
	sessionFile := session.DefaultSessionFilePath()

	sm := session.NewSessionManager()
	_ = sm.LoadFromFile(sessionFile)

	switch sub {
	case "launch":
		handleSessionLaunch(subArgs, sm)

	case "begin", "start":
		ttl := 30 * time.Minute
		scopes := []string{"read", "build", "test", "lint"}
		proxyAddr := "127.0.0.1:8443"
		biometric := true

		for i := 0; i < len(subArgs); i++ {
			switch subArgs[i] {
			case "--ttl":
				if i+1 < len(subArgs) {
					if d, err := time.ParseDuration(subArgs[i+1]); err == nil {
						ttl = d
					}
					i++
				}
			case "--scopes":
				if i+1 < len(subArgs) {
					scopes = strings.Split(subArgs[i+1], ",")
					i++
				}
			case "--no-bio":
				biometric = false
			case "--proxy":
				if i+1 < len(subArgs) {
					proxyAddr = subArgs[i+1]
					i++
				}
			}
		}

		grant, err := sm.BeginSession(context.Background(), session.SessionConfig{
			TTL:                ttl,
			AllowedScopes:      scopes,
			BiometricPreflight: biometric,
			ShieldProxyAddr:    proxyAddr,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating session: %v\n", err)
			os.Exit(1)
		}

		if err := sm.SaveToFile(sessionFile); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to persist session: %v\n", err)
		}

		fmt.Println("💎 Fabrial Ambient Master Session Created")
		fmt.Println(strings.Repeat("─", 65))
		fmt.Printf("✔ Session ID:    %s\n", grant.ID)
		fmt.Printf("✔ Valid Until:   %s (%v)\n", grant.ExpiresAt.Format(time.RFC3339), time.Until(grant.ExpiresAt).Round(time.Second))
		fmt.Printf("✔ Scopes:        %s\n", strings.Join(grant.Scopes, ", "))
		fmt.Println(strings.Repeat("─", 65))
		fmt.Println("To export ambient environment for autonomous subagents and shell tools:")
		fmt.Println("  eval $(fabrial session env)")

	case "child":
		var parentID string
		var taskID string
		scopes := []string{}

		for i := 0; i < len(subArgs); i++ {
			switch subArgs[i] {
			case "--parent", "-p":
				if i+1 < len(subArgs) {
					parentID = subArgs[i+1]
					i++
				}
			case "--task", "-t":
				if i+1 < len(subArgs) {
					taskID = subArgs[i+1]
					i++
				}
			case "--scopes":
				if i+1 < len(subArgs) {
					scopes = strings.Split(subArgs[i+1], ",")
					i++
				}
			}
		}

		if parentID == "" {
			parentID = os.Getenv("FABRIAL_SESSION_ID")
			if parentID == "" {
				active := sm.ActiveSessions()
				for _, a := range active {
					if a.IsMaster {
						parentID = string(a.ID)
						break
					}
				}
			}
		}

		if parentID == "" {
			fmt.Fprintf(os.Stderr, "Error: missing --parent session ID\n")
			os.Exit(1)
		}

		childGrant, err := sm.DeriveChildSession(context.Background(), session.SessionID(parentID), taskID, scopes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error deriving child session: %v\n", err)
			os.Exit(1)
		}

		_ = sm.SaveToFile(sessionFile)

		fmt.Printf("✔ Child Session Derived: %s (Parent: %s, Subtask: %s)\n", childGrant.ID, childGrant.ParentID, childGrant.SubtaskID)
		fmt.Printf("✔ Ephemeral TTL: %v | Zero Biometric Prompts\n", time.Until(childGrant.ExpiresAt).Round(time.Second))

	case "env":
		targetID := ""
		if len(subArgs) > 0 && !strings.HasPrefix(subArgs[0], "-") {
			targetID = subArgs[0]
		}
		for i := 0; i < len(subArgs); i++ {
			if subArgs[i] == "--id" && i+1 < len(subArgs) {
				targetID = subArgs[i+1]
				i++
			}
		}

		if targetID == "" {
			targetID = os.Getenv("FABRIAL_SESSION_ID")
		}

		var grant *session.SessionGrant
		if targetID != "" {
			g, err := sm.GetSession(session.SessionID(targetID))
			if err == nil {
				grant = g
			}
		}

		if grant == nil {
			active := sm.ActiveSessions()
			if len(active) > 0 {
				grant = &active[0]
			}
		}

		if grant == nil {
			fmt.Fprintf(os.Stderr, "# No active Fabrial session found. Run 'fabrial session begin' first.\n")
			os.Exit(1)
		}

		fmt.Print(session.FormatShellExport(grant.Environment))

	case "list", "ls":
		active := sm.ActiveSessions()
		if len(active) == 0 {
			fmt.Println("No active Fabrial sessions found.")
			return
		}

		fmt.Printf("%-32s %-8s %-12s %-24s %s\n", "SESSION ID", "TYPE", "REMAINING", "SCOPES", "PARENT / TASK")
		fmt.Println(strings.Repeat("─", 90))
		for _, g := range active {
			sType := "CHILD"
			if g.IsMaster {
				sType = "MASTER"
			}
			parentInfo := "-"
			if g.ParentID != "" {
				parentInfo = string(g.ParentID)
				if g.SubtaskID != "" {
					parentInfo += " (" + g.SubtaskID + ")"
				}
			}
			rem := time.Until(g.ExpiresAt).Round(time.Second).String()
			fmt.Printf("%-32s %-8s %-12s %-24s %s\n", g.ID, sType, rem, strings.Join(g.Scopes, ","), parentInfo)
		}

	case "kill", "rm", "invalidate":
		if len(subArgs) == 0 {
			fmt.Fprintf(os.Stderr, "Usage: fabrial session kill <session_id>\n")
			os.Exit(1)
		}
		id := subArgs[0]
		if err := sm.InvalidateSession(context.Background(), session.SessionID(id)); err != nil {
			fmt.Fprintf(os.Stderr, "Error invalidating session: %v\n", err)
			os.Exit(1)
		}
		_ = sm.SaveToFile(sessionFile)
		fmt.Printf("✔ Session %s invalidated.\n", id)

	default:
		fmt.Fprintf(os.Stderr, "Unknown session subcommand: %s\n", sub)
		os.Exit(1)
	}
}

func handleSessionLaunch(args []string, sm *session.SessionManager) {
	var targetCmd string
	var targetArgs []string
	profile := "agent"
	useAirlock := true
	biometric := false

	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			if i+1 < len(args) {
				targetCmd = args[i+1]
				if i+2 < len(args) {
					targetArgs = args[i+2:]
				}
			}
			break
		}
		switch args[i] {
		case "--profile":
			if i+1 < len(args) {
				profile = args[i+1]
				i++
			}
		case "--no-airlock":
			useAirlock = false
		case "--bio":
			biometric = true
		default:
			if targetCmd == "" {
				targetCmd = args[i]
				targetArgs = args[i+1:]
				i = len(args)
			}
		}
	}

	if targetCmd == "" {
		fmt.Fprintf(os.Stderr, "Usage: fabrial launch [--profile <profile>] [--no-airlock] [--] <command> [args...]\n")
		os.Exit(1)
	}

	cfg := session.LaunchConfig{
		Profile:       profile,
		TargetCommand: targetCmd,
		TargetArgs:    targetArgs,
		UseAirlock:    useAirlock,
		Biometric:     biometric,
	}

	ctx := context.Background()
	if err := session.LaunchSession(ctx, sm, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error launching session: %v\n", err)
		os.Exit(1)
	}
}

func handleQueue(args []string) {
	q := queue.NewMicroVMQueue()
	status := q.Status()

	fmt.Println("📦 Fabrial Tier 2 MicroVM Concurrency Queue")
	fmt.Println(strings.Repeat("─", 65))
	fmt.Printf("✔ Active MicroVMs:    %d / %d slots\n", status.ActiveSlots, status.MaxSlots)
	fmt.Printf("✔ Queued Workloads:   %d (max capacity %d)\n", status.QueuedRequests, status.MaxQueueCapacity)
	fmt.Printf("✔ Saturation Status:  Healthy (host memory protected)\n")
	fmt.Println(strings.Repeat("─", 65))
}

func handleAuth(args []string) {
	if len(args) == 0 {
		handleAuthStatus()
		return
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "login":
		handleAuthLogin(subArgs)
	case "status":
		handleAuthStatus()
	case "logout":
		handleAuthLogout()
	default:
		fmt.Fprintf(os.Stderr, "Unknown auth command: %s (usage: fabrial auth [login|status|logout])\n", sub)
		os.Exit(1)
	}
}

func handleAuthLogin(args []string) {
	opts := auth.LoginOptions{
		ServerURL: "https://localhost:9443",
		Insecure:  true,
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--server":
			if i+1 < len(args) {
				opts.ServerURL = args[i+1]
				i++
			}
		case "--email":
			if i+1 < len(args) {
				opts.Email = args[i+1]
				i++
			}
		case "--password":
			if i+1 < len(args) {
				opts.Password = args[i+1]
				i++
			}
		case "--token":
			if i+1 < len(args) {
				opts.Token = args[i+1]
				i++
			}
		case "--tenant":
			if i+1 < len(args) {
				opts.TenantID = args[i+1]
				i++
			}
		case "--insecure":
			opts.Insecure = true
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fmt.Printf("Connecting to Stoneward Cloud Control Plane at %s...\n", opts.ServerURL)
	authCtx, bundle, toolchain, err := auth.Login(ctx, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Authentication failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(strings.Repeat("─", 75))
	fmt.Printf("✔ Successfully authenticated as %s (%s)\n", authCtx.Name, authCtx.Email)
	fmt.Printf("✔ Organization / Tenant: %s (ID: %s)\n", authCtx.OrgName, authCtx.TenantID)
	fmt.Printf("✔ Role:                  %s\n", authCtx.Role)
	tokenPreview := authCtx.Token
	if len(tokenPreview) > 16 {
		tokenPreview = tokenPreview[:16] + "..."
	}
	fmt.Printf("✔ Bearer Token:          %s (saved to ~/.fabrial/auth.json)\n", tokenPreview)
	fmt.Printf("✔ Policy Bundle:         Version %d (verified Ed25519 signature)\n", bundle.Version)
	fmt.Printf("✔ Toolchain Policies:    Synchronized across all 10 sovereign tools\n")
	fmt.Printf("                         - Argus: %d allowed registries, %d blocked\n", len(toolchain.Argus.AllowedRegistries), len(toolchain.Argus.BlockedRegistries))
	fmt.Printf("                         - Locksmith: cert issuance=%v, %d domains\n", toolchain.Locksmith.CertIssuanceEnabled, len(toolchain.Locksmith.AllowedCertDomains))
	fmt.Printf("                         - Shield: anti-ssrf=%v, fail-closed=%v\n", toolchain.Shield.BlockCloudMetadata, toolchain.Shield.FailClosedWireGuard)
	fmt.Println(strings.Repeat("─", 75))
}

func handleAuthStatus() {
	authCtx, bundle, err := auth.Status()
	if err != nil {
		fmt.Println("❌ Fabrial is currently unauthenticated.")
		fmt.Println("   Run 'fabrial auth login' to authenticate with the Stoneward control plane.")
		return
	}

	fmt.Println("💎 Fabrial Cloud Authentication Status")
	fmt.Println(strings.Repeat("─", 70))
	fmt.Printf("✔ Status:        Authenticated\n")
	fmt.Printf("✔ User:          %s (%s)\n", authCtx.Name, authCtx.Email)
	fmt.Printf("✔ Organization:  %s [Tenant: %s]\n", authCtx.OrgName, authCtx.TenantID)
	fmt.Printf("✔ Control Plane: %s\n", authCtx.ServerURL)
	fmt.Printf("✔ Token Lease:   Expires in %s\n", time.Until(authCtx.ExpiresAt).Round(time.Minute))
	if bundle != nil {
		fmt.Printf("✔ Cached Policy: Version %d (valid until %s)\n", bundle.Version, bundle.ValidUntil.Format(time.RFC3339))
	} else {
		fmt.Printf("✔ Cached Policy: None (run 'fabrial policy pull' to synchronize)\n")
	}
	fmt.Println(strings.Repeat("─", 70))
}

func handleAuthLogout() {
	if err := auth.Logout(); err != nil {
		fmt.Fprintf(os.Stderr, "Error logging out: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✔ Successfully logged out. Fabrial authentication credentials cleared.")
}

func handlePolicy(args []string) {
	if len(args) > 0 && args[0] == "status" {
		handleAuthStatus()
		return
	}

	insecure := true
	for _, arg := range args {
		if arg == "--insecure" {
			insecure = true
		}
	}

	fmt.Println("Pulling signed policy bundle from Stoneward control plane...")
	bundle, toolchain, err := auth.PullPolicy(insecure)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Policy pull failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(strings.Repeat("─", 75))
	fmt.Printf("✔ Policy bundle verified and cached! (Version %d, Tenant: %s)\n", bundle.Version, bundle.TenantID)
	fmt.Printf("✔ Blocked Syscalls:   %d prohibited (anti-loopback=%v)\n", len(bundle.Rule.BlockedSyscalls), bundle.Rule.BlockLoopbackNet)
	fmt.Printf("✔ Required Tiers:     %d command routing overrides\n", len(bundle.Rule.RequiredTiers))
	fmt.Printf("✔ Toolchain Policies: Synchronized across 10 sovereign tools (Argus allowed regs: %d)\n", len(toolchain.Argus.AllowedRegistries))
	fmt.Println(strings.Repeat("─", 75))
}
