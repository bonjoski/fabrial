// Command fabrial is the unified orchestrator for the Sovereign AI Agent Security Fabric:
// Airlock (sandbox), Locksmith (secrets), Aegisbox (microVM), and Argus (telemetry).
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/bonjoski/fabrial/pkg/circuitbreaker"
	"github.com/bonjoski/fabrial/pkg/doctor"
	"github.com/bonjoski/fabrial/pkg/integration"
	"github.com/bonjoski/fabrial/pkg/router"
	"github.com/bonjoski/fabrial/pkg/server"
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

	case "exec", "run":
		handleExec(args)

	case "doctor":
		handleDoctor(args)

	case "daemon":
		handleDaemon(args)

	case "integrate", "init":
		handleIntegrate(args)

	case "circuit-breaker", "breaker":
		handleCircuitBreaker(args)

	case "serve":
		handleServe(args)

	case "ui", "cockpit":
		handleUI(args)

	default:
		// Direct shorthand: if first arg is a flag or executable, run it
		handleExec(os.Args[1:])
	}
}

func printUsage() {
	fmt.Println(`💎 Fabrial — The Sovereign AI Agent Security Fabric
Unifying Airlock, Locksmith, Aegisbox, and Argus into an end-to-end agentic runtime.

Usage:
  fabrial run [flags] [--] <command> [args...]
  fabrial exec [flags] [--] <command> [args...]
  fabrial doctor [--json]
  fabrial daemon [status|start|stop|restart]
  fabrial serve [--socket <path>] [--port <port>]
  fabrial ui
  fabrial integrate [superengineering] [path] [--global]
  fabrial version

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
	fmt.Println("  • Spanreed:   Strategic Architecture & AI-DLC Governance Registry")
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
	for _, a := range args {
		if a == "--json" {
			asJSON = true
		}
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
		case "--global", "-g":
			isGlobal = true
		case "help", "-h", "--help":
			fmt.Println(`Usage: fabrial integrate [superengineering] [path] [--global]
Bootstrap Bonjoski sovereign security fabric into agentic environments.

Options:
  --global, -g        Install globally into App Settings across ALL paths/workspaces

Supported targets:
  superengineering    Generate/update .super.engineering/config.json with hooks and commands`)
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
		} else {
			fmt.Printf("  • All commands already configured (idempotent)\n")
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

func handleUI(args []string) {
	home, _ := os.UserHomeDir()
	candidates := []string{
		"fabrial-cockpit",
		filepath.Join(home, ".local", "bin", "fabrial-cockpit"),
		"/Applications/Fabrial Cockpit.app/Contents/MacOS/fabrial-cockpit",
	}

	for _, cand := range candidates {
		if bin, err := router.FindExecutable(cand); err == nil && bin != "" {
			fmt.Printf("💎 Launching Fabrial Cockpit companion (%s)...\n", bin)
			cmd := exec.Command(bin, args...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "failed to launch cockpit: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	fmt.Println("💎 Fabrial Cockpit Companion is not installed on PATH.")
	fmt.Println("   Starting headless control plane API instead at http://127.0.0.1:9191...")
	handleServe(args)
}
