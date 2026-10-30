// Command fabrial is the unified orchestrator for the Sovereign AI Agent Security Fabric:
// Airlock (sandbox), Locksmith (secrets), Aegisbox (microVM), and Argus (telemetry).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bonjoski/airlock/pkg/bridge"
	"github.com/bonjoski/airlock/pkg/doctor"
	"github.com/bonjoski/airlock/pkg/secrets"
	"github.com/bonjoski/fabrial/pkg/circuitbreaker"
	"github.com/bonjoski/fabrial/pkg/router"
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

	case "circuit-breaker", "breaker":
		handleCircuitBreaker(args)

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
	fmt.Println("  • Airlock:   Kernel Confinement & Zero-VM Sandbox")
	fmt.Println("  • Locksmith: Biometric Hardware Vault & ETX Lease Engine")
	fmt.Println("  • Aegisbox:  Hardware MicroVM & Shadow CoW Workspace")
	fmt.Println("  • Argus:     Pre-Gate AST Inspection & SIEM Telemetry Bus")
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

type PillarHealth struct {
	Pillar  string `json:"pillar"`
	Role    string `json:"role"`
	Status  string `json:"status"` // "READY", "ONLINE", "DEGRADED", "OFFLINE"
	Details string `json:"details"`
}

func handleDoctor(args []string) {
	asJSON := false
	for _, a := range args {
		if a == "--json" {
			asJSON = true
		}
	}

	var results []PillarHealth

	// 1. Check Airlock Kernel Sandbox
	ctx := context.Background()
	airlockStatus := "READY"
	airlockDetails := "Native kernel boundary active"
	if rep, err := doctor.RunAllChecks(ctx, "."); err == nil && rep != nil {
		for _, r := range rep.Results {
			if r.Status == doctor.StatusFail {
				airlockStatus = "DEGRADED"
				airlockDetails = r.Title
				break
			}
		}
	}
	results = append(results, PillarHealth{
		Pillar:  "Airlock",
		Role:    "Tier 1 Kernel Sandbox Engine",
		Status:  airlockStatus,
		Details: airlockDetails,
	})

	// 2. Check Locksmith Resident Daemon & Socket
	lsSock := secrets.ResolveLocksmithSocket()
	lsStatus := "OFFLINE"
	lsDetails := fmt.Sprintf("Socket not found at %s", lsSock)
	if conn, err := net.DialTimeout("unix", lsSock, 500*time.Millisecond); err == nil {
		_ = conn.Close()
		lsStatus = "ONLINE"
		lsDetails = fmt.Sprintf("Active on %s", lsSock)
	}
	results = append(results, PillarHealth{
		Pillar:  "Locksmith",
		Role:    "Ephemeral Secret Lease Daemon",
		Status:  lsStatus,
		Details: lsDetails,
	})

	// 3. Check Aegisbox Hypervisor & Resident Daemon Socket
	aegisSock := router.ResolveAegisboxSocketPath()
	aegisBin, binErr := bridge.DiscoverAegisbox()
	if binErr != nil {
		aegisBin, binErr = router.FindExecutable("aegisbox")
	}

	aegisStatus := "OFFLINE"
	aegisDetails := fmt.Sprintf("Daemon socket not found at %s and hypervisor binary not detected", aegisSock)

	// Check if Aegisbox daemon socket is active
	socketOnline := false
	if conn, err := net.DialTimeout("unix", aegisSock, 500*time.Millisecond); err == nil {
		_ = conn.Close()
		socketOnline = true
	}

	if socketOnline {
		aegisStatus = "ONLINE"
		if binErr == nil {
			aegisDetails = fmt.Sprintf("Daemon active on %s (hypervisor at %s)", aegisSock, aegisBin)
		} else {
			aegisDetails = fmt.Sprintf("Daemon active on %s", aegisSock)
		}
	} else if binErr == nil {
		aegisStatus = "DEGRADED"
		aegisDetails = fmt.Sprintf("Available at %s (daemon socket %s offline; run 'fabrial daemon start')", aegisBin, aegisSock)
	}

	results = append(results, PillarHealth{
		Pillar:  "Aegisbox",
		Role:    "Tier 2 MicroVM Isolation Engine",
		Status:  aegisStatus,
		Details: aegisDetails,
	})

	// 4. Check Argus Telemetry Bus
	argusSock := resolveArgusSocketPath()
	argusStatus := "OFFLINE"
	argusDetails := fmt.Sprintf("Bus socket not found at %s", argusSock)
	if conn, err := net.DialTimeout("unix", argusSock, 500*time.Millisecond); err == nil {
		_ = conn.Close()
		argusStatus = "ONLINE"
		argusDetails = fmt.Sprintf("Listening on %s", argusSock)
	}
	results = append(results, PillarHealth{
		Pillar:  "Argus",
		Role:    "SIEM Telemetry & Killswitch Bus",
		Status:  argusStatus,
		Details: argusDetails,
	})

	if asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(results)
		return
	}

	fmt.Println("💎 Fabrial Multi-Pillar Diagnostic Suite")
	fmt.Println(strings.Repeat("─", 65))
	for _, r := range results {
		icon := "✅"
		if r.Status == "OFFLINE" || r.Status == "DEGRADED" {
			icon = "⚠️ "
		}
		fmt.Printf("%s %-12s [%-8s] %s\n", icon, r.Pillar, r.Status, r.Role)
		fmt.Printf("   Details: %s\n", r.Details)
	}
	fmt.Println(strings.Repeat("─", 65))
}

func handleDaemon(args []string) {
	action := "status"
	if len(args) > 0 {
		action = args[0]
	}

	switch action {
	case "status":
		handleDoctor(args[1:])
	case "start":
		startDaemons()
	case "stop":
		stopDaemons()
	case "restart":
		stopDaemons()
		time.Sleep(500 * time.Millisecond)
		startDaemons()
	default:
		fmt.Fprintf(os.Stderr, "Unknown daemon command: %q. Usage: fabrial daemon [status|start|stop|restart]\n", action)
		os.Exit(1)
	}
}

func startDaemons() {
	fmt.Println("💎 Starting Fabrial Sovereign Security Fabric Resident Daemons...")
	fmt.Println(strings.Repeat("─", 65))

	// 1. Locksmith Daemon
	lsSock := secrets.ResolveLocksmithSocket()
	if conn, err := net.DialTimeout("unix", lsSock, 300*time.Millisecond); err == nil {
		_ = conn.Close()
		fmt.Printf("✔ Locksmith ephemeral lease daemon is already active (%s)\n", lsSock)
	} else {
		lsBin, err := router.FindExecutable("locksmith")
		if err != nil {
			fmt.Printf("⚠️  Locksmith: %v (install via 'brew install bonjoski/tap/locksmith')\n", err)
		} else {
			home, _ := os.UserHomeDir()
			lsDir := filepath.Join(home, ".locksmith")
			_ = os.MkdirAll(lsDir, 0700)
			logFile, err := os.OpenFile(filepath.Join(lsDir, "daemon.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
			cmd := exec.Command(lsBin, "daemon")
			if err == nil {
				cmd.Stdout = logFile
				cmd.Stderr = logFile
			}
			if err := cmd.Start(); err != nil {
				fmt.Printf("❌ Failed to start Locksmith daemon: %v\n", err)
			} else {
				pidFile := filepath.Join(lsDir, "locksmith.pid")
				_ = os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0600)

				ready := false
				for i := 0; i < 20; i++ {
					time.Sleep(100 * time.Millisecond)
					if c, err := net.DialTimeout("unix", lsSock, 100*time.Millisecond); err == nil {
						_ = c.Close()
						ready = true
						break
					}
				}
				if ready {
					fmt.Printf("✔ Locksmith ephemeral lease daemon started (PID %d, %s)\n", cmd.Process.Pid, lsSock)
				} else {
					fmt.Printf("⚠️  Locksmith daemon process spawned (PID %d), waiting for socket...\n", cmd.Process.Pid)
				}
			}
		}
	}

	// 2. Argus Daemon
	argusSock := resolveArgusSocketPath()
	if conn, err := net.DialTimeout("unix", argusSock, 300*time.Millisecond); err == nil {
		_ = conn.Close()
		fmt.Printf("✔ Argus telemetry & killswitch bus is already active (%s)\n", argusSock)
	} else {
		argusBin, err := router.FindExecutable("argus")
		if err != nil {
			fmt.Printf("⚠️  Argus: %v (install via 'brew install bonjoski/tap/argus')\n", err)
		} else {
			cmd := exec.Command(argusBin, "daemon", "start")
			out, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Printf("❌ Failed to start Argus daemon: %v (%s)\n", err, strings.TrimSpace(string(out)))
			} else {
				ready := false
				for i := 0; i < 20; i++ {
					time.Sleep(100 * time.Millisecond)
					if c, err := net.DialTimeout("unix", argusSock, 100*time.Millisecond); err == nil {
						_ = c.Close()
						ready = true
						break
					}
				}
				if ready {
					fmt.Printf("✔ Argus telemetry & killswitch bus started (%s)\n", argusSock)
				} else {
					fmt.Println("✔ Argus daemon start command issued")
				}
			}
		}
	}

	// 3. Aegisbox Daemon
	aegisSock := router.ResolveAegisboxSocketPath()
	if conn, err := net.DialTimeout("unix", aegisSock, 300*time.Millisecond); err == nil {
		_ = conn.Close()
		fmt.Printf("✔ Aegisbox daemon is already active (%s)\n", aegisSock)
	} else {
		aegisBin, err := router.FindExecutable("aegisbox")
		if err != nil {
			fmt.Printf("⚠️  Aegisbox: %v (install via 'brew install bonjoski/tap/aegisbox')\n", err)
		} else {
			cmd := exec.Command(aegisBin, "daemon", "start")
			out, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Printf("⚠️  Aegisbox daemon start: %v (%s)\n", err, strings.TrimSpace(string(out)))
			} else {
				ready := false
				for i := 0; i < 20; i++ {
					time.Sleep(100 * time.Millisecond)
					if c, err := net.DialTimeout("unix", aegisSock, 100*time.Millisecond); err == nil {
						_ = c.Close()
						ready = true
						break
					}
				}
				if ready {
					fmt.Printf("✔ Aegisbox microvm daemon started (%s)\n", aegisSock)
				} else {
					fmt.Println("✔ Aegisbox daemon start command issued")
				}
			}
		}
	}

	fmt.Println(strings.Repeat("─", 65))
	fmt.Println("💎 Run 'fabrial doctor' to verify multi-pillar health.")
}

func stopDaemons() {
	fmt.Println("💎 Stopping Fabrial Sovereign Security Fabric Resident Daemons...")
	fmt.Println(strings.Repeat("─", 65))

	// 1. Stop Argus Daemon
	if argusBin, err := router.FindExecutable("argus"); err == nil {
		cmd := exec.Command(argusBin, "daemon", "stop")
		_ = cmd.Run()
		fmt.Println("✔ Argus telemetry & killswitch daemon stopped")
	} else {
		home, _ := os.UserHomeDir()
		pidPath := filepath.Join(home, ".argus", "argus.pid")
		if data, err := os.ReadFile(pidPath); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
				_ = terminateProcess(pid)
				_ = os.Remove(pidPath)
				fmt.Printf("✔ Argus daemon stopped (PID %d)\n", pid)
			}
		}
	}

	// 2. Stop Locksmith Daemon
	home, _ := os.UserHomeDir()
	lsPidFile := filepath.Join(home, ".locksmith", "locksmith.pid")
	stopped := false
	if data, err := os.ReadFile(lsPidFile); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
			if err := terminateProcess(pid); err == nil {
				fmt.Printf("✔ Locksmith daemon stopped (PID %d)\n", pid)
				stopped = true
			}
			_ = os.Remove(lsPidFile)
		}
	}
	if !stopped {
		cmd := exec.Command("pkill", "-f", "locksmith daemon")
		if err := cmd.Run(); err == nil {
			fmt.Println("✔ Locksmith daemon process terminated")
			stopped = true
		}
	}
	lsSock := secrets.ResolveLocksmithSocket()
	_ = os.Remove(lsSock)
	if !stopped {
		fmt.Println("✔ Locksmith daemon was not running")
	}

	// 3. Stop Aegisbox Daemon
	if aegisBin, err := router.FindExecutable("aegisbox"); err == nil {
		cmd := exec.Command(aegisBin, "daemon", "stop")
		_ = cmd.Run()
		fmt.Println("✔ Aegisbox daemon stopped")
	} else {
		cmd := exec.Command("pkill", "-f", "aegisboxd")
		_ = cmd.Run()
	}
	aegisSock := router.ResolveAegisboxSocketPath()
	_ = os.Remove(aegisSock)

	fmt.Println(strings.Repeat("─", 65))
	fmt.Println("💎 All resident fabric daemons stopped.")
}

func resolveArgusSocketPath() string {
	if s := os.Getenv("ARGUS_SOCKET"); s != "" {
		return s
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		p := fmt.Sprintf("%s/.argus/argus.sock", home)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	tmpCandidate := fmt.Sprintf("%s/argus-%d.sock", os.TempDir(), os.Getuid())
	if _, err := os.Stat(tmpCandidate); err == nil {
		return tmpCandidate
	}
	return fmt.Sprintf("%s/argus.sock", os.TempDir())
}

func terminateProcess(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Kill()
}

func handleCircuitBreaker(args []string) {
	sockPath := resolveArgusSocketPath()
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
