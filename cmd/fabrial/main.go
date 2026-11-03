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
	"github.com/bonjoski/fabrial/pkg/integration"
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

	case "integrate", "init":
		handleIntegrate(args)

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

	// 5. Check Shield Secret Redaction & Fail-Closed Wire Guard Proxy
	shieldBin, shieldBinErr := router.FindExecutable("shield")
	proxyAddr, proxyOnline := router.DetectShieldProxy()
	shieldStatus := "OFFLINE"
	shieldDetails := "shield binary not found on PATH"
	if proxyOnline {
		shieldStatus = "ONLINE"
		if shieldBinErr == nil {
			shieldDetails = fmt.Sprintf("Wire guard proxy active on %s (binary at %s)", proxyAddr, shieldBin)
		} else {
			shieldDetails = fmt.Sprintf("Wire guard proxy active on %s", proxyAddr)
		}
	} else if shieldBinErr == nil {
		shieldStatus = "DEGRADED"
		shieldDetails = fmt.Sprintf("Available at %s (proxy offline; run 'fabrial daemon start' or 'shield proxy')", shieldBin)
	}
	results = append(results, PillarHealth{
		Pillar:  "Shield",
		Role:    "Secret Redaction & Fail-Closed Wire Guard",
		Status:  shieldStatus,
		Details: shieldDetails,
	})

	// 6. Check Conjoiner NIST Agentic IAM Broker & DPoP Engine
	conjoinerBin, cjBinErr := router.FindExecutable("conjoiner")
	conjoinerSock := resolveConjoinerSocketPath()
	cjStatus := "OFFLINE"
	cjDetails := "conjoiner binary not found on PATH"
	cjSockOnline := false
	if conn, err := net.DialTimeout("unix", conjoinerSock, 300*time.Millisecond); err == nil {
		_ = conn.Close()
		cjSockOnline = true
	}
	if cjSockOnline {
		cjStatus = "ONLINE"
		cjDetails = fmt.Sprintf("Active on %s (NIST NHI DPoP broker)", conjoinerSock)
	} else if cjBinErr == nil {
		cjStatus = "READY"
		cjDetails = fmt.Sprintf("Available at %s (stateless DPoP & token engine ready)", conjoinerBin)
	}
	results = append(results, PillarHealth{
		Pillar:  "Conjoiner",
		Role:    "NIST Agentic IAM Broker & DPoP Gateway",
		Status:  cjStatus,
		Details: cjDetails,
	})

	// 7. Check Stormcage Context & Memory Firewall
	stormBin, stormBinErr := router.FindExecutable("stormcage")
	stormStatus := "OFFLINE"
	stormDetails := "stormcage binary not found on PATH"
	stormOnline := false
	if conn, err := net.DialTimeout("tcp", "127.0.0.1:8088", 150*time.Millisecond); err == nil {
		_ = conn.Close()
		stormOnline = true
	}
	if stormOnline {
		stormStatus = "ONLINE"
		stormDetails = fmt.Sprintf("Context firewall daemon active on 127.0.0.1:8088 (binary at %s)", stormBin)
	} else if stormBinErr == nil {
		stormStatus = "READY"
		stormDetails = fmt.Sprintf("Available at %s (inline sanitizer & AST normalizer ready)", stormBin)
	}
	results = append(results, PillarHealth{
		Pillar:  "Stormcage",
		Role:    "Context & Memory Prompt Firewall",
		Status:  stormStatus,
		Details: stormDetails,
	})

	// 8. Check Soulcaster Compiler Attestation & SLSA Provenance
	soulBin, soulBinErr := router.FindExecutable("soulcaster")
	soulStatus := "OFFLINE"
	soulDetails := "soulcaster binary not found on PATH"
	if soulBinErr == nil {
		soulStatus = "READY"
		soulDetails = fmt.Sprintf("Available at %s (in-toto v1.0 & SLSA v1.0 provenance active)", soulBin)
	}
	results = append(results, PillarHealth{
		Pillar:  "Soulcaster",
		Role:    "Runtime Compiler Attestation & SLSA Provenance",
		Status:  soulStatus,
		Details: soulDetails,
	})

	// 9. Check Bomhound CycloneDX Legal Attribution
	bomBin, bomBinErr := router.FindExecutable("bomhound")
	bomStatus := "OFFLINE"
	bomDetails := "bomhound binary not found on PATH"
	if bomBinErr == nil {
		bomStatus = "READY"
		bomDetails = fmt.Sprintf("Available at %s (CycloneDX legal attribution engine active)", bomBin)
	}
	results = append(results, PillarHealth{
		Pillar:  "Bomhound",
		Role:    "CycloneDX Legal Attribution & SBOM Engine",
		Status:  bomStatus,
		Details: bomDetails,
	})

	// 10. Check Spanreed Strategic Planning Hub
	spanreedPath := resolveSpanreedPath()
	spanreedStatus := "OFFLINE"
	spanreedDetails := "spanreed repository or registry not found"
	if spanreedPath != "" {
		spanreedStatus = "READY"
		spanreedDetails = fmt.Sprintf("Active at %s (AI-DLC planning state machine & RFC registry)", spanreedPath)
	}
	results = append(results, PillarHealth{
		Pillar:  "Spanreed",
		Role:    "Strategic Architecture & AI-DLC Governance",
		Status:  spanreedStatus,
		Details: spanreedDetails,
	})

	if asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(results)
		return
	}

	fmt.Println("💎 Fabrial Universal Security Fabric Diagnostic Suite")
	fmt.Println(strings.Repeat("─", 75))
	for _, r := range results {
		icon := "✅"
		if r.Status == "OFFLINE" || r.Status == "DEGRADED" {
			icon = "⚠️ "
		}
		fmt.Printf("%s %-12s [%-8s] %s\n", icon, r.Pillar, r.Status, r.Role)
		fmt.Printf("   Details: %s\n", r.Details)
	}
	fmt.Println(strings.Repeat("─", 75))
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

	// 4. Shield Proxy Daemon
	if _, online := router.DetectShieldProxy(); online {
		fmt.Println("✔ Shield fail-closed wire guard proxy is already active (127.0.0.1:8443)")
	} else {
		shieldBin, err := router.FindExecutable("shield")
		if err != nil {
			fmt.Printf("⚠️  Shield: %v (install via 'brew install bonjoski/tap/shield')\n", err)
		} else {
			home, _ := os.UserHomeDir()
			shieldDir := filepath.Join(home, ".shield")
			_ = os.MkdirAll(shieldDir, 0700)
			logFile, err := os.OpenFile(filepath.Join(shieldDir, "proxy.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
			cmd := exec.Command(shieldBin, "proxy", "--addr", "127.0.0.1:8443", "--tls")
			if err == nil {
				cmd.Stdout = logFile
				cmd.Stderr = logFile
			}
			if err := cmd.Start(); err != nil {
				fmt.Printf("⚠️  Shield proxy start: %v\n", err)
			} else {
				pidFile := filepath.Join(shieldDir, "shield.pid")
				_ = os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0600)
				time.Sleep(150 * time.Millisecond)
				fmt.Printf("✔ Shield wire guard proxy started (PID %d, 127.0.0.1:8443)\n", cmd.Process.Pid)
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

	// 4. Stop Shield Proxy
	home, _ = os.UserHomeDir()
	shieldPidFile := filepath.Join(home, ".shield", "shield.pid")
	if data, err := os.ReadFile(shieldPidFile); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
			_ = terminateProcess(pid)
			_ = os.Remove(shieldPidFile)
			fmt.Printf("✔ Shield wire guard proxy stopped (PID %d)\n", pid)
		}
	} else {
		_ = exec.Command("pkill", "-f", "shield proxy").Run()
	}

	fmt.Println(strings.Repeat("─", 65))
	fmt.Println("💎 All resident fabric daemons stopped.")
}

func resolveConjoinerSocketPath() string {
	if s := os.Getenv("CONJOINER_SOCKET"); s != "" {
		return s
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		p := filepath.Join(home, ".conjoiner", "conjoiner.sock")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	tmpCandidate := filepath.Join(os.TempDir(), fmt.Sprintf("conjoiner-%d.sock", os.Getuid()))
	if _, err := os.Stat(tmpCandidate); err == nil {
		return tmpCandidate
	}
	return filepath.Join(os.TempDir(), "conjoiner.sock")
}

func resolveSpanreedPath() string {
	if s := os.Getenv("SPANREED_PATH"); s != "" {
		if fi, err := os.Stat(s); err == nil && fi.IsDir() {
			return s
		}
	}
	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, "code", "spanreed"),
		filepath.Join(home, ".spanreed"),
		filepath.Join(".", "spanreed"),
	}
	for _, c := range candidates {
		if fi, err := os.Stat(filepath.Join(c, "docs", "plans")); err == nil && fi.IsDir() {
			return c
		}
	}
	return ""
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
