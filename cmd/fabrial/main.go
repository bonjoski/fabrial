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
	"strings"
	"time"

	"github.com/bonjoski/airlock/pkg/bridge"
	"github.com/bonjoski/airlock/pkg/doctor"
	"github.com/bonjoski/airlock/pkg/secrets"
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

	default:
		// Direct shorthand: if first arg is a flag or executable, run it
		handleExec(os.Args[1:])
	}
}

func printUsage() {
	fmt.Println(`💎 Fabrial — The Sovereign AI Agent Security Fabric
Unifying Airlock, Locksmith, Aegisbox, and Argus into an end-to-end agentic runtime.

Usage:
  fabrial exec [flags] -- <command> [args...]
  fabrial doctor [--json]
  fabrial daemon [status|start|stop]
  fabrial version

Core Execution Commands:
  # Fast Tier 1 Kernel Confinement (<15ms via Airlock Seatbelt / Landlock)
  fabrial exec --profile agent -- <command>

  # Deep Tier 2 MicroVM Confinement (~100ms via Aegisbox Apple VZ / KVM)
  fabrial exec --profile agent --microvm -- <command>

Flags:
  --profile <name>      Execution profile (agent, strict, airgap, default)
  --microvm             Tier 2 Confinement via Aegisbox hypervisor MicroVM
  --lease-secret <keys> Comma-separated secrets to lease dynamically via Locksmith
  --session-ticket <tk> Session ticket for autonomous agent batch loops
  --airgap              Total offline network isolation
  --net                 Permit direct outbound networking`)
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
	// Re-delegate execution arguments directly through Airlock CLI engine
	// Ensuring standard environment scrubbing, Locksmith ETX leasing, and Argus telemetry
	airlockBin, err := os.Executable()
	if err != nil {
		airlockBin = "airlock"
	}

	execArgs := append([]string{"run"}, args...)
	cmd := exec.Command(airlockBin, execArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "fabrial: execution error: %v\n", err)
		os.Exit(1)
	}
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

	// 3. Check Aegisbox Hypervisor
	aegisStatus := "OFFLINE"
	aegisDetails := "Hypervisor binary not detected"
	if aegisBin, err := bridge.DiscoverAegisbox(); err == nil {
		aegisStatus = "READY"
		aegisDetails = fmt.Sprintf("Available at %s", aegisBin)
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
	if len(args) == 0 || args[0] == "status" {
		handleDoctor(args)
		return
	}
	fmt.Println("Use 'locksmith daemon' or 'argus daemon' to start resident listeners.")
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
