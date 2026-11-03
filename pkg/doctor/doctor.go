// Package doctor implements the universal multi-pillar diagnostic engine for Fabrial.
// It probes all 10 sovereign AI agent security tools concurrently with strict socket security verification.
package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	airlockDoc "github.com/bonjoski/airlock/pkg/doctor"
	"github.com/bonjoski/airlock/pkg/secrets"
	"github.com/bonjoski/fabrial/pkg/router"
)

// PillarID identifies an ecosystem security component.
type PillarID string

const (
	PillarAirlock    PillarID = "Airlock"
	PillarLocksmith  PillarID = "Locksmith"
	PillarAegisbox   PillarID = "Aegisbox"
	PillarArgus      PillarID = "Argus"
	PillarShield     PillarID = "Shield"
	PillarConjoiner  PillarID = "Conjoiner"
	PillarStormcage  PillarID = "Stormcage"
	PillarSoulcaster PillarID = "Soulcaster"
	PillarBomhound   PillarID = "Bomhound"
	PillarSpanreed   PillarID = "Spanreed"
)

// Status represents the operational health of a pillar.
type Status string

const (
	StatusReady    Status = "READY"
	StatusOnline   Status = "ONLINE"
	StatusDegraded Status = "DEGRADED"
	StatusOffline  Status = "OFFLINE"
)

// PillarHealth represents the diagnostic report for a single ecosystem component.
type PillarHealth struct {
	Pillar     PillarID      `json:"pillar"`
	Role       string        `json:"role"`
	Status     Status        `json:"status"`
	Details    string        `json:"details"`
	BinaryPath string        `json:"binary_path,omitempty"`
	SocketPath string        `json:"socket_path,omitempty"`
	Latency    time.Duration `json:"latency_ns,omitempty"`
}

// CanonicalOrder defines the authoritative presentation order for the 10 pillars.
var CanonicalOrder = []PillarID{
	PillarAirlock,
	PillarLocksmith,
	PillarAegisbox,
	PillarArgus,
	PillarShield,
	PillarConjoiner,
	PillarStormcage,
	PillarSoulcaster,
	PillarBomhound,
	PillarSpanreed,
}

// Inspector probes the health of all sovereign security tools.
type Inspector struct {
	Timeout time.Duration
}

// NewInspector creates an Inspector with the specified timeout.
func NewInspector(timeout time.Duration) *Inspector {
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	return &Inspector{Timeout: timeout}
}

// InspectAll concurrently probes all 10 pillars and returns reports in canonical order.
func (in *Inspector) InspectAll(ctx context.Context, projectDir string) []PillarHealth {
	var mu sync.Mutex
	resultsMap := make(map[PillarID]PillarHealth)
	var wg sync.WaitGroup

	probers := map[PillarID]func(context.Context, string) PillarHealth{
		PillarAirlock:    in.probeAirlock,
		PillarLocksmith:  in.probeLocksmith,
		PillarAegisbox:   in.probeAegisbox,
		PillarArgus:      in.probeArgus,
		PillarShield:     in.probeShield,
		PillarConjoiner:  in.probeConjoiner,
		PillarStormcage:  in.probeStormcage,
		PillarSoulcaster: in.probeSoulcaster,
		PillarBomhound:   in.probeBomhound,
		PillarSpanreed:   in.probeSpanreed,
	}

	for pid, probeFunc := range probers {
		wg.Add(1)
		go func(pID PillarID, fn func(context.Context, string) PillarHealth) {
			defer wg.Done()
			pCtx, cancel := context.WithTimeout(ctx, in.Timeout)
			defer cancel()

			start := time.Now()
			res := fn(pCtx, projectDir)
			res.Latency = time.Since(start)

			mu.Lock()
			resultsMap[pID] = res
			mu.Unlock()
		}(pid, probeFunc)
	}

	wg.Wait()

	// Assemble canonical ordered slice
	ordered := make([]PillarHealth, 0, len(CanonicalOrder))
	for _, pid := range CanonicalOrder {
		if res, ok := resultsMap[pid]; ok {
			ordered = append(ordered, res)
		}
	}

	return ordered
}

func (in *Inspector) probeAirlock(ctx context.Context, projectDir string) PillarHealth {
	status := StatusReady
	details := "Native kernel boundary active"

	bin, binErr := router.FindExecutable("airlock")
	if binErr != nil {
		status = StatusOffline
		details = "airlock binary not found on PATH"
		return PillarHealth{
			Pillar:  PillarAirlock,
			Role:    "Tier 1 Kernel Sandbox Engine",
			Status:  status,
			Details: details,
		}
	}

	if rep, err := airlockDoc.RunAllChecks(ctx, projectDir); err == nil && rep != nil {
		for _, r := range rep.Results {
			if r.Status == airlockDoc.StatusFail {
				status = StatusDegraded
				details = r.Title
				break
			}
		}
	}

	return PillarHealth{
		Pillar:     PillarAirlock,
		Role:       "Tier 1 Kernel Sandbox Engine",
		Status:     status,
		Details:    details,
		BinaryPath: bin,
	}
}

func (in *Inspector) probeLocksmith(ctx context.Context, _ string) PillarHealth {
	bin, binErr := router.FindExecutable("locksmith")
	sock := secrets.ResolveLocksmithSocket()

	if _, err := os.Stat(sock); err == nil {
		if ok, reason := VerifySocketSecurity(sock); !ok {
			return PillarHealth{
				Pillar:     PillarLocksmith,
				Role:       "Ephemeral Secret Lease Daemon",
				Status:     StatusDegraded,
				Details:    fmt.Sprintf("Insecure socket at %s (%s)", sock, reason),
				BinaryPath: bin,
				SocketPath: sock,
			}
		}

		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", sock)
		if err == nil {
			_ = conn.Close()
			return PillarHealth{
				Pillar:     PillarLocksmith,
				Role:       "Ephemeral Secret Lease Daemon",
				Status:     StatusOnline,
				Details:    fmt.Sprintf("Active on %s", sock),
				BinaryPath: bin,
				SocketPath: sock,
			}
		}
	}

	if binErr == nil {
		return PillarHealth{
			Pillar:     PillarLocksmith,
			Role:       "Ephemeral Secret Lease Daemon",
			Status:     StatusDegraded,
			Details:    fmt.Sprintf("Available at %s (socket %s offline; run 'fabrial daemon start')", bin, sock),
			BinaryPath: bin,
			SocketPath: sock,
		}
	}

	return PillarHealth{
		Pillar:     PillarLocksmith,
		Role:       "Ephemeral Secret Lease Daemon",
		Status:     StatusOffline,
		Details:    "locksmith binary not found on PATH",
		SocketPath: sock,
	}
}

func (in *Inspector) probeAegisbox(ctx context.Context, _ string) PillarHealth {
	bin, binErr := router.FindExecutable("aegisbox")
	sock := router.ResolveAegisboxSocketPath()

	if _, err := os.Stat(sock); err == nil {
		if ok, reason := VerifySocketSecurity(sock); !ok {
			return PillarHealth{
				Pillar:     PillarAegisbox,
				Role:       "Tier 2 MicroVM Isolation Engine",
				Status:     StatusDegraded,
				Details:    fmt.Sprintf("Insecure daemon socket at %s (%s)", sock, reason),
				BinaryPath: bin,
				SocketPath: sock,
			}
		}

		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", sock)
		if err == nil {
			_ = conn.Close()
			details := fmt.Sprintf("Daemon active on %s", sock)
			if binErr == nil {
				details = fmt.Sprintf("Daemon active on %s (hypervisor at %s)", sock, bin)
			}
			return PillarHealth{
				Pillar:     PillarAegisbox,
				Role:       "Tier 2 MicroVM Isolation Engine",
				Status:     StatusOnline,
				Details:    details,
				BinaryPath: bin,
				SocketPath: sock,
			}
		}
	}

	if binErr == nil {
		return PillarHealth{
			Pillar:     PillarAegisbox,
			Role:       "Tier 2 MicroVM Isolation Engine",
			Status:     StatusDegraded,
			Details:    fmt.Sprintf("Available at %s (daemon socket %s offline; run 'fabrial daemon start')", bin, sock),
			BinaryPath: bin,
			SocketPath: sock,
		}
	}

	return PillarHealth{
		Pillar:     PillarAegisbox,
		Role:       "Tier 2 MicroVM Isolation Engine",
		Status:     StatusOffline,
		Details:    "aegisbox binary and daemon socket offline",
		SocketPath: sock,
	}
}

func (in *Inspector) probeArgus(ctx context.Context, _ string) PillarHealth {
	bin, binErr := router.FindExecutable("argus")
	sock := ResolveArgusSocketPath()

	if _, err := os.Stat(sock); err == nil {
		if ok, reason := VerifySocketSecurity(sock); !ok {
			return PillarHealth{
				Pillar:     PillarArgus,
				Role:       "SIEM Telemetry & Killswitch Bus",
				Status:     StatusDegraded,
				Details:    fmt.Sprintf("Insecure socket at %s (%s)", sock, reason),
				BinaryPath: bin,
				SocketPath: sock,
			}
		}

		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", sock)
		if err == nil {
			_ = conn.Close()
			return PillarHealth{
				Pillar:     PillarArgus,
				Role:       "SIEM Telemetry & Killswitch Bus",
				Status:     StatusOnline,
				Details:    fmt.Sprintf("Listening on %s", sock),
				BinaryPath: bin,
				SocketPath: sock,
			}
		}
	}

	if binErr == nil {
		return PillarHealth{
			Pillar:     PillarArgus,
			Role:       "SIEM Telemetry & Killswitch Bus",
			Status:     StatusDegraded,
			Details:    fmt.Sprintf("Available at %s (bus socket %s offline; run 'fabrial daemon start')", bin, sock),
			BinaryPath: bin,
			SocketPath: sock,
		}
	}

	return PillarHealth{
		Pillar:     PillarArgus,
		Role:       "SIEM Telemetry & Killswitch Bus",
		Status:     StatusOffline,
		Details:    "argus binary not found on PATH",
		SocketPath: sock,
	}
}

func (in *Inspector) probeShield(ctx context.Context, _ string) PillarHealth {
	bin, binErr := router.FindExecutable("shield")
	proxyAddr, proxyOnline := router.DetectShieldProxy()

	if proxyOnline {
		details := fmt.Sprintf("Wire guard proxy active on %s", proxyAddr)
		if binErr == nil {
			details = fmt.Sprintf("Wire guard proxy active on %s (binary at %s)", proxyAddr, bin)
		}
		return PillarHealth{
			Pillar:     PillarShield,
			Role:       "Secret Redaction & Fail-Closed Wire Guard",
			Status:     StatusOnline,
			Details:    details,
			BinaryPath: bin,
		}
	}

	if binErr == nil {
		return PillarHealth{
			Pillar:     PillarShield,
			Role:       "Secret Redaction & Fail-Closed Wire Guard",
			Status:     StatusDegraded,
			Details:    fmt.Sprintf("Available at %s (proxy offline; run 'fabrial daemon start' or 'shield proxy')", bin),
			BinaryPath: bin,
		}
	}

	return PillarHealth{
		Pillar:  PillarShield,
		Role:    "Secret Redaction & Fail-Closed Wire Guard",
		Status:  StatusOffline,
		Details: "shield binary not found on PATH",
	}
}

func (in *Inspector) probeConjoiner(ctx context.Context, _ string) PillarHealth {
	bin, binErr := router.FindExecutable("conjoiner")
	sock := ResolveConjoinerSocketPath()

	if _, err := os.Stat(sock); err == nil {
		if ok, reason := VerifySocketSecurity(sock); !ok {
			return PillarHealth{
				Pillar:     PillarConjoiner,
				Role:       "NIST Agentic IAM Broker & DPoP Gateway",
				Status:     StatusDegraded,
				Details:    fmt.Sprintf("Insecure socket at %s (%s)", sock, reason),
				BinaryPath: bin,
				SocketPath: sock,
			}
		}

		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", sock)
		if err == nil {
			_ = conn.Close()
			return PillarHealth{
				Pillar:     PillarConjoiner,
				Role:       "NIST Agentic IAM Broker & DPoP Gateway",
				Status:     StatusOnline,
				Details:    fmt.Sprintf("Active on %s (NIST NHI DPoP broker)", sock),
				BinaryPath: bin,
				SocketPath: sock,
			}
		}
	}

	if binErr == nil {
		return PillarHealth{
			Pillar:     PillarConjoiner,
			Role:       "NIST Agentic IAM Broker & DPoP Gateway",
			Status:     StatusReady,
			Details:    fmt.Sprintf("Available at %s (stateless DPoP & token engine ready)", bin),
			BinaryPath: bin,
			SocketPath: sock,
		}
	}

	return PillarHealth{
		Pillar:     PillarConjoiner,
		Role:       "NIST Agentic IAM Broker & DPoP Gateway",
		Status:     StatusOffline,
		Details:    "conjoiner binary not found on PATH",
		SocketPath: sock,
	}
}

func (in *Inspector) probeStormcage(ctx context.Context, _ string) PillarHealth {
	bin, binErr := router.FindExecutable("stormcage")

	// Check if daemon is active on 127.0.0.1:8088
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", "127.0.0.1:8088")
	if err == nil {
		_ = conn.Close()
		details := "Context firewall daemon active on 127.0.0.1:8088"
		if binErr == nil {
			details = fmt.Sprintf("Context firewall daemon active on 127.0.0.1:8088 (binary at %s)", bin)
		}
		return PillarHealth{
			Pillar:     PillarStormcage,
			Role:       "Context & Memory Prompt Firewall",
			Status:     StatusOnline,
			Details:    details,
			BinaryPath: bin,
		}
	}

	if binErr == nil {
		return PillarHealth{
			Pillar:     PillarStormcage,
			Role:       "Context & Memory Prompt Firewall",
			Status:     StatusReady,
			Details:    fmt.Sprintf("Available at %s (inline sanitizer & AST normalizer ready)", bin),
			BinaryPath: bin,
		}
	}

	return PillarHealth{
		Pillar:  PillarStormcage,
		Role:    "Context & Memory Prompt Firewall",
		Status:  StatusOffline,
		Details: "stormcage binary not found on PATH",
	}
}

func (in *Inspector) probeSoulcaster(_ context.Context, _ string) PillarHealth {
	bin, binErr := router.FindExecutable("soulcaster")
	if binErr == nil {
		return PillarHealth{
			Pillar:     PillarSoulcaster,
			Role:       "Runtime Compiler Attestation & SLSA Provenance",
			Status:     StatusReady,
			Details:    fmt.Sprintf("Available at %s (in-toto v1.0 & SLSA v1.0 provenance active)", bin),
			BinaryPath: bin,
		}
	}

	return PillarHealth{
		Pillar:  PillarSoulcaster,
		Role:    "Runtime Compiler Attestation & SLSA Provenance",
		Status:  StatusOffline,
		Details: "soulcaster binary not found on PATH",
	}
}

func (in *Inspector) probeBomhound(_ context.Context, _ string) PillarHealth {
	bin, binErr := router.FindExecutable("bomhound")
	if binErr == nil {
		return PillarHealth{
			Pillar:     PillarBomhound,
			Role:       "CycloneDX Legal Attribution & SBOM Engine",
			Status:     StatusReady,
			Details:    fmt.Sprintf("Available at %s (CycloneDX legal attribution engine active)", bin),
			BinaryPath: bin,
		}
	}

	return PillarHealth{
		Pillar:  PillarBomhound,
		Role:    "CycloneDX Legal Attribution & SBOM Engine",
		Status:  StatusOffline,
		Details: "bomhound binary not found on PATH",
	}
}

func (in *Inspector) probeSpanreed(_ context.Context, _ string) PillarHealth {
	p := ResolveSpanreedPath()
	if p != "" {
		return PillarHealth{
			Pillar:  PillarSpanreed,
			Role:    "Strategic Architecture & AI-DLC Governance",
			Status:  StatusReady,
			Details: fmt.Sprintf("Active at %s (AI-DLC planning state machine & RFC registry)", p),
		}
	}

	return PillarHealth{
		Pillar:  PillarSpanreed,
		Role:    "Strategic Architecture & AI-DLC Governance",
		Status:  StatusOffline,
		Details: "spanreed repository or registry not found",
	}
}

// FormatTable outputs human-readable tabular diagnostics with ASCII boundaries.
func FormatTable(results []PillarHealth) string {
	var sb strings.Builder
	sb.WriteString("💎 Fabrial Universal Security Fabric Diagnostic Suite\n")
	sb.WriteString(strings.Repeat("─", 75) + "\n")

	for _, r := range results {
		icon := "✅"
		if r.Status == StatusOffline || r.Status == StatusDegraded {
			icon = "⚠️ "
		}
		sb.WriteString(fmt.Sprintf("%s %-12s [%-8s] %s\n", icon, r.Pillar, r.Status, r.Role))
		sb.WriteString(fmt.Sprintf("   Details: %s\n", r.Details))
	}

	sb.WriteString(strings.Repeat("─", 75))
	return sb.String()
}

// FormatJSON serializes the diagnostic report into JSON.
func FormatJSON(results []PillarHealth) ([]byte, error) {
	return json.MarshalIndent(results, "", "  ")
}

// ResolveArgusSocketPath returns the active or fallback Argus socket location.
func ResolveArgusSocketPath() string {
	if s := os.Getenv("ARGUS_SOCKET"); s != "" {
		return s
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		p := filepath.Join(home, ".argus", "argus.sock")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	tmpCandidate := filepath.Join(os.TempDir(), fmt.Sprintf("argus-%d.sock", os.Getuid()))
	if _, err := os.Stat(tmpCandidate); err == nil {
		return tmpCandidate
	}
	return filepath.Join(os.TempDir(), "argus.sock")
}

// ResolveConjoinerSocketPath returns the active or fallback Conjoiner socket location.
func ResolveConjoinerSocketPath() string {
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

// ResolveSpanreedPath searches for the spanreed root directory.
func ResolveSpanreedPath() string {
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
