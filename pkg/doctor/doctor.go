// Package doctor implements the universal multi-pillar diagnostic engine for Fabrial.
// It probes all 9 sovereign AI agent security tools concurrently with strict socket security verification.
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
	"github.com/bonjoski/fabrial/pkg/pillars"
	"github.com/bonjoski/fabrial/pkg/router"
	"github.com/bonjoski/fabrial/pkg/ux"
)

// PillarID identifies an ecosystem security component.
type PillarID string

const (
	PillarAirlock    PillarID = "Airlock"
	PillarLocksmith  PillarID = "Locksmith"
	PillarAegisbox   PillarID = "Aegisbox"
	PillarArgus      PillarID = "Argus"
	PillarHalfshard  PillarID = "Halfshard"
	PillarConjoiner  PillarID = "Conjoiner"
	PillarStormcage  PillarID = "Stormcage"
	PillarSoulcaster PillarID = "Soulcaster"
	PillarBomhound   PillarID = "Bomhound"
)

// Status represents the operational health of a pillar.
type Status string

const (
	StatusReady    Status = "READY"
	StatusOnline   Status = "ONLINE"
	StatusDegraded Status = "DEGRADED"
	StatusOffline  Status = "OFFLINE"
	StatusOptional Status = "OPTIONAL"
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
	Required   bool          `json:"required,omitempty"`
}

// CanonicalOrder defines the authoritative presentation order for all security and supply-chain tools.
var CanonicalOrder = []PillarID{
	PillarAirlock,
	PillarLocksmith,
	PillarAegisbox,
	PillarArgus,
	PillarHalfshard,
	PillarConjoiner,
	PillarStormcage,
	PillarSoulcaster,
	PillarBomhound,
}

// CoreCanonicalOrder defines the 7 always-active public security pillars (excluding optional private pillars).
var CoreCanonicalOrder = []PillarID{
	PillarAirlock,
	PillarLocksmith,
	PillarAegisbox,
	PillarArgus,
	PillarConjoiner,
	PillarSoulcaster,
	PillarBomhound,
}

// Inspector probes the health of all active sovereign security tools.
type Inspector struct {
	Timeout      time.Duration
	Resolver     *pillars.Resolver
	Requirements *pillars.Requirements
}

func (in *Inspector) resolver() *pillars.Resolver {
	if in != nil && in.Resolver != nil {
		return in.Resolver
	}
	return pillars.DefaultResolver()
}

func (in *Inspector) resolveRequirements(projectDir string) pillars.Requirements {
	if in != nil && in.Requirements != nil {
		return *in.Requirements
	}
	req, err := pillars.LoadRequirements("", projectDir)
	if err != nil {
		return pillars.Requirements{}
	}
	return req
}

// NewInspector creates an Inspector with the specified timeout.
func NewInspector(timeout time.Duration) *Inspector {
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	return &Inspector{Timeout: timeout}
}

// InspectAll concurrently probes all active pillars and returns reports in canonical order.
// Optional private pillars (Halfshard, Stormcage) follow the 3-State discovery contract:
//   - State 1 (absent & unrequired): omitted completely so public users see zero noise or score degradation.
//   - State 2 (installed on PATH): auto-discovered and probed normally.
//   - State 3 (missing but explicitly required in fabrial.yaml): included as OFFLINE with Required=true.
func (in *Inspector) InspectAll(ctx context.Context, projectDir string) []PillarHealth {
	var mu sync.Mutex
	resultsMap := make(map[PillarID]PillarHealth)
	var wg sync.WaitGroup

	req := in.resolveRequirements(projectDir)
	res := in.resolver()
	halfshardRes := res.ResolveHalfshard(req)
	stormcageRes := res.ResolveStormcage(req)

	probers := map[PillarID]func(context.Context, string) PillarHealth{
		PillarAirlock:    in.probeAirlock,
		PillarLocksmith:  in.probeLocksmith,
		PillarAegisbox:   in.probeAegisbox,
		PillarArgus:      in.probeArgus,
		PillarConjoiner:  in.probeConjoiner,
		PillarSoulcaster: in.probeSoulcaster,
		PillarBomhound:   in.probeBomhound,
	}

	if halfshardRes.IsVisible() {
		hr := halfshardRes
		probers[PillarHalfshard] = func(pCtx context.Context, _ string) PillarHealth {
			return in.probeHalfshardWithResolution(pCtx, hr)
		}
	}
	if stormcageRes.IsVisible() {
		sc := stormcageRes
		probers[PillarStormcage] = func(pCtx context.Context, _ string) PillarHealth {
			return in.probeStormcageWithResolution(pCtx, sc)
		}
	}

	for pid, probeFunc := range probers {
		wg.Add(1)
		go func(pID PillarID, fn func(context.Context, string) PillarHealth) {
			defer wg.Done()
			pCtx, cancel := context.WithTimeout(ctx, in.Timeout)
			defer cancel()

			start := time.Now()
			r := fn(pCtx, projectDir)
			r.Latency = time.Since(start)

			mu.Lock()
			resultsMap[pID] = r
			mu.Unlock()
		}(pid, probeFunc)
	}

	wg.Wait()

	// Assemble canonical ordered slice (only visible pillars)
	ordered := make([]PillarHealth, 0, len(probers))
	for _, pid := range CanonicalOrder {
		if r, ok := resultsMap[pid]; ok {
			ordered = append(ordered, r)
		}
	}

	return ordered
}

// CheckRequiredHealth inspects diagnostic results and returns a calm UB-CLI-v2 FixForwardError
// (exit 126) if any explicitly required optional pillar is missing or unhealthy.
func CheckRequiredHealth(results []PillarHealth) *ux.FixForwardError {
	for _, r := range results {
		if !r.Required {
			continue
		}
		if r.Status != StatusOffline && r.Status != StatusDegraded {
			continue
		}
		opt, ok := pillars.IsOptionalPillar(string(r.Pillar))
		if !ok {
			continue
		}
		if r.BinaryPath == "" {
			return pillars.NewRequiredMissingError(opt, r.Details)
		}
		return pillars.NewRequiredUnhealthyError(opt, r.Details)
	}
	return nil
}

// HasDegraded reports whether any reported pillar is OFFLINE or DEGRADED.
func HasDegraded(results []PillarHealth) bool {
	for _, r := range results {
		if r.Status == StatusOffline || r.Status == StatusDegraded {
			return true
		}
	}
	return false
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
	sock := ResolveLocksmithSocketPath()

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

func (in *Inspector) probeHalfshardWithResolution(_ context.Context, res pillars.Resolution) PillarHealth {
	if res.State == pillars.StateRequiredMissing {
		return PillarHealth{
			Pillar:   PillarHalfshard,
			Role:     "Secret Redaction & Fail-Closed Wire Guard",
			Status:   StatusOffline,
			Details:  "REQUIRED by fabrial.yaml (require_halfshard: true), but halfshard binary not found on PATH",
			Required: true,
		}
	}

	bin := res.BinaryPath
	proxyAddr, proxyOnline := router.DetectHalfshardProxy()

	if proxyOnline {
		details := fmt.Sprintf("Wire guard proxy active on %s", proxyAddr)
		if bin != "" {
			details = fmt.Sprintf("Wire guard proxy active on %s (binary at %s)", proxyAddr, bin)
		}
		return PillarHealth{
			Pillar:     PillarHalfshard,
			Role:       "Secret Redaction & Fail-Closed Wire Guard",
			Status:     StatusOnline,
			Details:    details,
			BinaryPath: bin,
			Required:   res.Required,
		}
	}

	if bin != "" {
		return PillarHealth{
			Pillar:     PillarHalfshard,
			Role:       "Secret Redaction & Fail-Closed Wire Guard",
			Status:     StatusDegraded,
			Details:    fmt.Sprintf("Available at %s (proxy offline; run 'fabrial daemon start' or 'halfshard proxy')", bin),
			BinaryPath: bin,
			Required:   res.Required,
		}
	}

	return PillarHealth{
		Pillar:   PillarHalfshard,
		Role:     "Secret Redaction & Fail-Closed Wire Guard",
		Status:   StatusOffline,
		Details:  "halfshard binary not found on PATH",
		Required: res.Required,
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

func (in *Inspector) probeStormcageWithResolution(ctx context.Context, res pillars.Resolution) PillarHealth {
	if res.State == pillars.StateRequiredMissing {
		return PillarHealth{
			Pillar:   PillarStormcage,
			Role:     "Context & Memory Prompt Firewall",
			Status:   StatusOffline,
			Details:  "REQUIRED by fabrial.yaml (require_stormcage: true), but stormcage binary not found on PATH",
			Required: true,
		}
	}

	bin := res.BinaryPath

	// Check if daemon is active on 127.0.0.1:8088
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", "127.0.0.1:8088")
	if err == nil {
		_ = conn.Close()
		details := "Context firewall daemon active on 127.0.0.1:8088"
		if bin != "" {
			details = fmt.Sprintf("Context firewall daemon active on 127.0.0.1:8088 (binary at %s)", bin)
		}
		return PillarHealth{
			Pillar:     PillarStormcage,
			Role:       "Context & Memory Prompt Firewall",
			Status:     StatusOnline,
			Details:    details,
			BinaryPath: bin,
			Required:   res.Required,
		}
	}

	if bin != "" {
		return PillarHealth{
			Pillar:     PillarStormcage,
			Role:       "Context & Memory Prompt Firewall",
			Status:     StatusReady,
			Details:    fmt.Sprintf("Available at %s (inline sanitizer & AST normalizer ready)", bin),
			BinaryPath: bin,
			Required:   res.Required,
		}
	}

	return PillarHealth{
		Pillar:   PillarStormcage,
		Role:     "Context & Memory Prompt Firewall",
		Status:   StatusOffline,
		Details:  "stormcage binary not found on PATH",
		Required: res.Required,
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

	hasDegraded := false
	for _, r := range results {
		if r.Status == StatusOffline || r.Status == StatusDegraded {
			hasDegraded = true
			break
		}
	}
	if hasDegraded {
		sb.WriteString("\n💡 Found degraded component(s). Run 'fabrial doctor --fix' (or 'fabrial fix') to automatically remediate.")
	}
	return sb.String()
}

// FormatJSON serializes the diagnostic report into JSON.
func FormatJSON(results []PillarHealth) ([]byte, error) {
	return json.MarshalIndent(results, "", "  ")
}

// ResolveArgusSocketPath returns the canonical user-scoped Argus socket location (~/.argus/argus.sock).
// World-writable /tmp fallbacks are strictly forbidden to prevent local socket hijacking.
func ResolveArgusSocketPath() string {
	if s := os.Getenv("ARGUS_SOCKET"); s != "" {
		return s
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return filepath.Join(home, ".argus", "argus.sock")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("argus-uid-%d", os.Getuid()), "argus.sock")
}

// ResolveConjoinerSocketPath returns the canonical user-scoped Conjoiner socket location (~/.conjoiner/conjoiner.sock).
func ResolveConjoinerSocketPath() string {
	if s := os.Getenv("CONJOINER_SOCKET"); s != "" {
		return s
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return filepath.Join(home, ".conjoiner", "conjoiner.sock")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("conjoiner-uid-%d", os.Getuid()), "conjoiner.sock")
}
