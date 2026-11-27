package doctor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/bonjoski/fabrial/pkg/pillars"
	"github.com/bonjoski/fabrial/pkg/ux"
)

const (
	// DefaultAirgapProbeTimeout is the per-probe context deadline for air-gap hermeticity checks.
	DefaultAirgapProbeTimeout = 5 * time.Second
	// DefaultAirgapMaxOutputBytes caps stdout/stderr capture per probe at 2 MiB to prevent OOM.
	DefaultAirgapMaxOutputBytes int64 = 2 << 20
	// DefaultAirgapConcurrency bounds parallel probe execution for N=8 multi-agent safety.
	DefaultAirgapConcurrency = 4
)

// AirgapProbeResult records the empirical zero-egress hermeticity result for a single tool.
type AirgapProbeResult struct {
	Tool            string   `json:"tool"`
	BinaryPath      string   `json:"binary_path,omitempty"`
	OfflineArgs     []string `json:"offline_args"`
	Confinement     string   `json:"confinement"`
	Passed          bool     `json:"passed"`
	AttemptedEgress bool     `json:"attempted_egress"`
	TimedOut        bool     `json:"timed_out,omitempty"`
	Required        bool     `json:"required,omitempty"`
	DurationMs      int64    `json:"duration_ms"`
	ExitCode        int      `json:"exit_code"`
	Detail          string   `json:"detail"`
}

// AirgapAuditReport summarizes an empirical air-gap hermeticity audit across installed tools.
type AirgapAuditReport struct {
	Timestamp       string              `json:"timestamp"`
	AirlockEnforced bool                `json:"airlock_enforced"`
	AirlockBinary   string              `json:"airlock_binary,omitempty"`
	AllPassed       bool                `json:"all_passed"`
	EgressDetected  bool                `json:"egress_detected"`
	ProbesRun       int                 `json:"probes_run"`
	ProbesPassed    int                 `json:"probes_passed"`
	Results         []AirgapProbeResult `json:"results"`
}

// AirgapCommandResult captures the bounded outcome of a single air-gap probe invocation.
type AirgapCommandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
	TimedOut bool
}

// AirgapCommandRunner executes a single command with the given environment and returns its result.
// Injectable for deterministic unit and adversarial testing.
type AirgapCommandRunner func(ctx context.Context, bin string, args []string, env []string) AirgapCommandResult

// AirgapProbeTarget describes a binary and its offline diagnostic arguments to verify.
type AirgapProbeTarget struct {
	Tool        string
	BinaryPath  string
	OfflineArgs []string
	Optional    bool
	Required    bool
}

// AirgapAuditOptions configures RunAirgapAudit.
type AirgapAuditOptions struct {
	ProjectDir            string
	Resolver              *pillars.Resolver
	Requirements          *pillars.Requirements
	PerProbeTimeout       time.Duration
	MaxOutputBytes        int64
	Concurrency           int
	Runner                AirgapCommandRunner
	ExtraTargets          []AirgapProbeTarget
	OnlyExtraTargets      bool
	DisableAirlockWrapper bool
}

type airgapToolSpec struct {
	Tool        string
	OfflineArgs []string
	Optional    bool
}

// canonicalAirgapTools defines the ordered offline probe specs for the local toolchain.
var canonicalAirgapTools = []airgapToolSpec{
	{Tool: "airlock", OfflineArgs: []string{"version"}},
	{Tool: "aegisbox", OfflineArgs: []string{"version"}},
	{Tool: "argus", OfflineArgs: []string{"--version"}},
	{Tool: "bomhound", OfflineArgs: []string{"--version"}},
	{Tool: "conjoiner", OfflineArgs: []string{"version"}},
	{Tool: "coppermind", OfflineArgs: []string{"version"}},
	{Tool: "locksmith", OfflineArgs: []string{"version"}},
	{Tool: "soulcaster", OfflineArgs: []string{"--version"}},
	{Tool: "halfshard", OfflineArgs: []string{"version"}, Optional: true},
	{Tool: "stormcage", OfflineArgs: []string{"version"}, Optional: true},
}

// limitedBuffer caps memory captured from child stdout/stderr streams.
type limitedBuffer struct {
	buf       bytes.Buffer
	maxBytes  int64
	truncated bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	origLen := len(p)
	if l.maxBytes <= 0 {
		return origLen, nil
	}
	remaining := l.maxBytes - int64(l.buf.Len())
	if remaining <= 0 {
		l.truncated = true
		return origLen, nil
	}
	if int64(len(p)) > remaining {
		_, _ = l.buf.Write(p[:remaining])
		l.truncated = true
		return origLen, nil
	}
	_, _ = l.buf.Write(p)
	return origLen, nil
}

func (l *limitedBuffer) String() string {
	return l.buf.String()
}

// BuildAirgapEnv returns a clean child environment with all proxy variables cleared,
// NO_PROXY="*" enforced, and FABRIAL_AIRGAP=1 set.
func BuildAirgapEnv(baseEnv []string) []string {
	stripped := make([]string, 0, len(baseEnv)+9)
	for _, entry := range baseEnv {
		key, _, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		switch strings.ToUpper(strings.TrimSpace(key)) {
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FABRIAL_AIRGAP":
			continue
		default:
			stripped = append(stripped, entry)
		}
	}
	stripped = append(stripped,
		"HTTP_PROXY=",
		"HTTPS_PROXY=",
		"ALL_PROXY=",
		"http_proxy=",
		"https_proxy=",
		"all_proxy=",
		"NO_PROXY=*",
		"no_proxy=*",
		"FABRIAL_AIRGAP=1",
	)
	return stripped
}

// defaultAirgapCommandRunner executes bin directly with bounded stdout/stderr capture
// and process-group termination on context deadline expiry.
func defaultAirgapCommandRunner(maxBytes int64) AirgapCommandRunner {
	if maxBytes <= 0 {
		maxBytes = DefaultAirgapMaxOutputBytes
	}
	return func(ctx context.Context, bin string, args []string, env []string) AirgapCommandResult {
		cmd := exec.Command(bin, args...)
		cmd.Env = env
		configureAirgapCmdProcessGroup(cmd)

		var stdoutBuf limitedBuffer
		stdoutBuf.maxBytes = maxBytes
		var stderrBuf limitedBuffer
		stderrBuf.maxBytes = maxBytes
		cmd.Stdout = &stdoutBuf
		cmd.Stderr = &stderrBuf

		if err := cmd.Start(); err != nil {
			return AirgapCommandResult{
				Stdout:   stdoutBuf.String(),
				Stderr:   stderrBuf.String(),
				ExitCode: -1,
				Err:      err,
			}
		}

		waitDone := make(chan error, 1)
		go func() {
			waitDone <- cmd.Wait()
		}()

		var waitErr error
		timedOut := false
		select {
		case waitErr = <-waitDone:
		case <-ctx.Done():
			timedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
			terminateAirgapCmdProcessGroup(cmd)
			<-waitDone
			waitErr = ctx.Err()
		}

		exitCode := 0
		if waitErr != nil {
			var exitErr *exec.ExitError
			if errors.As(waitErr, &exitErr) {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = -1
			}
		}

		return AirgapCommandResult{
			Stdout:   stdoutBuf.String(),
			Stderr:   stderrBuf.String(),
			ExitCode: exitCode,
			Err:      waitErr,
			TimedOut: timedOut,
		}
	}
}

// RunAirgapAudit executes offline diagnostic/version commands for installed local toolchain
// binaries inside an airlock --airgap (network-denied) jail (when airlock is available) with
// proxy environment variables cleared and FABRIAL_AIRGAP=1 set.
//
// It strictly honors the 3-State optional pillar contract:
//   - State 1 (absent & unrequired): optional pillars are omitted completely.
//   - State 2 (installed): optional pillars are discovered and probed.
//   - State 3 (required & missing/invalid): recorded as failed with Required=true and returns
//     a *ux.FixForwardError (exit 126) alongside the report.
func RunAirgapAudit(ctx context.Context, opts AirgapAuditOptions) (*AirgapAuditReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	timeout := opts.PerProbeTimeout
	if timeout <= 0 {
		timeout = DefaultAirgapProbeTimeout
	}
	maxBytes := opts.MaxOutputBytes
	if maxBytes <= 0 {
		maxBytes = DefaultAirgapMaxOutputBytes
	}
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = DefaultAirgapConcurrency
	}

	resolver := opts.Resolver
	if resolver == nil {
		resolver = pillars.DefaultResolver()
	}

	var req pillars.Requirements
	if opts.Requirements != nil {
		req = *opts.Requirements
	} else {
		projectDir := opts.ProjectDir
		if projectDir == "" {
			projectDir = "."
		}
		if loaded, err := pillars.LoadRequirements("", projectDir); err == nil {
			req = loaded
		}
	}

	runner := opts.Runner
	if runner == nil {
		runner = defaultAirgapCommandRunner(maxBytes)
	}

	lookupFn := resolver.Lookup
	if lookupFn == nil {
		lookupFn = pillars.DefaultLookup
	}

	// Discover airlock for kernel-enforced --airgap confinement.
	airlockBin := ""
	airlockEnforced := false
	if !opts.DisableAirlockWrapper {
		if bin, err := lookupFn("airlock"); err == nil && bin != "" {
			airlockBin = bin
			airlockEnforced = true
		}
	}

	targets := make([]AirgapProbeTarget, 0, len(canonicalAirgapTools)+len(opts.ExtraTargets))
	var requiredErr *ux.FixForwardError
	var missingRequiredResults []AirgapProbeResult

	if !opts.OnlyExtraTargets {
		for _, spec := range canonicalAirgapTools {
			if spec.Optional {
				opt, ok := pillars.IsOptionalPillar(spec.Tool)
				if !ok {
					continue
				}
				res := resolver.Resolve(opt, req)
				switch res.State {
				case pillars.StateAbsent:
					// State 1: completely invisible.
					continue
				case pillars.StateRequiredMissing:
					// State 3: fail closed (exit 126).
					detail := fmt.Sprintf("REQUIRED by fabrial.yaml (%s: true), but verified %s binary not found on trusted PATH", opt.ConfigField(), spec.Tool)
					if res.Err != nil {
						detail = res.Err.Error()
					}
					missingRequiredResults = append(missingRequiredResults, AirgapProbeResult{
						Tool:        spec.Tool,
						BinaryPath:  res.BinaryPath,
						OfflineArgs: append([]string(nil), spec.OfflineArgs...),
						Confinement: "missing",
						Passed:      false,
						Required:    true,
						ExitCode:    pillars.ExitCodeRequiredMissing,
						Detail:      detail,
					})
					if requiredErr == nil {
						var ffe *ux.FixForwardError
						if errors.As(res.Err, &ffe) && ffe != nil {
							requiredErr = ffe
						} else {
							requiredErr = pillars.NewRequiredMissingError(opt, detail)
						}
					}
				case pillars.StateInstalled:
					targets = append(targets, AirgapProbeTarget{
						Tool:        spec.Tool,
						BinaryPath:  res.BinaryPath,
						OfflineArgs: append([]string(nil), spec.OfflineArgs...),
						Optional:    true,
						Required:    res.Required,
					})
				}
				continue
			}

			bin, err := lookupFn(spec.Tool)
			if err != nil || bin == "" {
				continue
			}
			targets = append(targets, AirgapProbeTarget{
				Tool:        spec.Tool,
				BinaryPath:  bin,
				OfflineArgs: append([]string(nil), spec.OfflineArgs...),
			})
		}
	}

	for _, extra := range opts.ExtraTargets {
		if strings.TrimSpace(extra.Tool) == "" || strings.TrimSpace(extra.BinaryPath) == "" {
			continue
		}
		targets = append(targets, AirgapProbeTarget{
			Tool:        extra.Tool,
			BinaryPath:  extra.BinaryPath,
			OfflineArgs: append([]string(nil), extra.OfflineArgs...),
			Optional:    extra.Optional,
			Required:    extra.Required,
		})
	}

	airgapEnv := BuildAirgapEnv(os.Environ())
	results := make([]AirgapProbeResult, len(targets))

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, target := range targets {
		wg.Add(1)
		go func(idx int, tgt AirgapProbeTarget) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			pCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			execBin := tgt.BinaryPath
			execArgs := append([]string(nil), tgt.OfflineArgs...)
			confinement := "env-airgap"

			if airlockEnforced && airlockBin != "" {
				confinement = "airlock-airgap"
				wrapped := make([]string, 0, len(tgt.OfflineArgs)+4)
				wrapped = append(wrapped, "run", "--airgap", "--", tgt.BinaryPath)
				wrapped = append(wrapped, tgt.OfflineArgs...)
				execBin = airlockBin
				execArgs = wrapped
			}

			start := time.Now()
			cmdRes := runner(pCtx, execBin, execArgs, airgapEnv)
			dur := time.Since(start)

			combined := strings.TrimSpace(strings.Join([]string{cmdRes.Stdout, cmdRes.Stderr}, "\n"))
			egressAttempted := detectEgressSignal(combined, cmdRes.ExitCode, airlockEnforced)
			timedOut := cmdRes.TimedOut || errors.Is(pCtx.Err(), context.DeadlineExceeded)

			passed := cmdRes.Err == nil && cmdRes.ExitCode == 0 && !egressAttempted && !timedOut

			detail := buildAirgapProbeDetail(tgt, cmdRes, combined, egressAttempted, timedOut, confinement)
			results[idx] = AirgapProbeResult{
				Tool:            tgt.Tool,
				BinaryPath:      tgt.BinaryPath,
				OfflineArgs:     tgt.OfflineArgs,
				Confinement:     confinement,
				Passed:          passed,
				AttemptedEgress: egressAttempted,
				TimedOut:        timedOut,
				Required:        tgt.Required,
				DurationMs:      dur.Milliseconds(),
				ExitCode:        cmdRes.ExitCode,
				Detail:          detail,
			}
		}(i, target)
	}

	wg.Wait()

	allResults := make([]AirgapProbeResult, 0, len(results)+len(missingRequiredResults))
	allResults = append(allResults, results...)
	allResults = append(allResults, missingRequiredResults...)

	allPassed := requiredErr == nil
	egressDetected := false
	probesPassed := 0

	for _, r := range allResults {
		if r.Passed {
			probesPassed++
		} else {
			allPassed = false
		}
		if r.AttemptedEgress {
			egressDetected = true
			allPassed = false
		}
	}

	report := &AirgapAuditReport{
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		AirlockEnforced: airlockEnforced,
		AirlockBinary:   airlockBin,
		AllPassed:       allPassed,
		EgressDetected:  egressDetected,
		ProbesRun:       len(allResults),
		ProbesPassed:    probesPassed,
		Results:         allResults,
	}

	if requiredErr != nil {
		return report, requiredErr
	}
	return report, nil
}

// detectEgressSignal inspects bounded probe output for evidence of outbound network or DNS
// dial attempts (including Seatbelt/Landlock EPERM denials and Go/curl/OS dial failures).
func detectEgressSignal(combinedOutput string, exitCode int, airlockEnforced bool) bool {
	lower := strings.ToLower(combinedOutput)
	if lower == "" {
		return false
	}

	// Strong signals that always indicate an attempted outbound network operation
	// (even if the binary swallowed the error and exited 0).
	strongSignals := []string{
		"dial tcp",
		"dial udp",
		"network is unreachable",
		"no route to host",
		"connect: operation not permitted",
		"socket: operation not permitted",
		"sendto: operation not permitted",
		"connect: permission denied",
		"socket: permission denied",
		"outbound network",
		"network denied",
		"egress blocked",
		"egress_attempted",
		"could not resolve host",
		"temporary failure in name resolution",
		"no such host",
		"i/o timeout",
	}
	for _, sig := range strongSignals {
		if strings.Contains(lower, sig) {
			return true
		}
	}

	// Under kernel-enforced airlock --airgap, Seatbelt/Landlock denies outbound sockets with
	// EPERM / "operation not permitted" or "airlock" denial messages on non-zero exit.
	if airlockEnforced && exitCode != 0 {
		airlockSignals := []string{
			"operation not permitted",
			"eperm",
			"network-outbound",
			"connection refused",
			"dns lookup",
		}
		for _, sig := range airlockSignals {
			if strings.Contains(lower, sig) {
				return true
			}
		}
	}

	return false
}

func buildAirgapProbeDetail(tgt AirgapProbeTarget, res AirgapCommandResult, combined string, egress, timedOut bool, confinement string) string {
	if timedOut {
		return fmt.Sprintf("probe timed out under %s confinement (possible hang or blocked socket)", confinement)
	}
	if egress {
		snippet := firstNonEmptyLine(combined, 140)
		if snippet != "" {
			return fmt.Sprintf("EGRESS ATTEMPT DETECTED under %s: %s", confinement, snippet)
		}
		return fmt.Sprintf("EGRESS ATTEMPT DETECTED under %s (exit %d)", confinement, res.ExitCode)
	}
	if res.Err != nil || res.ExitCode != 0 {
		snippet := firstNonEmptyLine(combined, 140)
		if snippet != "" {
			return fmt.Sprintf("offline probe failed (exit %d): %s", res.ExitCode, snippet)
		}
		if res.Err != nil {
			return fmt.Sprintf("offline probe failed (exit %d): %v", res.ExitCode, res.Err)
		}
		return fmt.Sprintf("offline probe failed with exit code %d", res.ExitCode)
	}
	snippet := firstNonEmptyLine(combined, 100)
	if snippet != "" {
		return fmt.Sprintf("0 egress attempts (%s) — %s", confinement, snippet)
	}
	return fmt.Sprintf("0 egress attempts (%s)", confinement)
}

func firstNonEmptyLine(s string, maxLen int) string {
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if maxLen > 0 && len(trimmed) > maxLen {
			return trimmed[:maxLen] + "..."
		}
		return trimmed
	}
	return ""
}

// FormatAirgapTable renders an AirgapAuditReport as a calm, human-readable ASCII table.
func FormatAirgapTable(report *AirgapAuditReport) string {
	if report == nil {
		return "No air-gap audit report available."
	}

	var sb strings.Builder
	sb.WriteString("💎 Fabrial Air-Gap Hermeticity Audit\n")
	sb.WriteString(strings.Repeat("─", 78) + "\n")

	if report.AirlockEnforced {
		sb.WriteString(fmt.Sprintf("Confinement: 🔒 Airlock Kernel Air-Gap (%s)\n", report.AirlockBinary))
	} else {
		sb.WriteString("Confinement: 🛡️  Environment Air-Gap (HTTP_PROXY/HTTPS_PROXY cleared, FABRIAL_AIRGAP=1)\n")
	}
	sb.WriteString(strings.Repeat("─", 78) + "\n")

	if len(report.Results) == 0 {
		sb.WriteString("No installed toolchain binaries found to probe.\n")
	} else {
		for _, r := range report.Results {
			statusTag := "PASS   "
			icon := "✅"
			switch {
			case r.AttemptedEgress:
				icon = "🚨"
				statusTag = "EGRESS "
			case r.TimedOut:
				icon = "⏱️ "
				statusTag = "TIMEOUT"
			case !r.Passed:
				icon = "❌"
				statusTag = "FAIL   "
			}
			sb.WriteString(fmt.Sprintf("%s %-12s [%s] (%dms) %s\n", icon, r.Tool, statusTag, r.DurationMs, r.Detail))
		}
	}

	sb.WriteString(strings.Repeat("─", 78) + "\n")
	if report.AllPassed && !report.EgressDetected {
		sb.WriteString(fmt.Sprintf("✅ Air-Gap Hermeticity PROVEN (%d/%d probes passed, 0 outbound egress attempts).", report.ProbesPassed, report.ProbesRun))
	} else if report.EgressDetected {
		sb.WriteString(fmt.Sprintf("🚨 Air-Gap Hermeticity FAILED: outbound network egress detected (%d/%d probes passed).", report.ProbesPassed, report.ProbesRun))
	} else {
		sb.WriteString(fmt.Sprintf("❌ Air-Gap Hermeticity FAILED (%d/%d probes passed).", report.ProbesPassed, report.ProbesRun))
	}
	return sb.String()
}

// FormatAirgapJSON serializes an AirgapAuditReport as indented JSON.
func FormatAirgapJSON(report *AirgapAuditReport) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}
