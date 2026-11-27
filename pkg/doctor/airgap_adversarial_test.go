package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bonjoski/fabrial/pkg/pillars"
	"github.com/bonjoski/fabrial/pkg/ux"
)

func TestAirgapAudit_CanaryEgressFailsAudit(t *testing.T) {
	t.Run("InjectableRunner_DetectsOutboundTCPAttempt", func(t *testing.T) {
		var mu sync.Mutex
		var seenEnv []string
		var seenBin string
		var seenArgs []string

		resolver := &pillars.Resolver{
			Lookup: pillars.StaticLookup(map[string]string{
				"airlock": "/opt/homebrew/bin/airlock",
				"argus":   "/opt/homebrew/bin/argus",
			}),
			DisableTrustStore: true,
		}

		report, err := RunAirgapAudit(context.Background(), AirgapAuditOptions{
			Resolver:     resolver,
			Requirements: &pillars.Requirements{},
			ExtraTargets: []AirgapProbeTarget{
				{
					Tool:        "canary-egress",
					BinaryPath:  "/tmp/canary-egress",
					OfflineArgs: []string{"--probe"},
				},
			},
			Runner: func(ctx context.Context, bin string, args []string, env []string) AirgapCommandResult {
				// Record airlock wrapper invocation on the canary target:
				// args = ["run", "--airgap", "--", "/tmp/canary-egress", "--probe"]
				if len(args) >= 4 && args[3] == "/tmp/canary-egress" {
					mu.Lock()
					seenBin = bin
					seenArgs = append([]string(nil), args...)
					seenEnv = append([]string(nil), env...)
					mu.Unlock()
					return AirgapCommandResult{
						Stderr:   "dial tcp 192.0.2.1:443: connect: operation not permitted",
						ExitCode: 1,
						Err:      errors.New("exit status 1"),
					}
				}
				return AirgapCommandResult{
					Stdout:   "ok v1.0.0",
					ExitCode: 0,
				}
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !report.AirlockEnforced {
			t.Fatalf("expected AirlockEnforced=true when airlock is resolved")
		}
		if seenBin != "/opt/homebrew/bin/airlock" {
			t.Fatalf("expected canary to execute via airlock, got %q", seenBin)
		}
		if len(seenArgs) < 5 || seenArgs[0] != "run" || seenArgs[1] != "--airgap" || seenArgs[2] != "--" {
			t.Fatalf("expected airlock run --airgap -- <target>, got %v", seenArgs)
		}

		// Verify air-gap env sanitization.
		envMap := make(map[string]string)
		for _, kv := range seenEnv {
			if k, v, ok := strings.Cut(kv, "="); ok {
				envMap[k] = v
			}
		}
		if envMap["HTTP_PROXY"] != "" || envMap["HTTPS_PROXY"] != "" || envMap["ALL_PROXY"] != "" {
			t.Fatalf("expected proxy env vars cleared, got HTTP_PROXY=%q HTTPS_PROXY=%q ALL_PROXY=%q",
				envMap["HTTP_PROXY"], envMap["HTTPS_PROXY"], envMap["ALL_PROXY"])
		}
		if envMap["NO_PROXY"] != "*" || envMap["FABRIAL_AIRGAP"] != "1" {
			t.Fatalf("expected NO_PROXY=* and FABRIAL_AIRGAP=1, got NO_PROXY=%q FABRIAL_AIRGAP=%q",
				envMap["NO_PROXY"], envMap["FABRIAL_AIRGAP"])
		}

		if report.AllPassed {
			t.Fatalf("FAIL-OPEN: expected report.AllPassed=false when canary attempted egress")
		}
		if !report.EgressDetected {
			t.Fatalf("FAIL-OPEN: expected report.EgressDetected=true when canary attempted egress")
		}

		foundCanary := false
		for _, r := range report.Results {
			if r.Tool == "canary-egress" {
				foundCanary = true
				if r.Passed {
					t.Fatalf("expected canary-egress Passed=false")
				}
				if !r.AttemptedEgress {
					t.Fatalf("expected canary-egress AttemptedEgress=true")
				}
			}
		}
		if !foundCanary {
			t.Fatalf("canary-egress missing from report results: %+v", report.Results)
		}

		tbl := FormatAirgapTable(report)
		if !strings.Contains(tbl, "EGRESS") || !strings.Contains(tbl, "FAILED") {
			t.Fatalf("expected EGRESS and FAILED in table output:\n%s", tbl)
		}
	})

	t.Run("SwallowedEgressExitZero_StillCaught", func(t *testing.T) {
		report, err := RunAirgapAudit(context.Background(), AirgapAuditOptions{
			OnlyExtraTargets:      true,
			DisableAirlockWrapper: true,
			ExtraTargets: []AirgapProbeTarget{
				{
					Tool:        "sneaky-canary",
					BinaryPath:  "/tmp/sneaky-canary",
					OfflineArgs: []string{"version"},
				},
			},
			Runner: func(ctx context.Context, bin string, args []string, env []string) AirgapCommandResult {
				// Tool catches dial error and exits 0 silently.
				return AirgapCommandResult{
					Stdout:   "version 1.0.0\nwarning: dial tcp 1.1.1.1:443: connect: operation not permitted",
					ExitCode: 0,
				}
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if report.AllPassed || !report.EgressDetected {
			t.Fatalf("FAIL-OPEN: tool that swallowed egress error and exited 0 must still fail audit: %+v", report)
		}
	})

	t.Run("RealCompiledCanaryBinary_UnderAirlockAirgap", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("unix kernel airlock canary test skipped on windows")
		}
		airlockPath, err := exec.LookPath("airlock")
		if err != nil {
			t.Skip("airlock not installed on PATH; skipping real kernel airgap canary probe")
		}

		tmpDir := t.TempDir()
		srcPath := filepath.Join(tmpDir, "canary.go")
		binPath := filepath.Join(tmpDir, "canary")
		canarySrc := `package main
import (
	"fmt"
	"net"
	"os"
	"time"
)
func main() {
	conn, err := net.DialTimeout("tcp", "192.0.2.1:443", 500*time.Millisecond)
	if err != nil {
		fmt.Fprintf(os.Stderr, "canary egress attempt failed: %v\n", err)
		os.Exit(1)
	}
	_ = conn.Close()
	fmt.Println("egress succeeded unexpectedly")
}
`
		if err := os.WriteFile(srcPath, []byte(canarySrc), 0600); err != nil {
			t.Fatalf("write canary source: %v", err)
		}
		buildCmd := exec.Command("go", "build", "-o", binPath, srcPath)
		if out, err := buildCmd.CombinedOutput(); err != nil {
			t.Fatalf("compile canary binary: %v\n%s", err, string(out))
		}

		resolver := &pillars.Resolver{
			Lookup:            pillars.StaticLookup(map[string]string{"airlock": airlockPath}),
			DisableTrustStore: true,
		}
		report, err := RunAirgapAudit(context.Background(), AirgapAuditOptions{
			Resolver:         resolver,
			OnlyExtraTargets: true,
			PerProbeTimeout:  3 * time.Second,
			ExtraTargets: []AirgapProbeTarget{
				{
					Tool:        "real-canary",
					BinaryPath:  binPath,
					OfflineArgs: nil,
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if report.AllPassed {
			t.Fatalf("FAIL-OPEN: real canary attempting outbound TCP passed air-gap audit: %+v", report)
		}
		if !report.EgressDetected {
			t.Fatalf("expected EgressDetected=true for real canary under airlock --airgap: %+v", report)
		}
	})
}

func TestAirgapAudit_OptionalPillars_3StateContract(t *testing.T) {
	t.Run("State1_AbsentAndUnrequired_OmittedCleanly", func(t *testing.T) {
		resolver := &pillars.Resolver{
			Lookup: pillars.StaticLookup(map[string]string{
				"airlock": "/opt/homebrew/bin/airlock",
				"argus":   "/opt/homebrew/bin/argus",
			}),
			DisableTrustStore: true,
		}

		report, err := RunAirgapAudit(context.Background(), AirgapAuditOptions{
			Resolver:     resolver,
			Requirements: &pillars.Requirements{},
			Runner: func(ctx context.Context, bin string, args []string, env []string) AirgapCommandResult {
				return AirgapCommandResult{Stdout: "ok", ExitCode: 0}
			},
		})
		if err != nil {
			t.Fatalf("State 1: unexpected error: %v", err)
		}
		if !report.AllPassed || report.EgressDetected {
			t.Fatalf("State 1: expected AllPassed=true, EgressDetected=false; got %+v", report)
		}

		rawJSON, err := FormatAirgapJSON(report)
		if err != nil {
			t.Fatalf("FormatAirgapJSON failed: %v", err)
		}
		tbl := FormatAirgapTable(report)
		if strings.Contains(string(rawJSON), "halfshard") || strings.Contains(string(rawJSON), "stormcage") {
			t.Fatalf("State 1: JSON output leaked absent optional pillars:\n%s", string(rawJSON))
		}
		if strings.Contains(strings.ToLower(tbl), "halfshard") || strings.Contains(strings.ToLower(tbl), "stormcage") {
			t.Fatalf("State 1: Table output leaked absent optional pillars:\n%s", tbl)
		}
	})

	t.Run("State2_InstalledOptionalPillars_Probed", func(t *testing.T) {
		resolver := &pillars.Resolver{
			Lookup: pillars.StaticLookup(map[string]string{
				"airlock":   "/opt/homebrew/bin/airlock",
				"halfshard": "/opt/homebrew/bin/halfshard",
				"stormcage": "/opt/homebrew/bin/stormcage",
			}),
			DisableTrustStore: true,
		}

		report, err := RunAirgapAudit(context.Background(), AirgapAuditOptions{
			Resolver:     resolver,
			Requirements: &pillars.Requirements{},
			Runner: func(ctx context.Context, bin string, args []string, env []string) AirgapCommandResult {
				return AirgapCommandResult{Stdout: "ok", ExitCode: 0}
			},
		})
		if err != nil {
			t.Fatalf("State 2: unexpected error: %v", err)
		}
		if !report.AllPassed {
			t.Fatalf("State 2: expected AllPassed=true, got %+v", report)
		}
		seen := make(map[string]bool)
		for _, r := range report.Results {
			seen[r.Tool] = true
		}
		if !seen["halfshard"] || !seen["stormcage"] {
			t.Fatalf("State 2: expected halfshard and stormcage to be probed, got %+v", seen)
		}
	})

	t.Run("State3_RequiredMissing_FailsClosedExit126", func(t *testing.T) {
		resolver := &pillars.Resolver{
			Lookup:            pillars.LookupInPATH(t.TempDir()),
			DisableTrustStore: true,
		}
		req := &pillars.Requirements{
			RequireHalfshard: true,
			RequireStormcage: true,
		}

		report, err := RunAirgapAudit(context.Background(), AirgapAuditOptions{
			Resolver:     resolver,
			Requirements: req,
			Runner: func(ctx context.Context, bin string, args []string, env []string) AirgapCommandResult {
				return AirgapCommandResult{Stdout: "ok", ExitCode: 0}
			},
		})
		if err == nil {
			t.Fatalf("FAIL-OPEN: expected FixForwardError (exit 126) in State 3, got nil")
		}
		var ffe *ux.FixForwardError
		if !errors.As(err, &ffe) || ffe == nil {
			t.Fatalf("expected *ux.FixForwardError, got %T: %v", err, err)
		}
		if ffe.ExitCode != pillars.ExitCodeRequiredMissing {
			t.Fatalf("expected ExitCode 126, got %d", ffe.ExitCode)
		}
		if report == nil || report.AllPassed {
			t.Fatalf("expected populated failed report in State 3, got %+v", report)
		}
	})
}

func TestAirgapAudit_HungProbeHitsContextTimeoutCleanly(t *testing.T) {
	t.Run("InjectableHungProbe", func(t *testing.T) {
		start := time.Now()
		report, err := RunAirgapAudit(context.Background(), AirgapAuditOptions{
			OnlyExtraTargets:      true,
			DisableAirlockWrapper: true,
			PerProbeTimeout:       120 * time.Millisecond,
			ExtraTargets: []AirgapProbeTarget{
				{
					Tool:        "hung-tool",
					BinaryPath:  "/tmp/hung-tool",
					OfflineArgs: []string{"version"},
				},
			},
			Runner: func(ctx context.Context, bin string, args []string, env []string) AirgapCommandResult {
				<-ctx.Done()
				return AirgapCommandResult{
					ExitCode: -1,
					Err:      ctx.Err(),
					TimedOut: errors.Is(ctx.Err(), context.DeadlineExceeded),
				}
			},
		})
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if elapsed > 2*time.Second {
			t.Fatalf("hung probe took too long to cancel: %v", elapsed)
		}
		if report.AllPassed {
			t.Fatalf("FAIL-OPEN: expected hung probe to fail air-gap audit")
		}
		if len(report.Results) != 1 || !report.Results[0].TimedOut || report.Results[0].Passed {
			t.Fatalf("expected TimedOut=true and Passed=false, got %+v", report.Results)
		}
	})

	t.Run("RealProcessHungProbe_PGIDKilled", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("unix sleep subprocess test skipped on windows")
		}
		sleepBin, err := exec.LookPath("sleep")
		if err != nil {
			t.Skip("sleep binary not found")
		}
		start := time.Now()
		report, err := RunAirgapAudit(context.Background(), AirgapAuditOptions{
			OnlyExtraTargets:      true,
			DisableAirlockWrapper: true,
			PerProbeTimeout:       150 * time.Millisecond,
			ExtraTargets: []AirgapProbeTarget{
				{
					Tool:        "hung-sleep",
					BinaryPath:  sleepBin,
					OfflineArgs: []string{"15"},
				},
			},
		})
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if elapsed > 2*time.Second {
			t.Fatalf("hung real process did not terminate within timeout: %v", elapsed)
		}
		if report.AllPassed || len(report.Results) != 1 || !report.Results[0].TimedOut {
			t.Fatalf("expected real hung process to time out cleanly: %+v", report)
		}
	})
}

func TestAirgapAudit_BoundedOutputCapture(t *testing.T) {
	lb := &limitedBuffer{maxBytes: 64}
	big := strings.Repeat("A", 1024)
	n, err := lb.Write([]byte(big))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != len(big) {
		t.Fatalf("expected Write to report full length %d so child never hits SIGPIPE, got %d", len(big), n)
	}
	if len(lb.String()) != 64 || !lb.truncated {
		t.Fatalf("expected buffer capped at 64 bytes with truncated=true, got len=%d truncated=%v", len(lb.String()), lb.truncated)
	}
}

func TestAirgapAudit_MultiAgentConcurrency_N8_Race(t *testing.T) {
	const workers = 8
	var wg sync.WaitGroup
	errCh := make(chan error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			resolver := &pillars.Resolver{
				Lookup: pillars.StaticLookup(map[string]string{
					"airlock":   "/opt/homebrew/bin/airlock",
					"aegisbox":  "/opt/homebrew/bin/aegisbox",
					"argus":     "/opt/homebrew/bin/argus",
					"conjoiner": "/opt/homebrew/bin/conjoiner",
					"locksmith": "/opt/homebrew/bin/locksmith",
				}),
				DisableTrustStore: true,
			}
			report, err := RunAirgapAudit(context.Background(), AirgapAuditOptions{
				Resolver:     resolver,
				Requirements: &pillars.Requirements{},
				Runner: func(ctx context.Context, bin string, args []string, env []string) AirgapCommandResult {
					return AirgapCommandResult{Stdout: "v1.0.0", ExitCode: 0}
				},
			})
			if err != nil {
				errCh <- err
				return
			}
			if !report.AllPassed || report.EgressDetected || report.ProbesRun != 5 {
				errCh <- errors.New("unexpected audit outcome in concurrent worker")
				return
			}
			data, jErr := FormatAirgapJSON(report)
			if jErr != nil {
				errCh <- jErr
				return
			}
			var decoded AirgapAuditReport
			if uErr := json.Unmarshal(data, &decoded); uErr != nil {
				errCh <- uErr
				return
			}
		}(i)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent N=8 worker failed: %v", err)
	}
}
