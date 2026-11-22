package check

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bonjoski/fabrial/pkg/ux"
)

func TestCheck_RejectsNonLoopbackAITarget(t *testing.T) {
	dir := t.TempDir()
	hostileTargets := []string{
		"https://api.openai.com/v1",
		"http://169.254.169.254/latest/meta-data",
		"http://10.0.0.5:8080",
		"http://192.168.1.1:8080",
		"http://0.0.0.0:8080",
		"http://[::]:8080",
		"http://[::ffff:169.254.169.254]:8080",
		"http://[::ffff:127.0.0.1]:8080",
		"http://evil.com@127.0.0.1:8080",
		"http://user:pass@localhost:8080",
		"http://localhost.evil.com:8080",
		"file:///etc/passwd",
		"javascript:alert(1)",
		"gopher://127.0.0.1:6379/_INFO",
		"http://127.0.0.1:8080/\x1b]52;c;evil\x07",
	}

	for _, target := range hostileTargets {
		invoked := false
		_, err := Run(context.Background(), CheckOptions{
			Dir:      dir,
			DiffOnly: true,
			AITarget: target,
			LookPath: func(file string) (string, error) {
				invoked = true
				return "/usr/local/bin/" + file, nil
			},
			RunCommand: func(ctx context.Context, dir, binPath string, args []string) ([]byte, []byte, int, error) {
				invoked = true
				return nil, nil, 0, nil
			},
		})
		if err == nil {
			t.Fatalf("expected non-loopback/hostile --ai-target %q to be rejected fail-closed", target)
		}
		if invoked {
			t.Fatalf("commands MUST NOT run when --ai-target %q is rejected", target)
		}
		ffe, ok := err.(*ux.FixForwardError)
		if !ok {
			t.Fatalf("expected *ux.FixForwardError for %q, got %T: %v", target, err, err)
		}
		if ffe.Code != "FABRIAL_CHECK_INVALID_AI_TARGET" || ffe.RemediationCmd == "" {
			t.Fatalf("unexpected FixForwardError for %q: %+v", target, ffe)
		}
	}

	validTargets := []string{
		"http://127.0.0.1:8080",
		"http://localhost:3000/api/chat",
		"https://[::1]:8443/v1",
	}
	for _, target := range validTargets {
		got, err := ValidateLoopbackTarget(target)
		if err != nil || got == "" {
			t.Fatalf("expected valid loopback target %q to pass, got err=%v", target, err)
		}
	}
}

func TestCheck_RejectsUnsafeBaseRef(t *testing.T) {
	dir := t.TempDir()
	unsafeRefs := []string{
		"--exec=id",
		"-rf",
		"HEAD; rm -rf /",
		"HEAD && id",
		"../secret",
		"HEAD\n--flag",
	}
	for _, ref := range unsafeRefs {
		_, err := Run(context.Background(), CheckOptions{
			Dir:     dir,
			BaseRef: ref,
		})
		if err == nil {
			t.Fatalf("expected unsafe --base ref %q to fail closed", ref)
		}
		if _, ok := err.(*ux.FixForwardError); !ok {
			t.Fatalf("expected FixForwardError for unsafe base ref %q, got %T", ref, err)
		}
	}
}

func TestCheck_ANSIStrippingProvenOnlyAndSecretScrubbing(t *testing.T) {
	dir := t.TempDir()
	osc52 := "\x1b]52;c;SGVsbG8gd29ybGQ=\x07"
	csi := "\x1b[31mRED_SPOOF\x1b[0m"
	canary := "sk-live-CANARY9999999999"

	argusPayload := map[string]any{
		"findings": []map[string]any{
			{"proven": false, "summary": "UNPROVEN_NOISE_SHOULD_DROP", "fix": "ignore"},
			{"proven": "true", "summary": "STRING_TRUE_SHOULD_DROP", "fix": "ignore"},
			{"summary": "MISSING_PROVEN_SHOULD_DROP", "fix": "ignore"},
			{
				"proven":  true,
				"tool":    "argus",
				"rule_id": "ARGUS_SLOPSQUAT",
				"package": "reqeusts" + osc52,
				"summary": csi + "Hallucinated package detected with canary " + canary + osc52,
				"fix":     "pip install requests",
				"why":     "Typosquatted packages steal keys.",
			},
		},
	}
	argusJSONBytes, err := json.Marshal(argusPayload)
	if err != nil {
		t.Fatalf("failed to marshal mock argus JSON: %v", err)
	}
	argusJSON := string(argusJSONBytes)

	soulcasterJSON := `{"findings": [{"proven": false, "summary": "speculative ast warning"}]}`

	res, err := Run(context.Background(), CheckOptions{
		Dir:      dir,
		DiffOnly: true,
		LookPath: func(file string) (string, error) { return "/mock/" + file, nil },
		RunCommand: func(ctx context.Context, workdir, binPath string, args []string) ([]byte, []byte, int, error) {
			if strings.HasSuffix(binPath, "argus") {
				return []byte(argusJSON), nil, 1, nil
			}
			return []byte(soulcasterJSON), nil, 0, nil
		},
	})
	if err != nil {
		t.Fatalf("Run failed unexpectedly: %v", err)
	}
	if res.Passed {
		t.Fatal("expected Passed=false when a proven finding exists")
	}
	if res.ProvenCount != 1 || len(res.Findings) != 1 {
		t.Fatalf("expected strictly 1 proven finding (dropping 4 unproven), got %d: %+v", res.ProvenCount, res.Findings)
	}

	var humanBuf, whyBuf, jsonBuf bytes.Buffer
	if err := res.Render(&humanBuf, false, false); err != nil {
		t.Fatalf("Render human failed: %v", err)
	}
	if err := res.Render(&whyBuf, false, true); err != nil {
		t.Fatalf("Render --why failed: %v", err)
	}
	if err := res.Render(&jsonBuf, true, false); err != nil {
		t.Fatalf("Render --json failed: %v", err)
	}

	for mode, out := range map[string]string{
		"human":  humanBuf.String(),
		"--why":  whyBuf.String(),
		"--json": jsonBuf.String(),
	} {
		if strings.ContainsRune(out, 0x1b) {
			t.Fatalf("%s output contains raw ESC (0x1b): %q", mode, out)
		}
		if strings.Contains(out, "SGVsbG8") || strings.Contains(out, "[31m") {
			t.Fatalf("%s output leaked OSC52/CSI fragment: %q", mode, out)
		}
		if strings.Contains(out, canary) {
			t.Fatalf("%s output leaked canary secret %q: %q", mode, canary, out)
		}
		if strings.Contains(out, "SHOULD_DROP") || strings.Contains(out, "speculative ast warning") {
			t.Fatalf("%s output leaked unproven finding: %q", mode, out)
		}
	}

	var decoded CheckResult
	if err := json.Unmarshal(jsonBuf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid single-line JSON output: %v (raw: %q)", err, jsonBuf.String())
	}
	if decoded.ProvenCount != 1 || decoded.Passed {
		t.Fatalf("unexpected decoded JSON result: %+v", decoded)
	}
}

func TestCheck_TimeoutBounding(t *testing.T) {
	dir := t.TempDir()
	start := time.Now()

	res, err := Run(context.Background(), CheckOptions{
		Dir:      dir,
		DiffOnly: true,
		Timeout:  120 * time.Millisecond,
		LookPath: func(file string) (string, error) { return "/mock/" + file, nil },
		RunCommand: func(ctx context.Context, workdir, binPath string, args []string) ([]byte, []byte, int, error) {
			if strings.HasSuffix(binPath, "argus") {
				<-ctx.Done()
				return nil, nil, 124, ctx.Err()
			}
			return []byte(`{"findings":[]}`), nil, 0, nil
		},
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Run should record timeout gracefully without crashing, got err: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("timeout check took too long: %v", elapsed)
	}
	if len(res.Checks) != 2 || res.Checks[0].Status != "timeout" || res.Checks[1].Status != "passed" {
		t.Fatalf("expected argus=timeout and soulcaster=passed, got: %+v", res.Checks)
	}
}

func TestCheck_GracefulMissingTools(t *testing.T) {
	dir := t.TempDir()
	res, err := Run(context.Background(), CheckOptions{
		Dir:      dir,
		DiffOnly: true,
		AITarget: "http://127.0.0.1:8080",
		LookPath: func(file string) (string, error) {
			return "", errors.New("executable file not found in $PATH")
		},
	})
	if err != nil {
		t.Fatalf("missing optional tools should report gracefully, got err: %v", err)
	}
	if !res.Passed || len(res.MissingTools) != 3 {
		t.Fatalf("expected Passed=true and 3 missing tools, got: %+v", res)
	}
	if !strings.Contains(res.RemediationCmd, "brew install bonjoski/tap/argus") {
		t.Fatalf("expected brew install Fix-Forward hint, got: %q", res.RemediationCmd)
	}

	var out bytes.Buffer
	if err := res.Render(&out, false, false); err != nil {
		t.Fatalf("Render failed: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) > 3 {
		t.Fatalf("expected calm <=3-line default output when clean/skipped, got %d lines:\n%s", len(lines), out.String())
	}
}

func TestCheck_ConcurrentWorktrees_N8(t *testing.T) {
	const workers = 8
	worktrees := make([]string, workers)
	for i := 0; i < workers; i++ {
		worktrees[i] = t.TempDir()
	}

	start := time.Now()
	var wg sync.WaitGroup
	errs := make(chan error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			res, err := Run(context.Background(), CheckOptions{
				Dir:      worktrees[idx],
				DiffOnly: true,
				AITarget: fmt.Sprintf("http://127.0.0.1:%d", 18080+idx),
				LookPath: func(file string) (string, error) { return "/mock/" + file, nil },
				RunCommand: func(ctx context.Context, workdir, binPath string, args []string) ([]byte, []byte, int, error) {
					if workdir != worktrees[idx] {
						return nil, nil, 1, fmt.Errorf("worktree cross-contamination: got %s want %s", workdir, worktrees[idx])
					}
					return []byte(`{"findings":[]}`), nil, 0, nil
				},
			})
			if err != nil {
				errs <- err
				return
			}
			var buf bytes.Buffer
			if err := res.Render(&buf, true, false); err != nil {
				errs <- err
				return
			}
			var decoded CheckResult
			if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
				errs <- err
				return
			}
			if !decoded.Passed || decoded.Workspace != worktrees[idx] || len(decoded.Checks) != 3 {
				errs <- fmt.Errorf("worker %d unexpected result: %+v", idx, decoded)
			}
		}(i)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent worktree dry-run failed: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("N=8 concurrent worktree dry-runs exceeded budget: %v", elapsed)
	}
}
