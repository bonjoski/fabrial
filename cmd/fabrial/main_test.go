package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bonjoski/fabrial/pkg/doctor"
	"github.com/bonjoski/fabrial/pkg/pillars"
	"github.com/bonjoski/fabrial/pkg/router"
)

func createFakePillarBin(t *testing.T, dir, name string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if runtime.GOOS == "windows" {
		p += ".exe"
	}
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write fake %s: %v", name, err)
	}
}

func captureOutput(f func()) string {
	orig := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	f()

	_ = w.Close()
	os.Stdout = orig

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

func TestFabrial_PrintVersion(t *testing.T) {
	t.Run("State1_AbsentAndUnrequired", func(t *testing.T) {
		restore := pillars.SetDefaultLookup(pillars.LookupInPATH(t.TempDir()))
		defer restore()

		out := captureOutput(func() {
			printVersion()
		})

		if !strings.Contains(out, "Fabrial Unified Fabric") {
			t.Fatalf("expected Fabrial header in version output, got: %s", out)
		}
		if !strings.Contains(out, "Locksmith") || !strings.Contains(out, "Aegisbox") || !strings.Contains(out, "Argus") {
			t.Fatalf("version output missing core pillars: %s", out)
		}
		if strings.Contains(out, "Halfshard") || strings.Contains(out, "Stormcage") {
			t.Fatalf("State 1: version output leaked absent optional pillars:\n%s", out)
		}
	})

	t.Run("State2_Installed", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		restore := pillars.SetDefaultLookup(pillars.StaticLookup(map[string]string{
			"halfshard": "/opt/homebrew/Cellar/halfshard/0.4.0/bin/halfshard",
			"stormcage": "/opt/homebrew/Cellar/stormcage/0.4.0/bin/stormcage",
		}))
		defer restore()

		out := captureOutput(func() {
			printVersion()
		})
		if !strings.Contains(out, "Halfshard") || !strings.Contains(out, "Stormcage") {
			t.Fatalf("State 2: expected Halfshard and Stormcage in version output:\n%s", out)
		}
	})
}

func TestFabrial_PrintUsage(t *testing.T) {
	restore := pillars.SetDefaultLookup(pillars.LookupInPATH(t.TempDir()))
	defer restore()

	out := captureOutput(func() {
		printUsage()
	})

	if !strings.Contains(out, "Fabrial — The Sovereign AI Agent Security Fabric") {
		t.Fatalf("unexpected usage output: %s", out)
	}
	if !strings.Contains(out, "--profile agent") || !strings.Contains(out, "--microvm") {
		t.Fatalf("usage missing key execution flags: %s", out)
	}
	if strings.Contains(out, "Halfshard") || strings.Contains(out, "Stormcage") || strings.Contains(out, "HTTP_PROXY") {
		t.Fatalf("State 1: usage output should not mention Halfshard, Stormcage, or HTTP_PROXY:\n%s", out)
	}
}

func TestFabrial_Doctor(t *testing.T) {
	t.Run("State1_AbsentOptionalPillarsOmitted", func(t *testing.T) {
		restore := pillars.SetDefaultLookup(pillars.LookupInPATH(t.TempDir()))
		defer restore()

		var stdout, stderr bytes.Buffer
		code := runDoctor([]string{}, t.TempDir(), &stdout, &stderr)
		if code != 0 {
			t.Fatalf("State 1: expected exit 0, got %d (stderr: %s)", code, stderr.String())
		}
		out := stdout.String()
		if !strings.Contains(out, "Fabrial Universal Security Fabric Diagnostic Suite") {
			t.Fatalf("unexpected doctor output: %s", out)
		}
		for _, pillar := range []string{"Airlock", "Locksmith", "Aegisbox", "Argus", "Conjoiner", "Soulcaster", "Bomhound"} {
			if !strings.Contains(out, pillar) {
				t.Fatalf("doctor output missing core pillar %q: %s", pillar, out)
			}
		}
		if strings.Contains(out, "Halfshard") || strings.Contains(out, "Stormcage") {
			t.Fatalf("State 1: doctor output leaked absent optional pillars:\n%s", out)
		}
	})

	t.Run("State2_InstalledOptionalPillarsShown", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		restore := pillars.SetDefaultLookup(pillars.StaticLookup(map[string]string{
			"halfshard": "/opt/homebrew/Cellar/halfshard/0.4.0/bin/halfshard",
			"stormcage": "/opt/homebrew/Cellar/stormcage/0.4.0/bin/stormcage",
		}))
		defer restore()

		var stdout, stderr bytes.Buffer
		code := runDoctor([]string{}, t.TempDir(), &stdout, &stderr)
		if code != 0 {
			t.Fatalf("State 2 (unrequired): expected exit 0, got %d (stderr: %s)", code, stderr.String())
		}
		out := stdout.String()
		allPillars := []string{
			"Airlock", "Locksmith", "Aegisbox", "Argus",
			"Halfshard", "Conjoiner", "Stormcage", "Soulcaster", "Bomhound",
		}
		for _, pillar := range allPillars {
			if !strings.Contains(out, pillar) {
				t.Fatalf("doctor output missing pillar %q: %s", pillar, out)
			}
		}
	})

	t.Run("State3_RequiredMissing_Exits126", func(t *testing.T) {
		restore := pillars.SetDefaultLookup(pillars.LookupInPATH(t.TempDir()))
		defer restore()

		workDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(workDir, "fabrial.yaml"), []byte("version: \"1\"\nrequire_halfshard: true\n"), 0644); err != nil {
			t.Fatalf("write fabrial.yaml: %v", err)
		}

		var stdout, stderr bytes.Buffer
		code := runDoctor([]string{}, workDir, &stdout, &stderr)
		if code != pillars.ExitCodeRequiredMissing {
			t.Fatalf("FAIL-OPEN: expected exit 126 for missing required Halfshard, got %d (stderr: %s)", code, stderr.String())
		}
		if !strings.Contains(stderr.String(), "require_halfshard") {
			t.Fatalf("expected FixForwardError mentioning require_halfshard on stderr, got: %s", stderr.String())
		}

		// Also verify runPolicy and runExec fail closed with exit 126
		var polOut, polErr bytes.Buffer
		polCode := runPolicy([]string{"status"}, workDir, &polOut, &polErr)
		if polCode != pillars.ExitCodeRequiredMissing {
			t.Fatalf("FAIL-OPEN: expected runPolicy exit 126, got %d (stderr: %s)", polCode, polErr.String())
		}

		var execOut, execErr bytes.Buffer
		execCode := runExec([]string{"--policy", filepath.Join(workDir, "fabrial.yaml"), "--", "echo", "hi"}, &execOut, &execErr)
		if execCode != pillars.ExitCodeRequiredMissing {
			t.Fatalf("FAIL-OPEN: expected runExec exit 126, got %d (stderr: %s)", execCode, execErr.String())
		}
	})
}

func TestFabrial_DoctorJSON(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	restore := pillars.SetDefaultLookup(pillars.StaticLookup(map[string]string{
		"halfshard": "/opt/homebrew/Cellar/halfshard/0.4.0/bin/halfshard",
		"stormcage": "/opt/homebrew/Cellar/stormcage/0.4.0/bin/stormcage",
	}))
	defer restore()

	var stdout, stderr bytes.Buffer
	code := runDoctor([]string{"--json"}, t.TempDir(), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr: %s)", code, stderr.String())
	}
	out := stdout.String()

	var report []doctor.PillarHealth
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("failed to unmarshal JSON output: %v (raw: %s)", err, out)
	}

	allPillars := []string{
		"Airlock", "Locksmith", "Aegisbox", "Argus",
		"Halfshard", "Conjoiner", "Stormcage", "Soulcaster", "Bomhound",
	}
	for _, pillar := range allPillars {
		found := false
		for _, p := range report {
			if string(p.Pillar) == pillar {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected JSON output containing %s pillar, got: %s", pillar, out)
		}
	}
}

func TestFabrial_DaemonStatus(t *testing.T) {
	restore := pillars.SetDefaultLookup(pillars.LookupInPATH(t.TempDir()))
	defer restore()

	var stdout, stderr bytes.Buffer
	code := runDaemon([]string{"status"}, t.TempDir(), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("State 1: expected daemon status exit 0, got %d", code)
	}
	out := stdout.String()

	if !strings.Contains(out, "Fabrial Resident Daemons Status") {
		t.Fatalf("unexpected daemon status output: %s", out)
	}
	if strings.Contains(out, "Halfshard") || strings.Contains(out, "Stormcage") {
		t.Fatalf("State 1: daemon status leaked absent optional daemons:\n%s", out)
	}
}

func TestFabrial_ResolveAegisboxSocket(t *testing.T) {
	// Without env override, should point to ~/.aegisbox/aegisboxd.sock
	origEnv := os.Getenv("AEGISBOX_SOCKET")
	defer func() {
		if origEnv != "" {
			_ = os.Setenv("AEGISBOX_SOCKET", origEnv)
		} else {
			_ = os.Unsetenv("AEGISBOX_SOCKET")
		}
	}()

	_ = os.Unsetenv("AEGISBOX_SOCKET")
	sock := router.ResolveAegisboxSocketPath()
	expectedSuffix := filepath.Join(".aegisbox", "aegisboxd.sock")
	if !strings.HasSuffix(sock, expectedSuffix) {
		t.Fatalf("expected socket to end with %s, got: %s", expectedSuffix, sock)
	}

	// With env override
	_ = os.Setenv("AEGISBOX_SOCKET", "/tmp/custom-aegisbox.sock")
	if router.ResolveAegisboxSocketPath() != "/tmp/custom-aegisbox.sock" {
		t.Fatalf("expected env override socket path, got: %s", router.ResolveAegisboxSocketPath())
	}
}

func TestFabrial_Doctor_AegisboxSocketOnline(t *testing.T) {
	// macOS Unix socket path length limit is 104 chars; keep path short in /tmp
	sockPath := filepath.Join(os.TempDir(), "agb_test.sock")
	_ = os.Remove(sockPath)

	origEnv := os.Getenv("AEGISBOX_SOCKET")
	defer func() {
		if origEnv != "" {
			_ = os.Setenv("AEGISBOX_SOCKET", origEnv)
		} else {
			_ = os.Unsetenv("AEGISBOX_SOCKET")
		}
		_ = os.Remove(sockPath)
	}()

	_ = os.Setenv("AEGISBOX_SOCKET", sockPath)

	// Create active Unix listener
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen on test socket %s: %v", sockPath, err)
	}
	defer ln.Close()
	_ = os.Chmod(sockPath, 0600)

	out := captureOutput(func() {
		handleDoctor([]string{"--json"})
	})

	var report []doctor.PillarHealth
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("failed to unmarshal doctor output: %v (raw: %s)", err, out)
	}

	found := false
	for _, p := range report {
		if p.Pillar == doctor.PillarAegisbox {
			found = true
			if p.Status != "ONLINE" {
				t.Fatalf("expected Aegisbox to report ONLINE status when daemon socket is active, got: %s", p.Status)
			}
			if !strings.Contains(p.Details, sockPath) {
				t.Fatalf("expected doctor output to reference socket path %s, got: %s", sockPath, p.Details)
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected Aegisbox in doctor JSON: %s", out)
	}
}

func TestFabrial_Doctor_AegisboxSocketOffline(t *testing.T) {
	origEnv := os.Getenv("AEGISBOX_SOCKET")
	defer func() {
		if origEnv != "" {
			_ = os.Setenv("AEGISBOX_SOCKET", origEnv)
		} else {
			_ = os.Unsetenv("AEGISBOX_SOCKET")
		}
	}()

	// Point to a guaranteed non-existent socket
	nonExistentSock := filepath.Join(os.TempDir(), "nonexistent_aegisbox.sock")
	_ = os.Remove(nonExistentSock)
	_ = os.Setenv("AEGISBOX_SOCKET", nonExistentSock)

	out := captureOutput(func() {
		handleDoctor([]string{"--json"})
	})

	var report []doctor.PillarHealth
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("failed to unmarshal doctor output: %v (raw: %s)", err, out)
	}

	found := false
	for _, p := range report {
		if p.Pillar == doctor.PillarAegisbox {
			found = true
			if p.Status != "DEGRADED" && p.Status != "OFFLINE" {
				t.Fatalf("expected Aegisbox to report DEGRADED or OFFLINE status when daemon socket is offline, got: %s", p.Status)
			}
			detailsLower := strings.ToLower(p.Details)
			if !strings.Contains(detailsLower, "offline") && !strings.Contains(detailsLower, "not found") {
				t.Fatalf("expected doctor details to mention socket is offline or not found, got: %s", p.Details)
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected Aegisbox in doctor JSON: %s", out)
	}
}

func TestReadPasswordFrom_Terminal(t *testing.T) {
	origReadPassword := readPasswordFn
	defer func() { readPasswordFn = origReadPassword }()

	readPasswordFn = func(fd int) ([]byte, error) {
		return []byte("super-secret-pass"), nil
	}

	var out bytes.Buffer
	pass, err := readPasswordFrom(strings.NewReader(""), 0, true, "Password: ", &out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if pass != "super-secret-pass" {
		t.Fatalf("expected 'super-secret-pass', got: %q", pass)
	}

	if !strings.Contains(out.String(), "Password: ") {
		t.Fatalf("expected output to contain prompt, got: %q", out.String())
	}
}

func TestReadPasswordFrom_PipedNonTerminal(t *testing.T) {
	var out bytes.Buffer
	input := strings.NewReader("piped-password-123\n")

	pass, err := readPasswordFrom(input, 0, false, "Password: ", &out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if pass != "piped-password-123" {
		t.Fatalf("expected 'piped-password-123', got: %q", pass)
	}

	if !strings.Contains(out.String(), "Password: ") {
		t.Fatalf("expected output to contain prompt, got: %q", out.String())
	}
}

func TestReadTextFrom(t *testing.T) {
	var out bytes.Buffer
	input := strings.NewReader("user@example.com\n")

	text, err := readTextFrom(input, "Email: ", &out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if text != "user@example.com" {
		t.Fatalf("expected 'user@example.com', got: %q", text)
	}

	if !strings.Contains(out.String(), "Email: ") {
		t.Fatalf("expected output to contain prompt, got: %q", out.String())
	}
}

func TestFabrial_DoctorAirgap(t *testing.T) {
	t.Run("State1_AirgapJSON_NoOptionalLeak", func(t *testing.T) {
		restore := pillars.SetDefaultLookup(pillars.LookupInPATH(t.TempDir()))
		defer restore()

		var stdout, stderr bytes.Buffer
		code := runDoctor([]string{"--airgap", "--json"}, t.TempDir(), &stdout, &stderr)
		if code != 0 {
			t.Fatalf("State 1 airgap: expected exit 0, got %d (stderr: %s)", code, stderr.String())
		}
		var rep doctor.AirgapAuditReport
		if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
			t.Fatalf("failed to parse airgap JSON: %v (raw: %s)", err, stdout.String())
		}
		if !rep.AllPassed || rep.EgressDetected {
			t.Fatalf("expected passing airgap audit with zero egress, got %+v", rep)
		}
		if strings.Contains(stdout.String(), "halfshard") || strings.Contains(stdout.String(), "stormcage") {
			t.Fatalf("State 1 airgap JSON leaked absent optional pillars:\n%s", stdout.String())
		}
	})

	t.Run("State3_AirgapRequiredMissing_Exits126", func(t *testing.T) {
		restore := pillars.SetDefaultLookup(pillars.LookupInPATH(t.TempDir()))
		defer restore()

		workDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(workDir, "fabrial.yaml"), []byte("version: \"1\"\nrequire_halfshard: true\n"), 0644); err != nil {
			t.Fatalf("write fabrial.yaml: %v", err)
		}

		var stdout, stderr bytes.Buffer
		code := runDoctor([]string{"--airgap", "--json"}, workDir, &stdout, &stderr)
		if code != pillars.ExitCodeRequiredMissing {
			t.Fatalf("FAIL-OPEN: expected exit 126 in State 3 airgap, got %d (stderr: %s)", code, stderr.String())
		}
		if !strings.Contains(stderr.String(), "require_halfshard") {
			t.Fatalf("expected FixForwardError mentioning require_halfshard on stderr, got: %s", stderr.String())
		}
	})
}
