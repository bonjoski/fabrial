package main

import (
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
	out := captureOutput(func() {
		printVersion()
	})

	if !strings.Contains(out, "Fabrial Unified Fabric") {
		t.Fatalf("expected Fabrial header in version output, got: %s", out)
	}
	if !strings.Contains(out, "Locksmith") || !strings.Contains(out, "Aegisbox") || !strings.Contains(out, "Argus") {
		t.Fatalf("version output missing core pillars: %s", out)
	}
}

func TestFabrial_PrintUsage(t *testing.T) {
	out := captureOutput(func() {
		printUsage()
	})

	if !strings.Contains(out, "Fabrial — The Sovereign AI Agent Security Fabric") {
		t.Fatalf("unexpected usage output: %s", out)
	}
	if !strings.Contains(out, "--profile agent") || !strings.Contains(out, "--microvm") {
		t.Fatalf("usage missing key execution flags: %s", out)
	}
}

func TestFabrial_Doctor(t *testing.T) {
	out := captureOutput(func() {
		handleDoctor([]string{})
	})

	if !strings.Contains(out, "Fabrial Multi-Pillar Diagnostic Suite") {
		t.Fatalf("unexpected doctor output: %s", out)
	}
	for _, pillar := range []string{"Airlock", "Locksmith", "Aegisbox", "Argus"} {
		if !strings.Contains(out, pillar) {
			t.Fatalf("doctor output missing pillar %q: %s", pillar, out)
		}
	}
}

func TestFabrial_DoctorJSON(t *testing.T) {
	out := captureOutput(func() {
		handleDoctor([]string{"--json"})
	})

	if !strings.Contains(out, `"pillar":"Airlock"`) {
		t.Fatalf("expected JSON output containing Airlock pillar, got: %s", out)
	}
}

func TestFabrial_DaemonStatus(t *testing.T) {
	out := captureOutput(func() {
		handleDaemon([]string{"status"})
	})

	if !strings.Contains(out, "Fabrial Multi-Pillar Diagnostic Suite") {
		t.Fatalf("unexpected daemon status output: %s", out)
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
	sock := resolveAegisboxSocketPath()
	if !strings.HasSuffix(sock, ".aegisbox/aegisboxd.sock") {
		t.Fatalf("expected socket to end with .aegisbox/aegisboxd.sock, got: %s", sock)
	}

	// With env override
	_ = os.Setenv("AEGISBOX_SOCKET", "/tmp/custom-aegisbox.sock")
	if resolveAegisboxSocketPath() != "/tmp/custom-aegisbox.sock" {
		t.Fatalf("expected env override socket path, got: %s", resolveAegisboxSocketPath())
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

	out := captureOutput(func() {
		handleDoctor([]string{"--json"})
	})

	if !strings.Contains(out, `"pillar":"Aegisbox"`) {
		t.Fatalf("expected Aegisbox in doctor JSON: %s", out)
	}
	if !strings.Contains(out, `"status":"ONLINE"`) {
		t.Fatalf("expected Aegisbox to report ONLINE status when daemon socket is active, got: %s", out)
	}
	if !strings.Contains(out, sockPath) {
		t.Fatalf("expected doctor output to reference socket path %s, got: %s", sockPath, out)
	}
}
