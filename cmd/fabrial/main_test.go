package main

import (
	"bytes"
	"io"
	"os"
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
