package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bonjoski/fabrial/pkg/pillars"
)

func TestFabrial_TrustCommand(t *testing.T) {
	// Compile a real Go fixture with module github.com/bonjoski/shield so `fabrial trust pillar shield`
	// exercises authentic Layer 1 + Layer 2 + Layer 3 SHA-256 pinning end-to-end.
	srcDir := t.TempDir()
	pkgDir := filepath.Join(srcDir, "cmd", "shield")
	if err := os.MkdirAll(pkgDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "go.mod"), []byte("module github.com/bonjoski/shield\n\ngo 1.24\n"), 0644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "main.go"), []byte("package main\nfunc main() {}\n"), 0644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}

	binDir := t.TempDir()
	outBin := filepath.Join(binDir, "shield")
	if runtime.GOOS == "windows" {
		outBin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", outBin, "./cmd/shield")
	cmd.Dir = srcDir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build shield fixture: %v: %s", err, string(out))
	}

	storePath := filepath.Join(t.TempDir(), ".fabrial", "trusted-pillars.json")
	lookup := pillars.LookupInPATH(binDir)

	// 1. Pin shield
	var stdout, stderr bytes.Buffer
	code := runTrust([]string{"pillar", "shield", "--json"}, storePath, lookup, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runTrust pillar shield failed (code=%d): %s", code, stderr.String())
	}
	var res pillars.TrustPillarResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal trust result: %v (raw=%s)", err, stdout.String())
	}
	if res.Name != "shield" || res.ModulePath != "github.com/bonjoski/shield" || !pillars.IsValidSHA256Hex(res.SHA256) {
		t.Fatalf("unexpected trust result: %+v", res)
	}

	// 2. List pins
	stdout.Reset()
	stderr.Reset()
	code = runTrust([]string{"list"}, storePath, lookup, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), res.SHA256) {
		t.Fatalf("runTrust list failed (code=%d): out=%q err=%q", code, stdout.String(), stderr.String())
	}

	// 3. Reject shell-script trojan for stormcage
	if runtime.GOOS != "windows" {
		_ = os.WriteFile(filepath.Join(binDir, "stormcage"), []byte("#!/bin/sh\nexit 0\n"), 0755)
		stdout.Reset()
		stderr.Reset()
		if code := runTrust([]string{"pillar", "stormcage"}, storePath, lookup, &stdout, &stderr); code == 0 {
			t.Fatal("FAIL-OPEN: fabrial trust pillar accepted shell-script trojan")
		}
	}

	// 4. Remove pin
	stdout.Reset()
	stderr.Reset()
	code = runTrust([]string{"remove", "shield"}, storePath, lookup, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "Removed") {
		t.Fatalf("runTrust remove failed (code=%d): out=%q err=%q", code, stdout.String(), stderr.String())
	}
}
