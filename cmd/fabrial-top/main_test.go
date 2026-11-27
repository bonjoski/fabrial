package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bonjoski/fabrial/pkg/topui"
)

func TestCLI_VersionAndWhy(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"--version"}, &out, &errBuf); code != 0 {
		t.Fatalf("expected exit 0 for --version, got %d (%s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "fabrial-top") {
		t.Fatalf("expected fabrial-top version string, got %q", out.String())
	}

	out.Reset()
	if code := run([]string{"--why"}, &out, &errBuf); code != 0 {
		t.Fatalf("expected exit 0 for --why, got %d", code)
	}
	if !strings.Contains(out.String(), "0.00ms Hop Tax") {
		t.Fatalf("expected --why explanation, got %q", out.String())
	}
}

func TestCLI_SnapshotJSON(t *testing.T) {
	var out, errBuf bytes.Buffer
	tmp := t.TempDir()
	code := run([]string{"--snapshot", "--json", "--no-doctor", "--dir", tmp, "--timeout", "200ms"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("expected exit 0 for --snapshot --json, got %d (stderr=%s)", code, errBuf.String())
	}
	var snap topui.WorkstationSnapshot
	if err := json.Unmarshal(out.Bytes(), &snap); err != nil {
		t.Fatalf("invalid snapshot JSON: %v\n%s", err, out.String())
	}
	if snap.CollectedAt.IsZero() {
		t.Fatalf("expected non-zero CollectedAt timestamp")
	}
}
