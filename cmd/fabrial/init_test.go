package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bonjoski/fabrial/pkg/initscan"
	"github.com/bonjoski/fabrial/pkg/ux"
)

func TestFabrialCLI_InitReadOnlyAndFlags(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"dependencies":{"openai":"^4.0.0","@modelcontextprotocol/sdk":"^1.0.0"}}`), 0644); err != nil {
		t.Fatal(err)
	}

	// Default <=3 lines
	var out, errBuf bytes.Buffer
	code := runInit([]string{"--dir", dir}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("runInit exited %d, stderr: %s", code, errBuf.String())
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) > 3 {
		t.Fatalf("expected <=3 lines for default fabrial init, got %d:\n%s", len(lines), out.String())
	}
	if !strings.Contains(out.String(), "openai") || !strings.Contains(out.String(), "0 YAML written") {
		t.Fatalf("unexpected default init output:\n%s", out.String())
	}

	// --json
	out.Reset()
	errBuf.Reset()
	code = runInit([]string{"--dir", dir, "--json"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("runInit --json exited %d, stderr: %s", code, errBuf.String())
	}
	var res initscan.ScanResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("invalid init --json output: %v (raw: %s)", err, out.String())
	}
	if !res.ReadOnly || res.YAMLWritten {
		t.Fatalf("expected read-only zero-YAML scan, got: %+v", res)
	}

	// --why
	out.Reset()
	errBuf.Reset()
	code = runInit([]string{"--dir", dir, "--why"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("runInit --why exited %d", code)
	}
	if !strings.Contains(out.String(), "Deep Dive (--why):") || !strings.Contains(out.String(), "ai-app-and-rag-safety.capsule") {
		t.Fatalf("expected --why breakdown with AI safety tip, got:\n%s", out.String())
	}

	// Unknown flag returns UB-CLI-v2 FixForwardError JSON
	out.Reset()
	errBuf.Reset()
	code = runInit([]string{"--bogus-flag", "--json"}, &out, &errBuf)
	if code == 0 {
		t.Fatalf("expected non-zero exit for unknown flag")
	}
	var ffe ux.FixForwardError
	if err := json.Unmarshal(errBuf.Bytes(), &ffe); err != nil {
		t.Fatalf("expected FixForwardError JSON on stderr, got: %v (raw: %s)", err, errBuf.String())
	}
	if ffe.Code == "" || ffe.RemediationCmd == "" || ffe.WhyOneLiner == "" {
		t.Fatalf("FixForwardError missing required fields: %+v", ffe)
	}
}

func TestFabrialCLI_Explain(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runExplain([]string{"sandbox"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("runExplain sandbox failed: %d %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "Deep Dive (--why):") || !strings.Contains(out.String(), "Airlock") {
		t.Fatalf("unexpected explain output:\n%s", out.String())
	}
}
