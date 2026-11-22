package initscan

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestScan_DetectsMultiStackAndAISDKsReadOnly(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(`module example.com/app
go 1.27.4
require (
	github.com/modelcontextprotocol/go-sdk v1.8.0
	github.com/openai/openai-go v1.0.0
)
`), 0644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{
  "name": "ai-web",
  "dependencies": {
    "@anthropic-ai/sdk": "^0.30.0",
    "@google/genai": "^1.0.0",
    "langgraph": "^0.2.0"
  }
}`), 0644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(`[project]
dependencies = ["langchain>=0.3", "mcp>=1.0", "anthropic>=0.40"]
`), 0644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte(`[package]
name = "worker"
[dependencies]
tokio = "1"
`), 0644); err != nil {
		t.Fatal(err)
	}

	res, err := Scan(ScanOptions{
		Dir: dir,
		LookPath: func(bin string) (string, error) {
			if bin == "airlock" || bin == "argus" || bin == "locksmith" {
				return "/usr/local/bin/" + bin, nil
			}
			return "", errors.New("not found")
		},
	})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	for _, eco := range []string{"go", "node", "python", "rust"} {
		if !slices.Contains(res.Ecosystems, eco) {
			t.Errorf("expected ecosystem %q, got %v", eco, res.Ecosystems)
		}
	}
	for _, sdk := range []string{"openai", "anthropic", "@anthropic-ai/sdk", "@google/genai", "langchain", "langgraph", "@modelcontextprotocol/sdk", "mcp"} {
		if !slices.Contains(res.AISDKs, sdk) {
			t.Errorf("expected AI SDK %q, got %v", sdk, res.AISDKs)
		}
	}

	if !res.ReadOnly || res.YAMLWritten {
		t.Fatalf("expected ReadOnly=true and YAMLWritten=false, got %+v", res)
	}
	if _, err := os.Stat(filepath.Join(dir, "fabrial.yaml")); !os.IsNotExist(err) {
		t.Fatalf("fabrial init must NOT write fabrial.yaml by default")
	}

	// Default render: <=3 lines
	var defaultBuf bytes.Buffer
	if err := res.Render(&defaultBuf, false, false); err != nil {
		t.Fatalf("Render default failed: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(defaultBuf.String(), "\n"), "\n")
	if len(lines) > 3 {
		t.Fatalf("default fabrial init render exceeded 3 lines (%d):\n%s", len(lines), defaultBuf.String())
	}

	// --why render includes AI safety capsule & aegisbox tip
	var whyBuf bytes.Buffer
	if err := res.Render(&whyBuf, false, true); err != nil {
		t.Fatalf("Render --why failed: %v", err)
	}
	if !strings.Contains(whyBuf.String(), "ai-app-and-rag-safety.capsule") || !strings.Contains(whyBuf.String(), "aegisbox test --ai-safety") {
		t.Fatalf("--why output missing AI safety tips:\n%s", whyBuf.String())
	}

	// --json render parses cleanly
	var jsonBuf bytes.Buffer
	if err := res.Render(&jsonBuf, true, false); err != nil {
		t.Fatalf("Render --json failed: %v", err)
	}
	var decoded ScanResult
	if err := json.Unmarshal(jsonBuf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(decoded.AISDKs) != len(res.AISDKs) {
		t.Fatalf("JSON mismatch: got %v, want %v", decoded.AISDKs, res.AISDKs)
	}
}

func TestScan_DetectsPlaintextEnvWithoutReadingIt(t *testing.T) {
	dir := t.TempDir()
	canary := "sk-live-DO_NOT_LEAK_CANARY"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("OPENAI_API_KEY="+canary+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	res, err := Scan(ScanOptions{
		Dir:      dir,
		LookPath: func(bin string) (string, error) { return "/usr/local/bin/" + bin, nil },
	})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if !res.HasPlaintextEnv {
		t.Fatalf("expected HasPlaintextEnv=true")
	}
	if res.NextCmd != "locksmith migrate .env" {
		t.Fatalf("expected NextCmd='locksmith migrate .env', got %q", res.NextCmd)
	}

	var buf bytes.Buffer
	_ = res.Render(&buf, false, true)
	_ = res.Render(&buf, true, false)
	if strings.Contains(buf.String(), canary) {
		t.Fatalf("canary secret leaked into fabrial init output!")
	}
}
