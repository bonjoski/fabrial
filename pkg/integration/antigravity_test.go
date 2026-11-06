package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAntigravity_LocalIntegration(t *testing.T) {
	tempDir := t.TempDir()

	res, err := Antigravity(tempDir, false)
	if err != nil {
		t.Fatalf("Antigravity integration failed: %v", err)
	}

	if len(res.ServersAdded) != 3 {
		t.Errorf("Expected 3 servers added, got %d (%v)", len(res.ServersAdded), res.ServersAdded)
	}

	// Verify file content
	expectedPath := filepath.Join(tempDir, ".agents", "mcp_config.json")
	data, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("Failed to read %s: %v", expectedPath, err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	servers, ok := parsed["mcpServers"].(map[string]interface{})
	if !ok {
		t.Fatalf("mcpServers key missing or not a map")
	}

	for _, name := range []string{"aegisbox", "locksmith", "airlock"} {
		if _, exists := servers[name]; !exists {
			t.Errorf("Expected server %s to exist", name)
		}
	}

	// Test idempotency
	res2, err := Antigravity(tempDir, false)
	if err != nil {
		t.Fatalf("Second Antigravity integration failed: %v", err)
	}
	if len(res2.ServersAdded) != 0 {
		t.Errorf("Expected 0 servers added on re-run, got %d", len(res2.ServersAdded))
	}
}
