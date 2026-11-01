package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSuperEngineering_FreshDirectory(t *testing.T) {
	tempDir := t.TempDir()

	res, err := SuperEngineering(tempDir)
	if err != nil {
		t.Fatalf("SuperEngineering failed: %v", err)
	}

	if !res.Created {
		t.Errorf("expected Created to be true on fresh directory")
	}
	if len(res.CommandsAdded) != 6 {
		t.Errorf("expected 6 commands added, got %d", len(res.CommandsAdded))
	}
	if len(res.SetupAdded) != 1 || res.SetupAdded[0] != "fabrial doctor" {
		t.Errorf("unexpected SetupAdded: %v", res.SetupAdded)
	}
	if len(res.RunAdded) != 1 || res.RunAdded[0] != "shield" {
		t.Errorf("unexpected RunAdded: %v", res.RunAdded)
	}

	// Verify file on disk
	configPath := filepath.Join(tempDir, ".super.engineering", "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read generated config: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON generated: %v", err)
	}

	setupList := parsed["setup"].([]interface{})
	if len(setupList) != 1 || setupList[0] != "fabrial doctor" {
		t.Errorf("unexpected setup in JSON: %v", setupList)
	}

	cmdList := parsed["commands"].([]interface{})
	if len(cmdList) != 6 {
		t.Errorf("expected 6 commands in JSON, got %d", len(cmdList))
	}
}

func TestSuperEngineering_Idempotent(t *testing.T) {
	tempDir := t.TempDir()

	// First run
	_, err := SuperEngineering(tempDir)
	if err != nil {
		t.Fatalf("first run failed: %v", err)
	}

	// Second run
	res2, err := SuperEngineering(tempDir)
	if err != nil {
		t.Fatalf("second run failed: %v", err)
	}

	if res2.Created {
		t.Errorf("expected Created to be false on second run")
	}
	if len(res2.CommandsAdded) != 0 {
		t.Errorf("expected 0 commands added on second run, got %d", len(res2.CommandsAdded))
	}
	if len(res2.SetupAdded) != 0 {
		t.Errorf("expected 0 setup added on second run, got %d", len(res2.SetupAdded))
	}
	if len(res2.RunAdded) != 0 {
		t.Errorf("expected 0 run added on second run, got %d", len(res2.RunAdded))
	}
}

func TestSuperEngineering_PreservesExistingConfig(t *testing.T) {
	tempDir := t.TempDir()
	configDir := filepath.Join(tempDir, ".super.engineering")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatal(err)
	}

	existingJSON := `{
  "custom_user_key": "custom_value",
  "setup": ["npm install"],
  "commands": [
    {
      "id": "my-id-123",
      "name": "my-command",
      "command": "echo test"
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte(existingJSON), 0644); err != nil {
		t.Fatal(err)
	}

	res, err := SuperEngineering(tempDir)
	if err != nil {
		t.Fatalf("SuperEngineering failed: %v", err)
	}

	if res.Created {
		t.Errorf("expected Created to be false when config exists")
	}

	data, err := os.ReadFile(filepath.Join(configDir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}

	if parsed["custom_user_key"] != "custom_value" {
		t.Errorf("expected custom_user_key to be preserved, got %v", parsed["custom_user_key"])
	}

	setupList := parsed["setup"].([]interface{})
	if len(setupList) != 2 {
		t.Errorf("expected 2 setup items (npm install + fabrial doctor), got %v", setupList)
	}

	cmdList := parsed["commands"].([]interface{})
	if len(cmdList) != 7 { // 1 existing + 6 default
		t.Errorf("expected 7 commands, got %d", len(cmdList))
	}
}
