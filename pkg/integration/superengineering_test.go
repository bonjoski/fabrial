package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultCommands(t *testing.T) {
	cmds := DefaultCommands()
	if len(cmds) != 8 {
		t.Fatalf("expected 8 default commands, got %d", len(cmds))
	}

	cmdMap := make(map[string]CustomCommand)
	for _, c := range cmds {
		if c.ID == "" {
			t.Errorf("command %s has empty ID", c.Name)
		}
		if _, exists := cmdMap[c.Name]; exists {
			t.Errorf("duplicate default command name %s", c.Name)
		}
		cmdMap[c.Name] = c
	}

	// Verify fabrial-doctor uses fabrial doctor --fix
	fabrial, ok := cmdMap["fabrial-doctor"]
	if !ok {
		t.Fatal("fabrial-doctor command missing")
	}
	if fabrial.Command != "fabrial doctor --fix" {
		t.Errorf("expected fabrial-doctor command to be 'fabrial doctor --fix', got %q", fabrial.Command)
	}

	// Verify airlock-status uses airlock doctor
	airlock, ok := cmdMap["airlock-status"]
	if !ok {
		t.Fatal("airlock-status command missing")
	}
	if airlock.Command != "airlock doctor" {
		t.Errorf("expected airlock-status command to be 'airlock doctor', got %q", airlock.Command)
	}

	// Verify argus-audit uses argus vet --diff
	argus, ok := cmdMap["argus-audit"]
	if !ok {
		t.Fatal("argus-audit command missing")
	}
	if argus.Command != "argus vet --diff" {
		t.Errorf("expected argus-audit command to be 'argus vet --diff', got %q", argus.Command)
	}

	// Verify shield-status uses shield status
	shield, ok := cmdMap["shield-status"]
	if !ok {
		t.Fatal("shield-status command missing")
	}
	if shield.Command != "shield status" {
		t.Errorf("expected shield-status command to be 'shield status', got %q", shield.Command)
	}

	// Verify conjoiner-check uses fabrial session list
	conjoiner, ok := cmdMap["conjoiner-check"]
	if !ok {
		t.Fatal("conjoiner-check command missing")
	}
	if conjoiner.Command != "fabrial session list" {
		t.Errorf("expected conjoiner-check command to be 'fabrial session list', got %q", conjoiner.Command)
	}

	// Verify soulcaster-verify uses soulcaster verify-patch -base HEAD
	soulcaster, ok := cmdMap["soulcaster-verify"]
	if !ok {
		t.Fatal("soulcaster-verify command missing")
	}
	if soulcaster.Command != "soulcaster verify-patch -base HEAD" {
		t.Errorf("expected soulcaster-verify command to be 'soulcaster verify-patch -base HEAD', got %q", soulcaster.Command)
	}

	// Ensure private security-audit is NOT present in public default commands
	if _, exists := cmdMap["security-audit"]; exists {
		t.Errorf("private security-audit command should not be present in public DefaultCommands")
	}
}

func TestSuperEngineering_FreshDirectory(t *testing.T) {
	tempDir := t.TempDir()

	res, err := SuperEngineering(tempDir)
	if err != nil {
		t.Fatalf("SuperEngineering failed: %v", err)
	}

	if !res.Created {
		t.Errorf("expected Created to be true on fresh directory")
	}
	if len(res.CommandsAdded) != 8 {
		t.Errorf("expected 8 commands added, got %d", len(res.CommandsAdded))
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
	if len(cmdList) != 8 {
		t.Errorf("expected 8 commands in JSON, got %d", len(cmdList))
	}

	// Verify specific command contents in JSON
	cmdMap := make(map[string]map[string]interface{})
	for _, raw := range cmdList {
		m := raw.(map[string]interface{})
		cmdMap[m["name"].(string)] = m
	}

	if airlock, ok := cmdMap["airlock-status"]; !ok || airlock["command"] != "airlock doctor" {
		t.Errorf("expected airlock-status to have command 'airlock doctor', got %v", airlock["command"])
	}
	if argus, ok := cmdMap["argus-audit"]; !ok || argus["command"] != "argus vet --diff" {
		t.Errorf("expected argus-audit to have command 'argus vet --diff', got %v", argus["command"])
	}
	if shield, ok := cmdMap["shield-status"]; !ok || shield["command"] != "shield status" {
		t.Errorf("expected shield-status to have command 'shield status', got %v", shield["command"])
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
	if len(res2.CommandsUpdated) != 0 {
		t.Errorf("expected 0 commands updated on second run, got %d", len(res2.CommandsUpdated))
	}
	if len(res2.SetupAdded) != 0 {
		t.Errorf("expected 0 setup added on second run, got %d", len(res2.SetupAdded))
	}
	if len(res2.RunAdded) != 0 {
		t.Errorf("expected 0 run added on second run, got %d", len(res2.RunAdded))
	}

	// Third run
	res3, err := SuperEngineering(tempDir)
	if err != nil {
		t.Fatalf("third run failed: %v", err)
	}
	if len(res3.CommandsAdded) != 0 || len(res3.CommandsUpdated) != 0 {
		t.Errorf("expected 0 added/updated on third run, got %d added, %d updated",
			len(res3.CommandsAdded), len(res3.CommandsUpdated))
	}
}

func TestSuperEngineering_UpdatesExistingCommandAndPreservesID(t *testing.T) {
	tempDir := t.TempDir()
	configDir := filepath.Join(tempDir, ".super.engineering")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Pre-populate with older command versions and existing UUIDs
	existingJSON := `{
  "setup": ["fabrial doctor"],
  "commands": [
    {
      "id": "existing-airlock-uuid-1111",
      "name": "airlock-status",
      "command": "airlock status",
      "icon": "🔒"
    },
    {
      "id": "existing-argus-uuid-2222",
      "name": "argus-audit",
      "command": "argus scan .",
      "icon": "👁️"
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

	// 6 other commands added (8 defaults - 2 existing)
	if len(res.CommandsAdded) != 6 {
		t.Errorf("expected 6 commands added, got %d: %v", len(res.CommandsAdded), res.CommandsAdded)
	}

	// airlock-status and argus-audit should be updated
	if len(res.CommandsUpdated) != 2 {
		t.Errorf("expected 2 commands updated, got %d: %v", len(res.CommandsUpdated), res.CommandsUpdated)
	}

	data, err := os.ReadFile(filepath.Join(configDir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}

	cmdList := parsed["commands"].([]interface{})
	if len(cmdList) != 8 {
		t.Fatalf("expected 8 total commands, got %d", len(cmdList))
	}

	cmdMap := make(map[string]map[string]interface{})
	for _, raw := range cmdList {
		m := raw.(map[string]interface{})
		cmdMap[m["name"].(string)] = m
	}

	// airlock-status: ID preserved, command updated
	airlock := cmdMap["airlock-status"]
	if airlock["id"] != "existing-airlock-uuid-1111" {
		t.Errorf("expected ID 'existing-airlock-uuid-1111' to be preserved, got %v", airlock["id"])
	}
	if airlock["command"] != "airlock doctor" {
		t.Errorf("expected command to be updated to 'airlock doctor', got %v", airlock["command"])
	}

	// argus-audit: ID preserved, command updated
	argus := cmdMap["argus-audit"]
	if argus["id"] != "existing-argus-uuid-2222" {
		t.Errorf("expected ID 'existing-argus-uuid-2222' to be preserved, got %v", argus["id"])
	}
	if argus["command"] != "argus vet --diff" {
		t.Errorf("expected command to be updated to 'argus vet --diff', got %v", argus["command"])
	}
}

func TestSuperEngineering_Deduplication(t *testing.T) {
	tempDir := t.TempDir()
	configDir := filepath.Join(tempDir, ".super.engineering")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Pre-populate with duplicate commands having the same name
	existingJSON := `{
  "commands": [
    {
      "id": "dup-doctor-1",
      "name": "fabrial-doctor",
      "command": "fabrial doctor"
    },
    {
      "id": "dup-doctor-2",
      "name": "fabrial-doctor",
      "command": "fabrial doctor --verbose"
    },
    {
      "id": "dup-custom-1",
      "name": "custom-tool",
      "command": "echo one"
    },
    {
      "id": "dup-custom-2",
      "name": "custom-tool",
      "command": "echo two"
    },
    {
      "id": "dup-airlock-1",
      "name": "airlock-status",
      "command": "airlock status"
    },
    {
      "id": "dup-airlock-2",
      "name": "airlock-status",
      "command": "airlock status --debug"
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

	// 6 new commands added (8 defaults - 2 existing matching default names: fabrial-doctor and airlock-status)
	if len(res.CommandsAdded) != 6 {
		t.Errorf("expected 6 commands added, got %d: %v", len(res.CommandsAdded), res.CommandsAdded)
	}

	data, err := os.ReadFile(filepath.Join(configDir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}

	cmdList := parsed["commands"].([]interface{})
	// Total commands: 8 defaults + 1 custom-tool = 9
	if len(cmdList) != 9 {
		t.Fatalf("expected 9 deduplicated commands, got %d", len(cmdList))
	}

	// Count occurrences of each name
	nameCounts := make(map[string]int)
	cmdMap := make(map[string]map[string]interface{})
	for _, raw := range cmdList {
		m := raw.(map[string]interface{})
		name := m["name"].(string)
		nameCounts[name]++
		cmdMap[name] = m
	}

	for name, count := range nameCounts {
		if count > 1 {
			t.Errorf("duplicate command found for %s (count: %d)", name, count)
		}
	}

	// Verify first occurrence ID was preserved
	if cmdMap["fabrial-doctor"]["id"] != "dup-doctor-1" {
		t.Errorf("expected 'dup-doctor-1' to be preserved, got %v", cmdMap["fabrial-doctor"]["id"])
	}
	if cmdMap["custom-tool"]["id"] != "dup-custom-1" {
		t.Errorf("expected 'dup-custom-1' to be preserved, got %v", cmdMap["custom-tool"]["id"])
	}
	if cmdMap["airlock-status"]["id"] != "dup-airlock-1" {
		t.Errorf("expected 'dup-airlock-1' to be preserved, got %v", cmdMap["airlock-status"]["id"])
	}
	if cmdMap["airlock-status"]["command"] != "airlock doctor" {
		t.Errorf("expected airlock-status to be updated to 'airlock doctor', got %v", cmdMap["airlock-status"]["command"])
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
	if len(cmdList) != 9 { // 1 existing + 8 default
		t.Errorf("expected 9 commands, got %d", len(cmdList))
	}
}
