package integration

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bonjoski/fabrial/pkg/pillars"
	"github.com/bonjoski/fabrial/pkg/ux"
)

func TestDefaultCommands(t *testing.T) {
	cmds := DefaultCommands()
	if len(cmds) != 2 {
		t.Fatalf("expected 2 default commands, got %d", len(cmds))
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

	// Verify stack-doctor uses fabrial doctor --fix
	doc, ok := cmdMap["stack-doctor"]
	if !ok {
		t.Fatal("stack-doctor command missing")
	}
	if doc.Command != "fabrial doctor --fix" {
		t.Errorf("expected stack-doctor command to be 'fabrial doctor --fix', got %q", doc.Command)
	}
	if doc.Icon != "🩺" {
		t.Errorf("expected stack-doctor icon to be '🩺', got %q", doc.Icon)
	}

	// Verify pre-flight uses argus vet --diff && soulcaster verify-patch -base HEAD
	pf, ok := cmdMap["pre-flight"]
	if !ok {
		t.Fatal("pre-flight command missing")
	}
	if pf.Command != "argus vet --diff && soulcaster verify-patch -base HEAD" {
		t.Errorf("expected pre-flight command to be 'argus vet --diff && soulcaster verify-patch -base HEAD', got %q", pf.Command)
	}
	if pf.Icon != "🛡️" {
		t.Errorf("expected pre-flight icon to be '🛡️', got %q", pf.Icon)
	}

	// Ensure private security-audit is NOT present in public default commands
	if _, exists := cmdMap["security-audit"]; exists {
		t.Errorf("private security-audit command should not be present in public DefaultCommands")
	}
}

func TestSuperEngineering_FreshDirectory(t *testing.T) {
	t.Run("State1_ShieldAbsent_NoShieldRunScript", func(t *testing.T) {
		tempDir := t.TempDir()
		emptyBin := t.TempDir()
		resolver := &pillars.Resolver{Lookup: pillars.LookupInPATH(emptyBin)}

		res, err := SuperEngineeringWithResolver(tempDir, resolver)
		if err != nil {
			t.Fatalf("SuperEngineeringWithResolver failed: %v", err)
		}

		if !res.Created {
			t.Errorf("expected Created to be true on fresh directory")
		}
		if len(res.CommandsAdded) != 2 {
			t.Errorf("expected 2 commands added, got %d: %v", len(res.CommandsAdded), res.CommandsAdded)
		}
		if len(res.SetupAdded) != 1 || res.SetupAdded[0] != "fabrial doctor" {
			t.Errorf("unexpected SetupAdded: %v", res.SetupAdded)
		}
		if len(res.RunAdded) != 0 {
			t.Errorf("State 1: expected zero run scripts added when shield is absent, got: %v", res.RunAdded)
		}

		configPath := filepath.Join(tempDir, ".super.engineering", "config.json")
		data, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatalf("failed to read generated config: %v", err)
		}
		var parsed map[string]interface{}
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("invalid JSON generated: %v", err)
		}
		if _, hasRun := parsed["run"]; hasRun {
			t.Errorf("State 1: expected no 'run' key in fresh config when shield is absent, got: %v", parsed["run"])
		}
	})

	t.Run("State2_ShieldInstalled_ShieldRunScriptAdded", func(t *testing.T) {
		tempDir := t.TempDir()
		resolver := &pillars.Resolver{
			Lookup:            pillars.StaticLookup(map[string]string{"shield": "/opt/homebrew/Cellar/shield/0.4.0/bin/shield"}),
			DisableTrustStore: true,
		}

		res, err := SuperEngineeringWithResolver(tempDir, resolver)
		if err != nil {
			t.Fatalf("SuperEngineeringWithResolver failed: %v", err)
		}
		if len(res.RunAdded) != 1 || res.RunAdded[0] != "shield" {
			t.Errorf("State 2: expected RunAdded=[shield], got %v", res.RunAdded)
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
		if len(cmdList) != 2 {
			t.Errorf("expected 2 commands in JSON, got %d", len(cmdList))
		}

		cmdMap := make(map[string]map[string]interface{})
		for _, raw := range cmdList {
			m := raw.(map[string]interface{})
			cmdMap[m["name"].(string)] = m
		}

		if doc, ok := cmdMap["stack-doctor"]; !ok || doc["command"] != "fabrial doctor --fix" {
			t.Errorf("expected stack-doctor to have command 'fabrial doctor --fix', got %v", doc["command"])
		}
		if pf, ok := cmdMap["pre-flight"]; !ok || pf["command"] != "argus vet --diff && soulcaster verify-patch -base HEAD" {
			t.Errorf("expected pre-flight to have command 'argus vet --diff && soulcaster verify-patch -base HEAD', got %v", pf["command"])
		}
	})

	t.Run("State3_RequireShieldMissing_FailClosedExit126", func(t *testing.T) {
		tempDir := t.TempDir()
		emptyBin := t.TempDir()
		if err := os.WriteFile(filepath.Join(tempDir, "fabrial.yaml"), []byte("version: \"1\"\nrequire_shield: true\n"), 0644); err != nil {
			t.Fatalf("write fabrial.yaml: %v", err)
		}
		resolver := &pillars.Resolver{Lookup: pillars.LookupInPATH(emptyBin)}

		_, err := SuperEngineeringWithResolver(tempDir, resolver)
		if err == nil {
			t.Fatal("FAIL-OPEN: expected SuperEngineeringWithResolver to fail closed when require_shield: true and shield is missing")
		}
		var ffe *ux.FixForwardError
		if !errors.As(err, &ffe) || ffe.ExitCode != pillars.ExitCodeRequiredMissing {
			t.Fatalf("expected FixForwardError exit 126, got %v", err)
		}
	})
}

func TestSuperEngineering_PrunesDeprecatedCommands(t *testing.T) {
	tempDir := t.TempDir()
	configDir := filepath.Join(tempDir, ".super.engineering")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatal(err)
	}

	existingJSON := `{
  "commands": [
    {
      "id": "old-doc",
      "name": "fabrial-doctor",
      "command": "fabrial doctor"
    },
    {
      "id": "old-airlock",
      "name": "airlock-status",
      "command": "airlock doctor"
    },
    {
      "id": "old-shield",
      "name": "shield-status",
      "command": "shield status"
    },
    {
      "id": "old-argus",
      "name": "argus-audit",
      "command": "argus daemon status"
    },
    {
      "id": "keep-custom",
      "name": "security-audit",
      "command": "sentinel review"
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

	if len(res.CommandsRemoved) != 4 {
		t.Errorf("expected 4 deprecated commands removed, got %d: %v", len(res.CommandsRemoved), res.CommandsRemoved)
	}
	if len(res.CommandsAdded) != 2 {
		t.Errorf("expected 2 default commands added, got %d: %v", len(res.CommandsAdded), res.CommandsAdded)
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
	// Total commands: 1 preserved custom ("security-audit") + 2 defaults = 3
	if len(cmdList) != 3 {
		t.Fatalf("expected 3 commands in JSON, got %d: %v", len(cmdList), cmdList)
	}

	cmdMap := make(map[string]map[string]interface{})
	for _, raw := range cmdList {
		m := raw.(map[string]interface{})
		cmdMap[m["name"].(string)] = m
	}

	if _, exists := cmdMap["fabrial-doctor"]; exists {
		t.Errorf("fabrial-doctor should have been pruned")
	}
	if _, exists := cmdMap["airlock-status"]; exists {
		t.Errorf("airlock-status should have been pruned")
	}
	if _, exists := cmdMap["shield-status"]; exists {
		t.Errorf("shield-status should have been pruned")
	}
	if _, exists := cmdMap["argus-audit"]; exists {
		t.Errorf("argus-audit should have been pruned")
	}
	if custom, exists := cmdMap["security-audit"]; !exists || custom["id"] != "keep-custom" {
		t.Errorf("expected security-audit to be preserved with id 'keep-custom', got %v", custom)
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
	if len(res2.CommandsRemoved) != 0 {
		t.Errorf("expected 0 commands removed on second run, got %d", len(res2.CommandsRemoved))
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
	if len(res3.CommandsAdded) != 0 || len(res3.CommandsUpdated) != 0 || len(res3.CommandsRemoved) != 0 {
		t.Errorf("expected 0 added/updated/removed on third run, got %d added, %d updated, %d removed",
			len(res3.CommandsAdded), len(res3.CommandsUpdated), len(res3.CommandsRemoved))
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
      "id": "existing-doc-uuid-1111",
      "name": "stack-doctor",
      "command": "fabrial doctor",
      "icon": "💎"
    },
    {
      "id": "existing-pf-uuid-2222",
      "name": "pre-flight",
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

	if len(res.CommandsAdded) != 0 {
		t.Errorf("expected 0 commands added, got %d: %v", len(res.CommandsAdded), res.CommandsAdded)
	}

	// stack-doctor and pre-flight should be updated
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
	if len(cmdList) != 2 {
		t.Fatalf("expected 2 total commands, got %d", len(cmdList))
	}

	cmdMap := make(map[string]map[string]interface{})
	for _, raw := range cmdList {
		m := raw.(map[string]interface{})
		cmdMap[m["name"].(string)] = m
	}

	// stack-doctor: ID preserved, command updated
	doc := cmdMap["stack-doctor"]
	if doc["id"] != "existing-doc-uuid-1111" {
		t.Errorf("expected ID 'existing-doc-uuid-1111' to be preserved, got %v", doc["id"])
	}
	if doc["command"] != "fabrial doctor --fix" {
		t.Errorf("expected command to be updated to 'fabrial doctor --fix', got %v", doc["command"])
	}
	if doc["icon"] != "🩺" {
		t.Errorf("expected icon to be updated to '🩺', got %v", doc["icon"])
	}

	// pre-flight: ID preserved, command updated
	pf := cmdMap["pre-flight"]
	if pf["id"] != "existing-pf-uuid-2222" {
		t.Errorf("expected ID 'existing-pf-uuid-2222' to be preserved, got %v", pf["id"])
	}
	if pf["command"] != "argus vet --diff && soulcaster verify-patch -base HEAD" {
		t.Errorf("expected command to be updated, got %v", pf["command"])
	}
	if pf["icon"] != "🛡️" {
		t.Errorf("expected icon to be updated to '🛡️', got %v", pf["icon"])
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
      "name": "stack-doctor",
      "command": "fabrial doctor"
    },
    {
      "id": "dup-doctor-2",
      "name": "stack-doctor",
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

	// 1 new default command added (pre-flight, since stack-doctor already existed)
	if len(res.CommandsAdded) != 1 {
		t.Errorf("expected 1 command added, got %d: %v", len(res.CommandsAdded), res.CommandsAdded)
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
	// Total commands: 2 defaults (stack-doctor, pre-flight) + 1 custom-tool = 3
	if len(cmdList) != 3 {
		t.Fatalf("expected 3 deduplicated commands, got %d: %v", len(cmdList), cmdList)
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
	if cmdMap["stack-doctor"]["id"] != "dup-doctor-1" {
		t.Errorf("expected 'dup-doctor-1' to be preserved, got %v", cmdMap["stack-doctor"]["id"])
	}
	if cmdMap["custom-tool"]["id"] != "dup-custom-1" {
		t.Errorf("expected 'dup-custom-1' to be preserved, got %v", cmdMap["custom-tool"]["id"])
	}
	if cmdMap["stack-doctor"]["command"] != "fabrial doctor --fix" {
		t.Errorf("expected stack-doctor to be updated to 'fabrial doctor --fix', got %v", cmdMap["stack-doctor"]["command"])
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
	if len(cmdList) != 3 { // 1 existing custom + 2 defaults
		t.Errorf("expected 3 commands, got %d", len(cmdList))
	}
}
