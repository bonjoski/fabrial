// Package integration provides tooling to bootstrap and integrate the
// Bonjoski sovereign AI agent security fabric into developer environments,
// IDEs, and agentic desktop platforms such as super.engineering.
package integration

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// SuperEngineeringConfig represents the .super.engineering/config.json schema.
type SuperEngineeringConfig struct {
	Setup    []string                 `json:"setup,omitempty"`
	Run      []RunScript              `json:"run,omitempty"`
	Commands []CustomCommand          `json:"commands,omitempty"`
	Extra    map[string]interface{}   `json:"-"`
}

// RunScript represents an app-managed background script in super.engineering.
type RunScript struct {
	Name     string   `json:"name"`
	Commands []string `json:"commands"`
	Default  bool     `json:"default,omitempty"`
}

// CustomCommand represents a chat slash command in super.engineering.
type CustomCommand struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Command           string `json:"command"`
	DispatchMode      string `json:"dispatch_mode,omitempty"`
	ViewPreference    string `json:"view_preference,omitempty"`
	ProviderPresetKey string `json:"provider_preset_key,omitempty"`
	Icon              string `json:"icon,omitempty"`
	AutoSubmit        bool   `json:"auto_submit"`
}

// Result describes the actions performed during integration.
type Result struct {
	ConfigPath     string   `json:"config_path"`
	Created        bool     `json:"created"`
	SetupAdded     []string `json:"setup_added"`
	RunAdded       []string `json:"run_added"`
	CommandsAdded  []string `json:"commands_added"`
}

// DefaultCommands returns the canonical Bonjoski security commands for super.engineering.
func DefaultCommands() []CustomCommand {
	return []CustomCommand{
		{
			ID:                generateUUID(),
			Name:              "fabrial-doctor",
			Command:           "fabrial doctor",
			DispatchMode:      "inject_current_chat",
			ViewPreference:    "default",
			ProviderPresetKey: "none",
			Icon:              "💎",
			AutoSubmit:        true,
		},
		{
			ID:                generateUUID(),
			Name:              "argus-audit",
			Command:           "argus scan .",
			DispatchMode:      "inject_current_chat",
			ViewPreference:    "default",
			ProviderPresetKey: "none",
			Icon:              "👁️",
			AutoSubmit:        true,
		},
		{
			ID:                generateUUID(),
			Name:              "airlock-status",
			Command:           "airlock status",
			DispatchMode:      "inject_current_chat",
			ViewPreference:    "default",
			ProviderPresetKey: "none",
			Icon:              "🔒",
			AutoSubmit:        true,
		},
		{
			ID:                generateUUID(),
			Name:              "shield-status",
			Command:           "shield status",
			DispatchMode:      "inject_current_chat",
			ViewPreference:    "default",
			ProviderPresetKey: "none",
			Icon:              "🛡️",
			AutoSubmit:        true,
		},
		{
			ID:                generateUUID(),
			Name:              "conjoiner-check",
			Command:           "conjoiner version",
			DispatchMode:      "inject_current_chat",
			ViewPreference:    "default",
			ProviderPresetKey: "none",
			Icon:              "🔗",
			AutoSubmit:        true,
		},
		{
			ID:                generateUUID(),
			Name:              "stormcage-scan",
			Command:           "stormcage scan",
			DispatchMode:      "inject_current_chat",
			ViewPreference:    "default",
			ProviderPresetKey: "none",
			Icon:              "⚡",
			AutoSubmit:        true,
		},
		{
			ID:                generateUUID(),
			Name:              "soulcaster-verify",
			Command:           "soulcaster verify",
			DispatchMode:      "inject_current_chat",
			ViewPreference:    "default",
			ProviderPresetKey: "none",
			Icon:              "🔮",
			AutoSubmit:        true,
		},
		{
			ID:                generateUUID(),
			Name:              "bomhound-enrich",
			Command:           "bomhound .",
			DispatchMode:      "inject_current_chat",
			ViewPreference:    "default",
			ProviderPresetKey: "none",
			Icon:              "🐾",
			AutoSubmit:        true,
		},
		{
			ID:                generateUUID(),
			Name:              "security-audit",
			Command:           "Run an adversarial security review on recent changes using the adversarial-sentinel guidelines, checking for sandbox escapes, secrets leakage, and fail-open vulnerabilities.",
			DispatchMode:      "inject_current_chat",
			ViewPreference:    "default",
			Icon:              "⚔️",
			AutoSubmit:        true,
		},
	}
}

// SuperEngineering integrates the Bonjoski security fabric into the specified target directory.
func SuperEngineering(targetDir string) (*Result, error) {
	if targetDir == "" {
		targetDir = "."
	}

	configDir := filepath.Join(targetDir, ".super.engineering")
	configPath := filepath.Join(configDir, "config.json")

	result := &Result{
		ConfigPath: configPath,
	}

	var rawMap map[string]interface{}
	data, err := os.ReadFile(configPath)
	if err == nil {
		if err := json.Unmarshal(data, &rawMap); err != nil {
			return nil, fmt.Errorf("failed to parse existing %s: %w", configPath, err)
		}
	} else if os.IsNotExist(err) {
		rawMap = make(map[string]interface{})
		result.Created = true
	} else {
		return nil, fmt.Errorf("failed to read %s: %w", configPath, err)
	}

	// 1. Ensure setup hook has "fabrial doctor"
	var setupList []string
	if existingSetup, ok := rawMap["setup"].([]interface{}); ok {
		for _, item := range existingSetup {
			if s, ok := item.(string); ok {
				setupList = append(setupList, s)
			}
		}
	}
	hasDoctor := false
	for _, s := range setupList {
		if s == "fabrial doctor" {
			hasDoctor = true
			break
		}
	}
	if !hasDoctor {
		setupList = append(setupList, "fabrial doctor")
		result.SetupAdded = append(result.SetupAdded, "fabrial doctor")
	}
	rawMap["setup"] = setupList

	// 2. Ensure run targets has "shield"
	var runList []map[string]interface{}
	if existingRun, ok := rawMap["run"].([]interface{}); ok {
		for _, item := range existingRun {
			if m, ok := item.(map[string]interface{}); ok {
				runList = append(runList, m)
			}
		}
	}
	hasShield := false
	for _, r := range runList {
		if name, ok := r["name"].(string); ok && name == "shield" {
			hasShield = true
			break
		}
	}
	if !hasShield {
		shieldRun := map[string]interface{}{
			"name": "shield",
			"commands": []interface{}{
				"shield proxy --addr 127.0.0.1:8443 --tls",
			},
			"default": false,
		}
		runList = append(runList, shieldRun)
		result.RunAdded = append(result.RunAdded, "shield")
	}
	rawMap["run"] = runList

	// 3. Ensure shared slash commands
	var cmdList []map[string]interface{}
	if existingCmds, ok := rawMap["commands"].([]interface{}); ok {
		for _, item := range existingCmds {
			if m, ok := item.(map[string]interface{}); ok {
				cmdList = append(cmdList, m)
			}
		}
	}

	existingCmdNames := make(map[string]bool)
	for _, c := range cmdList {
		if name, ok := c["name"].(string); ok {
			existingCmdNames[name] = true
		}
	}

	for _, def := range DefaultCommands() {
		if !existingCmdNames[def.Name] {
			cmdMap := map[string]interface{}{
				"id":                  def.ID,
				"name":                def.Name,
				"command":             def.Command,
				"dispatch_mode":       def.DispatchMode,
				"view_preference":     def.ViewPreference,
				"icon":                def.Icon,
				"auto_submit":         def.AutoSubmit,
			}
			if def.ProviderPresetKey != "" {
				cmdMap["provider_preset_key"] = def.ProviderPresetKey
			}
			cmdList = append(cmdList, cmdMap)
			result.CommandsAdded = append(result.CommandsAdded, def.Name)
		}
	}
	rawMap["commands"] = cmdList

	// Write atomically
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory %s: %w", configDir, err)
	}

	marshaled, err := json.MarshalIndent(rawMap, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to encode JSON config: %w", err)
	}
	marshaled = append(marshaled, '\n')

	tmpFile := filepath.Join(configDir, fmt.Sprintf("config.%s.tmp", generateUUID()[:8]))
	if err := os.WriteFile(tmpFile, marshaled, 0644); err != nil {
		return nil, fmt.Errorf("failed to write temporary config %s: %w", tmpFile, err)
	}
	if err := os.Rename(tmpFile, configPath); err != nil {
		_ = os.Remove(tmpFile)
		return nil, fmt.Errorf("failed to atomically rename config %s: %w", configPath, err)
	}

	return result, nil
}

// SuperEngineeringGlobal installs the Bonjoski security fabric globally across all
// paths and workspaces via super.engineering App Settings using the `sc` CLI.
func SuperEngineeringGlobal() (*Result, error) {
	scPath, err := exec.LookPath("sc")
	if err != nil {
		return nil, fmt.Errorf("'sc' CLI not found in PATH; super.engineering must be running for global App Settings installation")
	}

	result := &Result{
		ConfigPath: "super.engineering App Settings (global)",
	}

	// 1. Get existing global commands to ensure idempotency
	listCmd := exec.Command(scPath, "commands", "list", "--scope", "global", "--json")
	out, err := listCmd.Output()
	existingNames := make(map[string]bool)
	if err == nil {
		var listResp struct {
			Commands []struct {
				Name string `json:"name"`
			} `json:"commands"`
		}
		if err := json.Unmarshal(out, &listResp); err == nil {
			for _, c := range listResp.Commands {
				existingNames[c.Name] = true
			}
		}
	}

	// 2. Register global commands
	for _, def := range DefaultCommands() {
		if !existingNames[def.Name] {
			args := []string{"commands", "create", def.Name, "--command", def.Command, "--scope", "global"}
			if def.ProviderPresetKey != "" {
				args = append(args, "--provider", def.ProviderPresetKey)
			}
			if def.Icon != "" {
				args = append(args, "--icon", def.Icon)
			}
			if def.AutoSubmit {
				args = append(args, "--auto-submit")
			}
			cmd := exec.Command(scPath, args...)
			if err := cmd.Run(); err == nil {
				result.CommandsAdded = append(result.CommandsAdded, def.Name)
			}
		}
	}

	// 3. Register user fallback scripts
	setupCmd := exec.Command(scPath, "project", "scripts", "set", "setup", "fabrial doctor", "--scope", "user")
	if err := setupCmd.Run(); err == nil {
		result.SetupAdded = append(result.SetupAdded, "fabrial doctor (user fallback)")
	}

	runCmd := exec.Command(scPath, "project", "scripts", "set", "run", "shield", "shield proxy --addr 127.0.0.1:8443 --tls", "--scope", "user")
	if err := runCmd.Run(); err == nil {
		result.RunAdded = append(result.RunAdded, "shield (user fallback)")
	}

	return result, nil
}

func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
