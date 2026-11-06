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
	ConfigPath      string   `json:"config_path"`
	Created         bool     `json:"created"`
	SetupAdded      []string `json:"setup_added"`
	RunAdded        []string `json:"run_added"`
	CommandsAdded   []string `json:"commands_added"`
	CommandsUpdated []string `json:"commands_updated,omitempty"`
}

// DefaultCommands returns the canonical Bonjoski security commands for super.engineering.
func DefaultCommands() []CustomCommand {
	return []CustomCommand{
		{
			ID:                generateUUID(),
			Name:              "fabrial-doctor",
			Command:           "fabrial doctor --fix",
			DispatchMode:      "inject_current_chat",
			ViewPreference:    "default",
			ProviderPresetKey: "none",
			Icon:              "💎",
			AutoSubmit:        true,
		},
		{
			ID:                generateUUID(),
			Name:              "argus-audit",
			Command:           "argus vet --diff",
			DispatchMode:      "inject_current_chat",
			ViewPreference:    "default",
			ProviderPresetKey: "none",
			Icon:              "👁️",
			AutoSubmit:        true,
		},
		{
			ID:                generateUUID(),
			Name:              "airlock-status",
			Command:           "airlock doctor",
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
			Command:           "fabrial session list",
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
			Command:           "soulcaster verify-patch -base HEAD",
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

	// Deduplicate existing commands by name, preserving the first occurrence.
	// Commands without a name are preserved.
	var dedupedList []map[string]interface{}
	existingByName := make(map[string]map[string]interface{})
	for _, c := range cmdList {
		name, ok := c["name"].(string)
		if !ok || name == "" {
			dedupedList = append(dedupedList, c)
			continue
		}
		if _, seen := existingByName[name]; seen {
			// Duplicate command with same name: drop subsequent occurrences
			continue
		}
		existingByName[name] = c
		dedupedList = append(dedupedList, c)
	}

	// Sync default commands: update existing in-place (preserving ID) or append new
	for _, def := range DefaultCommands() {
		if existing, exists := existingByName[def.Name]; exists {
			var updated bool
			if c, ok := existing["command"].(string); !ok || c != def.Command {
				existing["command"] = def.Command
				updated = true
			}
			if dm, ok := existing["dispatch_mode"].(string); !ok || dm != def.DispatchMode {
				existing["dispatch_mode"] = def.DispatchMode
				updated = true
			}
			if vp, ok := existing["view_preference"].(string); !ok || vp != def.ViewPreference {
				existing["view_preference"] = def.ViewPreference
				updated = true
			}
			if icon, ok := existing["icon"].(string); !ok || icon != def.Icon {
				existing["icon"] = def.Icon
				updated = true
			}
			if as, ok := existing["auto_submit"].(bool); !ok || as != def.AutoSubmit {
				existing["auto_submit"] = def.AutoSubmit
				updated = true
			}
			if def.ProviderPresetKey != "" {
				if pk, ok := existing["provider_preset_key"].(string); !ok || pk != def.ProviderPresetKey {
					existing["provider_preset_key"] = def.ProviderPresetKey
					updated = true
				}
			} else {
				if _, hasKey := existing["provider_preset_key"]; hasKey {
					delete(existing, "provider_preset_key")
					updated = true
				}
			}
			// Preserve ID if non-empty; if missing/empty set to def.ID
			if id, ok := existing["id"].(string); !ok || id == "" {
				existing["id"] = def.ID
				updated = true
			}
			if updated {
				result.CommandsUpdated = append(result.CommandsUpdated, def.Name)
			}
		} else {
			cmdMap := map[string]interface{}{
				"id":              def.ID,
				"name":            def.Name,
				"command":         def.Command,
				"dispatch_mode":   def.DispatchMode,
				"view_preference": def.ViewPreference,
				"icon":            def.Icon,
				"auto_submit":     def.AutoSubmit,
			}
			if def.ProviderPresetKey != "" {
				cmdMap["provider_preset_key"] = def.ProviderPresetKey
			}
			dedupedList = append(dedupedList, cmdMap)
			existingByName[def.Name] = cmdMap
			result.CommandsAdded = append(result.CommandsAdded, def.Name)
		}
	}
	rawMap["commands"] = dedupedList

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

	type scCmdInfo struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Command    string `json:"command"`
		Dispatch   string `json:"dispatch"`
		View       string `json:"view"`
		Provider   string `json:"provider"`
		Icon       string `json:"icon"`
		AutoSubmit bool   `json:"auto_submit"`
	}

	// 1. Get existing global commands to ensure idempotency and deduplication
	listCmd := exec.Command(scPath, "commands", "list", "--scope", "global", "--json")
	out, err := listCmd.Output()
	existingByName := make(map[string][]scCmdInfo)
	if err == nil {
		var listResp struct {
			Commands []scCmdInfo `json:"commands"`
			Response struct {
				Commands []scCmdInfo `json:"commands"`
			} `json:"response"`
		}
		if err := json.Unmarshal(out, &listResp); err == nil {
			cmds := listResp.Commands
			if len(cmds) == 0 && len(listResp.Response.Commands) > 0 {
				cmds = listResp.Response.Commands
			}
			for _, c := range cmds {
				if c.Name != "" {
					existingByName[c.Name] = append(existingByName[c.Name], c)
				}
			}
		}
	}

	// 2. Deduplicate existing global commands if duplicate commands with the same name exist
	for name, entries := range existingByName {
		if len(entries) > 1 {
			// Keep entries[0], delete entries[1:]
			for _, dup := range entries[1:] {
				if dup.ID != "" {
					_ = exec.Command(scPath, "commands", "delete", dup.ID, "--scope", "global").Run()
				}
			}
			existingByName[name] = entries[:1]
		}
	}

	// 3. Register or update global commands matching by name
	for _, def := range DefaultCommands() {
		entries, exists := existingByName[def.Name]
		if exists && len(entries) > 0 {
			primary := entries[0]
			needsUpdate := primary.Command != def.Command ||
				(def.Icon != "" && primary.Icon != def.Icon) ||
				(def.ProviderPresetKey != "" && primary.Provider != def.ProviderPresetKey) ||
				primary.AutoSubmit != def.AutoSubmit

			if needsUpdate {
				updateArgs := []string{"commands", "update", primary.ID, "--scope", "global", "--command", def.Command}
				if def.ProviderPresetKey != "" {
					updateArgs = append(updateArgs, "--provider", def.ProviderPresetKey)
				} else if primary.Provider != "" {
					updateArgs = append(updateArgs, "--clear-provider")
				}
				if def.Icon != "" {
					updateArgs = append(updateArgs, "--icon", def.Icon)
				} else if primary.Icon != "" {
					updateArgs = append(updateArgs, "--clear-icon")
				}
				if def.AutoSubmit {
					updateArgs = append(updateArgs, "--auto-submit")
				} else {
					updateArgs = append(updateArgs, "--no-auto-submit")
				}
				cmd := exec.Command(scPath, updateArgs...)
				if err := cmd.Run(); err == nil {
					result.CommandsUpdated = append(result.CommandsUpdated, def.Name)
				}
			}
		} else {
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
