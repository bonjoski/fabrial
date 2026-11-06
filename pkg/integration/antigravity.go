package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// AntigravityResult describes the actions taken during Antigravity integration.
type AntigravityResult struct {
	ConfigPath     string   `json:"config_path"`
	ServersAdded   []string `json:"servers_added"`
	ServersUpdated []string `json:"servers_updated"`
}

// DefaultMCPServers returns the canonical Bonjoski MCP server definitions for Antigravity.
func DefaultMCPServers() map[string]map[string]interface{} {
	return map[string]map[string]interface{}{
		"aegisbox": {
			"command": "aegisbox",
			"args":    []string{"mcp"},
		},
		"locksmith": {
			"command": "locksmith",
			"args":    []string{"mcp"},
		},
		"airlock": {
			"command": "airlock",
			"args":    []string{"mcp"},
		},
	}
}

// Antigravity integrates the Bonjoski security MCP tools into Antigravity's configuration.
// If isGlobal is true, it writes to ~/.gemini/config/mcp_config.json.
// Otherwise, it writes to filepath.Join(targetDir, ".agents", "mcp_config.json").
func Antigravity(targetDir string, isGlobal bool) (*AntigravityResult, error) {
	var configPath string

	if isGlobal {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("unable to determine home directory: %w", err)
		}
		configPath = filepath.Join(home, ".gemini", "config", "mcp_config.json")
	} else {
		if targetDir == "" {
			targetDir = "."
		}
		configPath = filepath.Join(targetDir, ".agents", "mcp_config.json")
	}

	result := &AntigravityResult{
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
	} else {
		return nil, fmt.Errorf("failed to read %s: %w", configPath, err)
	}

	serversMap, ok := rawMap["mcpServers"].(map[string]interface{})
	if !ok || serversMap == nil {
		serversMap = make(map[string]interface{})
	}

	defaults := DefaultMCPServers()
	for name, def := range defaults {
		if existing, exists := serversMap[name]; exists {
			// Compare command and args
			existingMap, ok := existing.(map[string]interface{})
			if !ok {
				serversMap[name] = def
				result.ServersUpdated = append(result.ServersUpdated, name)
				continue
			}
			cmdMatch := existingMap["command"] == def["command"]
			if !cmdMatch {
				serversMap[name] = def
				result.ServersUpdated = append(result.ServersUpdated, name)
			}
		} else {
			serversMap[name] = def
			result.ServersAdded = append(result.ServersAdded, name)
		}
	}

	rawMap["mcpServers"] = serversMap

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory for %s: %w", configPath, err)
	}

	outData, err := json.MarshalIndent(rawMap, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize %s: %w", configPath, err)
	}

	tmpFile := fmt.Sprintf("%s.tmp.%d", configPath, os.Getpid())
	if err := os.WriteFile(tmpFile, outData, 0644); err != nil {
		return nil, fmt.Errorf("failed to write %s: %w", tmpFile, err)
	}

	if err := os.Rename(tmpFile, configPath); err != nil {
		_ = os.Remove(tmpFile)
		return nil, fmt.Errorf("failed to atomically replace %s: %w", configPath, err)
	}

	// If global, also maintain symlink for legacy/CLI paths (~/.gemini/antigravity-cli/mcp_servers.json)
	if isGlobal {
		home, _ := os.UserHomeDir()
		legacyPath := filepath.Join(home, ".gemini", "antigravity-cli", "mcp_servers.json")
		_ = os.MkdirAll(filepath.Dir(legacyPath), 0755)
		_ = os.Remove(legacyPath)
		_ = os.Symlink(configPath, legacyPath)
	}

	return result, nil
}
