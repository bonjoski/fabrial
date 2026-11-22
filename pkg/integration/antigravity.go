package integration

import (
	"fmt"
	"os"
	"path/filepath"
)

// AntigravityResult describes the actions taken during Antigravity integration.
type AntigravityResult struct {
	ConfigPath     string   `json:"config_path"`
	BackupPath     string   `json:"backup_path,omitempty"`
	ServersAdded   []string `json:"servers_added"`
	ServersUpdated []string `json:"servers_updated"`
}

// DefaultMCPServers returns the 5 canonical Bonjoski MCP server definitions.
func DefaultMCPServers() map[string]map[string]interface{} {
	specs, _ := CanonicalMCPServers(false, nil)
	out := make(map[string]map[string]interface{}, len(specs))
	for name, spec := range specs {
		out[name] = map[string]interface{}{
			"command": spec.Command,
			"args":    append([]string(nil), spec.Args...),
		}
	}
	return out
}

// Antigravity integrates the Bonjoski security MCP tools into Antigravity's configuration.
// If isGlobal is true, it writes to ~/.gemini/config/mcp_config.json.
// Otherwise, it writes to filepath.Join(targetDir, ".agents", "mcp_config.json").
func Antigravity(targetDir string, isGlobal bool) (*AntigravityResult, error) {
	report, err := PlanAndApplyMCP(MCPInitOptions{
		WorktreeDir: targetDir,
		Global:      isGlobal,
		Apply:       true,
		Targets:     []string{TargetAntigravity},
	})
	if err != nil {
		return nil, err
	}
	if len(report.Plans) == 0 {
		return nil, fmt.Errorf("antigravity integration produced no plan")
	}
	p := report.Plans[0]

	// If global, also maintain symlink for legacy/CLI paths (~/.gemini/antigravity-cli/mcp_servers.json)
	if isGlobal {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			legacyPath := filepath.Join(home, ".gemini", "antigravity-cli", "mcp_servers.json")
			if mkErr := os.MkdirAll(filepath.Dir(legacyPath), 0700); mkErr == nil {
				if rmErr := os.Remove(legacyPath); rmErr == nil || os.IsNotExist(rmErr) {
					_ = os.Symlink(p.ConfigPath, legacyPath)
				}
			}
		}
	}

	return &AntigravityResult{
		ConfigPath:     p.ConfigPath,
		BackupPath:     p.BackupPath,
		ServersAdded:   p.ServersAdded,
		ServersUpdated: p.ServersUpdated,
	}, nil
}
