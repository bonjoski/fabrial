package integration

import "fmt"

// VSCode plans or applies the canonical Bonjoski MCP server configuration
// into VS Code / GitHub Copilot (os.UserConfigDir()/Code/User/mcp.json when global,
// or <targetDir>/.vscode/mcp.json when local), using the top-level "servers" schema
// with explicit "type": "stdio" while preserving "inputs" and user servers.
func VSCode(targetDir string, isGlobal bool, apply bool, conjoinerWrap bool) (*MCPTargetPlan, error) {
	report, err := PlanAndApplyMCP(MCPInitOptions{
		WorktreeDir:   targetDir,
		Global:        isGlobal,
		Apply:         apply,
		ConjoinerWrap: conjoinerWrap,
		Targets:       []string{TargetVSCode},
	})
	if err != nil {
		return nil, err
	}
	if len(report.Plans) == 0 {
		return nil, fmt.Errorf("vscode integration produced no plan")
	}
	return &report.Plans[0], nil
}
