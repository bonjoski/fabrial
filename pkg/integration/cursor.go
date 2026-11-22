package integration

import "fmt"

// Cursor plans or applies the canonical Bonjoski MCP server configuration
// into Cursor (~/.cursor/mcp.json when global, or <targetDir>/.cursor/mcp.json when local).
func Cursor(targetDir string, isGlobal bool, apply bool, conjoinerWrap bool) (*MCPTargetPlan, error) {
	report, err := PlanAndApplyMCP(MCPInitOptions{
		WorktreeDir:   targetDir,
		Global:        isGlobal,
		Apply:         apply,
		ConjoinerWrap: conjoinerWrap,
		Targets:       []string{TargetCursor},
	})
	if err != nil {
		return nil, err
	}
	if len(report.Plans) == 0 {
		return nil, fmt.Errorf("cursor integration produced no plan")
	}
	return &report.Plans[0], nil
}
