package integration

import "fmt"

// ClaudeCode plans or applies the canonical Bonjoski MCP server configuration
// into Claude Code (~/.claude.json when global, or <targetDir>/.mcp.json when local).
func ClaudeCode(targetDir string, isGlobal bool, apply bool, conjoinerWrap bool) (*MCPTargetPlan, error) {
	report, err := PlanAndApplyMCP(MCPInitOptions{
		WorktreeDir:   targetDir,
		Global:        isGlobal,
		Apply:         apply,
		ConjoinerWrap: conjoinerWrap,
		Targets:       []string{TargetClaude},
	})
	if err != nil {
		return nil, err
	}
	if len(report.Plans) == 0 {
		return nil, fmt.Errorf("claude code integration produced no plan")
	}
	return &report.Plans[0], nil
}
