package integration

import "fmt"

// Gemini plans or applies the canonical Bonjoski MCP server configuration
// into Gemini CLI (~/.gemini/settings.json when global, or
// <targetDir>/.gemini/settings.json when local), preserving all existing
// settings keys (general, theme, selectedAuthType, hooks, and user servers).
func Gemini(targetDir string, isGlobal bool, apply bool, conjoinerWrap bool) (*MCPTargetPlan, error) {
	report, err := PlanAndApplyMCP(MCPInitOptions{
		WorktreeDir:   targetDir,
		Global:        isGlobal,
		Apply:         apply,
		ConjoinerWrap: conjoinerWrap,
		Targets:       []string{TargetGemini},
	})
	if err != nil {
		return nil, err
	}
	if len(report.Plans) == 0 {
		return nil, fmt.Errorf("gemini integration produced no plan")
	}
	return &report.Plans[0], nil
}
