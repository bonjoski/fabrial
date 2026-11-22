package integration

import "fmt"

// Codex plans or applies the canonical Bonjoski MCP server configuration
// into OpenAI Codex CLI (~/.codex/config.toml when global, or
// <targetDir>/.codex/config.toml when local) using comment-preserving TOML merge.
func Codex(targetDir string, isGlobal bool, apply bool, conjoinerWrap bool) (*MCPTargetPlan, error) {
	report, err := PlanAndApplyMCP(MCPInitOptions{
		WorktreeDir:   targetDir,
		Global:        isGlobal,
		Apply:         apply,
		ConjoinerWrap: conjoinerWrap,
		Targets:       []string{TargetCodex},
	})
	if err != nil {
		return nil, err
	}
	if len(report.Plans) == 0 {
		return nil, fmt.Errorf("codex integration produced no plan")
	}
	return &report.Plans[0], nil
}
