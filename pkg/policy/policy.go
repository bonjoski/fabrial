// Package policy defines the standardized fabrial.yaml policy schema,
// tier definitions, and command-to-tier matching engine.
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Tier represents the isolation tier in the Sovereign Security Fabric.
type Tier int

const (
	// TierUnknown represents an unconfigured or invalid tier.
	TierUnknown Tier = 0
	// Tier1 represents Airlock kernel confinement (<15ms cold start, Seatbelt/Landlock).
	Tier1 Tier = 1
	// Tier2 represents Aegisbox MicroVM hardware virtualization (~100ms, Apple VZ/KVM).
	Tier2 Tier = 2
)

// String returns a human-readable representation of the Tier.
func (t Tier) String() string {
	switch t {
	case Tier1:
		return "Tier 1 (Airlock Kernel Sandbox)"
	case Tier2:
		return "Tier 2 (Aegisbox MicroVM)"
	default:
		return "Unknown Tier"
	}
}

// EngineName returns the primary engine name associated with the tier.
func (t Tier) EngineName() string {
	switch t {
	case Tier1:
		return "airlock"
	case Tier2:
		return "aegisbox"
	default:
		return "unknown"
	}
}

// ParseTier converts integer or string representations into a Tier enum.
func ParseTier(v any) (Tier, error) {
	switch val := v.(type) {
	case int:
		if val == 1 {
			return Tier1, nil
		}
		if val == 2 {
			return Tier2, nil
		}
		return TierUnknown, fmt.Errorf("invalid tier integer %d (expected 1 or 2)", val)
	case string:
		clean := strings.ToLower(strings.TrimSpace(val))
		switch clean {
		case "1", "tier1", "tier-1", "tier_1", "airlock", "fast":
			return Tier1, nil
		case "2", "tier2", "tier-2", "tier_2", "aegisbox", "microvm", "vm", "strict":
			return Tier2, nil
		default:
			return TierUnknown, fmt.Errorf("unknown tier name %q (expected 1, 2, tier1, tier2, airlock, or microvm)", val)
		}
	default:
		return TierUnknown, fmt.Errorf("unsupported tier value type %T", v)
	}
}

// UnmarshalYAML implements custom unmarshaling for Tier.
func (t *Tier) UnmarshalYAML(value *yaml.Node) error {
	var intVal int
	if err := value.Decode(&intVal); err == nil {
		parsed, err := ParseTier(intVal)
		if err != nil {
			return err
		}
		*t = parsed
		return nil
	}

	var strVal string
	if err := value.Decode(&strVal); err == nil {
		parsed, err := ParseTier(strVal)
		if err != nil {
			return err
		}
		*t = parsed
		return nil
	}

	return fmt.Errorf("failed to decode Tier: expected int or string, got node kind %v", value.Kind)
}

// MarshalYAML implements YAML marshaling for Tier.
func (t Tier) MarshalYAML() (any, error) {
	return int(t), nil
}

// TierDefinition specifies tools and command patterns for a specific tier.
type TierDefinition struct {
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
	Tools       []string `yaml:"tools" json:"tools"`
	Patterns    []string `yaml:"patterns,omitempty" json:"patterns,omitempty"`
}

// Rule defines an explicit matching rule mapping tools and patterns to a tier.
type Rule struct {
	Name        string   `yaml:"name,omitempty" json:"name,omitempty"`
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
	Tier        Tier     `yaml:"tier" json:"tier"`
	Tools       []string `yaml:"tools,omitempty" json:"tools,omitempty"`
	Patterns    []string `yaml:"patterns,omitempty" json:"patterns,omitempty"`
}

// RoutingConfig holds optional grouped routing configuration.
type RoutingConfig struct {
	DefaultTier Tier           `yaml:"default_tier,omitempty" json:"default_tier,omitempty"`
	Tier1       TierDefinition `yaml:"tier1,omitempty" json:"tier1,omitempty"`
	Tier2       TierDefinition `yaml:"tier2,omitempty" json:"tier2,omitempty"`
	Rules       []Rule         `yaml:"rules,omitempty" json:"rules,omitempty"`
}

// Policy defines the standardized schema for fabrial.yaml.
type Policy struct {
	Version     string         `yaml:"version" json:"version"`
	Name        string         `yaml:"name,omitempty" json:"name,omitempty"`
	DefaultTier Tier           `yaml:"default_tier,omitempty" json:"default_tier,omitempty"`
	Tier1       TierDefinition `yaml:"tier1,omitempty" json:"tier1,omitempty"`
	Tier2       TierDefinition `yaml:"tier2,omitempty" json:"tier2,omitempty"`
	Routing     *RoutingConfig `yaml:"routing,omitempty" json:"routing,omitempty"`
	Rules       []Rule         `yaml:"rules,omitempty" json:"rules,omitempty"`
}

// GetDefaultTier returns the configured default tier or Tier1 if unspecified.
func (p *Policy) GetDefaultTier() Tier {
	if p.DefaultTier != TierUnknown {
		return p.DefaultTier
	}
	if p.Routing != nil && p.Routing.DefaultTier != TierUnknown {
		return p.Routing.DefaultTier
	}
	return Tier1
}

// Match determines which Tier should execute the specified command.
// Returns the matched Tier and a descriptive rationale.
func (p *Policy) Match(cmdArgs []string) (Tier, string) {
	if len(cmdArgs) == 0 {
		return p.GetDefaultTier(), "default (no command provided)"
	}

	fullCmd := strings.TrimSpace(strings.Join(cmdArgs, " "))
	rawBin := cmdArgs[0]
	bin := filepath.Base(rawBin)

	// 1. Evaluate explicit Rules (top-level rules take precedence)
	var allRules []Rule
	allRules = append(allRules, p.Rules...)
	if p.Routing != nil {
		allRules = append(allRules, p.Routing.Rules...)
	}

	for _, rule := range allRules {
		if rule.Tier == TierUnknown {
			continue
		}
		// Match rule tools first
		for _, tool := range rule.Tools {
			if matchTool(tool, bin, rawBin, fullCmd) {
				ruleName := rule.Name
				if ruleName == "" {
					ruleName = "custom-rule"
				}
				return rule.Tier, fmt.Sprintf("rule %q matched tool %q", ruleName, tool)
			}
		}
		// Match rule patterns
		for _, pattern := range rule.Patterns {
			if matchPattern(pattern, bin, rawBin, fullCmd) {
				ruleName := rule.Name
				if ruleName == "" {
					ruleName = "custom-rule"
				}
				return rule.Tier, fmt.Sprintf("rule %q matched pattern %q", ruleName, pattern)
			}
		}
	}

	// 2. Evaluate explicit Tool definitions (Tier 1 vs Tier 2)
	// Explicit tool mapping (e.g., linters in Tier 1, package managers in Tier 2)
	// takes precedence over generic wildcard patterns (like *.py or *install*).
	tier1Defs := []TierDefinition{p.Tier1}
	if p.Routing != nil {
		tier1Defs = append(tier1Defs, p.Routing.Tier1)
	}
	tier2Defs := []TierDefinition{p.Tier2}
	if p.Routing != nil {
		tier2Defs = append(tier2Defs, p.Routing.Tier2)
	}

	// Check explicit Tier 1 tools
	for _, t1 := range tier1Defs {
		for _, tool := range t1.Tools {
			if matchTool(tool, bin, rawBin, fullCmd) {
				return Tier1, fmt.Sprintf("Tier 1 policy matched tool %q", tool)
			}
		}
	}

	// Check explicit Tier 2 tools
	for _, t2 := range tier2Defs {
		for _, tool := range t2.Tools {
			if matchTool(tool, bin, rawBin, fullCmd) {
				return Tier2, fmt.Sprintf("Tier 2 policy matched tool %q", tool)
			}
		}
	}

	// 3. Evaluate Wildcard / Glob Patterns
	// Tier 2 patterns (e.g. *.sh, *.py, *install*)
	for _, t2 := range tier2Defs {
		for _, pattern := range t2.Patterns {
			if matchPattern(pattern, bin, rawBin, fullCmd) {
				return Tier2, fmt.Sprintf("Tier 2 policy matched pattern %q", pattern)
			}
		}
	}

	// Tier 1 patterns (e.g. *lint*, *format*)
	for _, t1 := range tier1Defs {
		for _, pattern := range t1.Patterns {
			if matchPattern(pattern, bin, rawBin, fullCmd) {
				return Tier1, fmt.Sprintf("Tier 1 policy matched pattern %q", pattern)
			}
		}
	}

	// 4. Fallback to default tier
	def := p.GetDefaultTier()
	return def, fmt.Sprintf("default tier (%s)", def.String())
}

func matchTool(toolDef, bin, rawBin, fullCmd string) bool {
	toolDef = strings.TrimSpace(toolDef)
	if toolDef == "" {
		return false
	}

	// Exact binary match: "eslint" matches bin "eslint" or rawBin "/usr/bin/eslint"
	if strings.EqualFold(bin, toolDef) || strings.EqualFold(rawBin, toolDef) {
		return true
	}

	// Multi-word command prefix match: "git diff" matches "git diff HEAD~1"
	if strings.Contains(toolDef, " ") {
		if strings.EqualFold(fullCmd, toolDef) || strings.HasPrefix(strings.ToLower(fullCmd), strings.ToLower(toolDef)+" ") {
			return true
		}
	}

	return false
}

func matchPattern(pattern, bin, rawBin, fullCmd string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}

	patLower := strings.ToLower(pattern)

	// Check wildcard matching against binary name
	if matched, _ := filepath.Match(patLower, strings.ToLower(bin)); matched {
		return true
	}

	// Check wildcard matching against raw binary path
	if matched, _ := filepath.Match(patLower, strings.ToLower(rawBin)); matched {
		return true
	}

	// Check wildcard matching against full command string
	if matched, _ := filepath.Match(patLower, strings.ToLower(fullCmd)); matched {
		return true
	}

	// Simple substring wildcard fallback if not pure glob
	if strings.HasPrefix(patLower, "*") && strings.HasSuffix(patLower, "*") {
		sub := strings.Trim(patLower, "*")
		if strings.Contains(strings.ToLower(bin), sub) || strings.Contains(strings.ToLower(fullCmd), sub) {
			return true
		}
	}

	return false
}

// DefaultPolicy returns the standard baseline policy mapping sensitive tools to
// Aegisbox Tier 2 and benign linting/formatting to Airlock Tier 1.
func DefaultPolicy() *Policy {
	return &Policy{
		Version:     "1",
		Name:        "default-sovereign-fabric-policy",
		DefaultTier: Tier1,
		Tier1: TierDefinition{
			Description: "Benign linting, formatting, type checking, and read-only inspection (<15ms cold start)",
			Tools: []string{
				"eslint",
				"prettier",
				"gofmt",
				"golangci-lint",
				"black",
				"ruff",
				"flake8",
				"isort",
				"tsc",
				"rubocop",
				"shellcheck",
				"markdownlint",
				"yamllint",
				"stylua",
				"biome",
				"clippy",
				"rustfmt",
				"git diff",
				"git status",
				"git log",
				"git show",
				"git branch",
				"ls",
				"cat",
				"head",
				"tail",
				"grep",
				"rg",
				"find",
				"echo",
				"which",
			},
			Patterns: []string{
				"*lint*",
				"*format*",
				"*prettier*",
				"*check*",
				"git diff*",
				"git status*",
			},
		},
		Tier2: TierDefinition{
			Description: "Sensitive tools, package managers, network egress, and untrusted scripts (~100ms MicroVM)",
			Tools: []string{
				"npm",
				"yarn",
				"pnpm",
				"pip",
				"pip3",
				"poetry",
				"cargo",
				"gem",
				"bundle",
				"composer",
				"maven",
				"gradle",
				"go get",
				"go install",
				"python",
				"python3",
				"node",
				"ruby",
				"perl",
				"bash",
				"sh",
				"zsh",
				"curl",
				"wget",
				"nc",
				"netcat",
				"ssh",
				"scp",
				"rsync",
				"docker",
				"podman",
				"kubectl",
				"terraform",
			},
			Patterns: []string{
				"*install*",
				"*build*",
				"*.sh",
				"*.py",
				"*.js",
				"curl *",
				"wget *",
				"bash *",
				"sh *",
			},
		},
	}
}

// LoadFromFile parses a fabrial.yaml policy from an explicit file path.
func LoadFromFile(filePath string) (*Policy, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file %s: %w", filePath, err)
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("failed to parse policy file %s: %w", filePath, err)
	}

	return &p, nil
}

// PolicyFileCandidates lists standard names for repository-level fabrial policy files.
var PolicyFileCandidates = []string{
	"fabrial.yaml",
	"fabrial.yml",
	".fabrial.yaml",
	".fabrial.yml",
}

// FindPolicyFile searches for a fabrial.yaml policy starting at startDir and ascending up.
func FindPolicyFile(startDir string) (string, error) {
	if startDir == "" {
		var err error
		startDir, err = os.Getwd()
		if err != nil {
			return "", err
		}
	}

	curr := startDir
	for {
		for _, name := range PolicyFileCandidates {
			cand := filepath.Join(curr, name)
			if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
				return cand, nil
			}
		}

		// Stop if .git is located at current level
		gitDir := filepath.Join(curr, ".git")
		if fi, err := os.Stat(gitDir); err == nil && fi.IsDir() {
			break
		}

		parent := filepath.Dir(curr)
		if parent == curr || parent == "" {
			break
		}
		curr = parent
	}

	return "", nil
}

// LoadPolicy resolves and loads the active repository policy.
// If an explicit path is provided, it loads that file.
// Otherwise, it discovers a repository policy file, falling back to DefaultPolicy() if none is found.
func LoadPolicy(explicitPath, startDir string) (*Policy, string, error) {
	if explicitPath != "" {
		p, err := LoadFromFile(explicitPath)
		if err != nil {
			return nil, "", err
		}
		return p, explicitPath, nil
	}

	foundPath, err := FindPolicyFile(startDir)
	if err != nil {
		return nil, "", err
	}

	if foundPath != "" {
		p, err := LoadFromFile(foundPath)
		if err != nil {
			return nil, "", err
		}
		return p, foundPath, nil
	}

	// Fallback to built-in default policy
	return DefaultPolicy(), "", nil
}
