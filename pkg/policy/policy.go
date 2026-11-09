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

// AttestationConfig configures build-time hermetic attestation and provenance (Soulcaster).
type AttestationConfig struct {
	Enabled          bool     `yaml:"enabled" json:"enabled"`
	Engine           string   `yaml:"engine,omitempty" json:"engine,omitempty"`
	EnforceHermetic  bool     `yaml:"enforce_hermetic,omitempty" json:"enforce_hermetic,omitempty"`
	Targets          []string `yaml:"targets,omitempty" json:"targets,omitempty"`
	EmitSLSA         bool     `yaml:"emit_slsa,omitempty" json:"emit_slsa,omitempty"`
	OutputProvenance string   `yaml:"output_provenance,omitempty" json:"output_provenance,omitempty"`
}

// ShieldConfig configures client-side secret redaction and egress wire guard (Shield).
type ShieldConfig struct {
	Enabled               bool    `yaml:"enabled" json:"enabled"`
	ProxyAddr             string  `yaml:"proxy_addr,omitempty" json:"proxy_addr,omitempty"`
	AutoInjectEnv         bool    `yaml:"auto_inject_env,omitempty" json:"auto_inject_env,omitempty"`
	FailClosed            bool    `yaml:"fail_closed,omitempty" json:"fail_closed,omitempty"`
	EntropyThreshold      float64 `yaml:"entropy_threshold,omitempty" json:"entropy_threshold,omitempty"`
	StripUnicodeSmuggling bool    `yaml:"strip_unicode_smuggling,omitempty" json:"strip_unicode_smuggling,omitempty"`
}

// UnmarshalYAML defaults ShieldConfig.FailClosed to true unless explicitly set to false in YAML.
func (s *ShieldConfig) UnmarshalYAML(value *yaml.Node) error {
	type rawShieldConfig struct {
		Enabled               bool    `yaml:"enabled"`
		ProxyAddr             string  `yaml:"proxy_addr"`
		AutoInjectEnv         bool    `yaml:"auto_inject_env"`
		FailClosed            *bool   `yaml:"fail_closed"`
		EntropyThreshold      float64 `yaml:"entropy_threshold"`
		StripUnicodeSmuggling bool    `yaml:"strip_unicode_smuggling"`
	}
	var raw rawShieldConfig
	if err := value.Decode(&raw); err != nil {
		return err
	}
	s.Enabled = raw.Enabled
	s.ProxyAddr = raw.ProxyAddr
	s.AutoInjectEnv = raw.AutoInjectEnv
	if raw.FailClosed != nil {
		s.FailClosed = *raw.FailClosed
	} else {
		s.FailClosed = true
	}
	s.EntropyThreshold = raw.EntropyThreshold
	s.StripUnicodeSmuggling = raw.StripUnicodeSmuggling
	return nil
}

// FirewallConfig configures prompt context and memory injection defense (Stormcage).
type FirewallConfig struct {
	Enabled           bool   `yaml:"enabled" json:"enabled"`
	Engine            string `yaml:"engine,omitempty" json:"engine,omitempty"`
	EnforceTaint      bool   `yaml:"enforce_taint,omitempty" json:"enforce_taint,omitempty"`
	CacheVerdicts     bool   `yaml:"cache_verdicts,omitempty" json:"cache_verdicts,omitempty"`
	RedactOnInjection bool   `yaml:"redact_on_injection,omitempty" json:"redact_on_injection,omitempty"`
}

// IAMConfig configures agentic non-human identity and DPoP token attenuation (Conjoiner).
type IAMConfig struct {
	Enabled                     bool   `yaml:"enabled" json:"enabled"`
	Broker                      string `yaml:"broker,omitempty" json:"broker,omitempty"`
	RequireDPoP                 bool   `yaml:"require_dpop,omitempty" json:"require_dpop,omitempty"`
	DefaultTTL                  string `yaml:"default_ttl,omitempty" json:"default_ttl,omitempty"`
	MaxTTL                      string `yaml:"max_ttl,omitempty" json:"max_ttl,omitempty"`
	EnforceMonotonicAttenuation bool   `yaml:"enforce_monotonic_attenuation,omitempty" json:"enforce_monotonic_attenuation,omitempty"`
}

// SupplyChainConfig configures legal attribution and CycloneDX SBOM compliance (Bomhound).
type SupplyChainConfig struct {
	AutoEnrichSBOM         bool   `yaml:"auto_enrich_sbom" json:"auto_enrich_sbom"`
	Engine                 string `yaml:"engine,omitempty" json:"engine,omitempty"`
	Spec                   string `yaml:"spec,omitempty" json:"spec,omitempty"`
	RetainCopyrightNotices bool   `yaml:"retain_copyright_notices,omitempty" json:"retain_copyright_notices,omitempty"`
}

// Policy defines the standardized schema for fabrial.yaml.
type Policy struct {
	Version     string             `yaml:"version" json:"version"`
	Name        string             `yaml:"name,omitempty" json:"name,omitempty"`
	DefaultTier Tier               `yaml:"default_tier,omitempty" json:"default_tier,omitempty"`
	Tier1       TierDefinition     `yaml:"tier1,omitempty" json:"tier1,omitempty"`
	Tier2       TierDefinition     `yaml:"tier2,omitempty" json:"tier2,omitempty"`
	Routing     *RoutingConfig     `yaml:"routing,omitempty" json:"routing,omitempty"`
	Rules       []Rule             `yaml:"rules,omitempty" json:"rules,omitempty"`
	Attestation *AttestationConfig `yaml:"attestation,omitempty" json:"attestation,omitempty"`
	Shield      *ShieldConfig      `yaml:"shield,omitempty" json:"shield,omitempty"`
	Firewall    *FirewallConfig    `yaml:"firewall,omitempty" json:"firewall,omitempty"`
	IAM         *IAMConfig         `yaml:"iam,omitempty" json:"iam,omitempty"`
	SupplyChain *SupplyChainConfig `yaml:"supply_chain,omitempty" json:"supply_chain,omitempty"`
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

type commandView struct {
	rawBin   string
	origBin  string
	normBin  string
	fullCmd  string
	canonCmd string
}

func buildCommandView(args []string) commandView {
	rawBin := args[0]
	origBin := strings.ToLower(strings.TrimSuffix(filepath.Base(rawBin), ".exe"))
	normBin := NormalizeBinaryName(rawBin)
	fullCmd := strings.TrimSpace(strings.Join(args, " "))
	canon := CanonicalizeCommand(args)
	canonCmd := strings.TrimSpace(strings.Join(canon, " "))
	return commandView{
		rawBin:   rawBin,
		origBin:  origBin,
		normBin:  normBin,
		fullCmd:  fullCmd,
		canonCmd: canonCmd,
	}
}

// Match determines which Tier should execute the specified command.
// It recursively unwraps leading KEY=VAL assignments and command wrappers
// (env, command, nohup, nice, timeout, stdbuf, xargs, sh/bash/zsh -c),
// canonicalizes versioned binaries and global flags, and evaluates Tier 2 rules
// BEFORE Tier 1 rules so dual-use tool flags cannot bypass microVM confinement.
func (p *Policy) Match(cmdArgs []string) (Tier, string) {
	if len(cmdArgs) == 0 {
		return p.GetDefaultTier(), "default (no command provided)"
	}

	candidates, exceeded := UnwrapCommands(cmdArgs)
	if exceeded {
		return Tier2, "wrapper nesting depth exceeded (fail-closed Tier 2)"
	}
	if len(candidates) == 0 {
		return p.GetDefaultTier(), "default (no executable after environment unwrapping)"
	}

	views := make([]commandView, 0, len(candidates))
	for _, c := range candidates {
		if len(c) > 0 {
			views = append(views, buildCommandView(c))
		}
	}
	if len(views) == 0 {
		return p.GetDefaultTier(), "default (no command provided)"
	}

	var allRules []Rule
	allRules = append(allRules, p.Rules...)
	if p.Routing != nil {
		allRules = append(allRules, p.Routing.Rules...)
	}

	// 1. Evaluate explicit Tier 2 Rules FIRST across all outer/inner unwrapped layers
	for _, rule := range allRules {
		if rule.Tier != Tier2 {
			continue
		}
		ruleName := rule.Name
		if ruleName == "" {
			ruleName = "custom-rule"
		}
		for _, v := range views {
			for _, tool := range rule.Tools {
				if matchToolView(tool, v) {
					return Tier2, fmt.Sprintf("rule %q matched tool %q", ruleName, tool)
				}
			}
			for _, pattern := range rule.Patterns {
				if matchPatternView(pattern, v) {
					return Tier2, fmt.Sprintf("rule %q matched pattern %q", ruleName, pattern)
				}
			}
		}
	}

	tier1Defs := []TierDefinition{p.Tier1}
	if p.Routing != nil {
		tier1Defs = append(tier1Defs, p.Routing.Tier1)
	}
	tier2Defs := []TierDefinition{p.Tier2}
	if p.Routing != nil {
		tier2Defs = append(tier2Defs, p.Routing.Tier2)
	}

	// 2. Evaluate explicit Tier 2 Tools & Tier 2 Patterns BEFORE Tier 1 across all layers
	for _, t2 := range tier2Defs {
		for _, v := range views {
			for _, tool := range t2.Tools {
				if matchToolView(tool, v) {
					return Tier2, fmt.Sprintf("Tier 2 policy matched tool %q", tool)
				}
			}
		}
	}
	for _, t2 := range tier2Defs {
		for _, v := range views {
			for _, pattern := range t2.Patterns {
				if matchPatternView(pattern, v) {
					return Tier2, fmt.Sprintf("Tier 2 policy matched pattern %q", pattern)
				}
			}
		}
	}

	// 3. Evaluate explicit Tier 1 Rules (only reached once no layer matched Tier 2)
	primary := views[len(views)-1]
	for _, rule := range allRules {
		if rule.Tier != Tier1 {
			continue
		}
		ruleName := rule.Name
		if ruleName == "" {
			ruleName = "custom-rule"
		}
		for _, tool := range rule.Tools {
			if matchToolView(tool, primary) {
				return Tier1, fmt.Sprintf("rule %q matched tool %q", ruleName, tool)
			}
		}
		for _, pattern := range rule.Patterns {
			if matchPatternView(pattern, primary) {
				return Tier1, fmt.Sprintf("rule %q matched pattern %q", ruleName, pattern)
			}
		}
	}

	// 4. Evaluate Tier 1 Tools & Tier 1 Patterns on the unwrapped command
	for _, t1 := range tier1Defs {
		for _, tool := range t1.Tools {
			if matchToolView(tool, primary) {
				return Tier1, fmt.Sprintf("Tier 1 policy matched tool %q", tool)
			}
		}
	}
	for _, t1 := range tier1Defs {
		for _, pattern := range t1.Patterns {
			if matchPatternView(pattern, primary) {
				return Tier1, fmt.Sprintf("Tier 1 policy matched pattern %q", pattern)
			}
		}
	}

	// 5. Fallback to default tier
	def := p.GetDefaultTier()
	return def, fmt.Sprintf("default tier (%s)", def.String())
}

func matchToolView(toolDef string, v commandView) bool {
	if matchTool(toolDef, v.normBin, v.rawBin, v.canonCmd) {
		return true
	}
	if v.origBin != v.normBin || v.fullCmd != v.canonCmd {
		if matchTool(toolDef, v.origBin, v.rawBin, v.fullCmd) {
			return true
		}
	}
	return false
}

func matchPatternView(pattern string, v commandView) bool {
	if matchPattern(pattern, v.normBin, v.rawBin, v.canonCmd) {
		return true
	}
	if v.origBin != v.normBin || v.fullCmd != v.canonCmd {
		if matchPattern(pattern, v.origBin, v.rawBin, v.fullCmd) {
			return true
		}
	}
	return false
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

func isExtensionOnlyPattern(patLower string) bool {
	if !strings.HasPrefix(patLower, "*.") {
		return false
	}
	ext := patLower[2:]
	return ext != "" && !strings.ContainsAny(ext, " */?")
}

func matchPattern(pattern, bin, rawBin, fullCmd string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}

	patLower := strings.ToLower(pattern)
	binLower := strings.ToLower(bin)
	rawBinLower := strings.ToLower(rawBin)
	fullLower := strings.ToLower(fullCmd)

	// Check slash-aware wildcard matching against binary name and raw binary path
	if WildcardMatch(patLower, binLower) || WildcardMatch(patLower, rawBinLower) {
		return true
	}

	// Single-token script extension patterns (e.g. "*.sh", "*.py", "*.js") apply to the
	// invoked executable rather than filename arguments passed to linters/formatters.
	if isExtensionOnlyPattern(patLower) {
		return false
	}

	// Check slash-aware wildcard matching against full command string (matches '*' across '/')
	if WildcardMatch(patLower, fullLower) {
		return true
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
				"npx",
				"yarn",
				"pnpm",
				"pnpm dlx",
				"bun",
				"bunx",
				"deno",
				"pip",
				"pip3",
				"pipx",
				"poetry",
				"uv",
				"uvx",
				"cargo",
				"cargo test",
				"cargo run",
				"cargo install",
				"gem",
				"bundle",
				"composer",
				"maven",
				"gradle",
				"go get",
				"go install",
				"go run",
				"go test",
				"go generate",
				"git clone",
				"git push",
				"git pull",
				"git fetch",
				"git submodule",
				"python",
				"python3",
				"node",
				"ruby",
				"perl",
				"php",
				"lua",
				"bash",
				"sh",
				"zsh",
				"dash",
				"ksh",
				"fish",
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
				"zsh *",
				"find *-exec*",
				"find *-ok*",
				"find *-delete*",
				"find *-fprint*",
				"find *-fls*",
				"git *--ext-diff*",
				"git *--upload-pack*",
				"git *--receive-pack*",
				"git *--exec-path*",
				"git *--config-env*",
				"git *-c *",
			},
		},
		Attestation: &AttestationConfig{
			Enabled:          true,
			Engine:           "soulcaster",
			EnforceHermetic:  true,
			Targets:          []string{"go build*", "go install*", "cargo build*", "cargo check*", "make*", "cmake*", "ninja*", "gcc*", "g++*", "clang*", "rustc*"},
			EmitSLSA:         true,
			OutputProvenance: ".intoto.jsonl",
		},
		Shield: &ShieldConfig{
			Enabled:          true,
			ProxyAddr:        "127.0.0.1:8443",
			AutoInjectEnv:    true,
			FailClosed:       true,
			EntropyThreshold: 4.2,
		},
		Firewall: &FirewallConfig{
			Enabled:           true,
			Engine:            "stormcage",
			EnforceTaint:      true,
			CacheVerdicts:     true,
			RedactOnInjection: true,
		},
		IAM: &IAMConfig{
			Enabled:                     true,
			Broker:                      "conjoiner",
			RequireDPoP:                 true,
			DefaultTTL:                  "30s",
			MaxTTL:                      "60s",
			EnforceMonotonicAttenuation: true,
		},
		SupplyChain: &SupplyChainConfig{
			AutoEnrichSBOM:         true,
			Engine:                 "bomhound",
			Spec:                   "cyclonedx-1.5",
			RetainCopyrightNotices: true,
		},
	}
}

// ShouldAttest checks if the command should be wrapped with an attestation compiler wrapper (e.g. soulcaster).
func (p *Policy) ShouldAttest(cmdArgs []string) bool {
	if p == nil {
		return false
	}
	if p.Attestation != nil && !p.Attestation.Enabled {
		return false
	}
	if len(cmdArgs) == 0 {
		return false
	}

	targets := []string{
		"go build*", "go install*", "cargo build*", "cargo check*", "make*", "cmake*", "ninja*", "gcc*", "g++*", "clang*", "rustc*",
	}
	if p.Attestation != nil && len(p.Attestation.Targets) > 0 {
		targets = p.Attestation.Targets
	}

	candidates, exceeded := UnwrapCommands(cmdArgs)
	if exceeded {
		return true
	}
	for _, cand := range candidates {
		if len(cand) == 0 {
			continue
		}
		v := buildCommandView(cand)
		for _, pattern := range targets {
			if matchPatternView(pattern, v) {
				return true
			}
		}
	}
	return false
}

// GetShieldConfig returns the configured Shield policy or defaults if active.
func (p *Policy) GetShieldConfig() *ShieldConfig {
	if p == nil || p.Shield == nil {
		return &ShieldConfig{
			Enabled:       true,
			ProxyAddr:     "127.0.0.1:8443",
			AutoInjectEnv: true,
			FailClosed:    true,
		}
	}
	cfg := *p.Shield
	if cfg.ProxyAddr == "" {
		cfg.ProxyAddr = "127.0.0.1:8443"
	}
	return &cfg
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

		// Stop if .git is located at current level (directory for standard repos, regular file for git worktrees)
		gitDir := filepath.Join(curr, ".git")
		if _, err := os.Stat(gitDir); err == nil {
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
