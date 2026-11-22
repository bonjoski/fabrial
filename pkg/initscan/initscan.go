package initscan

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bonjoski/fabrial/pkg/ux"
)

// MaxManifestBytes caps single root-manifest reads to prevent DoS from giant files.
const MaxManifestBytes = 256 * 1024

// EcosystemTools are the local bonjoski binaries checked during zero-config onboarding.
var EcosystemTools = []string{
	"airlock",
	"argus",
	"locksmith",
	"coppermind",
	"aegisbox",
	"soulcaster",
	"bomhound",
}

// ScanOptions configures the strictly read-only workspace stack & AI SDK scan.
type ScanOptions struct {
	Dir      string
	LookPath func(file string) (string, error)
}

// ScanResult captures detected languages, AI SDKs, and local toolchain readiness
// without writing any YAML or mutating dotfiles.
type ScanResult struct {
	Tool             string   `json:"tool"`
	Workspace        string   `json:"workspace"`
	Manifests        []string `json:"manifests"`
	Ecosystems       []string `json:"ecosystems"`
	AISDKs           []string `json:"ai_sdks,omitempty"`
	HasPlaintextEnv  bool     `json:"has_plaintext_env"`
	ToolsReady       []string `json:"tools_ready"`
	ToolsMissing     []string `json:"tools_missing,omitempty"`
	SkippedSymlinks  []string `json:"skipped_symlinks,omitempty"`
	ReadOnly         bool     `json:"read_only"`
	YAMLWritten      bool     `json:"yaml_written"`
	NextCmd          string   `json:"next_cmd"`
	AITips           []string `json:"ai_tips,omitempty"`
	Why              string   `json:"why"`
	DeepWhy          string   `json:"deep_why"`
}

// Scan performs a strictly read-only, depth-1 workspace scan via os.OpenRoot.
func Scan(opts ScanOptions) (*ScanResult, error) {
	dir := opts.Dir
	if strings.TrimSpace(dir) == "" {
		dir = "."
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, &ux.FixForwardError{
			Tool:           "fabrial",
			Code:           "FABRIAL_INIT_INVALID_PATH",
			Summary:        "Could not resolve target workspace path",
			RemediationCmd: "fabrial init",
			WhyOneLiner:    "fabrial init must run against a readable local repository directory.",
			DeepWhy:        "Workspace scoping uses os.OpenRoot so fabrial never traverses outside the active repository.",
			ExitCode:       1,
		}
	}

	root, err := os.OpenRoot(absDir)
	if err != nil {
		return nil, &ux.FixForwardError{
			Tool:           "fabrial",
			Code:           "FABRIAL_INIT_OPEN_ROOT_FAILED",
			Summary:        "Target workspace directory does not exist or is not accessible",
			RemediationCmd: "fabrial init",
			WhyOneLiner:    "fabrial init inspects only the current repository root and never traverses parent directories.",
			DeepWhy:        fmt.Sprintf("os.OpenRoot failed for %s: %v", ux.SanitizeTerminalText(absDir), err),
			ExitCode:       1,
		}
	}
	defer func() { _ = root.Close() }()

	lookPath := opts.LookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}

	ecoSet := make(map[string]struct{})
	sdkSet := make(map[string]struct{})
	var manifests []string
	var skippedSymlinks []string

	readRootFile := func(name string) ([]byte, bool) {
		info, lErr := root.Lstat(name)
		if lErr != nil {
			return nil, false
		}
		if info.Mode()&os.ModeSymlink != 0 {
			skippedSymlinks = append(skippedSymlinks, name)
			return nil, false
		}
		if !info.Mode().IsRegular() {
			return nil, false
		}
		f, oErr := root.Open(name)
		if oErr != nil {
			return nil, false
		}
		defer func() { _ = f.Close() }()
		data, rErr := io.ReadAll(io.LimitReader(f, MaxManifestBytes))
		if rErr != nil {
			return nil, false
		}
		return data, true
	}

	// 1. Go (go.mod)
	if data, ok := readRootFile("go.mod"); ok {
		manifests = append(manifests, "go.mod")
		ecoSet["go"] = struct{}{}
		detectGoAISDKs(string(data), sdkSet)
	}

	// 2. Node (package.json)
	if data, ok := readRootFile("package.json"); ok {
		manifests = append(manifests, "package.json")
		ecoSet["node"] = struct{}{}
		detectNodeAISDKs(data, sdkSet)
	}

	// 3. Python (pyproject.toml, requirements.txt)
	if data, ok := readRootFile("pyproject.toml"); ok {
		manifests = append(manifests, "pyproject.toml")
		ecoSet["python"] = struct{}{}
		detectPythonAISDKs(string(data), sdkSet)
	}
	if data, ok := readRootFile("requirements.txt"); ok {
		manifests = append(manifests, "requirements.txt")
		ecoSet["python"] = struct{}{}
		detectPythonAISDKs(string(data), sdkSet)
	}

	// 4. Rust (Cargo.toml)
	if data, ok := readRootFile("Cargo.toml"); ok {
		manifests = append(manifests, "Cargo.toml")
		ecoSet["rust"] = struct{}{}
		detectRustAISDKs(string(data), sdkSet)
	}

	// 5. Read-only existence check for plaintext .env (NEVER reads .env contents)
	hasPlaintextEnv := false
	if envInfo, err := root.Lstat(".env"); err == nil && envInfo.Mode().IsRegular() {
		hasPlaintextEnv = true
	}

	// 6. Local bonjoski binary availability
	var toolsReady []string
	var toolsMissing []string
	for _, bin := range EcosystemTools {
		if _, err := lookPath(bin); err == nil {
			toolsReady = append(toolsReady, bin)
		} else {
			toolsMissing = append(toolsMissing, bin)
		}
	}

	ecosystems := sortedKeys(ecoSet)
	aiSDKs := sortedKeys(sdkSet)
	sort.Strings(manifests)
	sort.Strings(skippedSymlinks)

	var aiTips []string
	if len(aiSDKs) > 0 {
		aiTips = []string{
			"coppermind import ai-app-and-rag-safety.capsule",
			"aegisbox test --ai-safety",
		}
	}

	nextCmd := buildNextCommand(ecosystems, hasPlaintextEnv, toolsMissing)
	why := "Zero-config local defaults are active (0 YAML written, strictly read-only)."
	if hasPlaintextEnv {
		why = "Plaintext .env detected; moving secrets to Touch ID keychain protects them from git and AI agents."
	} else if len(aiSDKs) > 0 {
		why = "AI SDKs detected; local sandboxing and ai-app-and-rag-safety.capsule guard prompts, keys, and installs."
	}

	deepWhy := buildDeepWhy(ecosystems, manifests, aiSDKs, toolsReady, toolsMissing, hasPlaintextEnv, skippedSymlinks)

	return &ScanResult{
		Tool:            "fabrial",
		Workspace:       absDir,
		Manifests:       manifests,
		Ecosystems:      ecosystems,
		AISDKs:          aiSDKs,
		HasPlaintextEnv: hasPlaintextEnv,
		ToolsReady:      toolsReady,
		ToolsMissing:    toolsMissing,
		SkippedSymlinks: skippedSymlinks,
		ReadOnly:        true,
		YAMLWritten:     false,
		NextCmd:         nextCmd,
		AITips:          aiTips,
		Why:             why,
		DeepWhy:         deepWhy,
	}, nil
}

// Render emits JSON (--json), calm <=3-line default output, or full progressive disclosure (--why).
func (r *ScanResult) Render(w io.Writer, asJSON bool, showWhy bool) error {
	if r == nil {
		return nil
	}
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		return enc.Encode(r)
	}

	stackLabel := "generic repo"
	if len(r.Ecosystems) > 0 {
		stackLabel = strings.Join(r.Ecosystems, ", ")
	}
	aiLabel := ""
	if len(r.AISDKs) > 0 {
		aiLabel = fmt.Sprintf(" (AI SDKs: %s)", strings.Join(r.AISDKs, ", "))
	}

	totalTools := len(r.ToolsReady) + len(r.ToolsMissing)
	// Line 1: calm summary
	if _, err := fmt.Fprintf(w, "✓ fabrial: detected %s%s; %d/%d local tools ready (0 YAML written)\n",
		ux.SanitizeTerminalText(stackLabel),
		ux.SanitizeTerminalText(aiLabel),
		len(r.ToolsReady),
		totalTools,
	); err != nil {
		return err
	}

	// Line 2: immediate copy-pasteable next command
	if _, err := fmt.Fprintf(w, "  Next: %s\n", ux.SanitizeTerminalText(r.NextCmd)); err != nil {
		return err
	}

	// Line 3: educational 1-liner + progressive disclosure pointer
	whyLine := ux.SanitizeTerminalText(r.Why)
	if !showWhy {
		whyLine = fmt.Sprintf("%s (re-run with --why for details)", whyLine)
	}
	if _, err := fmt.Fprintf(w, "  Why:  %s\n", whyLine); err != nil {
		return err
	}

	if showWhy {
		if _, err := fmt.Fprintf(w, "\n  Deep Dive (--why):\n  %s\n",
			strings.ReplaceAll(ux.SanitizeTerminalText(r.DeepWhy), "\n", "\n  ")); err != nil {
			return err
		}
		for _, tip := range r.AITips {
			if _, err := fmt.Fprintf(w, "  Tip:  %s\n", ux.SanitizeTerminalText(tip)); err != nil {
				return err
			}
		}
	}

	return nil
}

func buildNextCommand(ecosystems []string, hasPlaintextEnv bool, toolsMissing []string) string {
	if hasPlaintextEnv {
		return "locksmith migrate .env"
	}
	if len(toolsMissing) > 0 {
		safeBins := make([]string, 0, len(toolsMissing))
		for _, b := range toolsMissing {
			if ux.ValidateRemediationToken(b) {
				safeBins = append(safeBins, b)
			}
		}
		if len(safeBins) > 0 {
			return "brew install bonjoski/tap/" + strings.Join(safeBins, " bonjoski/tap/")
		}
	}
	for _, eco := range ecosystems {
		switch eco {
		case "go":
			return "fabrial run -- go test ./..."
		case "node":
			return "fabrial run -- npm test"
		case "python":
			return "fabrial run -- pytest"
		case "rust":
			return "fabrial run -- cargo test"
		}
	}
	return "fabrial doctor"
}

func buildDeepWhy(ecosystems, manifests, aiSDKs, toolsReady, toolsMissing []string, hasPlaintextEnv bool, skippedSymlinks []string) string {
	var parts []string
	if len(manifests) > 0 {
		parts = append(parts, fmt.Sprintf("Root manifests inspected (depth 1, <=256KB, read-only): %s", strings.Join(manifests, ", ")))
	} else {
		parts = append(parts, "No root language manifests found (checked go.mod, package.json, pyproject.toml, requirements.txt, Cargo.toml).")
	}
	if len(ecosystems) > 0 {
		parts = append(parts, fmt.Sprintf("Detected ecosystems: %s (Tier 1 Airlock <15ms for linters/tests; Tier 2 Aegisbox for package installs).", strings.Join(ecosystems, ", ")))
	}
	if len(aiSDKs) > 0 {
		parts = append(parts, fmt.Sprintf("Detected AI SDKs: %s — recommended: load ai-app-and-rag-safety.capsule and run `aegisbox test --ai-safety`.", strings.Join(aiSDKs, ", ")))
	}
	if hasPlaintextEnv {
		parts = append(parts, "Plaintext .env exists in workspace root (not read by fabrial init). Run `locksmith migrate .env` to move secrets into Touch ID/TPM keychain and shred disk plaintext.")
	}
	if len(toolsReady) > 0 {
		parts = append(parts, fmt.Sprintf("Installed local tools: %s", strings.Join(toolsReady, ", ")))
	}
	if len(toolsMissing) > 0 {
		parts = append(parts, fmt.Sprintf("Optional missing tools: %s", strings.Join(toolsMissing, ", ")))
	}
	if len(skippedSymlinks) > 0 {
		parts = append(parts, fmt.Sprintf("Skipped symlinked manifests (fail-closed): %s", strings.Join(skippedSymlinks, ", ")))
	}
	parts = append(parts, "Scope: 100% local single-developer workstation DevEx; zero cloud control plane and zero YAML required.")
	return strings.Join(parts, "\n")
}

func detectNodeAISDKs(raw []byte, sdkSet map[string]struct{}) {
	var pkg struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(raw, &pkg); err != nil {
		return
	}
	knownNode := map[string]string{
		"openai":                    "openai",
		"anthropic":                 "anthropic",
		"@anthropic-ai/sdk":         "@anthropic-ai/sdk",
		"@google/genai":             "@google/genai",
		"langchain":                 "langchain",
		"@langchain/core":           "langchain",
		"langgraph":                 "langgraph",
		"@langchain/langgraph":      "langgraph",
		"@modelcontextprotocol/sdk": "@modelcontextprotocol/sdk",
		"mcp":                       "mcp",
	}
	for _, m := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.PeerDependencies, pkg.OptionalDependencies} {
		for dep := range m {
			if canonical, ok := knownNode[strings.ToLower(strings.TrimSpace(dep))]; ok {
				sdkSet[canonical] = struct{}{}
			}
		}
	}
}

func detectGoAISDKs(content string, sdkSet map[string]struct{}) {
	lower := strings.ToLower(content)
	patterns := []struct {
		substr    string
		canonical string
	}{
		{"github.com/openai/openai-go", "openai"},
		{"github.com/sashabaranov/go-openai", "openai"},
		{"github.com/anthropics/anthropic-sdk-go", "anthropic"},
		{"google.golang.org/genai", "@google/genai"},
		{"github.com/tmc/langchaingo", "langchain"},
		{"langgraph", "langgraph"},
		{"github.com/modelcontextprotocol/go-sdk", "@modelcontextprotocol/sdk"},
		{"github.com/mark3labs/mcp-go", "mcp"},
	}
	for _, p := range patterns {
		if strings.Contains(lower, p.substr) {
			sdkSet[p.canonical] = struct{}{}
		}
	}
}

func detectPythonAISDKs(content string, sdkSet map[string]struct{}) {
	candidates := []struct {
		token     string
		canonical string
	}{
		{"openai", "openai"},
		{"anthropic", "anthropic"},
		{"google-genai", "@google/genai"},
		{"google_genai", "@google/genai"},
		{"langchain", "langchain"},
		{"langgraph", "langgraph"},
		{"mcp", "mcp"},
	}
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lower := strings.ToLower(trimmed)
		for _, c := range candidates {
			if hasPackageToken(lower, c.token) {
				sdkSet[c.canonical] = struct{}{}
			}
		}
	}
}

func detectRustAISDKs(content string, sdkSet map[string]struct{}) {
	candidates := []struct {
		token     string
		canonical string
	}{
		{"async-openai", "openai"},
		{"openai", "openai"},
		{"anthropic", "anthropic"},
		{"langchain-rust", "langchain"},
		{"langchain", "langchain"},
		{"langgraph", "langgraph"},
		{"rmcp", "mcp"},
		{"mcp", "mcp"},
	}
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lower := strings.ToLower(trimmed)
		for _, c := range candidates {
			if hasPackageToken(lower, c.token) {
				sdkSet[c.canonical] = struct{}{}
			}
		}
	}
}

// hasPackageToken checks whether tok appears as a standalone dependency identifier token.
func hasPackageToken(line, tok string) bool {
	idx := 0
	for {
		pos := strings.Index(line[idx:], tok)
		if pos < 0 {
			return false
		}
		start := idx + pos
		end := start + len(tok)
		leftOK := start == 0 || !isIdentChar(line[start-1])
		rightOK := end == len(line) || !isIdentChar(line[end])
		if leftOK && rightOK {
			return true
		}
		idx = start + 1
	}
}

func isIdentChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_' || b == '-'
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
