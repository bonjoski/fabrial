// Package pillars implements 3-State Smart Optional Discovery with 3-Layer Binary
// Provenance & Identity Verification for security fabric pillars (Shield and Stormcage,
// plus zero-execution Go buildinfo verification for all bonjoski ecosystem binaries).
//
// 3-State Contract:
//   - State 1 (StateAbsent): Verified binary not found and NOT required in fabrial.yaml -> completely invisible.
//   - State 2 (StateInstalled): Verified bonjoski binary found (Layers 1-3 passed) -> auto-discovered & active.
//   - State 3 (StateRequiredMissing): Binary missing/invalid/tampered while explicitly required
//     (or failing an explicit SHA-256 digest pin) -> fail-closed with exit code 126.
package pillars

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/bonjoski/fabrial/pkg/policy"
	"github.com/bonjoski/fabrial/pkg/ux"
)

// OptionalPillar identifies a private/optional ecosystem pillar subject to 3-state discovery.
type OptionalPillar string

const (
	Shield    OptionalPillar = "shield"
	Stormcage OptionalPillar = "stormcage"
)

// DiscoveryState represents the resolved 3-state status of an optional pillar.
type DiscoveryState string

const (
	// StateAbsent indicates no verified binary is installed and it is not required by policy (invisible).
	StateAbsent DiscoveryState = "absent"
	// StateInstalled indicates a verified bonjoski executable passed Layers 1-3 (auto-discovered & active).
	StateInstalled DiscoveryState = "installed"
	// StateRequiredMissing indicates the binary is missing/invalid/tampered while required or pinned (fail-closed).
	StateRequiredMissing DiscoveryState = "required_missing"
)

// ExitCodeRequiredMissing is the fail-closed exit code returned when a required optional pillar
// is missing, unhealthy, or fails cryptographic digest verification (POSIX EACCES/ENOEXEC).
const ExitCodeRequiredMissing = 126

// LookupFunc resolves an executable name to an absolute canonical path or returns an error.
type LookupFunc func(name string) (string, error)

// Requirements captures explicit policy requirements and cryptographic pins for optional pillars.
type Requirements struct {
	RequireShield       bool
	RequireStormcage    bool
	StrictPillarPinning bool
	PillarDigests       map[string]string
}

// Resolution captures the 3-state discovery and provenance verification result for an optional pillar.
type Resolution struct {
	Pillar     OptionalPillar
	State      DiscoveryState
	BinaryPath string
	ModulePath string
	SHA256     string
	Required   bool
	Err        error
}

// IsVisible returns true if the pillar should be surfaced in CLI output, doctor, or supervisor
// (i.e. StateInstalled or StateRequiredMissing). In StateAbsent, it returns false.
func (r Resolution) IsVisible() bool {
	return r.State == StateInstalled || r.State == StateRequiredMissing
}

// IsActive returns true only when a verified binary is installed and passes all checks (StateInstalled).
func (r Resolution) IsActive() bool {
	return r.State == StateInstalled
}

// DisplayName returns the canonical capitalized display name of the pillar.
func (p OptionalPillar) DisplayName() string {
	switch p {
	case Shield:
		return "Shield"
	case Stormcage:
		return "Stormcage"
	default:
		return string(p)
	}
}

// ConfigField returns the fabrial.yaml boolean field name that mandates this pillar.
func (p OptionalPillar) ConfigField() string {
	switch p {
	case Shield:
		return "require_shield"
	case Stormcage:
		return "require_stormcage"
	default:
		return "require_" + string(p)
	}
}

// IsOptionalPillar reports whether name (case-insensitive) identifies an optional pillar.
func IsOptionalPillar(name string) (OptionalPillar, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "shield":
		return Shield, true
	case "stormcage":
		return Stormcage, true
	default:
		return "", false
	}
}

// RequirementsFromPolicy extracts optional pillar requirements and SHA-256 pins from a parsed fabrial Policy.
func RequirementsFromPolicy(p *policy.Policy) Requirements {
	if p == nil {
		return Requirements{}
	}
	var digests map[string]string
	if len(p.PillarDigests) > 0 {
		digests = make(map[string]string, len(p.PillarDigests))
		for k, v := range p.PillarDigests {
			digests[k] = v
		}
	}
	return Requirements{
		RequireShield:       p.RequireShield,
		RequireStormcage:    p.RequireStormcage,
		StrictPillarPinning: p.StrictPillarPinning,
		PillarDigests:       digests,
	}
}

// LoadRequirements loads fabrial.yaml policy requirements starting from startDir (or explicitPath).
// If no fabrial.yaml exists, it returns zero-value Requirements (all optional pillars unrequired).
func LoadRequirements(explicitPath, startDir string) (Requirements, error) {
	pol, _, err := policy.LoadPolicy(explicitPath, startDir)
	if err != nil {
		return Requirements{}, err
	}
	return RequirementsFromPolicy(pol), nil
}

// Resolver evaluates the 3-state contract using an injectable executable lookup function
// and an optional local trust store path (defaulting to ~/.fabrial/trusted-pillars.json).
type Resolver struct {
	Lookup         LookupFunc
	TrustStorePath string
	// DisableTrustStore disables reading ~/.fabrial/trusted-pillars.json when true (e.g. isolated tests).
	DisableTrustStore bool
}

var (
	defaultLookupMu sync.RWMutex
	defaultLookupFn LookupFunc = DefaultLookup
)

// DefaultResolver returns a Resolver backed by the current package default LookupFunc.
func DefaultResolver() *Resolver {
	defaultLookupMu.RLock()
	fn := defaultLookupFn
	defaultLookupMu.RUnlock()
	if fn == nil {
		fn = DefaultLookup
	}
	return &Resolver{Lookup: fn}
}

// SetDefaultLookup overrides the package-level default lookup function (for deterministic
// downstream unit tests without mutating global PATH) and returns a restore closure.
func SetDefaultLookup(fn LookupFunc) func() {
	defaultLookupMu.Lock()
	prev := defaultLookupFn
	if fn == nil {
		defaultLookupFn = DefaultLookup
	} else {
		defaultLookupFn = fn
	}
	defaultLookupMu.Unlock()

	return func() {
		defaultLookupMu.Lock()
		defaultLookupFn = prev
		defaultLookupMu.Unlock()
	}
}

// StaticLookup returns a deterministic LookupFunc backed by an explicit name->path map.
// Intended strictly for downstream unit tests that mock installed/absent states without
// compiling real Go binaries; production discovery always uses DefaultLookup / LookupInPATH.
func StaticLookup(binaries map[string]string) LookupFunc {
	copied := make(map[string]string, len(binaries))
	for k, v := range binaries {
		copied[strings.ToLower(strings.TrimSpace(k))] = v
	}
	return func(name string) (string, error) {
		if p, ok := copied[strings.ToLower(strings.TrimSpace(name))]; ok && p != "" {
			return p, nil
		}
		return "", fmt.Errorf("%s binary not found", name)
	}
}

// LookupExecutable resolves a binary using the active default LookupFunc.
func LookupExecutable(name string) (string, error) {
	return DefaultResolver().lookup(name)
}

func (r *Resolver) lookup(name string) (string, error) {
	if r != nil && r.Lookup != nil {
		return r.Lookup(name)
	}
	defaultLookupMu.RLock()
	fn := defaultLookupFn
	defaultLookupMu.RUnlock()
	if fn == nil {
		fn = DefaultLookup
	}
	return fn(name)
}

func (r *Resolver) trustStorePath() string {
	if r != nil {
		if r.DisableTrustStore {
			return ""
		}
		if r.TrustStorePath != "" {
			return r.TrustStorePath
		}
	}
	return DefaultTrustStorePath()
}

// Resolve evaluates the 3-state contract and 3-layer binary provenance for a single optional pillar.
func (r *Resolver) Resolve(p OptionalPillar, req Requirements) Resolution {
	required := false
	switch p {
	case Shield:
		required = req.RequireShield
	case Stormcage:
		required = req.RequireStormcage
	}

	bin, err := r.lookup(string(p))
	if err == nil && bin != "" {
		// Layer 3: Verify SHA-256 cryptographic digest pin (when pinned or strict_pillar_pinning: true).
		digest, pinErr := VerifyPinnedDigest(p, bin, req, r.trustStorePath())
		if pinErr != nil {
			// If strict_pillar_pinning rejected an unpinned binary while optional (not required),
			// keep it hidden/unloaded rather than crashing unrelated workflows;
			// ALWAYS fail closed on an explicit digest mismatch or when required!
			var ffe *ux.FixForwardError
			isUnpinnedOnly := false
			if asFixForward(pinErr, &ffe) && ffe.Code == "FABRIAL_PILLAR_UNPINNED" {
				isUnpinnedOnly = true
			}
			if isUnpinnedOnly && !required {
				return Resolution{
					Pillar:   p,
					State:    StateAbsent,
					Required: false,
				}
			}
			return Resolution{
				Pillar:     p,
				State:      StateRequiredMissing,
				BinaryPath: bin,
				SHA256:     digest,
				Required:   true,
				Err:        pinErr,
			}
		}

		modPath, _ := VerifyGoBuildInfo(bin, string(p))
		return Resolution{
			Pillar:     p,
			State:      StateInstalled,
			BinaryPath: bin,
			ModulePath: modPath,
			SHA256:     digest,
			Required:   required,
		}
	}

	if required {
		return Resolution{
			Pillar:   p,
			State:    StateRequiredMissing,
			Required: true,
			Err:      NewRequiredMissingError(p, ""),
		}
	}

	return Resolution{
		Pillar:   p,
		State:    StateAbsent,
		Required: false,
	}
}

func asFixForward(err error, target **ux.FixForwardError) bool {
	if err == nil {
		return false
	}
	if ffe, ok := err.(*ux.FixForwardError); ok {
		*target = ffe
		return true
	}
	return false
}

// ResolveShield evaluates the 3-state contract for Shield.
func (r *Resolver) ResolveShield(req Requirements) Resolution {
	return r.Resolve(Shield, req)
}

// ResolveStormcage evaluates the 3-state contract for Stormcage.
func (r *Resolver) ResolveStormcage(req Requirements) Resolution {
	return r.Resolve(Stormcage, req)
}

// EnforceRequired verifies that all explicitly required (or digest-pinned) optional pillars pass.
// Returns a *ux.FixForwardError with ExitCode 126 on any required-missing or digest-mismatch failure.
func (r *Resolver) EnforceRequired(req Requirements) error {
	for _, p := range []OptionalPillar{Shield, Stormcage} {
		res := r.Resolve(p, req)
		if res.Err != nil {
			return res.Err
		}
	}
	return nil
}

// Resolve evaluates the 3-state contract using the default resolver.
func Resolve(p OptionalPillar, req Requirements) Resolution {
	return DefaultResolver().Resolve(p, req)
}

// ResolveShield evaluates Shield using the default resolver.
func ResolveShield(req Requirements) Resolution {
	return DefaultResolver().ResolveShield(req)
}

// ResolveStormcage evaluates Stormcage using the default resolver.
func ResolveStormcage(req Requirements) Resolution {
	return DefaultResolver().ResolveStormcage(req)
}

// EnforceRequired checks all required and pinned optional pillars using the default resolver.
func EnforceRequired(req Requirements) error {
	return DefaultResolver().EnforceRequired(req)
}

// NewRequiredMissingError constructs a calm UB-CLI-v2 FixForwardError (exit 126) for a
// missing required optional pillar.
func NewRequiredMissingError(p OptionalPillar, detail string) *ux.FixForwardError {
	name := p.DisplayName()
	bin := string(p)
	field := p.ConfigField()
	summary := fmt.Sprintf("Required pillar %s (%s) not found on trusted PATH while %s: true is set", name, bin, field)
	if detail != "" {
		summary = fmt.Sprintf("%s (%s)", summary, detail)
	}
	return &ux.FixForwardError{
		Tool:           "fabrial",
		Code:           "FABRIAL_REQUIRED_PILLAR_MISSING",
		Summary:        summary,
		RemediationCmd: fmt.Sprintf("Install verified bonjoski %s on a trusted PATH directory or set %s: false in fabrial.yaml", bin, field),
		WhyOneLiner:    fmt.Sprintf("fabrial.yaml requires %s (%s: true), so Fabrial fails closed instead of silently downgrading protection.", name, field),
		DeepWhy:        fmt.Sprintf("When %s: true is declared in fabrial.yaml, Fabrial enforces fail-closed execution (exit 126) if a verified bonjoski %s binary (matching Go buildinfo, filesystem/UID hygiene, and any pinned SHA-256 digest) is absent.", field, bin),
		References:     []string{"docs/use-cases/07-optional-pillar-discovery.md"},
		ExitCode:       ExitCodeRequiredMissing,
	}
}

// NewRequiredUnhealthyError constructs a calm UB-CLI-v2 FixForwardError (exit 126) for an
// unhealthy/offline required optional pillar.
func NewRequiredUnhealthyError(p OptionalPillar, detail string) *ux.FixForwardError {
	name := p.DisplayName()
	bin := string(p)
	field := p.ConfigField()
	summary := fmt.Sprintf("Required pillar %s is unhealthy/offline while %s: true is set", name, field)
	if detail != "" {
		summary = fmt.Sprintf("%s: %s", summary, detail)
	}
	return &ux.FixForwardError{
		Tool:           "fabrial",
		Code:           "FABRIAL_REQUIRED_PILLAR_UNHEALTHY",
		Summary:        summary,
		RemediationCmd: fmt.Sprintf("fabrial doctor --fix %s", bin),
		WhyOneLiner:    fmt.Sprintf("fabrial.yaml mandates %s (%s: true); execution halts fail-closed until %s is healthy.", name, field, name),
		DeepWhy:        fmt.Sprintf("When %s: true is active, an offline or degraded %s daemon is treated as a hard security boundary violation (exit 126) rather than silently bypassed.", field, name),
		References:     []string{"docs/use-cases/07-optional-pillar-discovery.md"},
		ExitCode:       ExitCodeRequiredMissing,
	}
}

// LookupInPATH returns a LookupFunc that strictly searches only the absolute directories
// listed in pathEnv, enforcing Layer 1 (Go debug/buildinfo module identity) and Layer 2
// (regular executable, non-world-writable file & parent dir, UID ownership, canonical EvalSymlinks).
func LookupInPATH(pathEnv string) LookupFunc {
	return func(name string) (string, error) {
		if !isValidBinaryName(name) {
			return "", fmt.Errorf("invalid executable lookup name %q", name)
		}
		exts := executableExtensions()
		for _, dir := range filepath.SplitList(pathEnv) {
			if dir == "" || !filepath.IsAbs(dir) {
				continue
			}
			for _, ext := range exts {
				if resolved, _, ok := verifyExecutableWithProvenance(filepath.Join(dir, name+ext), name); ok {
					return resolved, nil
				}
			}
		}
		return "", fmt.Errorf("verified %s binary not found on trusted PATH", name)
	}
}

// DefaultLookup searches trusted Homebrew/system install prefixes FIRST (/opt/homebrew/bin,
// /usr/local/bin) before absolute PATH entries and fallback user bin directories, enforcing
// Layer 1 (Go buildinfo provenance) and Layer 2 (filesystem/UID/canonical-path hygiene).
//
// Searching Homebrew prefixes first prevents a poisoned user shell PATH from shadowing
// official Homebrew-installed bonjoski binaries.
func DefaultLookup(name string) (string, error) {
	if !isValidBinaryName(name) {
		return "", fmt.Errorf("invalid executable lookup name %q", name)
	}

	exts := executableExtensions()

	// 1. Trusted Homebrew / system install prefixes FIRST (defeats PATH shadowing).
	trustedPrefixes := []string{
		"/opt/homebrew/bin",
		"/usr/local/bin",
	}
	for _, dir := range trustedPrefixes {
		for _, ext := range exts {
			if resolved, _, ok := verifyExecutableWithProvenance(filepath.Join(dir, name+ext), name); ok {
				return resolved, nil
			}
		}
	}

	// 2. Absolute entries from PATH (every candidate still verified against Layers 1 & 2).
	if p, err := LookupInPATH(os.Getenv("PATH"))(name); err == nil {
		return p, nil
	}

	// 3. Remaining standard install locations.
	home, _ := os.UserHomeDir()
	fallbackDirs := []string{"/usr/bin", "/bin"}
	if home != "" {
		fallbackDirs = append(fallbackDirs,
			filepath.Join(home, ".local", "bin"),
			filepath.Join(home, "bin"),
			filepath.Join(home, "go", "bin"),
		)
	}
	for _, dir := range fallbackDirs {
		for _, ext := range exts {
			if resolved, _, ok := verifyExecutableWithProvenance(filepath.Join(dir, name+ext), name); ok {
				return resolved, nil
			}
		}
	}

	return "", fmt.Errorf("verified %s binary not found on trusted PATH or standard install directories", name)
}

func isValidBinaryName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if strings.ContainsRune(name, filepath.Separator) || strings.ContainsAny(name, `/\`) {
		return false
	}
	if strings.Contains(name, "..") || strings.ContainsRune(name, '\x00') {
		return false
	}
	return true
}

func executableExtensions() []string {
	if runtime.GOOS == "windows" {
		return []string{".exe", ".bat", ".cmd", ""}
	}
	return []string{""}
}
