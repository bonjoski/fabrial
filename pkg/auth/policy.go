package auth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	ErrSignatureVerificationFailed = errors.New("policy: ed25519 signature verification failed")
	ErrSignatureInvalid            = errors.New("policy signature verification failed; bundle is tampered or untrusted")
	ErrTenantMismatch              = errors.New("policy bundle tenant_id does not match requested tenant")
	ErrPolicyRollback              = errors.New("policy bundle rollback detected: incoming version or timestamp is older than active policy")
	ErrPolicyExpired               = errors.New("policy: policy bundle has expired")
	ErrMissingKey                  = errors.New("policy: public key or private key missing")
	ErrInvalidPolicyStructure      = errors.New("policy: invalid policy bundle structure")
	ErrUntrustedSigner             = errors.New("policy: signer public key is not in trusted authority keyring")
)

const maxPolicyHTTPBytes = 4 << 20 // 4 MiB cap on control-plane policy responses

// AirlockConfig defines Tier-1 kernel sandbox policy (Seatbelt, Landlock, seccomp).
type AirlockConfig struct {
	BlockedSyscalls     []string `json:"blocked_syscalls"`
	RestrictedPaths     []string `json:"restricted_paths"`
	AllowedWorktreeDirs []string `json:"allowed_worktree_dirs,omitempty"`
	BlockLoopbackNet    bool     `json:"block_loopback_net"`
	DenyNetworkEgress   bool     `json:"deny_network_egress"`
	MaxStartupMs        int      `json:"max_startup_ms"`
	ProfileMode         string   `json:"profile_mode"` // "strict", "read-only", "permissive"
	StripEnvVars        []string `json:"strip_env_vars,omitempty"`
}

// AegisboxConfig defines Tier-2 hardware microVM isolation policy (libkrun).
type AegisboxConfig struct {
	MaxMemoryMB       int      `json:"max_memory_mb"`
	MaxVCPUs          int      `json:"max_vcpus"`
	TimeoutSeconds    int      `json:"timeout_seconds"`
	EphemeralCOW      bool     `json:"ephemeral_cow"`
	NetworkIsolation  string   `json:"network_isolation"` // "airgapped" | "bridge" | "pinned"
	PinnedDNSDomains  []string `json:"pinned_dns_domains,omitempty"`
	PrewarmPoolSize   int      `json:"prewarm_pool_size"`
	VsockCIDBase      int      `json:"vsock_cid_base"`
	AllowHostApproval bool     `json:"allow_host_approval"`
}

// ArgusConfig defines pre-flight slopsquatting, registry whitelist/blacklist, and killswitch policy.
type ArgusConfig struct {
	AllowedRegistries        []string `json:"allowed_registries"`
	BlockedRegistries        []string `json:"blocked_registries"`
	AllowedInternalScopes    []string `json:"allowed_internal_scopes"`
	StrictSlopsquatting      bool     `json:"strict_slopsquatting"`
	MaxLevenshteinDistance   int      `json:"max_levenshtein_distance"`
	MinPackageAgeHours       int      `json:"min_package_age_hours"`
	QuarryEngineEnabled      bool     `json:"quarry_engine_enabled"`
	MinQuarryReputationScore int      `json:"min_quarry_reputation_score"`
	KillswitchBusActive      bool     `json:"killswitch_bus_active"`
	ActionOnBreach           string   `json:"action_on_breach"` // "SIGKILL", "BLOCK", "WARN"
	SupportedPackageManagers []string `json:"supported_package_managers"`
}

// LocksmithConfig defines hardware biometric secrets vault, sovereign SPIFFE CA & cert issuance policy.
type LocksmithConfig struct {
	BiometricRequired            bool     `json:"biometric_required"`
	BiometricAmortizationSeconds int      `json:"biometric_amortization_seconds"`
	MaxLeaseDurationMinutes      int      `json:"max_lease_duration_minutes"`
	DPoPProofEnforced            bool     `json:"dpop_proof_enforced"`
	InMemorySlicingEnabled       bool     `json:"in_memory_slicing_enabled"`
	CertIssuanceEnabled          bool     `json:"cert_issuance_enabled"`
	AllowedCertDomains           []string `json:"allowed_cert_domains"`
	MaxCertTTLHours              int      `json:"max_cert_ttl_hours"`
	AllowedKeyAlgorithms         []string `json:"allowed_key_algorithms"`
	SPIFFEAuthorityDomain        string   `json:"spiffe_authority_domain"`
	AllowedSPIFFEIDPatterns      []string `json:"allowed_spiffe_id_patterns"`
	MaxBurstSVIDsPerSec          int      `json:"max_burst_svids_per_sec"`
	MCPEnabled                   bool     `json:"mcp_enabled"`
	AllowedMCPTools              []string `json:"allowed_mcp_tools"`
	DisallowedSecretPrefixes     []string `json:"disallowed_secret_prefixes"`
}

// HalfshardConfig defines client-side secret redaction and fail-closed wire guard proxy policy.
type HalfshardConfig struct {
	EntropyThreshold          float64  `json:"entropy_threshold"`
	FailClosedWireGuard       bool     `json:"fail_closed_wire_guard"`
	RedactionMask             string   `json:"redaction_mask"`
	StripZeroWidthRunes       bool     `json:"strip_zero_width_runes"`
	BlockPrivateIPs           bool     `json:"block_private_ips"`
	BlockCloudMetadata        bool     `json:"block_cloud_metadata"`
	BlockedEgressPorts        []int    `json:"blocked_egress_ports"`
	AllowedDestinationDomains []string `json:"allowed_destination_domains"`
	MaxRequestSizeMB          int      `json:"max_request_size_mb"`
	DeTokenizationEnabled     bool     `json:"detokenization_enabled"`
}

// ShieldConfig is a deprecated type alias for HalfshardConfig.
type ShieldConfig = HalfshardConfig

// ConjoinerConfig defines NIST SP 800-207A agentic IAM broker & gateway policy.
type ConjoinerConfig struct {
	NISTTenetsEnforced     bool     `json:"nist_tenets_enforced"`
	AllowedMCPTools        []string `json:"allowed_mcp_tools"`
	MonotonicAttenuation   bool     `json:"monotonic_attenuation"`
	MaxTokenTTLSeconds     int      `json:"max_token_ttl_seconds"`
	DPoPRequired           bool     `json:"dpop_required"`
	MaxDelegationDepth     int      `json:"max_delegation_depth"`
	InstantRevocationBus   bool     `json:"instant_revocation_bus"`
	AllowedTargetAudiences []string `json:"allowed_target_audiences,omitempty"`
}

// StormcageConfig defines cross-agent context & memory firewall policy.
type StormcageConfig struct {
	PromptInjectionShield    bool     `json:"prompt_injection_shield"`
	NFKCNormalization        bool     `json:"nfkc_normalization"`
	StripZeroWidthRunes      bool     `json:"strip_zero_width_runes"`
	SemanticTaintTracking    bool     `json:"semantic_taint_tracking"`
	ProhibitTaintedExecution bool     `json:"prohibit_tainted_execution"`
	MaxContextTokens         int      `json:"max_context_tokens"`
	VerdictCacheEnabled      bool     `json:"verdict_cache_enabled"`
	DisallowedPromptMarkers  []string `json:"disallowed_prompt_markers"`
}

// SoulcasterConfig defines runtime hermetic compiler attestation policy.
type SoulcasterConfig struct {
	SLSALevel                string   `json:"slsa_level"` // "SLSA_BUILD_LEVEL_1".."4"
	InTotoProvenance         bool     `json:"in_toto_provenance"`
	TOCTOUDefenseEnabled     bool     `json:"toctou_defense_enabled"`
	HermeticNetworkIsolation bool     `json:"hermetic_network_isolation"`
	StripHostPaths           bool     `json:"strip_host_paths"`
	AllowedCompilers         []string `json:"allowed_compilers"`
}

// BomhoundConfig defines CycloneDX SBOM compliance and legal attribution policy.
type BomhoundConfig struct {
	RequireCopyrightNotice   bool     `json:"require_copyright_notice"`
	StrictLicenseAttribution bool     `json:"strict_license_attribution"`
	DisallowedLicenses       []string `json:"disallowed_licenses"`
	ResolveVanityDomains     bool     `json:"resolve_vanity_domains"`
	OfflineLicenseCache      bool     `json:"offline_license_cache"`
	MaxRedirectHops          int      `json:"max_redirect_hops"`
}

// FabrialConfig defines multi-tier security fabric & dynamic routing policy.
type FabrialConfig struct {
	DefaultTier                 string            `json:"default_tier"` // "airlock" | "aegisbox"
	RequiredTiers               map[string]string `json:"required_tiers"`
	BiometricPreflightAmortized bool              `json:"biometric_preflight_amortized"`
	CircuitBreakerEnabled       bool              `json:"circuit_breaker_enabled"`
	MaxSubagentWorkers          int               `json:"max_subagent_workers"`
	EscalateShellBuiltins       bool              `json:"escalate_shell_builtins"`
	FailClosedOnError           bool              `json:"fail_closed_on_error"`
	RequireHalfshard            bool              `json:"require_halfshard,omitempty"`
	RequireShield               bool              `json:"require_shield,omitempty"` // Deprecated monotonic alias for RequireHalfshard.
	RequireStormcage            bool              `json:"require_stormcage,omitempty"`
}

// IsHalfshardRequired reports whether Halfshard is required (monotonically honoring legacy RequireShield).
func (f FabrialConfig) IsHalfshardRequired() bool {
	return f.RequireHalfshard || f.RequireShield
}

// ToolchainPolicies aggregates policies across all 10 bonjoski sovereign tools.
type ToolchainPolicies struct {
	Airlock    AirlockConfig    `json:"airlock"`
	Aegisbox   AegisboxConfig   `json:"aegisbox"`
	Argus      ArgusConfig      `json:"argus"`
	Locksmith  LocksmithConfig  `json:"locksmith"`
	Halfshard  HalfshardConfig  `json:"halfshard"`
	Shield     *HalfshardConfig `json:"shield,omitempty"` // Deprecated alias for Halfshard.
	Conjoiner  ConjoinerConfig  `json:"conjoiner"`
	Stormcage  StormcageConfig  `json:"stormcage"`
	Soulcaster SoulcasterConfig `json:"soulcaster"`
	Bomhound   BomhoundConfig   `json:"bomhound"`
	Fabrial    FabrialConfig    `json:"fabrial"`
}

// DefaultToolchainPolicies produces hardened, production-grade defaults for all ecosystem tools.
func DefaultToolchainPolicies() ToolchainPolicies {
	return ToolchainPolicies{
		Airlock: AirlockConfig{
			BlockedSyscalls:     []string{"ptrace", "process_vm_writev", "reboot", "sys_chroot", "setuid", "setgid", "kexec_load", "mount"},
			RestrictedPaths:     []string{"~/.ssh", "~/.aws", "~/.gnupg", "~/.kube/config", "~/.docker/config.json", "/etc/shadow", "~/Library/Keychains"},
			AllowedWorktreeDirs: []string{"."},
			BlockLoopbackNet:    true,
			DenyNetworkEgress:   false,
			MaxStartupMs:        15,
			ProfileMode:         "strict",
			StripEnvVars:        []string{"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "LD_LIBRARY_PATH"},
		},
		Aegisbox: AegisboxConfig{
			MaxMemoryMB:       2048,
			MaxVCPUs:          2,
			TimeoutSeconds:    300,
			EphemeralCOW:      true,
			NetworkIsolation:  "airgapped",
			PinnedDNSDomains:  []string{"github.com", "api.github.com", "registry.npmjs.org", "pypi.org"},
			PrewarmPoolSize:   2,
			VsockCIDBase:      2,
			AllowHostApproval: true,
		},
		Argus: ArgusConfig{
			AllowedRegistries: []string{
				"https://registry.npmjs.org",
				"https://pypi.org/simple",
				"https://crates.io",
				"https://proxy.golang.org",
			},
			BlockedRegistries: []string{
				"untrusted-registry.io",
				"internal-mirror.xyz",
			},
			AllowedInternalScopes: []string{
				"@bonjo/*",
				"@bonjoski/*",
			},
			StrictSlopsquatting:      true,
			MaxLevenshteinDistance:   2,
			MinPackageAgeHours:       72,
			QuarryEngineEnabled:      true,
			MinQuarryReputationScore: 70,
			KillswitchBusActive:      true,
			ActionOnBreach:           "SIGKILL",
			SupportedPackageManagers: []string{"npm", "pip", "cargo", "go", "rubygems", "composer"},
		},
		Locksmith: LocksmithConfig{
			BiometricRequired:            true,
			BiometricAmortizationSeconds: 300,
			MaxLeaseDurationMinutes:      15,
			DPoPProofEnforced:            true,
			InMemorySlicingEnabled:       true,
			CertIssuanceEnabled:          true,
			AllowedCertDomains: []string{
				"*.bonjo.dev",
				"localhost",
				"127.0.0.1",
				"*.internal",
			},
			MaxCertTTLHours: 24,
			AllowedKeyAlgorithms: []string{
				"Ed25519",
				"ECDSA_P256",
				"ECDSA_P384",
			},
			SPIFFEAuthorityDomain: "bonjo.dev",
			AllowedSPIFFEIDPatterns: []string{
				"spiffe://bonjo.dev/agent/*",
				"spiffe://bonjo.dev/workload/*",
			},
			MaxBurstSVIDsPerSec: 32,
			MCPEnabled:          true,
			AllowedMCPTools:     []string{"get_secret", "list_secrets"},
			DisallowedSecretPrefixes: []string{
				"ROOT_",
				"PROD_MASTER_",
			},
		},
		Halfshard: HalfshardConfig{
			EntropyThreshold:    4.2,
			FailClosedWireGuard: true,
			RedactionMask:       "[REDACTED_BY_HALFSHARD]",
			StripZeroWidthRunes: true,
			BlockPrivateIPs:     true,
			BlockCloudMetadata:  true,
			BlockedEgressPorts:  []int{25, 465, 587, 23},
			AllowedDestinationDomains: []string{
				"*.googleapis.com",
				"*.anthropic.com",
				"*.openai.com",
			},
			MaxRequestSizeMB:      10,
			DeTokenizationEnabled: true,
		},
		Conjoiner: ConjoinerConfig{
			NISTTenetsEnforced:   true,
			AllowedMCPTools:      []string{"read_file", "git_status", "run_command"},
			MonotonicAttenuation: true,
			MaxTokenTTLSeconds:   30,
			DPoPRequired:         true,
			MaxDelegationDepth:   3,
			InstantRevocationBus: true,
			AllowedTargetAudiences: []string{
				"https://api.bonjo.dev",
				"stoneward-control-plane",
			},
		},
		Stormcage: StormcageConfig{
			PromptInjectionShield:    true,
			NFKCNormalization:        true,
			StripZeroWidthRunes:      true,
			SemanticTaintTracking:    true,
			ProhibitTaintedExecution: true,
			MaxContextTokens:         128000,
			VerdictCacheEnabled:      true,
			DisallowedPromptMarkers: []string{
				"[SYSTEM_OVERRIDE]",
				"IGNORE PREVIOUS INSTRUCTIONS",
				"YOU ARE NOW DAN",
			},
		},
		Soulcaster: SoulcasterConfig{
			SLSALevel:                "SLSA_BUILD_LEVEL_3",
			InTotoProvenance:         true,
			TOCTOUDefenseEnabled:     true,
			HermeticNetworkIsolation: true,
			StripHostPaths:           true,
			AllowedCompilers: []string{
				"/usr/local/go/bin/go",
				"/usr/bin/go",
				"/usr/bin/clang",
				"/usr/bin/cargo",
			},
		},
		Bomhound: BomhoundConfig{
			RequireCopyrightNotice:   true,
			StrictLicenseAttribution: true,
			DisallowedLicenses: []string{
				"AGPL-3.0-only",
				"GPL-3.0-only",
				"SSPL-1.0",
			},
			ResolveVanityDomains: true,
			OfflineLicenseCache:  true,
			MaxRedirectHops:      3,
		},
		Fabrial: FabrialConfig{
			DefaultTier: "airlock",
			RequiredTiers: map[string]string{
				"npm install":  "aegisbox",
				"pip install":  "aegisbox",
				"cargo build":  "aegisbox",
				"docker build": "aegisbox",
				"git":          "airlock",
			},
			BiometricPreflightAmortized: true,
			CircuitBreakerEnabled:       true,
			MaxSubagentWorkers:          8,
			EscalateShellBuiltins:       true,
			FailClosedOnError:           true,
		},
	}
}

// PolicyRule defines specific constraints enforced by the local client sandbox.
type PolicyRule struct {
	AllowedTools     []string          `json:"allowed_tools"`
	BlockedSyscalls  []string          `json:"blocked_syscalls"`
	RestrictedPaths  []string          `json:"restricted_paths"`
	RequiredTiers    map[string]string `json:"required_tiers"`     // command prefix -> "airlock" | "aegisbox"
	BlockLoopbackNet bool              `json:"block_loopback_net"` // Block localhost/127.0.0.1 against CVE-2026-25253
	Tools            ToolchainPolicies `json:"tools"`
}

// PolicyBundle represents an immutable, signed organizational policy package.
type PolicyBundle struct {
	TenantID        string             `json:"tenant_id"`
	Version         int64              `json:"version"`
	CreatedAt       time.Time          `json:"created_at"`
	ValidUntil      time.Time          `json:"valid_until"`
	Rule            PolicyRule         `json:"rule"`
	Toolchain       *ToolchainPolicies `json:"toolchain,omitempty"`
	SignerPublicKey []byte             `json:"signer_public_key"`
	Signature       []byte             `json:"signature,omitempty"`
}

func canonicalDigest(bundle *PolicyBundle) ([]byte, error) {
	clone := *bundle
	clone.Signature = nil
	clone.CreatedAt = clone.CreatedAt.UTC().Truncate(time.Second)
	clone.ValidUntil = clone.ValidUntil.UTC().Truncate(time.Second)

	data, err := json.Marshal(clone)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy bundle: %w", err)
	}

	hash := sha256.Sum256(data)
	return hash[:], nil
}

// Sign compiles the canonical digest and signs it with the tenant's Ed25519 private key.
func (p *PolicyBundle) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return ErrMissingKey
	}

	p.CreatedAt = p.CreatedAt.UTC().Truncate(time.Second)
	p.ValidUntil = p.ValidUntil.UTC().Truncate(time.Second)

	pubKey := privateKey.Public().(ed25519.PublicKey)
	p.SignerPublicKey = pubKey

	digest, err := canonicalDigest(p)
	if err != nil {
		return err
	}

	p.Signature = ed25519.Sign(privateKey, digest)
	return nil
}

// Verify checks the cryptographic Ed25519 signature against the bundle contents.
func (p *PolicyBundle) Verify() (bool, error) {
	if len(p.Signature) != ed25519.SignatureSize || len(p.SignerPublicKey) != ed25519.PublicKeySize {
		return false, ErrInvalidPolicyStructure
	}

	digest, err := canonicalDigest(p)
	if err != nil {
		return false, err
	}

	valid := ed25519.Verify(p.SignerPublicKey, digest, p.Signature)
	if !valid {
		return false, ErrSignatureVerificationFailed
	}

	return true, nil
}

// VerifyWithTrustedKeys verifies the Ed25519 signature of the bundle AND enforces that
// SignerPublicKey matches one of trustedKeys (when at least one trusted key is supplied).
func (p *PolicyBundle) VerifyWithTrustedKeys(trustedKeys ...ed25519.PublicKey) (bool, error) {
	valid, err := p.Verify()
	if err != nil || !valid {
		return false, err
	}

	if len(trustedKeys) == 0 {
		return true, nil
	}

	for _, trusted := range trustedKeys {
		if len(trusted) == ed25519.PublicKeySize && subtle.ConstantTimeCompare(p.SignerPublicKey, trusted) == 1 {
			return true, nil
		}
	}

	return false, ErrUntrustedSigner
}

// ParseAuthorityPublicKeys parses comma-separated hex or base64 Ed25519 public keys.
func ParseAuthorityPublicKeys(raw string) ([]ed25519.PublicKey, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}

	parts := strings.Split(trimmed, ",")
	keys := make([]ed25519.PublicKey, 0, len(parts))
	for _, part := range parts {
		token := strings.TrimSpace(part)
		if token == "" {
			continue
		}
		if decoded, err := hex.DecodeString(token); err == nil && len(decoded) == ed25519.PublicKeySize {
			keys = append(keys, ed25519.PublicKey(decoded))
			continue
		}
		if decoded, err := base64.StdEncoding.DecodeString(token); err == nil && len(decoded) == ed25519.PublicKeySize {
			keys = append(keys, ed25519.PublicKey(decoded))
			continue
		}
		if decoded, err := base64.RawStdEncoding.DecodeString(token); err == nil && len(decoded) == ed25519.PublicKeySize {
			keys = append(keys, ed25519.PublicKey(decoded))
			continue
		}
		return nil, fmt.Errorf("%w: malformed ed25519 authority public key", ErrMissingKey)
	}

	if len(keys) == 0 {
		return nil, ErrMissingKey
	}
	return keys, nil
}

// IsExpired checks whether the bundle has exceeded its ValidUntil TTL.
func (p *PolicyBundle) IsExpired(at time.Time) bool {
	return at.After(p.ValidUntil)
}

// PolicyCache holds the cached policy bundle and toolchain policies on disk.
type PolicyCache struct {
	Bundle    *PolicyBundle      `json:"bundle"`
	Toolchain *ToolchainPolicies `json:"toolchain"`
	CachedAt  time.Time          `json:"cached_at"`
}

// GetFabrialPolicyPath returns the canonical path to ~/.fabrial/policy_cache.json.
func GetFabrialPolicyPath() string {
	if p := os.Getenv("FABRIAL_POLICY_FILE"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(os.TempDir(), "fabrial-policy-cache.json")
	}
	return filepath.Join(home, ".fabrial", "policy_cache.json")
}

func resolvePinnedAuthorityKeys(prevCache *PolicyCache) ([]ed25519.PublicKey, error) {
	if envPub := strings.TrimSpace(os.Getenv("STONEWARD_AUTHORITY_PUBKEY")); envPub != "" {
		return ParseAuthorityPublicKeys(envPub)
	}

	if auth, err := LoadFabrialAuth(); err == nil && auth != nil && strings.TrimSpace(auth.AuthorityPublicKey) != "" {
		return ParseAuthorityPublicKeys(auth.AuthorityPublicKey)
	}

	// TOFU authority key pinning across refreshes for the same tenant when a verified cache exists.
	if prevCache != nil && prevCache.Bundle != nil && len(prevCache.Bundle.SignerPublicKey) == ed25519.PublicKeySize {
		if ok, err := prevCache.Bundle.Verify(); err == nil && ok {
			pinned := make(ed25519.PublicKey, ed25519.PublicKeySize)
			copy(pinned, prevCache.Bundle.SignerPublicKey)
			return []ed25519.PublicKey{pinned}, nil
		}
	}

	return nil, nil
}

func hasSignedRuleToolchain(t ToolchainPolicies) bool {
	return len(t.Airlock.BlockedSyscalls) > 0 ||
		len(t.Airlock.RestrictedPaths) > 0 ||
		len(t.Argus.AllowedRegistries) > 0 ||
		t.Fabrial.DefaultTier != "" ||
		t.Soulcaster.SLSALevel != ""
}

// PullAndVerifyPolicy pulls the latest signed PolicyBundle and ToolchainPolicies from the Stoneward control plane.
// It cryptographically verifies the Ed25519 signature, pinned authority key, TenantID binding, expiration,
// and anti-rollback monotonicity before persisting to disk.
func PullAndVerifyPolicy(serverURL, token, tenantID string, insecure bool) (*PolicyBundle, *ToolchainPolicies, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
			MinVersion:         tls.VersionTLS13,
		},
	}
	httpClient := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}

	var prevCache *PolicyCache
	if existingData, err := os.ReadFile(GetFabrialPolicyPath()); err == nil {
		var parsed PolicyCache
		if json.Unmarshal(existingData, &parsed) == nil && parsed.Bundle != nil {
			if tenantID == "" || parsed.Bundle.TenantID == tenantID {
				prevCache = &parsed
			}
		}
	}

	trustedKeys, err := resolvePinnedAuthorityKeys(prevCache)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrSignatureInvalid, err)
	}

	// 1. Fetch PolicyBundle
	escapedTenant := url.QueryEscape(tenantID)
	bundleReq, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v1/policy?tenant_id=%s", strings.TrimRight(serverURL, "/"), escapedTenant), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build policy bundle request: %w", err)
	}
	if token != "" {
		bundleReq.Header.Set("Authorization", "Bearer "+token)
	}
	if tenantID != "" {
		bundleReq.Header.Set("X-Tenant-ID", tenantID)
	}

	bundleResp, err := httpClient.Do(bundleReq)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch policy bundle: %w", err)
	}
	defer bundleResp.Body.Close()

	if bundleResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(bundleResp.Body, 64<<10))
		return nil, nil, fmt.Errorf("control plane returned status %d: %s", bundleResp.StatusCode, string(body))
	}

	var bundle PolicyBundle
	if err := json.NewDecoder(io.LimitReader(bundleResp.Body, maxPolicyHTTPBytes)).Decode(&bundle); err != nil {
		return nil, nil, fmt.Errorf("invalid policy bundle response json: %w", err)
	}

	// Enforce strict tenant match
	if tenantID != "" && bundle.TenantID != tenantID {
		return nil, nil, fmt.Errorf("%w: expected %q, got %q", ErrTenantMismatch, tenantID, bundle.TenantID)
	}

	// Reject expired bundles on pull
	if bundle.IsExpired(time.Now()) {
		return nil, nil, fmt.Errorf("%w: %w", ErrSignatureInvalid, ErrPolicyExpired)
	}

	// Cryptographic signature & pinned authority key verification
	valid, err := bundle.VerifyWithTrustedKeys(trustedKeys...)
	if err != nil || !valid {
		return nil, nil, fmt.Errorf("%w: %w", ErrSignatureInvalid, err)
	}

	// Anti-rollback check against previously verified cache for the same tenant
	if prevCache != nil && prevCache.Bundle != nil && prevCache.Bundle.TenantID == bundle.TenantID {
		if ok, verifyErr := prevCache.Bundle.Verify(); verifyErr == nil && ok {
			if bundle.Version < prevCache.Bundle.Version || bundle.CreatedAt.Before(prevCache.Bundle.CreatedAt) {
				return nil, nil, fmt.Errorf("%w: incoming version=%d (created %s) < cached version=%d (created %s)",
					ErrPolicyRollback,
					bundle.Version, bundle.CreatedAt.UTC().Format(time.RFC3339),
					prevCache.Bundle.Version, prevCache.Bundle.CreatedAt.UTC().Format(time.RFC3339))
			}
		}
	}

	// 2. Resolve ToolchainPolicies
	var toolchain ToolchainPolicies
	switch {
	case bundle.Toolchain != nil:
		toolchain = *bundle.Toolchain
	case hasSignedRuleToolchain(bundle.Rule.Tools):
		toolchain = bundle.Rule.Tools
	default:
		toolsReq, reqErr := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v1/policy/tools?tenant_id=%s", strings.TrimRight(serverURL, "/"), escapedTenant), nil)
		if reqErr != nil {
			return nil, nil, fmt.Errorf("failed to build tools policy request: %w", reqErr)
		}
		if token != "" {
			toolsReq.Header.Set("Authorization", "Bearer "+token)
		}
		if tenantID != "" {
			toolsReq.Header.Set("X-Tenant-ID", tenantID)
		}

		toolsResp, doErr := httpClient.Do(toolsReq)
		if doErr != nil {
			return nil, nil, fmt.Errorf("failed to fetch toolchain policies: %w", doErr)
		}
		defer toolsResp.Body.Close()

		if toolsResp.StatusCode == http.StatusOK {
			if decErr := json.NewDecoder(io.LimitReader(toolsResp.Body, maxPolicyHTTPBytes)).Decode(&toolchain); decErr != nil {
				toolchain = DefaultToolchainPolicies()
			}
		} else {
			toolchain = DefaultToolchainPolicies()
		}
	}

	// Pin authority key into FabrialAuthContext on disk (TOFU) if session file exists without a pinned key.
	if authPath := GetFabrialAuthPath(); authPath != "" {
		if rawAuth, readErr := os.ReadFile(authPath); readErr == nil {
			var diskAuth FabrialAuthContext
			if json.Unmarshal(rawAuth, &diskAuth) == nil && diskAuth.IsValid() && strings.TrimSpace(diskAuth.AuthorityPublicKey) == "" && diskAuth.TenantID == bundle.TenantID {
				diskAuth.AuthorityPublicKey = hex.EncodeToString(bundle.SignerPublicKey)
				if saveErr := SaveFabrialAuth(&diskAuth); saveErr != nil {
					return nil, nil, fmt.Errorf("failed to pin authority key in auth context: %w", saveErr)
				}
			}
		}
	}

	// 3. Atomically persist to disk cache
	cache := PolicyCache{
		Bundle:    &bundle,
		Toolchain: &toolchain,
		CachedAt:  time.Now().UTC(),
	}

	if err := SavePolicyCache(&cache); err != nil {
		return &bundle, &toolchain, fmt.Errorf("failed to persist policy cache: %w", err)
	}

	return &bundle, &toolchain, nil
}

// SavePolicyCache atomically writes the verified policy cache to disk with 0600 permissions.
func SavePolicyCache(cache *PolicyCache) error {
	if cache == nil || cache.Bundle == nil {
		return errors.New("cannot save nil policy cache")
	}
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}

	return writeAtomic0600(GetFabrialPolicyPath(), data)
}

// LoadCachedPolicy loads and verifies the locally cached policy bundle against any pinned authority keys.
func LoadCachedPolicy() (*PolicyBundle, *ToolchainPolicies, error) {
	path := filepath.Clean(GetFabrialPolicyPath())
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("%w: refusing symlink policy cache", ErrSignatureInvalid)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	var cache PolicyCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, nil, err
	}

	if cache.Bundle == nil {
		return nil, nil, errors.New("policy cache has nil bundle")
	}

	trustedKeys, err := resolvePinnedAuthorityKeys(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrSignatureInvalid, err)
	}

	valid, err := cache.Bundle.VerifyWithTrustedKeys(trustedKeys...)
	if err != nil || !valid {
		return nil, nil, fmt.Errorf("%w: %w", ErrSignatureInvalid, err)
	}

	switch {
	case cache.Bundle.Toolchain != nil:
		tc := *cache.Bundle.Toolchain
		cache.Toolchain = &tc
	case hasSignedRuleToolchain(cache.Bundle.Rule.Tools):
		tc := cache.Bundle.Rule.Tools
		cache.Toolchain = &tc
	}

	return cache.Bundle, cache.Toolchain, nil
}
