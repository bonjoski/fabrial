package pillars

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/bonjoski/fabrial/pkg/ux"
)

// TrustStoreVersion is the schema version for ~/.fabrial/trusted-pillars.json.
const TrustStoreVersion = 1

// TrustStore persists user-pinned SHA-256 binary digests for local pillars.
type TrustStore struct {
	Version   int               `json:"version"`
	UpdatedAt string            `json:"updated_at,omitempty"`
	Digests   map[string]string `json:"digests"`
}

// DefaultTrustStorePath returns ~/.fabrial/trusted-pillars.json.
func DefaultTrustStorePath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".fabrial", "trusted-pillars.json")
}

// ComputeFileSHA256 streams the contents of path and returns its lowercase hex SHA-256 digest.
func ComputeFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open binary %q for SHA-256 verification: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash binary %q: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// IsValidSHA256Hex validates that s is a canonical 64-character lowercase hexadecimal SHA-256 digest.
func IsValidSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// NormalizeSHA256 strips an optional "sha256:" prefix and lowercases the hex digest.
func NormalizeSHA256(raw string) (string, error) {
	clean := strings.ToLower(strings.TrimSpace(raw))
	clean = strings.TrimPrefix(clean, "sha256:")
	if !IsValidSHA256Hex(clean) {
		return "", fmt.Errorf("invalid SHA-256 digest %q (expected 64 hex characters)", raw)
	}
	return clean, nil
}

// LoadTrustStore reads a local trust store file with strict non-symlink and permission hygiene.
// If the file does not exist, it returns an empty initialized TrustStore and nil error.
func LoadTrustStore(path string) (*TrustStore, error) {
	empty := &TrustStore{
		Version: TrustStoreVersion,
		Digests: make(map[string]string),
	}
	if strings.TrimSpace(path) == "" {
		return empty, nil
	}

	lfi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return empty, nil
		}
		return nil, fmt.Errorf("stat trust store %q: %w", path, err)
	}
	if lfi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing symlinked trust store %q (fail-closed)", path)
	}
	if !lfi.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing non-regular trust store %q", path)
	}
	if runtime.GOOS != "windows" {
		if lfi.Mode().Perm()&0022 != 0 {
			return nil, fmt.Errorf("refusing group/world-writable trust store %q (mode %04o; expected 0600)", path, lfi.Mode().Perm())
		}
		if !isOwnedByCurrentUserOrRoot(lfi) {
			return nil, fmt.Errorf("refusing trust store %q not owned by current user", path)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trust store %q: %w", path, err)
	}

	var ts TrustStore
	if err := json.Unmarshal(data, &ts); err != nil {
		return nil, fmt.Errorf("parse trust store %q: %w", path, err)
	}
	if ts.Digests == nil {
		ts.Digests = make(map[string]string)
	}
	normalized := make(map[string]string, len(ts.Digests))
	for k, v := range ts.Digests {
		name := strings.ToLower(strings.TrimSpace(k))
		if name == "" {
			continue
		}
		dig, err := NormalizeSHA256(v)
		if err != nil {
			return nil, fmt.Errorf("trust store %q invalid digest for %q: %w", path, name, err)
		}
		normalized[name] = dig
	}
	ts.Digests = normalized
	if ts.Version == 0 {
		ts.Version = TrustStoreVersion
	}
	return &ts, nil
}

// SaveTrustStore writes the trust store atomically (0600 inside 0700 parent dir) refusing symlinks.
func SaveTrustStore(path string, ts *TrustStore) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("trust store path cannot be empty")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create trust store dir %q: %w", dir, err)
	}
	if lfi, err := os.Lstat(dir); err == nil {
		if lfi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlinked trust store directory %q", dir)
		}
		if runtime.GOOS != "windows" {
			_ = os.Chmod(dir, 0700)
		}
	}
	if lfi, err := os.Lstat(path); err == nil && lfi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to overwrite symlinked trust store %q", path)
	}

	out := TrustStore{
		Version:   TrustStoreVersion,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Digests:   make(map[string]string, len(ts.Digests)),
	}
	for k, v := range ts.Digests {
		name := strings.ToLower(strings.TrimSpace(k))
		if name == "" {
			continue
		}
		dig, err := NormalizeSHA256(v)
		if err != nil {
			return fmt.Errorf("invalid digest for %q: %w", name, err)
		}
		out.Digests[name] = dig
	}

	payload, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal trust store: %w", err)
	}
	payload = append(payload, '\n')

	tmp, err := os.CreateTemp(dir, ".trusted-pillars-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp trust store: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if runtime.GOOS != "windows" {
		if err := tmp.Chmod(0600); err != nil {
			_ = tmp.Close()
			return fmt.Errorf("chmod temp trust store: %w", err)
		}
	}
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp trust store: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp trust store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp trust store: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("atomic rename trust store: %w", err)
	}
	cleanup = false
	return nil
}

// TrustPillarResult describes a newly pinned bonjoski binary.
type TrustPillarResult struct {
	Name       string `json:"name"`
	BinaryPath string `json:"binary_path"`
	ModulePath string `json:"module_path"`
	SHA256     string `json:"sha256"`
	StorePath  string `json:"store_path"`
}

// TrustPillar verifies Layers 1 & 2 for name using lookup, computes its SHA-256 digest,
// and persists the cryptographic pin into storePath.
func TrustPillar(name, storePath string, lookup LookupFunc) (*TrustPillarResult, error) {
	cleanName := strings.ToLower(strings.TrimSpace(name))
	if _, ok := KnownBinaryIdentity(cleanName); !ok {
		return nil, fmt.Errorf("unknown bonjoski pillar %q", name)
	}
	if lookup == nil {
		lookup = DefaultLookup
	}
	binPath, err := lookup(cleanName)
	if err != nil || binPath == "" {
		return nil, fmt.Errorf("verified bonjoski binary %q not found: %w", cleanName, err)
	}
	// Re-verify Layers 1 & 2 directly on disk before pinning.
	resolved, modPath, ok := verifyExecutableWithProvenance(binPath, cleanName)
	if !ok {
		return nil, fmt.Errorf("binary %q failed provenance or filesystem hygiene verification", binPath)
	}
	digest, err := ComputeFileSHA256(resolved)
	if err != nil {
		return nil, err
	}
	if storePath == "" {
		storePath = DefaultTrustStorePath()
	}
	ts, err := LoadTrustStore(storePath)
	if err != nil {
		return nil, err
	}
	ts.Digests[cleanName] = digest
	if err := SaveTrustStore(storePath, ts); err != nil {
		return nil, err
	}
	return &TrustPillarResult{
		Name:       cleanName,
		BinaryPath: resolved,
		ModulePath: modPath,
		SHA256:     digest,
		StorePath:  storePath,
	}, nil
}

// RemoveTrustedPillar removes name's SHA-256 pin from storePath.
func RemoveTrustedPillar(name, storePath string) (bool, error) {
	cleanName := strings.ToLower(strings.TrimSpace(name))
	if storePath == "" {
		storePath = DefaultTrustStorePath()
	}
	ts, err := LoadTrustStore(storePath)
	if err != nil {
		return false, err
	}
	if _, exists := ts.Digests[cleanName]; !exists {
		return false, nil
	}
	delete(ts.Digests, cleanName)
	if err := SaveTrustStore(storePath, ts); err != nil {
		return false, err
	}
	return true, nil
}

// ListTrustedPillars returns sorted pillar names currently pinned in storePath.
func ListTrustedPillars(storePath string) (*TrustStore, []string, error) {
	if storePath == "" {
		storePath = DefaultTrustStorePath()
	}
	ts, err := LoadTrustStore(storePath)
	if err != nil {
		return nil, nil, err
	}
	names := make([]string, 0, len(ts.Digests))
	for k := range ts.Digests {
		names = append(names, k)
	}
	sort.Strings(names)
	return ts, names, nil
}

// expectedPinForPillar merges fabrial.yaml pillar_digests and the local trust store.
// If BOTH specify a digest for the same pillar and they disagree, it fails closed.
func expectedPinForPillar(name string, req Requirements, trustStorePath string) (string, bool, error) {
	cleanName := strings.ToLower(strings.TrimSpace(name))

	var policyPin string
	var hasPolicyPin bool
	for k, v := range req.PillarDigests {
		if strings.EqualFold(strings.TrimSpace(k), cleanName) {
			dig, err := NormalizeSHA256(v)
			if err != nil {
				return "", false, fmt.Errorf("fabrial.yaml pillar_digests.%s: %w", cleanName, err)
			}
			policyPin = dig
			hasPolicyPin = true
			break
		}
	}

	var storePin string
	var hasStorePin bool
	if trustStorePath != "" {
		ts, err := LoadTrustStore(trustStorePath)
		if err != nil {
			return "", false, err
		}
		if v, ok := ts.Digests[cleanName]; ok && v != "" {
			storePin = v
			hasStorePin = true
		}
	}

	if hasPolicyPin && hasStorePin {
		if subtle.ConstantTimeCompare([]byte(policyPin), []byte(storePin)) != 1 {
			return "", true, fmt.Errorf("conflicting SHA-256 pins for %s between fabrial.yaml (%s) and trust store (%s)", cleanName, policyPin[:12], storePin[:12])
		}
		return policyPin, true, nil
	}
	if hasPolicyPin {
		return policyPin, true, nil
	}
	if hasStorePin {
		return storePin, true, nil
	}
	return "", false, nil
}

// VerifyPinnedDigest enforces Layer 3 cryptographic SHA-256 digest pinning on resolvedPath.
// Returns (actualDigest, nil) on success, or a fail-closed exit-126 *ux.FixForwardError on
// mismatch, tampering, invalid pin, or unpinned binary under StrictPillarPinning.
func VerifyPinnedDigest(p OptionalPillar, resolvedPath string, req Requirements, trustStorePath string) (string, error) {
	expected, pinned, err := expectedPinForPillar(string(p), req, trustStorePath)
	if err != nil {
		return "", NewDigestMismatchError(p, resolvedPath, err.Error())
	}

	if !pinned {
		if req.StrictPillarPinning {
			return "", NewUnpinnedPillarError(p, resolvedPath)
		}
		return "", nil
	}

	actual, err := ComputeFileSHA256(resolvedPath)
	if err != nil {
		return "", NewDigestMismatchError(p, resolvedPath, err.Error())
	}
	if subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
		return actual, NewDigestMismatchError(
			p,
			resolvedPath,
			fmt.Sprintf("SHA-256 mismatch (got %s..., expected %s...)", actual[:16], expected[:16]),
		)
	}
	return actual, nil
}

// NewDigestMismatchError constructs a calm UB-CLI-v2 fail-closed FixForwardError (exit 126)
// when a discovered binary fails SHA-256 digest verification (defeating forged Go binaries).
func NewDigestMismatchError(p OptionalPillar, binaryPath, detail string) *ux.FixForwardError {
	name := p.DisplayName()
	bin := string(p)
	summary := fmt.Sprintf("Pillar %s (%s) failed cryptographic SHA-256 digest verification: %s", name, binaryPath, detail)
	return &ux.FixForwardError{
		Tool:           "fabrial",
		Code:           "FABRIAL_PILLAR_DIGEST_MISMATCH",
		Summary:        summary,
		RemediationCmd: fmt.Sprintf("Verify binary provenance then run: fabrial trust pillar %s", bin),
		WhyOneLiner:    fmt.Sprintf("The %s binary on disk does not match its pinned SHA-256 digest; Fabrial refuses to execute an unverified or tampered binary.", name),
		DeepWhy:        fmt.Sprintf("Go debug/buildinfo prevents accidental name collisions, while SHA-256 pinning cryptographically blocks forged or trojanized %s binaries. Re-pin only after confirming a legitimate upgrade.", bin),
		References:     []string{"docs/use-cases/07-optional-pillar-discovery.md"},
		ExitCode:       ExitCodeRequiredMissing,
	}
}

// NewUnpinnedPillarError constructs a calm UB-CLI-v2 fail-closed FixForwardError (exit 126)
// when strict_pillar_pinning: true is active and a pillar has no SHA-256 pin.
func NewUnpinnedPillarError(p OptionalPillar, binaryPath string) *ux.FixForwardError {
	name := p.DisplayName()
	bin := string(p)
	return &ux.FixForwardError{
		Tool:           "fabrial",
		Code:           "FABRIAL_PILLAR_UNPINNED",
		Summary:        fmt.Sprintf("Pillar %s (%s) has no trusted SHA-256 pin while strict_pillar_pinning: true is active", name, binaryPath),
		RemediationCmd: fmt.Sprintf("fabrial trust pillar %s", bin),
		WhyOneLiner:    fmt.Sprintf("strict_pillar_pinning: true requires every loaded %s binary to match an explicit SHA-256 digest pin.", name),
		DeepWhy:        "Strict pinning prevents an adversary with local PATH write access from dropping a freshly compiled Go binary claiming our module path.",
		References:     []string{"docs/use-cases/07-optional-pillar-discovery.md"},
		ExitCode:       ExitCodeRequiredMissing,
	}
}
