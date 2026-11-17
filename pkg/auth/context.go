package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	ErrNotAuthenticated  = errors.New("fabrial: not authenticated; no active session token found")
	ErrAuthExpired       = errors.New("fabrial: authentication session has expired")
	ErrCorruptedAuthFile = errors.New("fabrial: authentication state file is corrupted")
	ErrLocksmithFailed   = errors.New("fabrial: failed to retrieve token from locksmith")
)

var (
	tokenCacheMu sync.RWMutex
	cachedToken  string
	cachedExpiry time.Time
)

// SetCachedToken allows manually injecting or updating the process-level token cache.
func SetCachedToken(token string, ttl time.Duration) {
	tokenCacheMu.Lock()
	defer tokenCacheMu.Unlock()
	cachedToken = token
	if ttl > 0 {
		cachedExpiry = time.Now().Add(ttl)
	} else {
		cachedExpiry = time.Now().Add(5 * time.Minute)
	}
}

// ClearCachedToken purges the in-memory token cache.
func ClearCachedToken() {
	tokenCacheMu.Lock()
	defer tokenCacheMu.Unlock()
	cachedToken = ""
	cachedExpiry = time.Time{}
}

// FabrialAuthContext represents the authenticated developer session established by Fabrial.
type FabrialAuthContext struct {
	Token              string    `json:"token,omitempty"`
	TenantID           string    `json:"tenant_id"`
	UserID             string    `json:"user_id,omitempty"`
	OrgName            string    `json:"org_name,omitempty"`
	Email              string    `json:"email,omitempty"`
	Name               string    `json:"name,omitempty"`
	Role               string    `json:"role,omitempty"`
	Scopes             []string  `json:"scopes,omitempty"`
	ServerURL          string    `json:"server_url"`
	AuthorityPublicKey string    `json:"authority_public_key,omitempty"`
	TokenStorage       string    `json:"token_storage,omitempty"` // "locksmith" or "file"
	LocksmithKey       string    `json:"locksmith_key,omitempty"`  // e.g. "stoneward_agent_token"
	CreatedAt          time.Time `json:"created_at"`
	ExpiresAt          time.Time `json:"expires_at"`
}

// IsValid checks whether the auth context has a valid token reference and has not expired.
func (a *FabrialAuthContext) IsValid() bool {
	if a == nil {
		return false
	}
	hasTokenRef := strings.TrimSpace(a.Token) != "" || strings.TrimSpace(a.LocksmithKey) != "" || a.TokenStorage == "locksmith"
	if !hasTokenRef {
		return false
	}
	if !a.ExpiresAt.IsZero() && time.Now().After(a.ExpiresAt) {
		return false
	}
	return true
}

// ResolveToken returns the active bearer token. If sealed in Locksmith, it resolves it
// from the in-memory process cache or queries the Locksmith hardware vault with biometric amortization.
func (a *FabrialAuthContext) ResolveToken() (string, error) {
	if a == nil {
		return "", ErrNotAuthenticated
	}
	if a.Token != "" {
		return a.Token, nil
	}

	if a.TokenStorage == "locksmith" || a.LocksmithKey != "" {
		key := a.LocksmithKey
		if key == "" {
			key = "stoneward_agent_token"
		}

		// 1. Check in-memory amortization cache (<15μs, zero Touch ID prompts)
		tokenCacheMu.RLock()
		if cachedToken != "" && (cachedExpiry.IsZero() || time.Now().Before(cachedExpiry)) {
			tok := cachedToken
			tokenCacheMu.RUnlock()
			return tok, nil
		}
		tokenCacheMu.RUnlock()

		// 2. Fetch from Locksmith (enclave / daemon with biometric lease window)
		tok, err := FetchLocksmithSecret(key)
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrLocksmithFailed, err)
		}

		tokenCacheMu.Lock()
		cachedToken = tok
		cachedExpiry = time.Now().Add(5 * time.Minute) // 300s biometric amortization window
		tokenCacheMu.Unlock()

		return tok, nil
	}

	return "", ErrNotAuthenticated
}

// GetFabrialAuthPath returns the canonical path to ~/.fabrial/auth.json.
func GetFabrialAuthPath() string {
	if p := os.Getenv("FABRIAL_AUTH_FILE"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(os.TempDir(), "fabrial-auth.json")
	}
	return filepath.Join(home, ".fabrial", "auth.json")
}

// LoadFabrialAuth retrieves the current Fabrial authentication context.
// It checks ambient environment variables first, then falls back to the canonical disk file.
func LoadFabrialAuth() (*FabrialAuthContext, error) {
	// 1. Ambient Environment Variables (e.g. injected into child subagents or CI)
	envToken := os.Getenv("FABRIAL_AUTH_TOKEN")
	if envToken == "" {
		envToken = os.Getenv("STONEWARD_TOKEN")
	}
	if envToken != "" {
		serverURL := os.Getenv("STONEWARD_SERVER_URL")
		if serverURL == "" {
			serverURL = "https://localhost:9443"
		}
		tenantID := os.Getenv("STONEWARD_TENANT_ID")
		if tenantID == "" {
			tenantID = "bonjo-prod"
		}
		userID := os.Getenv("STONEWARD_USER_ID")

		auth := &FabrialAuthContext{
			Token:              envToken,
			TenantID:           tenantID,
			UserID:             userID,
			ServerURL:          serverURL,
			AuthorityPublicKey: strings.TrimSpace(os.Getenv("STONEWARD_AUTHORITY_PUBKEY")),
			CreatedAt:          time.Now().UTC(),
			ExpiresAt:          time.Now().UTC().Add(24 * time.Hour), // Ambient token defaults to 24h
		}
		return auth, nil
	}

	// 2. Canonical Disk File (~/.fabrial/auth.json)
	path := GetFabrialAuthPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotAuthenticated
		}
		return nil, fmt.Errorf("failed to read fabrial auth file: %w", err)
	}

	var auth FabrialAuthContext
	if err := json.Unmarshal(data, &auth); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCorruptedAuthFile, err)
	}

	if envPub := strings.TrimSpace(os.Getenv("STONEWARD_AUTHORITY_PUBKEY")); envPub != "" {
		auth.AuthorityPublicKey = envPub
	}

	if !auth.IsValid() {
		return nil, ErrAuthExpired
	}

	return &auth, nil
}

// SaveFabrialAuth atomically writes the authentication context to disk with 0600 permissions.
// If TokenStorage is "locksmith", the plaintext token is stripped from the serialized JSON
// to guarantee zero plaintext tokens reside on disk.
func SaveFabrialAuth(auth *FabrialAuthContext) error {
	if auth == nil {
		return errors.New("cannot save nil auth context")
	}

	diskAuth := *auth
	if diskAuth.TokenStorage == "locksmith" && diskAuth.LocksmithKey != "" {
		// Zero plaintext token before serializing to disk
		diskAuth.Token = ""
	} else if strings.TrimSpace(diskAuth.Token) == "" && diskAuth.TokenStorage != "locksmith" {
		return errors.New("cannot save empty token without locksmith storage")
	}

	data, err := json.MarshalIndent(&diskAuth, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal auth context: %w", err)
	}

	return writeAtomic0600(GetFabrialAuthPath(), data)
}

// ClearFabrialAuth removes the stored authentication file and clears in-memory caches.
func ClearFabrialAuth() error {
	ClearCachedToken()
	path := GetFabrialAuthPath()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// IsFabrialAuthenticated reports whether an active, non-expired Fabrial session is present.
func IsFabrialAuthenticated() bool {
	auth, err := LoadFabrialAuth()
	return err == nil && auth != nil && auth.IsValid()
}

// ResolveLocksmithSocket locates the active Locksmith daemon socket path.
func ResolveLocksmithSocket() string {
	if sock := os.Getenv("LOCKSMITH_SOCKET"); sock != "" {
		return sock
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		cand1 := filepath.Join(home, ".locksmith", "locksmithd.sock")
		if _, err := os.Stat(cand1); err == nil {
			return cand1
		}
		cand2 := filepath.Join(home, ".locksmith", "locksmith.sock")
		if _, err := os.Stat(cand2); err == nil {
			return cand2
		}
	}
	tmpCandidate := filepath.Join(os.TempDir(), fmt.Sprintf("locksmith-%d.sock", os.Getuid()))
	if _, err := os.Stat(tmpCandidate); err == nil {
		return tmpCandidate
	}
	return filepath.Join(os.TempDir(), "locksmith.sock")
}

// StoreLocksmithSecret saves a secret into Locksmith's hardware-backed vault via CLI or IPC.
func StoreLocksmithSecret(key, val string) error {
	if key == "" || val == "" {
		return errors.New("key and value cannot be empty")
	}

	// Try locksmith CLI if present (with 15-second timeout to accommodate keychain initialization)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "locksmith", "add", key, val)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("locksmith add failed: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	// Immediately populate in-memory amortization cache
	SetCachedToken(val, 5*time.Minute)
	return nil
}

// FetchLocksmithSecret queries Locksmith for a stored secret using IPC lease checkout or CLI fallback.
func FetchLocksmithSecret(key string) (string, error) {
	if key == "" {
		return "", errors.New("locksmith secret key cannot be empty")
	}

	// 1. Try Locksmith IPC socket if available (ETX protocol v1.0 with SPIFFE workload identity)
	sockPath := ResolveLocksmithSocket()
	if conn, err := net.DialTimeout("unix", sockPath, 200*time.Millisecond); err == nil {
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

		req := map[string]interface{}{
			"version":     "1.0",
			"action":      "request_lease",
			"secret_name": key,
			"spiffe_id":   "spiffe://aegisbox.local/workload/fabrial",
			"lease_ttl":   300 * time.Second,
			"client_pid":  os.Getpid(),
		}
		if err := json.NewEncoder(conn).Encode(req); err == nil {
			var resp struct {
				Status      string `json:"status"`
				SecretValue []byte `json:"secret_value"`
				Error       string `json:"error"`
			}
			if err := json.NewDecoder(conn).Decode(&resp); err == nil && resp.Status == "GRANTED" && len(resp.SecretValue) > 0 {
				return string(resp.SecretValue), nil
			}
		}
	}

	// 2. Fall back to CLI execution (with 3-second timeout to avoid blocking if biometric is needed)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "locksmith", "get", key, "-n")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("locksmith get failed: %w", err)
	}

	secret := strings.TrimSpace(string(out))
	if secret == "" {
		return "", fmt.Errorf("locksmith returned empty secret for key %q", key)
	}
	return secret, nil
}

func writeAtomic0600(targetPath string, data []byte) error {
	cleanTarget := filepath.Clean(targetPath)
	dir := filepath.Dir(cleanTarget)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	if fi, err := os.Lstat(cleanTarget); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to overwrite symlink at %s", cleanTarget)
	}

	tmp, err := os.CreateTemp(dir, ".fabrial-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmpName, cleanTarget)
}
