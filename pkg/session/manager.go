package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	validIDRegex      = regexp.MustCompile(`^[a-zA-Z0-9_-]{8,128}$`)
	validSubtaskRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)
)

// BiometricVerifier verifies human/hardware biometric presence.
type BiometricVerifier func(ctx context.Context, reason string) error

// SessionManager manages active master and child agent sessions.
type SessionManager struct {
	mu                sync.RWMutex
	sessions          map[SessionID]*SessionGrant
	childrenByParent  map[SessionID][]SessionID
	biometricVerifier BiometricVerifier
	maxSessions       int
	defaultMasterTTL  time.Duration
	defaultChildTTL   time.Duration
}

// ManagerOption configures the SessionManager.
type ManagerOption func(*SessionManager)

// WithBiometricVerifier configures a custom biometric verifier (e.g. Locksmith Touch ID check).
func WithBiometricVerifier(v BiometricVerifier) ManagerOption {
	return func(sm *SessionManager) {
		sm.biometricVerifier = v
	}
}

// WithMaxSessions sets the maximum concurrent active sessions.
func WithMaxSessions(max int) ManagerOption {
	return func(sm *SessionManager) {
		sm.maxSessions = max
	}
}

// NewSessionManager creates a new SessionManager.
func NewSessionManager(opts ...ManagerOption) *SessionManager {
	sm := &SessionManager{
		sessions:         make(map[SessionID]*SessionGrant),
		childrenByParent: make(map[SessionID][]SessionID),
		maxSessions:      64,
		defaultMasterTTL: 30 * time.Minute,
		defaultChildTTL:  60 * time.Second,
	}

	for _, opt := range opts {
		opt(sm)
	}

	return sm
}

func (sm *SessionManager) activeCountLocked() int {
	count := 0
	now := time.Now()
	for _, g := range sm.sessions {
		if g != nil && !g.Revoked && !now.After(g.ExpiresAt) {
			count++
		}
	}
	return count
}

// BeginSession initializes a master session with ambient environment and optional biometric pre-flight.
func (sm *SessionManager) BeginSession(ctx context.Context, cfg SessionConfig) (*SessionGrant, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.pruneExpiredLocked()

	if sm.activeCountLocked() >= sm.maxSessions {
		return nil, ErrMaxConcurrencyLimit
	}

	// 1. Biometric Pre-Flight (Hardware Touch ID amortized once at master start)
	if cfg.BiometricPreflight && sm.biometricVerifier != nil {
		if err := sm.biometricVerifier(ctx, "Fabrial Master Session Inception"); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrBiometricFailed, err)
		}
	}

	// 2. Generate cryptographically strong SessionID & Master Token
	sessionID, err := generateRandomSessionID("master")
	if err != nil {
		return nil, err
	}

	masterToken, err := generateRandomToken(32)
	if err != nil {
		return nil, err
	}

	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = sm.defaultMasterTTL
	}
	if ttl > 4*time.Hour {
		ttl = 4 * time.Hour
	}

	now := time.Now()
	expiresAt := now.Add(ttl)

	scopes := cfg.AllowedScopes
	if len(scopes) == 0 {
		scopes = []string{"read", "build", "test", "lint"}
	}

	env := BuildEnvironment(sessionID, "", masterToken, cfg.ShieldProxyAddr, cfg.ShieldCACertPath)

	grant := &SessionGrant{
		ID:          sessionID,
		MasterToken: masterToken,
		Scopes:      scopes,
		CreatedAt:   now,
		ExpiresAt:   expiresAt,
		Environment: env,
		IsMaster:    true,
	}

	sm.sessions[sessionID] = grant
	sm.childrenByParent[sessionID] = make([]SessionID, 0, 8)

	return cloneGrant(grant), nil
}

// DeriveChildSession mints an attenuated subagent token without prompting Touch ID.
func (sm *SessionManager) DeriveChildSession(ctx context.Context, parentID SessionID, subtaskID string, requestedScopes []string) (*SessionGrant, error) {
	if subtaskID != "" && !validSubtaskRegex.MatchString(subtaskID) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidSubtaskID, subtaskID)
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.pruneExpiredLocked()

	if sm.activeCountLocked() >= sm.maxSessions {
		return nil, ErrMaxConcurrencyLimit
	}

	// 1. Validate Parent
	parent, exists := sm.sessions[parentID]
	if !exists {
		return nil, ErrSessionNotFound
	}
	if parent.Revoked {
		return nil, ErrSessionRevoked
	}
	if parent.IsExpired() {
		return nil, ErrSessionExpired
	}

	// 2. Monotonic Scope Attenuation Check
	if len(requestedScopes) == 0 {
		requestedScopes = append([]string(nil), parent.Scopes...)
	} else {
		for _, reqScope := range requestedScopes {
			if !hasScope(parent.Scopes, reqScope) {
				return nil, fmt.Errorf("%w: scope '%s' not present in parent grant", ErrScopeEscalation, reqScope)
			}
		}
	}

	// 3. Generate Child Session & Token
	childID, err := generateRandomSessionID("child")
	if err != nil {
		return nil, err
	}

	childToken, err := generateRandomToken(24)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	childTTL := sm.defaultChildTTL
	// Child TTL cannot exceed remaining parent TTL
	parentRemaining := time.Until(parent.ExpiresAt)
	if childTTL > parentRemaining {
		childTTL = parentRemaining
	}

	expiresAt := now.Add(childTTL)

	// Build child ambient environment
	env := BuildEnvironment(childID, parentID, childToken, parent.Environment["HTTP_PROXY"], parent.Environment["SSL_CERT_FILE"])
	if subtaskID != "" {
		env["FABRIAL_SUBTASK_ID"] = subtaskID
	}

	childGrant := &SessionGrant{
		ID:          childID,
		ParentID:    parentID,
		SubtaskID:   subtaskID,
		MasterToken: childToken,
		Scopes:      requestedScopes,
		CreatedAt:   now,
		ExpiresAt:   expiresAt,
		Environment: env,
		IsMaster:    false,
	}

	sm.sessions[childID] = childGrant
	sm.appendChildLocked(parentID, childID)

	return cloneGrant(childGrant), nil
}

func (sm *SessionManager) appendChildLocked(parentID, childID SessionID) {
	for _, existing := range sm.childrenByParent[parentID] {
		if existing == childID {
			return
		}
	}
	sm.childrenByParent[parentID] = append(sm.childrenByParent[parentID], childID)
}

// InvalidateSession tears down a specific session and any child sessions,
// persisting revocation tombstones until ExpiresAt so SaveToFile cannot resurrect them.
func (sm *SessionManager) InvalidateSession(ctx context.Context, id SessionID) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	return sm.invalidateLocked(id)
}

func (sm *SessionManager) invalidateLocked(id SessionID) error {
	grant, exists := sm.sessions[id]
	if !exists || grant == nil {
		return ErrSessionNotFound
	}
	if grant.Revoked {
		return ErrSessionRevoked
	}

	now := time.Now()

	// Cascade invalidation to children if this is a parent/master
	if children, ok := sm.childrenByParent[id]; ok {
		for _, childID := range children {
			if childGrant, childExists := sm.sessions[childID]; childExists && childGrant != nil {
				revokeGrantInPlace(childGrant, now)
			}
		}
	}
	// Also scan map in case children were loaded without parent index entry
	for _, g := range sm.sessions {
		if g != nil && g.ParentID == id {
			revokeGrantInPlace(g, now)
		}
	}

	// Persist tombstone on parent/target grant and scrub secrets
	revokeGrantInPlace(grant, now)

	return nil
}

func revokeGrantInPlace(g *SessionGrant, revokedAt time.Time) {
	if g == nil {
		return
	}
	g.Revoked = true
	if g.RevokedAt.IsZero() {
		g.RevokedAt = revokedAt
	}
	g.MasterToken = ""
	g.Environment = nil
}

// ValidateSession validates session ID syntax, existence, non-revocation (including parent lineage), and TTL.
func (sm *SessionManager) ValidateSession(id SessionID) (*SessionGrant, error) {
	if !ValidateSessionID(string(id)) {
		return nil, ErrInvalidSessionID
	}
	return sm.GetSession(id)
}

// GetSession returns a clone of the specified session grant if valid and unrevoked.
func (sm *SessionManager) GetSession(id SessionID) (*SessionGrant, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	grant, exists := sm.sessions[id]
	if !exists || grant == nil {
		return nil, ErrSessionNotFound
	}
	if grant.Revoked {
		return nil, ErrSessionRevoked
	}
	if grant.ParentID != "" {
		if parent, pExists := sm.sessions[grant.ParentID]; pExists && parent != nil && parent.Revoked {
			return nil, ErrSessionRevoked
		}
	}
	if grant.IsExpired() {
		return nil, ErrSessionExpired
	}

	return cloneGrant(grant), nil
}

// ActiveSessions returns a list of all active, unrevoked, unexpired session grants.
func (sm *SessionManager) ActiveSessions() []SessionGrant {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.pruneExpiredLocked()

	list := make([]SessionGrant, 0, len(sm.sessions))
	for _, g := range sm.sessions {
		if g == nil || g.Revoked || g.IsExpired() {
			continue
		}
		if g.ParentID != "" {
			if p, ok := sm.sessions[g.ParentID]; ok && p != nil && p.Revoked {
				continue
			}
		}
		list = append(list, *cloneGrant(g))
	}
	return list
}

func (sm *SessionManager) pruneExpiredLocked() {
	now := time.Now()
	for id, g := range sm.sessions {
		if g == nil || now.After(g.ExpiresAt) {
			delete(sm.sessions, id)
			delete(sm.childrenByParent, id)
		}
	}
	for parentID, children := range sm.childrenByParent {
		filtered := children[:0]
		for _, childID := range children {
			if _, ok := sm.sessions[childID]; ok {
				filtered = append(filtered, childID)
			}
		}
		if len(filtered) == 0 {
			delete(sm.childrenByParent, parentID)
		} else {
			sm.childrenByParent[parentID] = filtered
		}
	}
}

func hasScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target || s == "*" {
			return true
		}
	}
	return false
}

func generateRandomSessionID(prefix string) (SessionID, error) {
	bytes := make([]byte, 12)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	id := fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(bytes))
	if !validIDRegex.MatchString(id) {
		return "", ErrInvalidSessionID
	}
	return SessionID(id), nil
}

func generateRandomToken(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func cloneGrant(g *SessionGrant) *SessionGrant {
	if g == nil {
		return nil
	}
	c := *g
	if g.Scopes != nil {
		c.Scopes = append([]string(nil), g.Scopes...)
	}
	if g.Environment != nil {
		c.Environment = make(map[string]string, len(g.Environment))
		for k, v := range g.Environment {
			c.Environment[k] = v
		}
	}
	return &c
}

// DefaultSessionFilePath returns the canonical path ~/.fabrial/sessions.json.
func DefaultSessionFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(os.TempDir(), "fabrial-sessions.json")
	}
	return filepath.Join(home, ".fabrial", "sessions.json")
}

// SaveToFile persists active sessions and revocation tombstones to disk with 0600 permissions
// using atomic rename, inter-process locking, and monotonic Revoked merging.
func (sm *SessionManager) SaveToFile(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	lock, err := AcquireFileLock(path + ".lock")
	if err != nil {
		return err
	}
	defer func() { _ = lock.Release() }()

	// Read latest on-disk state and merge to prevent lost updates across parallel processes
	diskSessions := make(map[SessionID]*SessionGrant)
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &diskSessions)
	}

	sm.mu.Lock()
	sm.pruneExpiredLocked()

	now := time.Now()
	for id, diskG := range diskSessions {
		if diskG == nil || now.After(diskG.ExpiresAt) {
			continue
		}
		if memG, exists := sm.sessions[id]; exists && memG != nil {
			// Monotonic tombstone merge: Revoked = disk.Revoked || mem.Revoked
			if diskG.Revoked && !memG.Revoked {
				revokeGrantInPlace(memG, diskG.RevokedAt)
			} else if memG.Revoked {
				revokeGrantInPlace(memG, memG.RevokedAt)
			}
		} else {
			if diskG.Revoked {
				revokeGrantInPlace(diskG, diskG.RevokedAt)
			}
			sm.sessions[id] = cloneGrant(diskG)
			if diskG.ParentID != "" {
				sm.appendChildLocked(diskG.ParentID, id)
			}
		}
	}

	// Enforce parent -> child tombstone cascade across merged sessions
	for _, g := range sm.sessions {
		if g != nil && g.ParentID != "" {
			if parent, ok := sm.sessions[g.ParentID]; ok && parent != nil && parent.Revoked {
				revokeGrantInPlace(g, parent.RevokedAt)
			}
		}
	}

	data, err := json.MarshalIndent(sm.sessions, "", "  ")
	sm.mu.Unlock()

	if err != nil {
		return err
	}

	tmpFile := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return err
	}

	if err := os.Rename(tmpFile, path); err != nil {
		if rmErr := os.Remove(tmpFile); rmErr != nil && !os.IsNotExist(rmErr) {
			_ = rmErr
		}
		return err
	}
	return nil
}

// LoadFromFile loads sessions from disk with inter-process locking, pruning expired ones
// and preserving monotonic revocation tombstones.
func (sm *SessionManager) LoadFromFile(path string) error {
	lock, err := AcquireFileLock(path + ".lock")
	if err != nil {
		return err
	}
	defer func() { _ = lock.Release() }()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var loaded map[SessionID]*SessionGrant
	if err := json.Unmarshal(data, &loaded); err != nil {
		return err
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	prior := sm.sessions
	sm.sessions = make(map[SessionID]*SessionGrant)
	sm.childrenByParent = make(map[SessionID][]SessionID)

	now := time.Now()
	for id, diskG := range loaded {
		if diskG == nil || now.After(diskG.ExpiresAt) {
			continue
		}
		cloned := cloneGrant(diskG)
		if memG, ok := prior[id]; ok && memG != nil && memG.Revoked {
			revokeGrantInPlace(cloned, memG.RevokedAt)
		} else if cloned.Revoked {
			revokeGrantInPlace(cloned, cloned.RevokedAt)
		}
		sm.sessions[id] = cloned
		if cloned.ParentID != "" {
			sm.appendChildLocked(cloned.ParentID, id)
		}
	}

	// Preserve any unexpired in-memory tombstones not yet flushed to disk
	for id, memG := range prior {
		if memG == nil || now.After(memG.ExpiresAt) || !memG.Revoked {
			continue
		}
		if _, exists := sm.sessions[id]; !exists {
			tombstone := cloneGrant(memG)
			revokeGrantInPlace(tombstone, memG.RevokedAt)
			sm.sessions[id] = tombstone
		}
	}

	// Enforce parent -> child tombstone cascade
	for _, g := range sm.sessions {
		if g != nil && g.ParentID != "" {
			if parent, ok := sm.sessions[g.ParentID]; ok && parent != nil && parent.Revoked {
				revokeGrantInPlace(g, parent.RevokedAt)
			}
		}
	}

	return nil
}

// ValidateSessionID checks if a session ID adheres to strict character and length constraints.
func ValidateSessionID(id string) bool {
	if len(id) < 8 || len(id) > 128 {
		return false
	}
	return validIDRegex.MatchString(id) && !strings.Contains(id, "..")
}
