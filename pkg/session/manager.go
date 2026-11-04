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

// BeginSession initializes a master session with ambient environment and optional biometric pre-flight.
func (sm *SessionManager) BeginSession(ctx context.Context, cfg SessionConfig) (*SessionGrant, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.pruneExpiredLocked()

	if len(sm.sessions) >= sm.maxSessions {
		return nil, ErrMaxConcurrencyLimit
	}

	// 1. Biometric Pre-Flight (Hardware Touch ID amortized once at master start)
	if cfg.BiometricPreflight && sm.biometricVerifier != nil {
		if err := sm.biometricVerifier(ctx, "Fabrial Master Session Inception"); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBiometricFailed, err)
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

	// 1. Validate Parent
	parent, exists := sm.sessions[parentID]
	if !exists {
		return nil, ErrSessionNotFound
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
	sm.childrenByParent[parentID] = append(sm.childrenByParent[parentID], childID)

	return cloneGrant(childGrant), nil
}

// InvalidateSession tears down a specific session and any child sessions.
func (sm *SessionManager) InvalidateSession(ctx context.Context, id SessionID) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	return sm.invalidateLocked(id)
}

func (sm *SessionManager) invalidateLocked(id SessionID) error {
	grant, exists := sm.sessions[id]
	if !exists {
		return ErrSessionNotFound
	}

	// Cascade invalidation to children if this is a parent/master
	if children, ok := sm.childrenByParent[id]; ok {
		for _, childID := range children {
			if childGrant, childExists := sm.sessions[childID]; childExists {
				childGrant.MasterToken = ""
				delete(sm.sessions, childID)
			}
		}
		delete(sm.childrenByParent, id)
	}

	// Zeroize token memory
	grant.MasterToken = ""
	delete(sm.sessions, id)

	return nil
}

// GetSession returns a clone of the specified session grant if valid.
func (sm *SessionManager) GetSession(id SessionID) (*SessionGrant, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	grant, exists := sm.sessions[id]
	if !exists {
		return nil, ErrSessionNotFound
	}
	if grant.IsExpired() {
		return nil, ErrSessionExpired
	}

	return cloneGrant(grant), nil
}

// ActiveSessions returns a list of all active, unexpired session grants.
func (sm *SessionManager) ActiveSessions() []SessionGrant {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.pruneExpiredLocked()

	list := make([]SessionGrant, 0, len(sm.sessions))
	for _, g := range sm.sessions {
		list = append(list, *cloneGrant(g))
	}
	return list
}

func (sm *SessionManager) pruneExpiredLocked() {
	now := time.Now()
	for id, g := range sm.sessions {
		if now.After(g.ExpiresAt) {
			sm.invalidateLocked(id)
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
	c.Scopes = append([]string(nil), g.Scopes...)
	c.Environment = make(map[string]string, len(g.Environment))
	for k, v := range g.Environment {
		c.Environment[k] = v
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

// SaveToFile persists active sessions to disk with 0600 permissions using atomic rename and inter-process locking.
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

	// Merge: add active on-disk sessions not yet in memory
	now := time.Now()
	for id, g := range diskSessions {
		if !now.After(g.ExpiresAt) {
			if _, exists := sm.sessions[id]; !exists {
				sm.sessions[id] = g
				if g.ParentID != "" {
					sm.childrenByParent[g.ParentID] = append(sm.childrenByParent[g.ParentID], id)
				}
			}
		}
	}

	data, err := json.MarshalIndent(sm.sessions, "", "  ")
	sm.mu.Unlock()

	if err != nil {
		return err
	}

	tmpFile := path + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return err
	}

	return os.Rename(tmpFile, path)
}

// LoadFromFile loads sessions from disk with inter-process locking, pruning expired ones.
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

	sm.sessions = make(map[SessionID]*SessionGrant)
	sm.childrenByParent = make(map[SessionID][]SessionID)

	now := time.Now()
	for id, g := range loaded {
		if !now.After(g.ExpiresAt) {
			sm.sessions[id] = g
			if g.ParentID != "" {
				sm.childrenByParent[g.ParentID] = append(sm.childrenByParent[g.ParentID], id)
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
