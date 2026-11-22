package receipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	receiptsBaseRel     = ".fabrial/receipts"
	gitExcludeEntry     = ".fabrial/receipts/"
	maxReceiptFileBytes = 1024 * 1024 // 1 MiB cap per receipt file
)

var (
	// ErrSymlinkDetected is returned whenever any receipt directory or file is a symlink.
	ErrSymlinkDetected = errors.New("symlink detected in receipt storage path (fail-closed)")
	// ErrUnsafePermissions is returned when socket/directory ownership or permissions violate invariants.
	ErrUnsafePermissions = errors.New("unsafe permissions or ownership detected")
	// ErrInvalidSessionID indicates a session ID failed BLPR-v1 validation.
	ErrInvalidSessionID = errors.New("invalid BLPR-v1 session ID")
	// ErrInvalidTool indicates a producer tool name failed BLPR-v1 validation.
	ErrInvalidTool = errors.New("invalid BLPR-v1 producer tool")
)

// StoredReceipt pairs an on-disk receipt filename with its parsed DSSEEnvelope.
type StoredReceipt struct {
	SessionID string        `json:"session_id"`
	Filename  string        `json:"filename"`
	RelPath   string        `json:"rel_path"`
	Envelope  *DSSEEnvelope `json:"envelope"`
}

// VerifiedReceipt records a single cryptographically verified BLPR-v1 receipt.
type VerifiedReceipt struct {
	SessionID string     `json:"session_id"`
	Filename  string     `json:"filename"`
	ReceiptID string     `json:"receipt_id"`
	Tool      string     `json:"tool"`
	Version   string     `json:"version"`
	Stage     string     `json:"stage"`
	Verdict   Verdict    `json:"verdict"`
	Proven    bool       `json:"proven"`
	KeyID     string     `json:"keyid"`
	Timestamp time.Time  `json:"timestamp"`
	Statement *Statement `json:"statement,omitempty"`
}

// Store manages lock-free, symlink-hardened atomic BLPR-v1 receipt storage scoped
// to a single local repository worktree via os.OpenRoot.
type Store struct {
	WorktreeRoot string
	excludeMu    sync.Mutex
}

// NewStore creates a Store bound to worktreeRoot.
func NewStore(worktreeRoot string) (*Store, error) {
	if strings.TrimSpace(worktreeRoot) == "" {
		worktreeRoot = "."
	}
	absRoot, err := filepath.Abs(worktreeRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve worktree root: %w", err)
	}
	fi, err := os.Stat(absRoot)
	if err != nil {
		return nil, fmt.Errorf("stat worktree root %s: %w", absRoot, err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("worktree root %s is not a directory", absRoot)
	}
	return &Store{WorktreeRoot: absRoot}, nil
}

// SessionReceiptDir returns the absolute path <WorktreeRoot>/.fabrial/receipts/<sessionID>.
func (s *Store) SessionReceiptDir(sessionID string) (string, error) {
	if !ValidateSessionID(sessionID) {
		return "", fmt.Errorf("%w: %q", ErrInvalidSessionID, sessionID)
	}
	return filepath.Join(s.WorktreeRoot, ".fabrial", "receipts", sessionID), nil
}

// Write atomically persists a signed BLPR-v1 DSSEEnvelope under
// .fabrial/receipts/<session_id>/<unix_ms>-<tool>-<id>.dsse.json (0600)
// via os.OpenRoot, rejecting any symlink along the path.
func (s *Store) Write(env *DSSEEnvelope, stmt *Statement) (string, error) {
	if err := ValidateEnvelope(env); err != nil {
		return "", err
	}
	if err := ValidateStatement(stmt); err != nil {
		return "", err
	}
	return s.WriteEnvelope(
		stmt.Predicate.Session.SessionID,
		stmt.Predicate.Producer.Tool,
		stmt.Predicate.ReceiptID,
		env,
	)
}

// WriteEnvelope atomically writes env as <unix_ms>-<tool>-<receiptID>.dsse.json (0600)
// inside .fabrial/receipts/<sessionID>/ (0700), with zero cross-agent file locks.
func (s *Store) WriteEnvelope(sessionID, tool, receiptID string, env *DSSEEnvelope) (string, error) {
	if !ValidateSessionID(sessionID) {
		return "", fmt.Errorf("%w: %q", ErrInvalidSessionID, sessionID)
	}
	if !ValidateTool(tool) {
		return "", fmt.Errorf("%w: %q", ErrInvalidTool, tool)
	}
	if !ValidateReceiptID(receiptID) {
		return "", fmt.Errorf("invalid receipt_id %q", receiptID)
	}
	if err := ValidateEnvelope(env); err != nil {
		return "", err
	}

	root, err := os.OpenRoot(s.WorktreeRoot)
	if err != nil {
		return "", fmt.Errorf("open worktree root: %w", err)
	}
	defer func() { _ = root.Close() }()

	// Create/validate .fabrial -> .fabrial/receipts -> .fabrial/receipts/<sessionID>
	// with strict Lstat non-symlink and 0700 checks on every component.
	if err := ensureSafeDir(root, ".fabrial", "receipts", sessionID); err != nil {
		return "", err
	}

	// Best-effort idempotent .git/info/exclude registration if .git is a regular dir.
	if err := s.ensureGitInfoExclude(root); err != nil {
		return "", err
	}

	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal DSSE envelope: %w", err)
	}
	data = append(data, '\n')

	tsMs := time.Now().UTC().UnixMilli()
	finalName := fmt.Sprintf("%d-%s-%s.dsse.json", tsMs, tool, receiptID)
	sessionRelDir := filepath.Join(".fabrial", "receipts", sessionID)
	finalRel := filepath.Join(sessionRelDir, finalName)

	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate temp nonce: %w", err)
	}
	tmpRel := filepath.Join(sessionRelDir, fmt.Sprintf(".%s.%s.tmp", finalName, hex.EncodeToString(nonce)))

	// O_CREAT|O_EXCL prevents clobbering or symlink races on temp file creation.
	f, err := root.OpenFile(tmpRel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", fmt.Errorf("create temp receipt file: %w", err)
	}

	writeErr := func() error {
		if _, wErr := f.Write(data); wErr != nil {
			return fmt.Errorf("write temp receipt: %w", wErr)
		}
		if sErr := f.Sync(); sErr != nil {
			return fmt.Errorf("fsync temp receipt: %w", sErr)
		}
		return f.Close()
	}()
	if writeErr != nil {
		_ = f.Close()
		_ = root.Remove(tmpRel)
		return "", writeErr
	}

	// Re-verify final destination does not exist as a symlink before atomic rename.
	if fi, lErr := root.Lstat(finalRel); lErr == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			_ = root.Remove(tmpRel)
			return "", fmt.Errorf("%w: destination %s is a symlink", ErrSymlinkDetected, finalRel)
		}
	}

	if err := root.Rename(tmpRel, finalRel); err != nil {
		_ = root.Remove(tmpRel)
		return "", fmt.Errorf("atomic rename receipt %s: %w", finalRel, err)
	}

	return filepath.Join(s.WorktreeRoot, finalRel), nil
}

// ListSessions returns sorted BLPR-v1 session IDs found under .fabrial/receipts/.
// Rejects symlinks on .fabrial, .fabrial/receipts, or any session directory fail-closed.
func (s *Store) ListSessions() ([]string, error) {
	root, err := os.OpenRoot(s.WorktreeRoot)
	if err != nil {
		return nil, fmt.Errorf("open worktree root: %w", err)
	}
	defer func() { _ = root.Close() }()

	if exists, err := checkSafeExistingDir(root, ".fabrial"); err != nil {
		return nil, err
	} else if !exists {
		return nil, nil
	}

	if exists, err := checkSafeExistingDir(root, receiptsBaseRel); err != nil {
		return nil, err
	} else if !exists {
		return nil, nil
	}

	dirFile, err := root.Open(receiptsBaseRel)
	if err != nil {
		return nil, fmt.Errorf("open receipts dir: %w", err)
	}
	defer func() { _ = dirFile.Close() }()

	entries, err := dirFile.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("read receipts dir: %w", err)
	}

	var sessions []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		rel := filepath.Join(receiptsBaseRel, name)
		fi, lErr := root.Lstat(rel)
		if lErr != nil {
			return nil, fmt.Errorf("lstat %s: %w", rel, lErr)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: %s", ErrSymlinkDetected, rel)
		}
		if !fi.IsDir() {
			continue
		}
		if !ValidateSessionID(name) {
			return nil, fmt.Errorf("%w: unexpected directory %q in %s", ErrInvalidSessionID, name, receiptsBaseRel)
		}
		sessions = append(sessions, name)
	}
	sort.Strings(sessions)
	return sessions, nil
}

// ReadSession loads and parses all *.dsse.json receipts in .fabrial/receipts/<sessionID>/
// via os.OpenRoot, failing closed on any symlinked directory or file.
func (s *Store) ReadSession(sessionID string) ([]StoredReceipt, error) {
	if !ValidateSessionID(sessionID) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidSessionID, sessionID)
	}

	root, err := os.OpenRoot(s.WorktreeRoot)
	if err != nil {
		return nil, fmt.Errorf("open worktree root: %w", err)
	}
	defer func() { _ = root.Close() }()

	if exists, err := checkSafeExistingDir(root, ".fabrial"); err != nil {
		return nil, err
	} else if !exists {
		return nil, nil
	}
	if exists, err := checkSafeExistingDir(root, receiptsBaseRel); err != nil {
		return nil, err
	} else if !exists {
		return nil, nil
	}
	sessionRel := filepath.Join(receiptsBaseRel, sessionID)
	if exists, err := checkSafeExistingDir(root, sessionRel); err != nil {
		return nil, err
	} else if !exists {
		return nil, nil
	}

	dirFile, err := root.Open(sessionRel)
	if err != nil {
		return nil, fmt.Errorf("open session receipt dir: %w", err)
	}
	defer func() { _ = dirFile.Close() }()

	entries, err := dirFile.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("read session receipt dir: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".dsse.json") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	receipts := make([]StoredReceipt, 0, len(names))
	for _, name := range names {
		rel := filepath.Join(sessionRel, name)
		fi, lErr := root.Lstat(rel)
		if lErr != nil {
			return nil, fmt.Errorf("lstat receipt %s: %w", rel, lErr)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: %s", ErrSymlinkDetected, rel)
		}
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("receipt %s is not a regular file", rel)
		}
		if err := verifyOwnerUID(fi, rel); err != nil {
			return nil, err
		}
		if fi.Size() > maxReceiptFileBytes {
			return nil, fmt.Errorf("receipt %s exceeds %d byte limit", rel, maxReceiptFileBytes)
		}

		f, oErr := root.Open(rel)
		if oErr != nil {
			return nil, fmt.Errorf("open receipt %s: %w", rel, oErr)
		}
		raw, rErr := io.ReadAll(io.LimitReader(f, maxReceiptFileBytes+1))
		_ = f.Close()
		if rErr != nil {
			return nil, fmt.Errorf("read receipt %s: %w", rel, rErr)
		}
		if len(raw) > maxReceiptFileBytes {
			return nil, fmt.Errorf("receipt %s exceeds %d byte limit", rel, maxReceiptFileBytes)
		}

		env, pErr := ParseEnvelope(raw)
		if pErr != nil {
			return nil, fmt.Errorf("parse receipt %s: %w", name, pErr)
		}
		receipts = append(receipts, StoredReceipt{
			SessionID: sessionID,
			Filename:  name,
			RelPath:   rel,
			Envelope:  env,
		})
	}

	return receipts, nil
}

// VerifySession reads and cryptographically verifies every BLPR-v1 receipt in
// .fabrial/receipts/<sessionID>/ against pub, also ensuring each receipt's
// attested session_id matches the directory sessionID.
func (s *Store) VerifySession(sessionID string, pub ed25519.PublicKey) ([]VerifiedReceipt, error) {
	stored, err := s.ReadSession(sessionID)
	if err != nil {
		return nil, err
	}

	verified := make([]VerifiedReceipt, 0, len(stored))
	for _, item := range stored {
		stmt, err := VerifyEnvelope(item.Envelope, pub)
		if err != nil {
			return nil, fmt.Errorf("verify %s: %w", item.Filename, err)
		}
		if stmt.Predicate.Session.SessionID != sessionID {
			return nil, fmt.Errorf("%w: receipt %s claims session %q inside directory %q",
				ErrSignatureFailed, item.Filename, stmt.Predicate.Session.SessionID, sessionID)
		}
		verified = append(verified, VerifiedReceipt{
			SessionID: sessionID,
			Filename:  item.Filename,
			ReceiptID: stmt.Predicate.ReceiptID,
			Tool:      stmt.Predicate.Producer.Tool,
			Version:   stmt.Predicate.Producer.Version,
			Stage:     stmt.Predicate.Producer.Stage,
			Verdict:   stmt.Predicate.Verdict,
			Proven:    stmt.Predicate.Proven,
			KeyID:     SessionKeyID(sessionID),
			Timestamp: stmt.Predicate.Timestamp,
			Statement: stmt,
		})
	}

	return verified, nil
}

func ensureSafeDir(root *os.Root, components ...string) error {
	curr := ""
	for _, part := range components {
		if curr == "" {
			curr = part
		} else {
			curr = filepath.Join(curr, part)
		}
		fi, err := root.Lstat(curr)
		if err != nil {
			if os.IsNotExist(err) {
				if mkErr := root.Mkdir(curr, 0700); mkErr != nil && !os.IsExist(mkErr) {
					return fmt.Errorf("mkdir %s: %w", curr, mkErr)
				}
				fi, err = root.Lstat(curr)
				if err != nil {
					return fmt.Errorf("lstat created dir %s: %w", curr, err)
				}
			} else {
				return fmt.Errorf("lstat %s: %w", curr, err)
			}
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s", ErrSymlinkDetected, curr)
		}
		if !fi.IsDir() {
			return fmt.Errorf("expected directory at %s, found %s", curr, fi.Mode())
		}
		if err := verifyOwnerUID(fi, curr); err != nil {
			return err
		}
	}
	return nil
}

func checkSafeExistingDir(root *os.Root, rel string) (bool, error) {
	fi, err := root.Lstat(rel)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("lstat %s: %w", rel, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("%w: %s", ErrSymlinkDetected, rel)
	}
	if !fi.IsDir() {
		return false, fmt.Errorf("expected directory at %s", rel)
	}
	if err := verifyOwnerUID(fi, rel); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) ensureGitInfoExclude(root *os.Root) error {
	// Fast check: only touch .git/info/exclude when .git is a regular directory inside worktreeRoot.
	gitInfo, err := root.Lstat(".git")
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return nil
	}
	if gitInfo.Mode()&os.ModeSymlink != 0 || !gitInfo.IsDir() {
		return nil
	}

	s.excludeMu.Lock()
	defer s.excludeMu.Unlock()

	infoRel := filepath.Join(".git", "info")
	if fi, err := root.Lstat(infoRel); err != nil {
		if os.IsNotExist(err) {
			if mkErr := root.Mkdir(infoRel, 0755); mkErr != nil && !os.IsExist(mkErr) {
				return fmt.Errorf("mkdir .git/info: %w", mkErr)
			}
		} else {
			return nil
		}
	} else if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return nil
	}

	excludeRel := filepath.Join(".git", "info", "exclude")
	var existing []byte
	if fi, err := root.Lstat(excludeRel); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s", ErrSymlinkDetected, excludeRel)
		}
		if !fi.Mode().IsRegular() {
			return nil
		}
		data, rErr := root.ReadFile(excludeRel)
		if rErr != nil {
			return fmt.Errorf("read %s: %w", excludeRel, rErr)
		}
		existing = data
	} else if !os.IsNotExist(err) {
		return nil
	}

	for _, line := range strings.Split(string(existing), "\n") {
		if strings.TrimSpace(line) == gitExcludeEntry {
			return nil
		}
	}

	var buf bytes.Buffer
	buf.Write(existing)
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		buf.WriteByte('\n')
	}
	buf.WriteString(gitExcludeEntry)
	buf.WriteByte('\n')

	nonce := make([]byte, 6)
	_, _ = rand.Read(nonce)
	tmpRel := filepath.Join(infoRel, fmt.Sprintf(".exclude.%s.tmp", hex.EncodeToString(nonce)))
	f, err := root.OpenFile(tmpRel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return fmt.Errorf("create temp exclude file: %w", err)
	}
	if _, wErr := f.Write(buf.Bytes()); wErr != nil {
		_ = f.Close()
		_ = root.Remove(tmpRel)
		return fmt.Errorf("write temp exclude file: %w", wErr)
	}
	if sErr := f.Sync(); sErr != nil {
		_ = f.Close()
		_ = root.Remove(tmpRel)
		return fmt.Errorf("sync temp exclude file: %w", sErr)
	}
	if cErr := f.Close(); cErr != nil {
		_ = root.Remove(tmpRel)
		return fmt.Errorf("close temp exclude file: %w", cErr)
	}
	if rErr := root.Rename(tmpRel, excludeRel); rErr != nil {
		_ = root.Remove(tmpRel)
		return fmt.Errorf("replace %s: %w", excludeRel, rErr)
	}
	return nil
}
