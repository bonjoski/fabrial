package hooks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/bonjoski/fabrial/pkg/policy"
	"github.com/bonjoski/fabrial/pkg/receipt"
	"github.com/bonjoski/fabrial/pkg/router"
	"github.com/bonjoski/fabrial/pkg/ux"
	"github.com/bonjoski/fabrial/pkg/version"
)

const (
	maxHookWrapperDepth = 16
	maxArgusRespBytes   = 16 * 1024
	locksmithHookBudget = 50 * time.Millisecond
)

// DefaultEvaluator performs sub-5ms in-process security evaluation for pre-tool
// hooks and <1ms non-blocking async index enqueueing for post-tool hooks.
type DefaultEvaluator struct {
	WorktreeRoot         string
	ReceiptDir           string
	ArgusSocketPath      string
	CoppermindSocketPath string
	LocksmithSocketPath  string
	Strict               bool
	ArgusDialTimeout     time.Duration
	CoppermindTimeout    time.Duration
	ReceiptSigner        receipt.Signer
	Now                  func() time.Time

	appendMu sync.Mutex
}

// ReadAndParseInput reads a bounded JSON hook payload from r within timeout and
// normalizes Claude Code, Cursor, and Gemini CLI schemas into NormalizedHookInput.
func ReadAndParseInput(r io.Reader, client ClientDialect, event HookEvent, maxBytes int64, timeout time.Duration) (*NormalizedHookInput, error) {
	if r == nil {
		return nil, ErrEmptyInput
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxInputBytes
	}
	if timeout <= 0 {
		timeout = DefaultReadTimeout
	}

	raw, err := readBoundedWithTimeout(r, maxBytes, timeout)
	if err != nil {
		return nil, err
	}

	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, ErrEmptyInput
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(trimmed, &payload); err != nil {
		return nil, fmt.Errorf("invalid hook JSON payload: %w", err)
	}
	if payload == nil {
		return nil, ErrEmptyInput
	}

	return normalizePayload(payload, client, event), nil
}

type readResult struct {
	data []byte
	err  error
}

type readDeadliner interface {
	SetReadDeadline(time.Time) error
}

func readBoundedWithTimeout(r io.Reader, maxBytes int64, timeout time.Duration) ([]byte, error) {
	if d, ok := r.(readDeadliner); ok {
		_ = d.SetReadDeadline(time.Now().Add(timeout))
	}

	ch := make(chan readResult, 1)
	go func() {
		data, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
		ch <- readResult{data: data, err: err}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case res := <-ch:
		if int64(len(res.data)) > maxBytes {
			return nil, ErrInputTooLarge
		}
		if res.err != nil {
			if errors.Is(res.err, os.ErrDeadlineExceeded) {
				if len(bytes.TrimSpace(res.data)) > 0 {
					return res.data, nil
				}
				return nil, ErrInputTimeout
			}
			var netErr net.Error
			if errors.As(res.err, &netErr) && netErr.Timeout() {
				if len(bytes.TrimSpace(res.data)) > 0 {
					return res.data, nil
				}
				return nil, ErrInputTimeout
			}
			return nil, res.err
		}
		return res.data, nil
	case <-timer.C:
		return nil, ErrInputTimeout
	}
}

func normalizePayload(payload map[string]interface{}, client ClientDialect, event HookEvent) *NormalizedHookInput {
	in := &NormalizedHookInput{
		Client: client,
		Event:  event,
	}

	if in.Event == "" {
		if evStr := firstString(payload, "hook_event_name", "hookEventName", "event"); evStr != "" {
			if parsed, err := ParseHookEvent(evStr); err == nil {
				in.Event = parsed
			}
		}
	}

	in.ToolName = firstString(payload, "tool_name", "toolName", "tool")
	in.SessionID = firstString(payload, "session_id", "sessionId", "conversation_id", "conversationId")
	if in.SessionID == "" {
		in.SessionID = strings.TrimSpace(os.Getenv("FABRIAL_SESSION_ID"))
	}

	in.CWD = firstString(payload, "cwd", "working_directory", "workingDirectory")
	if in.CWD == "" {
		if roots, ok := payload["workspace_roots"].([]interface{}); ok && len(roots) > 0 {
			if s, ok := roots[0].(string); ok {
				in.CWD = s
			}
		}
	}

	// Direct top-level fields (Cursor beforeShellExecution / afterFileEdit)
	in.Command = firstString(payload, "command", "cmd")
	in.FilePath = firstString(payload, "file_path", "filePath", "path")

	// Nested tool_input / toolInput / input / parameters / args (Claude Code & Gemini CLI)
	for _, key := range []string{"tool_input", "toolInput", "input", "parameters", "args"} {
		if nested, ok := payload[key].(map[string]interface{}); ok && nested != nil {
			if in.Command == "" {
				in.Command = firstString(nested, "command", "cmd", "script")
			}
			if in.FilePath == "" {
				in.FilePath = firstString(nested, "file_path", "filePath", "path", "target_file", "targetFile", "filename", "file")
			}
			if in.CWD == "" {
				in.CWD = firstString(nested, "cwd", "dir", "directory", "workdir")
			}
		}
	}

	if in.ToolName == "" {
		if in.Command != "" {
			in.ToolName = "shell"
		} else if in.FilePath != "" {
			in.ToolName = "edit"
		}
	}

	return in
}

func firstString(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok {
				if trimmed := strings.TrimSpace(s); trimmed != "" {
					return trimmed
				}
			}
		}
	}
	return ""
}

// Evaluate executes deterministic local policy checks for pre-tool hooks or
// zero-latency worktree-scoped async index enqueueing for post-tool hooks.
func (e *DefaultEvaluator) Evaluate(ctx context.Context, in *NormalizedHookInput) (*Decision, error) {
	if in == nil {
		return e.finalizeDecision(ctx, &NormalizedHookInput{Event: EventPreTool}, &Decision{
			Allow:          false,
			Code:           "FABRIAL_HOOK_INVALID_INPUT",
			Summary:        "Hook input payload was empty or nil (fail-closed).",
			RemediationCmd: "fabrial hook eval --client claude --event pre-tool",
			Why:            "Pre-tool security hooks fail closed when input cannot be validated.",
		}), nil
	}

	if in.Event == EventPostTool {
		return e.evaluatePostTool(in), nil
	}

	return e.evaluatePreTool(ctx, in), nil
}

func (e *DefaultEvaluator) evaluatePreTool(ctx context.Context, in *NormalizedHookInput) *Decision {
	rawCmd := in.Command
	if strings.TrimSpace(rawCmd) == "" {
		return &Decision{
			Allow:   true,
			Code:    "FABRIAL_HOOK_ALLOW",
			Summary: "Allowed (no shell command present).",
		}
	}

	normCmd, hadHiddenRunes := normalizeNFKCAndStripInvisible(rawCmd)

	// Split pipeline/compound command into individual command segments and unwrap wrappers.
	segments := splitShellSegments(normCmd)
	var unwrapped [][]string
	depthExceeded := false

	for _, seg := range segments {
		if len(seg) == 0 {
			continue
		}
		cands, exceeded := unwrapHookCommand(seg, 0)
		if exceeded {
			depthExceeded = true
		}
		unwrapped = append(unwrapped, cands...)
	}

	if depthExceeded {
		return e.finalizeDecision(ctx, in, &Decision{
			Allow:          false,
			Code:           "FABRIAL_HOOK_WRAPPER_DEPTH_EXCEEDED",
			Summary:        "Blocked deeply nested shell wrapper/subshell chain exceeding safe analysis depth.",
			RemediationCmd: "fabrial run -- <command>",
			Why:            "Recursive wrapper chains (env/sh -c/eval) beyond 16 levels fail closed to prevent policy evasion.",
		})
	}

	// Rule 1: Credential / secret exfiltration chains & inline secret exposure
	if dec := detectExfiltrationOrSecrets(normCmd, segments, unwrapped, hadHiddenRunes); dec != nil {
		return e.finalizeDecision(ctx, in, dec)
	}

	// Rule 2: Destructive host escapes & fuzzing/memory inspection anomalies (via pkg/router)
	if dec := detectDestructiveHostEscape(normCmd, segments, unwrapped); dec != nil {
		return e.finalizeDecision(ctx, in, dec)
	}

	// Rule 3: Unvetted risky package installs, curl|sh pipes, & slopsquatting
	if dec := e.detectRiskyPackageInstall(ctx, normCmd, segments, unwrapped); dec != nil {
		return e.finalizeDecision(ctx, in, dec)
	}

	return &Decision{
		Allow:   true,
		Code:    "FABRIAL_HOOK_ALLOW",
		Summary: "Allowed by Fabrial pre-tool security hook.",
	}
}

func (e *DefaultEvaluator) evaluatePostTool(in *NormalizedHookInput) *Decision {
	if strings.TrimSpace(in.FilePath) == "" {
		return &Decision{
			Allow:   true,
			Code:    "FABRIAL_HOOK_POST_NOOP",
			Summary: "No file path in post-tool payload.",
		}
	}

	worktreeRoot := e.resolveWorktreeRoot(in.CWD)
	absRoot, err := filepath.Abs(worktreeRoot)
	if err != nil {
		return &Decision{
			Allow:   true,
			Code:    "FABRIAL_HOOK_POST_SKIPPED",
			Summary: "Skipped post-tool index enqueue (worktree unavailable).",
		}
	}

	relPath, ok := validateSafeWorktreeRelPath(absRoot, in.FilePath)
	if !ok {
		return &Decision{
			Allow:   true,
			Code:    "FABRIAL_HOOK_POST_UNSAFE_PATH",
			Summary: "Skipped post-tool index enqueue for symlink or out-of-worktree path.",
		}
	}

	nowFn := e.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	rec := pendingIndexRecord{
		Event:     "file_edited",
		Client:    string(in.Client),
		RelPath:   relPath,
		SessionID: sanitizeSingleLineText(in.SessionID),
		Timestamp: nowFn().UTC().Format(time.RFC3339Nano),
	}

	// Append single compact JSONL record to <worktree>/.fabrial/pending-index.jsonl (<1ms).
	_ = e.appendPendingIndex(absRoot, rec)

	// Non-blocking best-effort 10ms signal to ~/.coppermind/coppermind.sock if online.
	e.notifyCoppermindSocket(absRoot, rec)

	return &Decision{
		Allow:   true,
		Code:    "FABRIAL_HOOK_POST_QUEUED",
		Summary: "Queued edited file for Coppermind incremental indexing.",
	}
}

type pendingIndexRecord struct {
	Event     string `json:"event"`
	Client    string `json:"client,omitempty"`
	RelPath   string `json:"rel_path"`
	SessionID string `json:"session_id,omitempty"`
	Timestamp string `json:"timestamp"`
}

func (e *DefaultEvaluator) resolveWorktreeRoot(cwd string) string {
	if strings.TrimSpace(e.WorktreeRoot) != "" {
		return e.WorktreeRoot
	}
	if strings.TrimSpace(cwd) != "" {
		return cwd
	}
	if envRoot := strings.TrimSpace(os.Getenv("FABRIAL_WORKTREE_ROOT")); envRoot != "" {
		return envRoot
	}
	return "."
}

func validateSafeWorktreeRelPath(absRoot, rawPath string) (string, bool) {
	cleaned := filepath.Clean(strings.TrimSpace(rawPath))
	if cleaned == "" || cleaned == "." {
		return "", false
	}

	var rel string
	if filepath.IsAbs(cleaned) {
		r, err := filepath.Rel(absRoot, cleaned)
		if err != nil {
			return "", false
		}
		rel = filepath.Clean(r)
	} else {
		rel = cleaned
	}

	if rel == "" || rel == "." || rel == ".." || filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}

	// Reject any symlink along the relative path inside absRoot.
	if err := checkNoSymlinksAlongRel(absRoot, rel); err != nil {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

func (e *DefaultEvaluator) appendPendingIndex(absRoot string, rec pendingIndexRecord) error {
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	e.appendMu.Lock()
	defer e.appendMu.Unlock()

	root, err := os.OpenRoot(absRoot)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()

	fi, err := root.Lstat(".fabrial")
	if err != nil {
		if os.IsNotExist(err) {
			if mkErr := root.Mkdir(".fabrial", 0700); mkErr != nil && !os.IsExist(mkErr) {
				return mkErr
			}
		} else {
			return err
		}
	} else if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return ErrHooksSymlinkDetected
	}

	pendingRel := filepath.Join(".fabrial", "pending-index.jsonl")
	if pfi, pErr := root.Lstat(pendingRel); pErr == nil {
		if pfi.Mode()&os.ModeSymlink != 0 || !pfi.Mode().IsRegular() {
			return ErrHooksSymlinkDetected
		}
	}

	f, err := root.OpenFile(pendingRel, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	_, wErr := f.Write(line)
	cErr := f.Close()
	if wErr != nil {
		return wErr
	}
	return cErr
}

func (e *DefaultEvaluator) resolveCoppermindSocketPath() string {
	if s := strings.TrimSpace(e.CoppermindSocketPath); s != "" {
		return s
	}
	if s := strings.TrimSpace(os.Getenv("COPPERMIND_SOCK")); s != "" {
		return s
	}
	if s := strings.TrimSpace(os.Getenv("COPPERMIND_SOCKET")); s != "" {
		return s
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".coppermind", "coppermind.sock")
	}
	return ""
}

func (e *DefaultEvaluator) notifyCoppermindSocket(absRoot string, rec pendingIndexRecord) {
	sockPath := e.resolveCoppermindSocketPath()
	if sockPath == "" {
		return
	}
	if err := verifySocketSecurity(sockPath); err != nil {
		return
	}

	timeout := e.CoppermindTimeout
	if timeout <= 0 {
		timeout = DefaultCoppermindTimeout
	}
	conn, err := net.DialTimeout("unix", sockPath, timeout)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))

	msg := map[string]string{
		"action":     "index_file",
		"worktree":   absRoot,
		"rel_path":   rec.RelPath,
		"session_id": rec.SessionID,
		"timestamp":  rec.Timestamp,
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	data = append(data, '\n')
	_, _ = conn.Write(data)
}

func (e *DefaultEvaluator) finalizeDecision(ctx context.Context, in *NormalizedHookInput, dec *Decision) *Decision {
	if dec == nil {
		return &Decision{Allow: true}
	}
	dec.Summary = sanitizeOutputText(dec.Summary)
	dec.RemediationCmd = sanitizeOutputText(dec.RemediationCmd)
	dec.Why = sanitizeOutputText(dec.Why)
	dec.Code = sanitizeSingleLineText(dec.Code)

	if !dec.Allow {
		if rcptID := e.emitDenyReceiptIfActive(ctx, in, dec); rcptID != "" {
			dec.ReceiptID = rcptID
		}
		e.emitNonBlockingArgusAlert(in, dec)
	}
	return dec
}

func (e *DefaultEvaluator) emitDenyReceiptIfActive(ctx context.Context, in *NormalizedHookInput, dec *Decision) string {
	receiptDir := strings.TrimSpace(e.ReceiptDir)
	if receiptDir == "" {
		receiptDir = strings.TrimSpace(os.Getenv("FABRIAL_RECEIPT_DIR"))
	}
	if receiptDir == "" {
		return ""
	}

	cleanReceiptDir := filepath.Clean(receiptDir)
	sessionID := ""
	worktreeRoot := ""

	// Standard layout: <worktree>/.fabrial/receipts/<session_id>
	if base := filepath.Base(cleanReceiptDir); receipt.ValidateSessionID(base) {
		sessionID = base
		p1 := filepath.Dir(cleanReceiptDir)
		p2 := filepath.Dir(p1)
		if filepath.Base(p1) == "receipts" && filepath.Base(p2) == ".fabrial" {
			worktreeRoot = filepath.Dir(p2)
		}
	}
	if sessionID == "" && in != nil && receipt.ValidateSessionID(in.SessionID) {
		sessionID = in.SessionID
	}
	if sessionID == "" {
		if envSID := strings.TrimSpace(os.Getenv("FABRIAL_SESSION_ID")); receipt.ValidateSessionID(envSID) {
			sessionID = envSID
		}
	}
	if sessionID == "" {
		gen, err := receipt.NewSessionID()
		if err != nil {
			return ""
		}
		sessionID = gen
	}

	if worktreeRoot == "" {
		if in != nil {
			worktreeRoot = e.resolveWorktreeRoot(in.CWD)
		} else {
			worktreeRoot = e.resolveWorktreeRoot("")
		}
	}

	store, err := receipt.NewStore(worktreeRoot)
	if err != nil {
		return ""
	}

	rcptID, err := receipt.NewReceiptID()
	if err != nil {
		return ""
	}

	nowFn := e.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	cmdHash := sha256.Sum256([]byte(in.Command))
	headSHA := readGitHeadSHAFast(worktreeRoot)

	// Select amortized non-interactive signer: explicit -> Locksmith UDS (<=50ms, 0 Touch ID) -> ephemeral session Ed25519 fallback.
	var signer receipt.Signer
	signingMode := "custom"
	if e.ReceiptSigner != nil {
		signer = e.ReceiptSigner
	} else {
		lsSock := strings.TrimSpace(e.LocksmithSocketPath)
		if lsSock == "" {
			lsSock = receipt.ResolveLocksmithSocketPath()
		}
		if err := verifySocketSecurity(lsSock); err == nil {
			if udsSigner, sErr := receipt.NewLocksmithUDSSigner(sessionID, lsSock); sErr == nil {
				udsSigner.Timeout = locksmithHookBudget
				signer = udsSigner
				signingMode = "locksmith_uds"
			}
		}
	}

	buildAndSign := func(sig receipt.Signer, mode string) (*receipt.DSSEEnvelope, *receipt.Statement, error) {
		claimsObj := map[string]interface{}{
			"client":       string(in.Client),
			"event":        string(in.Event),
			"tool_name":    sanitizeSingleLineText(in.ToolName),
			"code":         dec.Code,
			"summary":      dec.Summary,
			"signing_mode": mode,
		}
		claimsRaw, mErr := json.Marshal(claimsObj)
		if mErr != nil {
			return nil, nil, mErr
		}
		stmt := &receipt.Statement{
			Type: receipt.StatementTypeV1,
			Subject: []receipt.Subject{
				{
					Name: fmt.Sprintf("hook:%s:%s", in.Client, in.Event),
					Digest: map[string]string{
						"sha256": hex.EncodeToString(cmdHash[:]),
					},
				},
			},
			PredicateType: receipt.PredicateTypeV1,
			Predicate: receipt.Predicate{
				SchemaVersion: receipt.SchemaVersionV1,
				ReceiptID:     rcptID,
				Timestamp:     nowFn().UTC(),
				Session: receipt.SessionLineage{
					SessionID:       sessionID,
					ActorMode:       string(receipt.ActorModeAIDLC),
					WorktreeHeadSHA: headSHA,
				},
				Producer: receipt.Producer{
					Tool:    "fabrial",
					Version: version.Version,
					Stage:   string(receipt.StageCodingSecrets),
				},
				Verdict:        receipt.VerdictDeny,
				Proven:         true,
				Claims:         claimsRaw,
				FixForwardCode: dec.Code,
			},
		}
		env, sErr := receipt.SignEnvelope(stmt, sig)
		return env, stmt, sErr
	}

	var env *receipt.DSSEEnvelope
	var stmt *receipt.Statement
	if signer != nil {
		env, stmt, err = buildAndSign(signer, signingMode)
	} else {
		err = errors.New("no active uds signer")
	}

	// Graceful non-blocking ephemeral local Ed25519 fallback when Locksmith UDS is unavailable (0 Touch ID stalls).
	if err != nil && e.ReceiptSigner == nil {
		_, priv, gErr := ed25519.GenerateKey(rand.Reader)
		if gErr != nil {
			return ""
		}
		localSigner, lErr := receipt.NewLocalEd25519Signer(sessionID, priv)
		if lErr != nil {
			return ""
		}
		env, stmt, err = buildAndSign(localSigner, "ephemeral_local_fallback")
		if err != nil {
			return ""
		}
	} else if err != nil {
		return ""
	}

	if _, wErr := store.Write(env, stmt); wErr != nil {
		return ""
	}
	return rcptID
}

// readGitHeadSHAFast reads HEAD SHA from .git/HEAD directly without spawning git subprocesses.
func readGitHeadSHAFast(worktreeRoot string) string {
	const fallback = "0000000"
	headBytes, err := os.ReadFile(filepath.Join(worktreeRoot, ".git", "HEAD"))
	if err != nil {
		return fallback
	}
	line := strings.TrimSpace(string(headBytes))
	if ref, ok := strings.CutPrefix(line, "ref:"); ok {
		refPath := strings.TrimSpace(ref)
		if strings.Contains(refPath, "..") || filepath.IsAbs(refPath) {
			return fallback
		}
		shaBytes, rErr := os.ReadFile(filepath.Join(worktreeRoot, ".git", filepath.FromSlash(refPath)))
		if rErr != nil {
			return fallback
		}
		line = strings.TrimSpace(string(shaBytes))
	}
	if len(line) >= 7 && len(line) <= 64 && isLowerHex(line) {
		return line
	}
	return fallback
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return len(s) > 0
}

func (e *DefaultEvaluator) resolveArgusSocketPath() string {
	if s := strings.TrimSpace(e.ArgusSocketPath); s != "" {
		return s
	}
	if s := strings.TrimSpace(os.Getenv("ARGUS_SOCK")); s != "" {
		return s
	}
	if s := strings.TrimSpace(os.Getenv("ARGUS_SOCKET")); s != "" {
		return s
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".argus", "argus.sock")
	}
	return ""
}

func (e *DefaultEvaluator) emitNonBlockingArgusAlert(in *NormalizedHookInput, dec *Decision) {
	sockPath := e.resolveArgusSocketPath()
	if sockPath == "" {
		return
	}
	if err := verifySocketSecurity(sockPath); err != nil {
		return
	}
	conn, err := net.DialTimeout("unix", sockPath, 5*time.Millisecond)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Millisecond))

	alert := map[string]interface{}{
		"event":      "hook_deny",
		"client":     string(in.Client),
		"code":       dec.Code,
		"session_id": sanitizeSingleLineText(in.SessionID),
		"summary":    dec.Summary,
	}
	data, err := json.Marshal(alert)
	if err != nil {
		return
	}
	data = append(data, '\n')
	_, _ = conn.Write(data)
}

// ============================================================================
// Pure-Go NFKC / Compatibility Normalization & Invisible Rune Stripping
// ============================================================================

// normalizeNFKCAndStripInvisible strips zero-width, bidi override, and invisible
// format runes, and folds fullwidth / compatibility / math-alphanumeric ASCII
// forms into canonical ASCII with zero external dependencies.
func normalizeNFKCAndStripInvisible(s string) (string, bool) {
	// Ultra-fast ASCII path (<1µs, zero allocations for clean ASCII commands).
	asciiClean := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 || s[i] == 0x00 || s[i] == 0x1b {
			asciiClean = false
			break
		}
	}
	if asciiClean {
		return s, false
	}

	var b strings.Builder
	b.Grow(len(s))
	hadHidden := false

	for _, r := range s {
		if isInvisibleOrBidiRune(r) {
			hadHidden = true
			continue
		}
		if unicode.Is(unicode.Mn, r) {
			// Strip combining diacritical marks that obfuscate ASCII tokens (e.g. c\u0301url)
			hadHidden = true
			continue
		}
		if folded, ok := foldCompatibilityRune(r); ok {
			b.WriteString(folded)
			continue
		}
		b.WriteRune(r)
	}
	return b.String(), hadHidden
}

func isInvisibleOrBidiRune(r rune) bool {
	switch {
	case r == 0x00ad: // soft hyphen
		return true
	case r == 0x034f: // combining grapheme joiner
		return true
	case r == 0x061c: // Arabic letter mark
		return true
	case r == 0x180e: // Mongolian vowel separator
		return true
	case r >= 0x200b && r <= 0x200f: // ZWSP, ZWNJ, ZWJ, LRM, RLM
		return true
	case r >= 0x202a && r <= 0x202e: // bidi LRE, RLE, PDF, LRO, RLO
		return true
	case r >= 0x2060 && r <= 0x2069: // word joiner, invisible ops, bidi isolates
		return true
	case r == 0xfeff: // BOM / ZWNBSP
		return true
	case r >= 0xfe00 && r <= 0xfe0f: // variation selectors
		return true
	case r >= 0xe0000 && r <= 0xe007f: // Unicode tag characters
		return true
	}
	return false
}

func foldCompatibilityRune(r rune) (string, bool) {
	// Fullwidth ASCII forms (！..～ -> !..~)
	if r >= 0xff01 && r <= 0xff5e {
		return string(rune(r - 0xff01 + 0x21)), true
	}
	// Compatibility & non-breaking spaces
	switch r {
	case 0x00a0, 0x1680, 0x202f, 0x205f, 0x3000:
		return " ", true
	}
	if r >= 0x2000 && r <= 0x200a {
		return " ", true
	}
	// Compatibility punctuation / slashes / dashes / quotes
	switch r {
	case 0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015, 0x2212, 0xfe58, 0xfe63:
		return "-", true
	case 0x2044, 0x2215, 0x29f8:
		return "/", true
	case 0x2018, 0x2019, 0x2032:
		return "'", true
	case 0x201c, 0x201d, 0x2033:
		return "\"", true
	case 0x223c, 0x02dc:
		return "~", true
	case 0xfb00:
		return "ff", true
	case 0xfb01:
		return "fi", true
	case 0xfb02:
		return "fl", true
	case 0xfb03:
		return "ffi", true
	case 0xfb04:
		return "ffl", true
	}
	// Mathematical alphanumeric Latin letters (bold/italic/monospace/sans-serif)
	if folded, ok := foldMathAlphanumeric(r); ok {
		return string(folded), true
	}
	return "", false
}

func foldMathAlphanumeric(r rune) (rune, bool) {
	// Uppercase blocks of 26 letters
	upperBases := []rune{0x1d400, 0x1d434, 0x1d468, 0x1d49c, 0x1d4d0, 0x1d504, 0x1d538, 0x1d56c, 0x1d5a0, 0x1d5d4, 0x1d608, 0x1d63c, 0x1d670}
	for _, base := range upperBases {
		if r >= base && r < base+26 {
			return 'A' + (r - base), true
		}
	}
	// Lowercase blocks of 26 letters
	lowerBases := []rune{0x1d41a, 0x1d44e, 0x1d482, 0x1d4b6, 0x1d4ea, 0x1d51e, 0x1d552, 0x1d586, 0x1d5ba, 0x1d5ee, 0x1d622, 0x1d656, 0x1d68a}
	for _, base := range lowerBases {
		if r >= base && r < base+26 {
			return 'a' + (r - base), true
		}
	}
	// Digits blocks of 10
	digitBases := []rune{0x1d7ce, 0x1d7d8, 0x1d7e2, 0x1d7ec, 0x1d7f6}
	for _, base := range digitBases {
		if r >= base && r < base+10 {
			return '0' + (r - base), true
		}
	}
	return 0, false
}

// ============================================================================
// Shell Splitting & Recursive Wrapper Unwrapping
// ============================================================================

func unwrapHookCommand(args []string, depth int) ([][]string, bool) {
	if depth > maxHookWrapperDepth {
		return nil, true
	}
	if len(args) == 0 {
		return nil, false
	}

	cands, exceeded := policy.UnwrapCommands(args)
	if exceeded {
		return cands, true
	}

	var out [][]string
	for _, cand := range cands {
		if len(cand) == 0 {
			continue
		}
		out = append(out, cand)

		bin := policy.NormalizeBinaryName(cand[0])
		switch bin {
		case "eval":
			script := strings.Join(cand[1:], " ")
			for _, seg := range splitShellSegments(script) {
				inner, ex := unwrapHookCommand(seg, depth+1)
				if ex {
					return out, true
				}
				out = append(out, inner...)
			}
		case "exec", "sudo", "doas":
			innerArgs := stripWrapperFlags(cand[1:])
			if len(innerArgs) > 0 {
				inner, ex := unwrapHookCommand(innerArgs, depth+1)
				if ex {
					return out, true
				}
				out = append(out, inner...)
			}
		case "sh", "bash", "zsh", "dash", "ksh":
			// Also handle process substitution or unquoted trailing scripts after -c
			for i := 1; i < len(cand)-1; i++ {
				if cand[i] == "-c" || (strings.HasPrefix(cand[i], "-") && !strings.HasPrefix(cand[i], "--") && strings.ContainsRune(cand[i][1:], 'c')) {
					for _, seg := range splitShellSegments(cand[i+1]) {
						inner, ex := unwrapHookCommand(seg, depth+1)
						if ex {
							return out, true
						}
						out = append(out, inner...)
					}
					break
				}
			}
		}
	}
	return out, false
}

func stripWrapperFlags(args []string) []string {
	for len(args) > 0 {
		a := args[0]
		if a == "--" {
			return args[1:]
		}
		if a == "-u" || a == "-g" || a == "-a" {
			if len(args) >= 2 {
				args = args[2:]
				continue
			}
			return nil
		}
		if strings.HasPrefix(a, "-") {
			args = args[1:]
			continue
		}
		break
	}
	return args
}

func splitShellSegments(script string) [][]string {
	var segments [][]string
	var cur strings.Builder
	inSingle := false
	inDouble := false
	escaped := false

	flush := func() {
		toks := tokenizeShellWords(cur.String())
		if len(toks) > 0 {
			segments = append(segments, toks)
		}
		cur.Reset()
	}

	for i := 0; i < len(script); i++ {
		c := script[i]
		if escaped {
			cur.WriteByte(c)
			escaped = false
			continue
		}
		if c == '\\' && !inSingle {
			escaped = true
			cur.WriteByte(c)
			continue
		}
		if c == '\'' && !inDouble {
			inSingle = !inSingle
			cur.WriteByte(c)
			continue
		}
		if c == '"' && !inSingle {
			inDouble = !inDouble
			cur.WriteByte(c)
			continue
		}
		if !inSingle {
			if c == '`' {
				flush()
				continue
			}
			if c == '$' && i+1 < len(script) && script[i+1] == '(' {
				flush()
				i++
				continue
			}
			if (c == '<' || c == '>') && i+1 < len(script) && script[i+1] == '(' {
				flush()
				i++
				continue
			}
		}
		if !inSingle && !inDouble {
			if c == ';' || c == '|' || c == '&' || c == '\n' || c == ')' || c == '(' {
				flush()
				continue
			}
		}
		cur.WriteByte(c)
	}
	flush()
	return segments
}

func tokenizeShellWords(s string) []string {
	var words []string
	var cur strings.Builder
	inToken := false
	inSingle := false
	inDouble := false
	escaped := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			cur.WriteByte(c)
			inToken = true
			escaped = false
			continue
		}
		if c == '\\' && !inSingle {
			escaped = true
			inToken = true
			continue
		}
		if c == '\'' && !inDouble {
			inSingle = !inSingle
			inToken = true
			continue
		}
		if c == '"' && !inSingle {
			inDouble = !inDouble
			inToken = true
			continue
		}
		if !inSingle && !inDouble && (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
			if inToken {
				words = append(words, cur.String())
				cur.Reset()
				inToken = false
			}
			continue
		}
		cur.WriteByte(c)
		inToken = true
	}
	if inToken {
		words = append(words, cur.String())
	}
	return words
}

// ============================================================================
// Rule 1: Credential / Secret Exfiltration & Inline Secret Guard
// ============================================================================

var (
	reSensitivePath = regexp.MustCompile(`(?i)((^|[\s"'=@:<(])(~/|\$HOME/|\$\{HOME\}/|/)?(\.ssh(/|$|\b)|\.aws(/|$|\b)|\.gnupg(/|$|\b)|\.kube/config\b|\.netrc\b|\.npmrc\b|\.pypirc\b|\.git-credentials\b)|(^|[\s"'=@:/<(])(\.env(\.[a-z0-9._-]+)?|id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys)($|[\s"'&|;>)])|/etc/shadow\b|/proc/self/(environ|mem)\b)`)
	reInlineSecret  = regexp.MustCompile(`(sk-(?:proj-|ant-|live-|test-)?[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|ghs_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,}|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)`)
	reDevTCP        = regexp.MustCompile(`(?i)/dev/(tcp|udp)/`)
	reNetInlineEval = regexp.MustCompile(`(?i)(\burllib\b|\brequests\b|\bhttp\.client\b|\bsocket\b|\bfetch\s*\(|\bnet\.connect\b|\bhttps?://)`)
)

var egressBinaries = map[string]bool{
	"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true,
	"socat": true, "scp": true, "sftp": true, "rsync": true, "ftp": true,
	"tftp": true, "telnet": true, "dig": true, "nslookup": true, "xh": true, "http": true,
}

func detectExfiltrationOrSecrets(normCmd string, segments [][]string, unwrapped [][]string, hadHiddenRunes bool) *Decision {
	hasEgress := reDevTCP.MatchString(normCmd)
	for _, cand := range unwrapped {
		canon := policy.CanonicalizeCommand(cand)
		if len(canon) == 0 {
			continue
		}
		bin := canon[0]
		if egressBinaries[bin] {
			hasEgress = true
		}
		if (bin == "python" || bin == "python3" || bin == "node" || bin == "ruby" || bin == "perl" || bin == "php") &&
			reNetInlineEval.MatchString(strings.Join(canon, " ")) {
			hasEgress = true
		}
	}

	hasSensitivePath := reSensitivePath.MatchString(normCmd)
	hasInlineSecret := reInlineSecret.MatchString(normCmd)

	if hasEgress && hasSensitivePath {
		return &Decision{
			Allow:          false,
			Code:           "FABRIAL_HOOK_EXFIL_CREDENTIAL_PATH",
			Summary:        "Blocked outbound network command referencing sensitive credential paths (~/.ssh, ~/.aws, .env, or private keys).",
			RemediationCmd: "locksmith status",
			Why:            "Exfiltrating local keys or .env files over curl/wget/nc is blocked fail-closed; inject scoped secrets via Locksmith instead.",
		}
	}

	if hasInlineSecret && hasEgress {
		return &Decision{
			Allow:          false,
			Code:           "FABRIAL_HOOK_EXFIL_INLINE_SECRET",
			Summary:        "Blocked outbound network command containing an inline API key, token, or private key.",
			RemediationCmd: "fabrial run --lease-secret <KEY_NAME> -- <command>",
			Why:            "Inline secrets in shell commands leak via process lists, history, and outbound requests; lease secrets ephemerally via Locksmith.",
		}
	}

	if hasInlineSecret {
		return &Decision{
			Allow:          false,
			Code:           "FABRIAL_HOOK_INLINE_SECRET_BLOCKED",
			Summary:        "Blocked shell command containing a raw secret or private key material.",
			RemediationCmd: "locksmith migrate .env",
			Why:            "Passing raw credentials (sk-, AKIA, ghp_, private keys) on the command line exposes secrets to shell history and subagents.",
		}
	}

	// Catch obfuscated commands using zero-width/bidi runes to disguise sensitive path reads
	if hadHiddenRunes && hasSensitivePath {
		return &Decision{
			Allow:          false,
			Code:           "FABRIAL_HOOK_OBFUSCATED_CREDENTIAL_ACCESS",
			Summary:        "Blocked obfuscated command (zero-width/bidi characters) accessing sensitive credential paths.",
			RemediationCmd: "fabrial doctor",
			Why:            "Invisible Unicode characters combined with credential path access indicate prompt-injection evasion.",
		}
	}

	return nil
}

// ============================================================================
// Rule 2: Destructive Host Escapes & Router AST Anomalies
// ============================================================================

var (
	reForkBomb         = regexp.MustCompile(`:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;`)
	reBase64PipeShell  = regexp.MustCompile(`(?i)\b(base64\s+(-d|--decode)|openssl\s+enc\s+-d)\b.*\|\s*(ba|z|da|k)?sh\b`)
	reSensitiveChmod   = regexp.MustCompile(`(?i)(^|[\s"'=])(~/|\$HOME/|\$\{HOME\}/|/)?(\.ssh(/|$)|\.aws(/|$)|\.gnupg(/|$)|etc(/|$))`)
	reShellRCWrite     = regexp.MustCompile(`(?i)(>>?|\btee\b).*?(~/|\$HOME/|\$\{HOME\}/)(\.bashrc|\.zshrc|\.profile|\.bash_profile|\.ssh/authorized_keys)`)
)

func detectDestructiveHostEscape(normCmd string, segments [][]string, unwrapped [][]string) *Decision {
	if reForkBomb.MatchString(normCmd) {
		return &Decision{
			Allow:          false,
			Code:           "FABRIAL_HOOK_DESTRUCTIVE_FORK_BOMB",
			Summary:        "Blocked destructive fork bomb shell payload.",
			RemediationCmd: "fabrial run --profile strict -- <command>",
			Why:            "Fork bombs cause host-wide denial of service across all local worktrees.",
		}
	}

	if reBase64PipeShell.MatchString(normCmd) {
		return &Decision{
			Allow:          false,
			Code:           "FABRIAL_HOOK_OBFUSCATED_EXEC",
			Summary:        "Blocked base64/encoded payload piped directly into a shell interpreter.",
			RemediationCmd: "fabrial run --microvm -- <command>",
			Why:            "Decoding opaque payloads directly into sh/bash bypasses static review and runs arbitrary host commands.",
		}
	}

	if reShellRCWrite.MatchString(normCmd) {
		return &Decision{
			Allow:          false,
			Code:           "FABRIAL_HOOK_HOST_PERSISTENCE",
			Summary:        "Blocked write to user shell profile or ~/.ssh/authorized_keys.",
			RemediationCmd: "fabrial explain sandbox",
			Why:            "Modifying ~/.bashrc, ~/.zshrc, or authorized_keys persists outside the repository worktree.",
		}
	}

	// Integrate fabrial/pkg/router AST parameter inspection on unwrapped segments
	for _, cand := range unwrapped {
		if isAmbiguous, reason := router.DetectAmbiguousParameters(cand); isAmbiguous {
			if strings.Contains(reason, "fuzzing") || strings.Contains(reason, "memory inspection") {
				return &Decision{
					Allow:          false,
					Code:           "FABRIAL_HOOK_ROUTER_ANOMALY",
					Summary:        "Blocked anomalous command payload detected by Fabrial router AST guard.",
					RemediationCmd: "fabrial run --microvm -- <command>",
					Why:            reason,
				}
			}
		}

		canon := policy.CanonicalizeCommand(cand)
		if len(canon) == 0 {
			continue
		}

		switch canon[0] {
		case "rm":
			if isDestructiveRM(canon[1:]) {
				return &Decision{
					Allow:          false,
					Code:           "FABRIAL_HOOK_DESTRUCTIVE_RM",
					Summary:        "Blocked destructive recursive deletion targeting root, home, or system directories.",
					RemediationCmd: "git status",
					Why:            "Recursive force deletion of /, ~, $HOME, or system directories is blocked fail-closed to prevent host damage.",
				}
			}

		case "git":
			if isDestructiveGitForcePush(canon[1:]) {
				return &Decision{
					Allow:          false,
					Code:           "FABRIAL_HOOK_DESTRUCTIVE_GIT_PUSH",
					Summary:        "Blocked force-push targeting protected branch (main/master/production).",
					RemediationCmd: "git push --force-with-lease origin <feature-branch>",
					Why:            "Force-pushing directly to main/master destroys shared commit history and bypasses review gates.",
				}
			}

		case "chmod":
			if isUnsafeChmod(canon[1:]) {
				return &Decision{
					Allow:          false,
					Code:           "FABRIAL_HOOK_DESTRUCTIVE_CHMOD",
					Summary:        "Blocked permissive chmod (e.g. 777/666/o+w) on sensitive directory or credentials.",
					RemediationCmd: "chmod 700 ~/.ssh && chmod 600 ~/.ssh/*",
					Why:            "World-readable or world-writable permissions on ~/.ssh, ~/.aws, or system paths expose host credentials.",
				}
			}

		case "dd":
			for _, a := range canon[1:] {
				la := strings.ToLower(a)
				if strings.HasPrefix(la, "of=/dev/disk") || strings.HasPrefix(la, "of=/dev/rdisk") || strings.HasPrefix(la, "of=/dev/sd") || strings.HasPrefix(la, "of=/dev/nvme") {
					return &Decision{
						Allow:          false,
						Code:           "FABRIAL_HOOK_DESTRUCTIVE_DISK_WRITE",
						Summary:        "Blocked raw block device write via dd.",
						RemediationCmd: "fabrial explain sandbox",
						Why:            "Direct writes to /dev/disk* or /dev/sd* can permanently destroy host partitions.",
					}
				}
			}
		}
	}

	return nil
}

func isDestructiveRM(args []string) bool {
	recursive := false
	var targets []string
	afterDoubleDash := false

	for _, a := range args {
		if !afterDoubleDash && a == "--" {
			afterDoubleDash = true
			continue
		}
		if !afterDoubleDash && strings.HasPrefix(a, "-") && a != "-" {
			if a == "--recursive" {
				recursive = true
				continue
			}
			if !strings.HasPrefix(a, "--") && (strings.ContainsRune(a[1:], 'r') || strings.ContainsRune(a[1:], 'R')) {
				recursive = true
				continue
			}
			continue
		}
		targets = append(targets, a)
	}

	if !recursive {
		return false
	}

	criticalTargets := map[string]bool{
		"/": true, "/*": true, "~": true, "~/": true, "~/*": true,
		"$HOME": true, "${HOME}": true, "$HOME/": true, "${HOME}/": true,
		"$HOME/*": true, "${HOME}/*": true,
		"/etc": true, "/usr": true, "/bin": true, "/sbin": true,
		"/var": true, "/System": true, "/Library": true, "/Users": true, "/home": true,
	}

	for _, t := range targets {
		clean := strings.TrimSpace(t)
		if criticalTargets[clean] {
			return true
		}
		if strings.HasPrefix(clean, "/.") || clean == ".." || clean == "../.." || strings.HasPrefix(clean, "../../../") {
			return true
		}
		if strings.HasPrefix(clean, "~/.ssh") || strings.HasPrefix(clean, "$HOME/.ssh") || strings.HasPrefix(clean, "${HOME}/.ssh") {
			return true
		}
	}
	return false
}

func isDestructiveGitForcePush(args []string) bool {
	if len(args) == 0 || args[0] != "push" {
		return false
	}
	force := false
	protectedTarget := false

	for _, a := range args[1:] {
		la := strings.ToLower(strings.TrimSpace(a))
		switch {
		case la == "-f" || la == "--force" || strings.HasPrefix(la, "--force-with-lease"):
			force = true
		case la == "--all" || la == "--mirror":
			protectedTarget = true
		case la == "main" || la == "master" || la == "production" || la == "prod":
			protectedTarget = true
		case strings.HasSuffix(la, ":main") || strings.HasSuffix(la, ":master") ||
			strings.HasSuffix(la, ":refs/heads/main") || strings.HasSuffix(la, ":refs/heads/master") ||
			la == "refs/heads/main" || la == "refs/heads/master" ||
			la == "+main" || la == "+master":
			if strings.HasPrefix(la, "+") {
				force = true
			}
			protectedTarget = true
		}
	}
	return force && protectedTarget
}

func isUnsafeChmod(args []string) bool {
	permissiveMode := false
	sensitiveTarget := false

	for _, a := range args {
		la := strings.ToLower(strings.TrimSpace(a))
		if strings.HasPrefix(la, "-") {
			continue
		}
		if !permissiveMode && (la == "777" || la == "0777" || la == "666" || la == "0666" ||
			strings.Contains(la, "a+rwx") || strings.Contains(la, "o+w") || strings.Contains(la, "o+rwx") || strings.Contains(la, "ugo+rwx")) {
			permissiveMode = true
			continue
		}
		if la == "/" || la == "~" || la == "~/" || la == "$home" || la == "${home}" || reSensitiveChmod.MatchString(la) ||
			strings.Contains(la, ".ssh") || strings.Contains(la, ".aws") || strings.Contains(la, "id_rsa") || strings.Contains(la, "id_ed25519") {
			sensitiveTarget = true
		}
	}
	return permissiveMode && sensitiveTarget
}

// ============================================================================
// Rule 3: Unvetted Package Installs, Pipe-to-Shell & Slopsquatting Guard
// ============================================================================

var (
	reCurlPipeShell = regexp.MustCompile(`(?i)\b(curl|wget)\b[^|;&\n]*\|\s*(env\s+|sudo\s+)?((/[\w/]+/)?(ba|z|da|k)?sh|python[23]?|perl|ruby|node)\b`)
	reShellProcSub  = regexp.MustCompile(`(?i)\b(ba|z|da|k)?sh\b[^;\n]*<\(\s*(curl|wget)\b`)
)

type packageInstall struct {
	Ecosystem string
	Packages  []string
	BadFlags  []string
}

// Known high-risk slopsquatted / hallucinated packages frequently emitted by LLMs.
var knownSlopsquats = map[string]string{
	"open-ai-sdk":        "openai",
	"openai-sdk":         "openai",
	"openai-python":      "openai",
	"reqeusts":           "requests",
	"requets":            "requests",
	"requestss":          "requests",
	"urllib4":            "urllib3",
	"beautifulsoup5":     "beautifulsoup4",
	"bs5":                "beautifulsoup4",
	"huggingface-cli":    "huggingface-hub",
	"anthropic-sdk":      "anthropic",
	"anthropic-sdk-py":   "anthropic",
	"python-dotenv-pro":  "python-dotenv",
	"colors-js":          "colors",
	"lodahs":             "lodash",
	"axois":              "axios",
	"expres":             "express",
	"react-dom-router":   "react-router-dom",
	"langchain-community-pro": "langchain-community",
	"serde-json-rs":      "serde_json",
	"tokio-async":        "tokio",
}

// Canonical popular packages for fast Levenshtein distance-1 typosquat detection.
var popularPackagesByEcosystem = map[string][]string{
	"npm": {
		"openai", "anthropic", "lodash", "express", "react", "axios", "chalk",
		"typescript", "eslint", "prettier", "webpack", "vite", "jest", "vitest",
		"dotenv", "commander", "yargs", "fastify", "prisma", "mongoose", "tailwindcss",
	},
	"pypi": {
		"openai", "anthropic", "requests", "urllib3", "flask", "django", "numpy",
		"pandas", "fastapi", "pydantic", "langchain", "boto3", "pytest", "scipy",
		"matplotlib", "sqlalchemy", "httpx", "aiohttp", "cryptography", "pillow",
	},
	"cargo": {
		"serde", "tokio", "reqwest", "clap", "anyhow", "thiserror", "tracing",
		"axum", "hyper", "rand", "regex", "chrono", "uuid", "sqlx", "futures",
	},
}

func (e *DefaultEvaluator) detectRiskyPackageInstall(ctx context.Context, normCmd string, segments [][]string, unwrapped [][]string) *Decision {
	if reCurlPipeShell.MatchString(normCmd) || reShellProcSub.MatchString(normCmd) {
		return &Decision{
			Allow:          false,
			Code:           "FABRIAL_HOOK_UNVETTED_PIPE_INSTALL",
			Summary:        "Blocked unverified remote script piped directly into a shell interpreter (curl|sh).",
			RemediationCmd: "fabrial run --microvm -- <command>",
			Why:            "Piping remote URLs directly into sh/bash executes unvetted code on the host; download, inspect checksum, or isolate in a Tier 2 microVM.",
		}
	}

	var installs []packageInstall
	for _, cand := range unwrapped {
		canon := policy.CanonicalizeCommand(cand)
		if inst, ok := extractPackageInstall(canon); ok {
			installs = append(installs, inst)
		}
	}

	if len(installs) == 0 {
		return nil
	}

	for _, inst := range installs {
		// 1. Check explicitly risky flags / insecure remote package URLs
		if len(inst.BadFlags) > 0 {
			return &Decision{
				Allow:          false,
				Code:           "FABRIAL_HOOK_RISKY_INSTALL_FLAG",
				Summary:        fmt.Sprintf("Blocked %s package install using risky flag or unverified URL (%s).", inst.Ecosystem, inst.BadFlags[0]),
				RemediationCmd: "argus vet " + strings.Join(safePackageTokens(inst.Packages), " "),
				Why:            "Flags like --unsafe-perm or plaintext http:// registries bypass package integrity and install-hook protections.",
			}
		}

		// 2. Fast-path query to ~/.argus/argus.sock with bounded 200ms dial timeout if reachable
		if len(inst.Packages) > 0 {
			argusReachable, denied, reason := e.queryArgusSocket(ctx, inst)
			if denied {
				remediation := "argus explain " + firstSafeToken(inst.Packages, "<package>")
				return &Decision{
					Allow:          false,
					Code:           "FABRIAL_HOOK_ARGUS_DENIED",
					Summary:        fmt.Sprintf("Argus blocked %s package install: %s", inst.Ecosystem, reason),
					RemediationCmd: remediation,
					Why:            "Argus pre-flight supply-chain inspection rejected one or more requested packages.",
				}
			}

			// 3. Fast in-process slopsquat / typosquat guard (zero subprocesses)
			for _, pkg := range inst.Packages {
				if suggestion, risky := detectSlopsquatOrTyposquat(inst.Ecosystem, pkg); risky {
					rem := "argus explain " + firstSafeToken([]string{suggestion}, "<package>")
					return &Decision{
						Allow:          false,
						Code:           "FABRIAL_HOOK_SLOPSQUAT_BLOCKED",
						Summary:        fmt.Sprintf("Blocked suspected %s slopsquat/typosquat package %q (did you mean %q?).", inst.Ecosystem, pkg, suggestion),
						RemediationCmd: rem,
						Why:            "AI-hallucinated or typosquatted packages frequently carry postinstall credential stealers; vet with Argus before installing.",
					}
				}
			}

			// 4. Fail-closed in --strict mode if Argus daemon is offline
			if e.Strict && !argusReachable {
				return &Decision{
					Allow:          false,
					Code:           "FABRIAL_HOOK_ARGUS_OFFLINE_STRICT",
					Summary:        fmt.Sprintf("Blocked %s package install in --strict mode because Argus daemon socket is offline.", inst.Ecosystem),
					RemediationCmd: "fabrial daemon start",
					Why:            "Strict mode requires live Argus provenance verification before installing external packages.",
				}
			}
		}
	}

	return nil
}

func extractPackageInstall(canon []string) (packageInstall, bool) {
	if len(canon) < 2 {
		return packageInstall{}, false
	}
	bin := canon[0]
	sub := strings.ToLower(canon[1])

	switch bin {
	case "npm":
		if sub == "install" || sub == "i" || sub == "add" || sub == "ci" {
			return parseInstallArgs("npm", canon[2:]), true
		}
	case "pnpm":
		if sub == "add" || sub == "install" || sub == "i" {
			return parseInstallArgs("npm", canon[2:]), true
		}
	case "yarn":
		if sub == "add" || sub == "install" {
			return parseInstallArgs("npm", canon[2:]), true
		}
	case "pip", "pip3":
		if sub == "install" {
			return parseInstallArgs("pypi", canon[2:]), true
		}
	case "python", "python3":
		// python -m pip install ...
		if len(canon) >= 4 && canon[1] == "-m" && (canon[2] == "pip" || canon[2] == "pip3") && strings.ToLower(canon[3]) == "install" {
			return parseInstallArgs("pypi", canon[4:]), true
		}
	case "uv":
		if sub == "add" {
			return parseInstallArgs("pypi", canon[2:]), true
		}
		if sub == "pip" && len(canon) >= 3 && strings.ToLower(canon[2]) == "install" {
			return parseInstallArgs("pypi", canon[3:]), true
		}
	case "cargo":
		if sub == "add" || sub == "install" {
			return parseInstallArgs("cargo", canon[2:]), true
		}
	}
	return packageInstall{}, false
}

func parseInstallArgs(ecosystem string, args []string) packageInstall {
	inst := packageInstall{Ecosystem: ecosystem}
	skipNext := false
	valueFlags := map[string]bool{
		"-r": true, "--requirement": true, "-c": true, "--constraint": true,
		"-t": true, "--target": true, "--prefix": true, "--registry": true,
		"-i": true, "--index-url": true, "--extra-index-url": true,
		"--trusted-host": true, "--features": true, "-F": true, "--git": true,
		"--path": true, "--version": true, "--tag": true, "--branch": true,
	}

	for i := 0; i < len(args); i++ {
		a := strings.TrimSpace(args[i])
		if a == "" {
			continue
		}
		if skipNext {
			skipNext = false
			if strings.HasPrefix(strings.ToLower(a), "http://") {
				inst.BadFlags = append(inst.BadFlags, a)
			}
			continue
		}
		la := strings.ToLower(a)
		if la == "--unsafe-perm" || strings.HasPrefix(la, "--unsafe-perm=") ||
			strings.HasPrefix(la, "http://") || strings.HasPrefix(la, "git+http://") {
			inst.BadFlags = append(inst.BadFlags, a)
			continue
		}
		if strings.HasPrefix(la, "--extra-index-url=http://") || strings.HasPrefix(la, "--index-url=http://") || strings.HasPrefix(la, "--registry=http://") {
			inst.BadFlags = append(inst.BadFlags, a)
			continue
		}
		if strings.HasPrefix(a, "-") {
			if valueFlags[la] {
				skipNext = true
			}
			continue
		}
		// Strip version specifiers (pkg==1.0, pkg>=1.0, pkg@1.2.3 preserving @scope/pkg)
		pkg := stripVersionSpec(a)
		if pkg != "" && pkg != "." && !strings.HasPrefix(pkg, "./") && !strings.HasPrefix(pkg, "../") {
			inst.Packages = append(inst.Packages, pkg)
		}
	}
	return inst
}

func stripVersionSpec(raw string) string {
	s := strings.TrimSpace(raw)
	if idx := strings.IndexAny(s, "=<>!~[;"); idx > 0 {
		s = s[:idx]
	}
	// Preserve npm scoped packages (@scope/name@1.0.0 -> @scope/name)
	if strings.HasPrefix(s, "@") {
		if slash := strings.IndexByte(s, '/'); slash > 0 {
			if at := strings.IndexByte(s[slash+1:], '@'); at > 0 {
				s = s[:slash+1+at]
			}
		}
	} else if at := strings.IndexByte(s, '@'); at > 0 {
		s = s[:at]
	}
	return strings.TrimSpace(s)
}

func detectSlopsquatOrTyposquat(ecosystem, pkg string) (string, bool) {
	norm := strings.ToLower(strings.TrimSpace(pkg))
	if norm == "" {
		return "", false
	}
	if canonical, ok := knownSlopsquats[norm]; ok {
		return canonical, true
	}

	// Check Levenshtein distance == 1 against canonical high-value packages
	// (only for names >= 5 chars so short legitimate crates/packages don't false-positive).
	if len(norm) >= 5 {
		for _, popular := range popularPackagesByEcosystem[ecosystem] {
			if norm == popular {
				return "", false
			}
			if len(popular) >= 5 && levenshteinAtMost1(norm, popular) {
				return popular, true
			}
		}
	}
	return "", false
}

// levenshteinAtMost1 returns true iff strings a and b have edit distance exactly 1
// (or a single adjacent transposition like "axois" <-> "axios" / "reqeusts" <-> "requests").
func levenshteinAtMost1(a, b string) bool {
	if a == b {
		return false
	}
	la, lb := len(a), len(b)
	diff := la - lb
	if diff < -1 || diff > 1 {
		return false
	}
	if la == lb {
		diffs := make([]int, 0, 2)
		for i := 0; i < la; i++ {
			if a[i] != b[i] {
				diffs = append(diffs, i)
				if len(diffs) > 2 {
					return false
				}
			}
		}
		if len(diffs) == 1 {
			return true
		}
		// Single adjacent transposition (Damerau-Levenshtein 1)
		if len(diffs) == 2 && diffs[1] == diffs[0]+1 && a[diffs[0]] == b[diffs[1]] && a[diffs[1]] == b[diffs[0]] {
			return true
		}
		return false
	}
	// Length differs by 1: single insertion/deletion
	short, long := a, b
	if la > lb {
		short, long = b, a
	}
	i, j := 0, 0
	skipped := false
	for i < len(short) && j < len(long) {
		if short[i] == long[j] {
			i++
			j++
			continue
		}
		if skipped {
			return false
		}
		skipped = true
		j++
	}
	return true
}

type argusVetRequest struct {
	Action    string   `json:"action"`
	Ecosystem string   `json:"ecosystem"`
	Packages  []string `json:"packages"`
}

type argusVetResponse struct {
	Verdict string `json:"verdict,omitempty"`
	Status  string `json:"status,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Error   string `json:"error,omitempty"`
}

func (e *DefaultEvaluator) queryArgusSocket(ctx context.Context, inst packageInstall) (reachable bool, denied bool, reason string) {
	sockPath := e.resolveArgusSocketPath()
	if sockPath == "" {
		return false, false, ""
	}
	if err := verifySocketSecurity(sockPath); err != nil {
		return false, false, ""
	}

	timeout := e.ArgusDialTimeout
	if timeout <= 0 {
		timeout = DefaultArgusDialTimeout
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "unix", sockPath)
	if err != nil {
		return false, false, ""
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := dialCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	req := argusVetRequest{
		Action:    "vet",
		Ecosystem: inst.Ecosystem,
		Packages:  inst.Packages,
	}
	data, err := json.Marshal(req)
	if err != nil {
		return true, false, ""
	}
	data = append(data, '\n')
	if _, err := conn.Write(data); err != nil {
		return true, false, ""
	}

	reader := bufio.NewReader(io.LimitReader(conn, maxArgusRespBytes))
	line, err := reader.ReadBytes('\n')
	if err != nil && (!errors.Is(err, io.EOF) || len(line) == 0) {
		return true, false, ""
	}

	var resp argusVetResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return true, false, ""
	}

	v := strings.ToLower(strings.TrimSpace(resp.Verdict))
	st := strings.ToLower(strings.TrimSpace(resp.Status))
	if v == "deny" || v == "block" || st == "denied" || st == "blocked" {
		msg := strings.TrimSpace(resp.Reason)
		if msg == "" {
			msg = strings.TrimSpace(resp.Error)
		}
		if msg == "" {
			msg = "package failed Argus pre-flight provenance checks"
		}
		return true, true, msg
	}
	return true, false, ""
}

// ============================================================================
// Output Sanitization & Secret Redaction (Zero Secret Echo Invariant)
// ============================================================================

var reBearerSecret = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}`)

func redactSecrets(s string) string {
	out := reInlineSecret.ReplaceAllString(s, "[REDACTED_SECRET]")
	out = reBearerSecret.ReplaceAllString(out, "Bearer [REDACTED_SECRET]")
	return out
}

func sanitizeOutputText(s string) string {
	clean, _ := normalizeNFKCAndStripInvisible(s)
	clean = ux.SanitizeTerminalText(clean)
	clean = redactSecrets(clean)
	clean = strings.ReplaceAll(clean, "\r", " ")
	clean = strings.ReplaceAll(clean, "\n", " ")
	clean = strings.ReplaceAll(clean, "\t", " ")
	return strings.TrimSpace(clean)
}

func sanitizeSingleLineText(s string) string {
	clean := ux.SanitizeTerminalText(s)
	clean = strings.ReplaceAll(clean, "\r", " ")
	clean = strings.ReplaceAll(clean, "\n", " ")
	clean = strings.ReplaceAll(clean, "\t", " ")
	return strings.TrimSpace(clean)
}

func safePackageTokens(pkgs []string) []string {
	var safe []string
	for _, p := range pkgs {
		if ux.ValidateRemediationToken(p) {
			safe = append(safe, p)
		}
	}
	if len(safe) == 0 {
		return []string{"<package>"}
	}
	return safe
}

func firstSafeToken(pkgs []string, fallback string) string {
	for _, p := range pkgs {
		if ux.ValidateRemediationToken(p) {
			return p
		}
	}
	return fallback
}
