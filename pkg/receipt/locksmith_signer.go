package receipt

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	locksmithProtocolVersion = "1.0"
	actionSignDSSE           = "sign_dsse"
	actionGetSessionPubKey   = "get_session_pubkey"
	defaultLocksmithTimeout  = 2 * time.Second
	maxLocksmithRespBytes    = 64 * 1024
)

type locksmithRequest struct {
	Version   string `json:"version"`
	Action    string `json:"action"`
	SessionID string `json:"session_id"`
	PAEB64    string `json:"pae_b64,omitempty"`
}

type locksmithResponse struct {
	Status    string `json:"status"`
	KeyID     string `json:"keyid,omitempty"`
	SigB64    string `json:"sig_b64,omitempty"`
	PubKeyB64 string `json:"pubkey_b64,omitempty"`
	Error     string `json:"error,omitempty"`
}

// ResolveLocksmithSocketPath returns the local Locksmith UDS socket path from
// LOCKSMITH_SOCKET, LOCKSMITH_SOCK, or ~/.locksmith/locksmith.sock.
func ResolveLocksmithSocketPath() string {
	if s := strings.TrimSpace(os.Getenv("LOCKSMITH_SOCKET")); s != "" {
		return s
	}
	if s := strings.TrimSpace(os.Getenv("LOCKSMITH_SOCK")); s != "" {
		return s
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".locksmith", "locksmith.sock")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("locksmith-uid-%d", os.Getuid()), "locksmith.sock")
}

// LocksmithUDSSigner signs BLPR-v1 DSSE PAE digests over the local Locksmith Unix
// domain socket using the session's amortized Ed25519 leaf key (0 extra Touch ID prompts).
type LocksmithUDSSigner struct {
	SocketPath string
	SessionID  string
	Timeout    time.Duration
}

// NewLocksmithUDSSigner creates a Locksmith UDS signer for the given BLPR-v1 session.
func NewLocksmithUDSSigner(sessionID string, socketPath string) (*LocksmithUDSSigner, error) {
	if !ValidateSessionID(sessionID) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidSessionID, sessionID)
	}
	if strings.TrimSpace(socketPath) == "" {
		socketPath = ResolveLocksmithSocketPath()
	}
	return &LocksmithUDSSigner{
		SocketPath: socketPath,
		SessionID:  sessionID,
		Timeout:    defaultLocksmithTimeout,
	}, nil
}

// SignDSSE implements Signer by requesting a session Ed25519 signature over UDS.
func (s *LocksmithUDSSigner) SignDSSE(pae []byte) (string, []byte, error) {
	return s.SignDSSEContext(context.Background(), pae)
}

// SignDSSEContext signs pae over the local Locksmith UDS socket with context cancellation.
func (s *LocksmithUDSSigner) SignDSSEContext(ctx context.Context, pae []byte) (string, []byte, error) {
	if s == nil {
		return "", nil, errors.New("locksmith signer is nil")
	}
	if !ValidateSessionID(s.SessionID) {
		return "", nil, fmt.Errorf("%w: %q", ErrInvalidSessionID, s.SessionID)
	}

	req := locksmithRequest{
		Version:   locksmithProtocolVersion,
		Action:    actionSignDSSE,
		SessionID: s.SessionID,
		PAEB64:    base64.StdEncoding.EncodeToString(pae),
	}

	resp, err := s.roundTrip(ctx, req)
	if err != nil {
		return "", nil, err
	}
	if resp.Status != "GRANTED" {
		msg := strings.TrimSpace(resp.Error)
		if msg == "" {
			msg = "locksmith denied sign_dsse request"
		}
		return "", nil, fmt.Errorf("locksmith sign_dsse %s: %s", resp.Status, msg)
	}

	expectedKeyID := SessionKeyID(s.SessionID)
	if resp.KeyID != expectedKeyID {
		return "", nil, fmt.Errorf("locksmith returned mismatched keyid %q (want %q)", resp.KeyID, expectedKeyID)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(resp.SigB64)
	if err != nil {
		return "", nil, fmt.Errorf("decode locksmith sig_b64: %w", err)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return "", nil, fmt.Errorf("locksmith returned invalid Ed25519 signature length %d", len(sigBytes))
	}

	return resp.KeyID, sigBytes, nil
}

// GetSessionPubKey queries Locksmith over UDS for the session's Ed25519 public key.
func (s *LocksmithUDSSigner) GetSessionPubKey(ctx context.Context) (ed25519.PublicKey, string, error) {
	if s == nil {
		return nil, "", errors.New("locksmith signer is nil")
	}
	if !ValidateSessionID(s.SessionID) {
		return nil, "", fmt.Errorf("%w: %q", ErrInvalidSessionID, s.SessionID)
	}

	req := locksmithRequest{
		Version:   locksmithProtocolVersion,
		Action:    actionGetSessionPubKey,
		SessionID: s.SessionID,
	}

	resp, err := s.roundTrip(ctx, req)
	if err != nil {
		return nil, "", err
	}
	if resp.Status != "GRANTED" {
		msg := strings.TrimSpace(resp.Error)
		if msg == "" {
			msg = "locksmith denied get_session_pubkey request"
		}
		return nil, "", fmt.Errorf("locksmith get_session_pubkey %s: %s", resp.Status, msg)
	}

	expectedKeyID := SessionKeyID(s.SessionID)
	if resp.KeyID != "" && resp.KeyID != expectedKeyID {
		return nil, "", fmt.Errorf("locksmith returned mismatched keyid %q (want %q)", resp.KeyID, expectedKeyID)
	}

	pubBytes, err := base64.StdEncoding.DecodeString(resp.PubKeyB64)
	if err != nil {
		return nil, "", fmt.Errorf("decode locksmith pubkey_b64: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return nil, "", fmt.Errorf("locksmith returned invalid Ed25519 public key length %d", len(pubBytes))
	}

	return ed25519.PublicKey(pubBytes), expectedKeyID, nil
}

func (s *LocksmithUDSSigner) roundTrip(ctx context.Context, req locksmithRequest) (*locksmithResponse, error) {
	sockPath := s.SocketPath
	if strings.TrimSpace(sockPath) == "" {
		sockPath = ResolveLocksmithSocketPath()
	}

	if err := verifySocketSecurity(sockPath); err != nil {
		return nil, err
	}

	timeout := s.Timeout
	if timeout <= 0 {
		timeout = defaultLocksmithTimeout
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("dial locksmith socket %s: %w", sockPath, err)
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := dialCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal locksmith request: %w", err)
	}
	payload = append(payload, '\n')

	if _, err := conn.Write(payload); err != nil {
		return nil, fmt.Errorf("write locksmith request: %w", err)
	}

	reader := bufio.NewReader(io.LimitReader(conn, maxLocksmithRespBytes))
	line, err := reader.ReadBytes('\n')
	if err != nil && (!errors.Is(err, io.EOF) || len(line) == 0) {
		return nil, fmt.Errorf("read locksmith response: %w", err)
	}

	var resp locksmithResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("decode locksmith response: %w", err)
	}
	return &resp, nil
}
