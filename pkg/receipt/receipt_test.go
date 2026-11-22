package receipt

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func makeTestStatement(t *testing.T, sessionID, tool, stage string) *Statement {
	t.Helper()
	rcptID, err := NewReceiptID()
	if err != nil {
		t.Fatalf("NewReceiptID: %v", err)
	}
	sum := sha256.Sum256([]byte("package-lock.json"))
	return &Statement{
		Type: StatementTypeV1,
		Subject: []Subject{
			{
				Name:   "package-lock.json",
				Digest: map[string]string{"sha256": hex.EncodeToString(sum[:])},
			},
		},
		PredicateType: PredicateTypeV1,
		Predicate: Predicate{
			SchemaVersion: SchemaVersionV1,
			ReceiptID:     rcptID,
			Timestamp:     time.Now().UTC().Truncate(time.Second),
			Session: SessionLineage{
				SessionID:       sessionID,
				ActorMode:       string(ActorModeAIDLC),
				WorktreeHeadSHA: "9f2c1a8b4d5e6f70",
			},
			Producer: Producer{
				Tool:    tool,
				Version: "0.9.2",
				Stage:   stage,
			},
			Verdict: VerdictAllow,
			Proven:  true,
			Claims:  json.RawMessage(`{"packages_vetted":42,"slopsquats_blocked":0}`),
		},
	}
}

func TestDSSE_SignAndVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	sessionID, err := NewSessionID()
	if err != nil {
		t.Fatalf("NewSessionID: %v", err)
	}
	signer, err := NewLocalEd25519Signer(sessionID, priv)
	if err != nil {
		t.Fatalf("NewLocalEd25519Signer: %v", err)
	}

	stmt := makeTestStatement(t, sessionID, "argus", string(StageScaffoldingDeps))

	// Verify PAE format per DSSE spec
	pae := PAE("text/plain", []byte("hello"))
	wantPAE := "DSSEv1 10 text/plain 5 hello"
	if string(pae) != wantPAE {
		t.Fatalf("PAE mismatch: got %q, want %q", string(pae), wantPAE)
	}

	env, err := SignEnvelope(stmt, signer)
	if err != nil {
		t.Fatalf("SignEnvelope failed: %v", err)
	}
	if env.PayloadType != DSSEPayloadType {
		t.Fatalf("unexpected payloadType %q", env.PayloadType)
	}
	if len(env.Signatures) != 1 || env.Signatures[0].KeyID != SessionKeyID(sessionID) {
		t.Fatalf("unexpected signatures: %+v", env.Signatures)
	}

	verified, err := VerifyEnvelope(env, pub)
	if err != nil {
		t.Fatalf("VerifyEnvelope failed: %v", err)
	}
	if verified.Predicate.ReceiptID != stmt.Predicate.ReceiptID {
		t.Fatalf("receipt_id mismatch: got %q, want %q", verified.Predicate.ReceiptID, stmt.Predicate.ReceiptID)
	}
	if verified.Predicate.Producer.Tool != "argus" || verified.Predicate.Verdict != VerdictAllow || !verified.Predicate.Proven {
		t.Fatalf("unexpected verified predicate: %+v", verified.Predicate)
	}
}

func TestStore_AtomicWriteAndGitExclude(t *testing.T) {
	worktree := t.TempDir()
	// Create a regular .git directory so .git/info/exclude is updated
	if err := os.MkdirAll(filepath.Join(worktree, ".git", "info"), 0755); err != nil {
		t.Fatal(err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := "sess_01JDX9J00TEST"
	signer, err := NewLocalEd25519Signer(sessionID, priv)
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewStore(worktree)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	stmt := makeTestStatement(t, sessionID, "airlock", string(StageScaffoldingDeps))
	env, err := SignEnvelope(stmt, signer)
	if err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}

	writtenPath, err := store.Write(env, stmt)
	if err != nil {
		t.Fatalf("Store.Write: %v", err)
	}
	if !strings.HasSuffix(writtenPath, ".dsse.json") {
		t.Fatalf("expected .dsse.json suffix, got %q", writtenPath)
	}

	fi, err := os.Stat(writtenPath)
	if err != nil {
		t.Fatalf("stat written receipt: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions on receipt file, got %04o", fi.Mode().Perm())
	}

	sessionDir := filepath.Join(worktree, ".fabrial", "receipts", sessionID)
	dfi, err := os.Stat(sessionDir)
	if err != nil {
		t.Fatalf("stat session dir: %v", err)
	}
	if dfi.Mode().Perm() != 0700 {
		t.Fatalf("expected 0700 permissions on session dir, got %04o", dfi.Mode().Perm())
	}

	// Verify idempotent .git/info/exclude registration
	excludePath := filepath.Join(worktree, ".git", "info", "exclude")
	excludeData, err := os.ReadFile(excludePath)
	if err != nil {
		t.Fatalf("read .git/info/exclude: %v", err)
	}
	if !strings.Contains(string(excludeData), ".fabrial/receipts/") {
		t.Fatalf("expected .fabrial/receipts/ in .git/info/exclude, got: %q", string(excludeData))
	}

	// Second write should NOT duplicate the exclude entry
	stmt2 := makeTestStatement(t, sessionID, "argus", string(StageScaffoldingDeps))
	env2, err := SignEnvelope(stmt2, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Write(env2, stmt2); err != nil {
		t.Fatalf("second Store.Write: %v", err)
	}
	excludeData2, err := os.ReadFile(excludePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(excludeData2), ".fabrial/receipts/") != 1 {
		t.Fatalf("expected exactly 1 .fabrial/receipts/ line in exclude, got:\n%s", string(excludeData2))
	}

	// Verify reading and cryptographic verification
	sessions, err := store.ListSessions()
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 || sessions[0] != sessionID {
		t.Fatalf("unexpected sessions: %v", sessions)
	}

	verified, err := store.VerifySession(sessionID, pub)
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if len(verified) != 2 {
		t.Fatalf("expected 2 verified receipts, got %d", len(verified))
	}
}

func TestLocksmithUDSSigner_SignAndGetPubKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := "sess_01LOCKSMITHUDS"

	// Short path in os.TempDir to avoid macOS 104-char sun_path limit
	sockDir, err := os.MkdirTemp("", "fab-ls-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(sockDir) }()
	sockPath := filepath.Join(sockDir, "l.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer func() { _ = ln.Close() }()
	if err := os.Chmod(sockPath, 0600); err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				line, rErr := bufio.NewReader(c).ReadBytes('\n')
				if rErr != nil {
					return
				}
				var req locksmithRequest
				if uErr := json.Unmarshal(line, &req); uErr != nil {
					return
				}
				var resp locksmithResponse
				switch req.Action {
				case actionSignDSSE:
					pae, _ := base64.StdEncoding.DecodeString(req.PAEB64)
					sig := ed25519.Sign(priv, pae)
					resp = locksmithResponse{
						Status:    "GRANTED",
						KeyID:     SessionKeyID(req.SessionID),
						SigB64:    base64.StdEncoding.EncodeToString(sig),
						PubKeyB64: base64.StdEncoding.EncodeToString(pub),
					}
				case actionGetSessionPubKey:
					resp = locksmithResponse{
						Status:    "GRANTED",
						KeyID:     SessionKeyID(req.SessionID),
						PubKeyB64: base64.StdEncoding.EncodeToString(pub),
					}
				default:
					resp = locksmithResponse{Status: "DENIED", Error: "unknown action"}
				}
				out, _ := json.Marshal(resp)
				_, _ = c.Write(append(out, '\n'))
			}(conn)
		}
	}()

	signer, err := NewLocksmithUDSSigner(sessionID, sockPath)
	if err != nil {
		t.Fatalf("NewLocksmithUDSSigner: %v", err)
	}

	stmt := makeTestStatement(t, sessionID, "locksmith", string(StageCodingSecrets))
	env, err := SignEnvelope(stmt, signer)
	if err != nil {
		t.Fatalf("SignEnvelope via UDS: %v", err)
	}

	gotPub, gotKeyID, err := signer.GetSessionPubKey(context.Background())
	if err != nil {
		t.Fatalf("GetSessionPubKey: %v", err)
	}
	if gotKeyID != SessionKeyID(sessionID) {
		t.Fatalf("unexpected keyid %q", gotKeyID)
	}

	verified, err := VerifyEnvelope(env, gotPub)
	if err != nil {
		t.Fatalf("VerifyEnvelope with fetched pubkey failed: %v", err)
	}
	if verified.Predicate.ReceiptID != stmt.Predicate.ReceiptID {
		t.Fatalf("receipt ID mismatch")
	}
}
