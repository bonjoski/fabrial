package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestReceipt_RejectsForgedUnsignedAndTamperedPayload verifies ADV-RCPT-01:
// 1-byte payload tamper, swapped keyid, unsigned envelope, wrong predicateType,
// wrong payloadType, and wrong signing key all fail closed.
func TestReceipt_RejectsForgedUnsignedAndTamperedPayload(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sessionID := "sess_01ADVTEST1234"
	signer, err := NewLocalEd25519Signer(sessionID, priv)
	if err != nil {
		t.Fatal(err)
	}

	stmt := makeTestStatement(t, sessionID, "argus", string(StageScaffoldingDeps))
	validEnv, err := SignEnvelope(stmt, signer)
	if err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}

	// Sanity check: unmodified envelope verifies
	if _, err := VerifyEnvelope(validEnv, pub); err != nil {
		t.Fatalf("baseline VerifyEnvelope failed: %v", err)
	}

	// 1. 1-byte tamper inside base64 payload
	rawPayload, err := base64.StdEncoding.DecodeString(validEnv.Payload)
	if err != nil {
		t.Fatal(err)
	}
	tamperedPayload := append([]byte(nil), rawPayload...)
	tamperedPayload[len(tamperedPayload)-2] ^= 0x01
	tamperedEnv := &DSSEEnvelope{
		PayloadType: validEnv.PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(tamperedPayload),
		Signatures:  append([]DSSESignature(nil), validEnv.Signatures...),
	}
	if _, err := VerifyEnvelope(tamperedEnv, pub); err == nil {
		t.Fatal("ADV-RCPT-01 FAIL-OPEN: 1-byte tampered payload accepted!")
	}

	// 2. Swapped keyid (attacker substitutes another session's SPIFFE URI)
	swappedKeyEnv := &DSSEEnvelope{
		PayloadType: validEnv.PayloadType,
		Payload:     validEnv.Payload,
		Signatures: []DSSESignature{
			{
				KeyID: "spiffe://bonjoski.local/session/sess_ATTACKER9999",
				Sig:   validEnv.Signatures[0].Sig,
			},
		},
	}
	if _, err := VerifyEnvelope(swappedKeyEnv, pub); err == nil {
		t.Fatal("ADV-RCPT-01 FAIL-OPEN: swapped keyid accepted!")
	}

	// 3. Unsigned envelope (zero signatures)
	unsignedEnv := &DSSEEnvelope{
		PayloadType: validEnv.PayloadType,
		Payload:     validEnv.Payload,
		Signatures:  nil,
	}
	if _, err := VerifyEnvelope(unsignedEnv, pub); err == nil {
		t.Fatal("ADV-RCPT-01 FAIL-OPEN: unsigned envelope accepted!")
	}

	// 4. Wrong predicateType (signed by valid key, forged predicateType)
	wrongPredStmt := *stmt
	wrongPredStmt.PredicateType = "https://evil.example/attestation/v1"
	wrongPredBytes, err := json.Marshal(wrongPredStmt)
	if err != nil {
		t.Fatal(err)
	}
	wrongPredPAE := PAE(DSSEPayloadType, wrongPredBytes)
	wrongPredSig := ed25519.Sign(priv, wrongPredPAE)
	wrongPredEnv := &DSSEEnvelope{
		PayloadType: DSSEPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(wrongPredBytes),
		Signatures: []DSSESignature{
			{
				KeyID: SessionKeyID(sessionID),
				Sig:   base64.StdEncoding.EncodeToString(wrongPredSig),
			},
		},
	}
	if _, err := VerifyEnvelope(wrongPredEnv, pub); err == nil {
		t.Fatal("ADV-RCPT-01 FAIL-OPEN: wrong predicateType accepted!")
	}

	// 5. Wrong payloadType
	wrongTypeEnv := &DSSEEnvelope{
		PayloadType: "application/json",
		Payload:     validEnv.Payload,
		Signatures:  validEnv.Signatures,
	}
	if _, err := VerifyEnvelope(wrongTypeEnv, pub); err == nil {
		t.Fatal("ADV-RCPT-01 FAIL-OPEN: wrong payloadType accepted!")
	}

	// 6. Wrong public key
	if _, err := VerifyEnvelope(validEnv, otherPub); err == nil {
		t.Fatal("ADV-RCPT-01 FAIL-OPEN: envelope verified under wrong Ed25519 public key!")
	}
}

// TestReceipt_RejectsSymlinkReceiptDir verifies ADV-RCPT-01 symlink containment:
// replacing .fabrial/receipts (or a session dir or receipt file) with a symlink
// outside the worktree fails closed and writes 0 bytes to the target.
func TestReceipt_RejectsSymlinkReceiptDir(t *testing.T) {
	worktree := t.TempDir()
	outsideDir := t.TempDir()

	if err := os.MkdirAll(filepath.Join(worktree, ".fabrial"), 0700); err != nil {
		t.Fatal(err)
	}
	// Plant symlink: <worktree>/.fabrial/receipts -> <outsideDir>
	if err := os.Symlink(outsideDir, filepath.Join(worktree, ".fabrial", "receipts")); err != nil {
		t.Fatal(err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := "sess_01SYMLINKTEST"
	signer, err := NewLocalEd25519Signer(sessionID, priv)
	if err != nil {
		t.Fatal(err)
	}
	stmt := makeTestStatement(t, sessionID, "airlock", string(StageScaffoldingDeps))
	env, err := SignEnvelope(stmt, signer)
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewStore(worktree)
	if err != nil {
		t.Fatal(err)
	}

	// Write must fail closed with ErrSymlinkDetected
	if _, err := store.Write(env, stmt); !errors.Is(err, ErrSymlinkDetected) {
		t.Fatalf("ADV-RCPT-01 FAIL-OPEN: expected ErrSymlinkDetected on write, got: %v", err)
	}

	// Zero files may be written to outsideDir
	outsideEntries, err := os.ReadDir(outsideDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(outsideEntries) != 0 {
		t.Fatalf("ADV-RCPT-01 FAIL-OPEN: %d entries written through symlink into %s", len(outsideEntries), outsideDir)
	}

	// ListSessions and VerifySession must also fail closed on symlinked receipts dir
	if _, err := store.ListSessions(); !errors.Is(err, ErrSymlinkDetected) {
		t.Fatalf("expected ErrSymlinkDetected from ListSessions, got: %v", err)
	}
	if _, err := store.VerifySession(sessionID, pub); !errors.Is(err, ErrSymlinkDetected) {
		t.Fatalf("expected ErrSymlinkDetected from VerifySession, got: %v", err)
	}

	// Also verify symlinked receipt file inside a legitimate session directory fails closed
	worktree2 := t.TempDir()
	store2, err := NewStore(worktree2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store2.Write(env, stmt); err != nil {
		t.Fatalf("baseline write failed: %v", err)
	}
	outsideFile := filepath.Join(outsideDir, "forged.dsse.json")
	if err := os.WriteFile(outsideFile, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	symlinkReceipt := filepath.Join(worktree2, ".fabrial", "receipts", sessionID, "999-argus-rcpt_fake.dsse.json")
	if err := os.Symlink(outsideFile, symlinkReceipt); err != nil {
		t.Fatal(err)
	}
	if _, err := store2.VerifySession(sessionID, pub); !errors.Is(err, ErrSymlinkDetected) {
		t.Fatalf("ADV-RCPT-01 FAIL-OPEN: symlinked receipt file not rejected, got: %v", err)
	}
}

// TestConcurrentReceipts_N8NoLockContention verifies NFR-CONC-01:
// 8 concurrent goroutines each writing and verifying 50 signed BLPR-v1 receipts
// across distinct session directories with zero data races and zero corruptions.
func TestConcurrentReceipts_N8NoLockContention(t *testing.T) {
	worktree := t.TempDir()
	if err := os.MkdirAll(filepath.Join(worktree, ".git", "info"), 0755); err != nil {
		t.Fatal(err)
	}

	store, err := NewStore(worktree)
	if err != nil {
		t.Fatal(err)
	}

	const (
		agents             = 8
		receiptsPerAgent   = 50
	)

	tools := []string{"coppermind", "argus", "airlock", "locksmith", "aegisbox", "soulcaster", "bomhound", "conjoiner"}

	var wg sync.WaitGroup
	errCh := make(chan error, agents*receiptsPerAgent)

	for i := 0; i < agents; i++ {
		wg.Add(1)
		go func(agentIdx int) {
			defer wg.Done()

			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				errCh <- err
				return
			}
			sessionID, err := NewSessionID()
			if err != nil {
				errCh <- err
				return
			}
			signer, err := NewLocalEd25519Signer(sessionID, priv)
			if err != nil {
				errCh <- err
				return
			}

			for j := 0; j < receiptsPerAgent; j++ {
				tool := tools[(agentIdx+j)%len(tools)]
				stmt := makeTestStatement(t, sessionID, tool, string(StageTestingValidation))
				env, err := SignEnvelope(stmt, signer)
				if err != nil {
					errCh <- err
					return
				}
				if _, err := store.Write(env, stmt); err != nil {
					errCh <- err
					return
				}
			}

			verified, err := store.VerifySession(sessionID, pub)
			if err != nil {
				errCh <- err
				return
			}
			if len(verified) != receiptsPerAgent {
				errCh <- errors.New("unexpected verified receipt count for concurrent agent")
				return
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("N=8 concurrency failure: %v", err)
	}

	sessions, err := store.ListSessions()
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != agents {
		t.Fatalf("expected %d distinct session directories, got %d", agents, len(sessions))
	}
}
