package main

import (
	"bufio"
	"bytes"
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

	"github.com/bonjoski/fabrial/pkg/receipt"
	"github.com/bonjoski/fabrial/pkg/ux"
)

func writeSignedTestReceipt(t *testing.T, worktree, sessionID, tool string, priv ed25519.PrivateKey) string {
	t.Helper()
	store, err := receipt.NewStore(worktree)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := receipt.NewLocalEd25519Signer(sessionID, priv)
	if err != nil {
		t.Fatal(err)
	}
	rcptID, err := receipt.NewReceiptID()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("go.sum"))
	stmt := &receipt.Statement{
		Type: receipt.StatementTypeV1,
		Subject: []receipt.Subject{
			{
				Name:   "go.sum",
				Digest: map[string]string{"sha256": hex.EncodeToString(sum[:])},
			},
		},
		PredicateType: receipt.PredicateTypeV1,
		Predicate: receipt.Predicate{
			SchemaVersion: receipt.SchemaVersionV1,
			ReceiptID:     rcptID,
			Timestamp:     time.Now().UTC().Truncate(time.Second),
			Session: receipt.SessionLineage{
				SessionID:       sessionID,
				ActorMode:       string(receipt.ActorModeAIDLC),
				WorktreeHeadSHA: "abcdef123456",
			},
			Producer: receipt.Producer{
				Tool:    tool,
				Version: "1.0.0",
				Stage:   string(receipt.StageScaffoldingDeps),
			},
			Verdict: receipt.VerdictAllow,
			Proven:  true,
			Claims:  json.RawMessage(`{"packages_vetted":10}`),
		},
	}
	env, err := receipt.SignEnvelope(stmt, signer)
	if err != nil {
		t.Fatal(err)
	}
	path, err := store.Write(env, stmt)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCLI_ReceiptVerifyAndJSON(t *testing.T) {
	t.Setenv("FABRIAL_SESSION_ID", "")
	t.Setenv("FABRIAL_WORKTREE_ROOT", "")

	worktree := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	sessionID := "sess_01CLITEST9999"

	writtenPath := writeSignedTestReceipt(t, worktree, sessionID, "argus", priv)

	// 1. Default human output <= 3 lines
	var out, errBuf bytes.Buffer
	code := runReceipt([]string{"verify", "--dir", worktree, "--session", sessionID, "--pubkey-b64", pubB64}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("verify exited %d, stderr: %s", code, errBuf.String())
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) > 3 {
		t.Fatalf("expected <=3 lines for default verify output, got %d:\n%s", len(lines), out.String())
	}

	// 2. --json output
	out.Reset()
	errBuf.Reset()
	code = runReceipt([]string{"verify", "--dir", worktree, "--session", sessionID, "--pubkey-b64", pubB64, "--json"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("verify --json exited %d, stderr: %s", code, errBuf.String())
	}
	var verifyRes receiptVerifyOutput
	if err := json.Unmarshal(out.Bytes(), &verifyRes); err != nil {
		t.Fatalf("invalid verify --json output: %v (raw: %s)", err, out.String())
	}
	if verifyRes.Status != "verified" || verifyRes.VerifiedCount != 1 {
		t.Fatalf("unexpected verify result: %+v", verifyRes)
	}

	// 3. --why output
	out.Reset()
	errBuf.Reset()
	code = runReceipt([]string{"verify", "--dir", worktree, "--session", sessionID, "--pubkey-b64", pubB64, "--why"}, &out, &errBuf)
	if code != 0 || !strings.Contains(out.String(), "Deep Dive (--why):") {
		t.Fatalf("expected --why details, code=%d out=%s", code, out.String())
	}

	// 4. status --json output
	out.Reset()
	errBuf.Reset()
	code = runReceipt([]string{"status", "--dir", worktree, "--session", sessionID, "--json"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("status --json exited %d, stderr: %s", code, errBuf.String())
	}
	var statusRes receiptStatusOutput
	if err := json.Unmarshal(out.Bytes(), &statusRes); err != nil {
		t.Fatalf("invalid status --json output: %v", err)
	}
	if statusRes.Count != 1 || statusRes.ByTool["argus"] != 1 || statusRes.Verified {
		t.Fatalf("unexpected status result: %+v", statusRes)
	}

	// 5. Verify over mock Locksmith UDS socket (without --pubkey-b64)
	sockDir, err := os.MkdirTemp("", "fab-cli-ls-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(sockDir) }()
	sockPath := filepath.Join(sockDir, "l.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
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
				_, _ = bufio.NewReader(c).ReadBytes('\n')
				resp := map[string]string{
					"status":     "GRANTED",
					"keyid":      receipt.SessionKeyID(sessionID),
					"pubkey_b64": pubB64,
				}
				b, _ := json.Marshal(resp)
				_, _ = c.Write(append(b, '\n'))
			}(conn)
		}
	}()

	out.Reset()
	errBuf.Reset()
	code = runReceipt([]string{"verify", "--dir", worktree, "--session", sessionID, "--socket", sockPath, "--json"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("verify via locksmith socket exited %d, stderr: %s", code, errBuf.String())
	}

	// 6. Tampered receipt MUST fail closed with ExitCode 10 and FixForwardError JSON
	raw, err := os.ReadFile(writtenPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(raw, []byte(`"payload": "`), []byte(`"payload": "A`), 1)
	if err := os.WriteFile(writtenPath, tampered, 0600); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errBuf.Reset()
	code = runReceipt([]string{"verify", "--dir", worktree, "--session", sessionID, "--pubkey-b64", pubB64, "--json"}, &out, &errBuf)
	if code != receipt.ExitPolicyDeny {
		t.Fatalf("expected exit code %d on tampered receipt, got %d (stderr: %s)", receipt.ExitPolicyDeny, code, errBuf.String())
	}
	var ffe ux.FixForwardError
	if err := json.Unmarshal(errBuf.Bytes(), &ffe); err != nil {
		t.Fatalf("expected FixForwardError JSON on stderr, got: %v (raw: %s)", err, errBuf.String())
	}
	if ffe.ExitCode != receipt.ExitPolicyDeny || ffe.Code == "" || ffe.RemediationCmd == "" {
		t.Fatalf("unexpected FixForwardError payload: %+v", ffe)
	}

	// 7. Symlinked .fabrial/receipts MUST fail closed with ExitCode 10
	symWorktree := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(symWorktree, ".fabrial"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(symWorktree, ".fabrial", "receipts")); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errBuf.Reset()
	code = runReceipt([]string{"verify", "--dir", symWorktree, "--pubkey-b64", pubB64, "--json"}, &out, &errBuf)
	if code != receipt.ExitPolicyDeny {
		t.Fatalf("expected exit code %d on symlinked receipts dir, got %d", receipt.ExitPolicyDeny, code)
	}
	var symFFE ux.FixForwardError
	if err := json.Unmarshal(errBuf.Bytes(), &symFFE); err != nil {
		t.Fatalf("expected FixForwardError JSON on symlink failure, got: %v", err)
	}
	if symFFE.Code != "FABRIAL_RECEIPT_SYMLINK_REJECTED" {
		t.Fatalf("unexpected error code %q", symFFE.Code)
	}
}
