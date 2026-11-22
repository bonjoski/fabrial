package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/bonjoski/fabrial/pkg/receipt"
	"github.com/bonjoski/fabrial/pkg/ux"
)

type receiptVerifyOutput struct {
	Tool          string                    `json:"tool"`
	Status        string                    `json:"status"`
	Worktree      string                    `json:"worktree"`
	Sessions      []string                  `json:"sessions"`
	VerifiedCount int                       `json:"verified_count"`
	Receipts      []receipt.VerifiedReceipt `json:"receipts"`
}

type receiptStatusItem struct {
	SessionID string          `json:"session_id"`
	Filename  string          `json:"filename"`
	ReceiptID string          `json:"receipt_id"`
	Tool      string          `json:"tool"`
	Version   string          `json:"version"`
	Stage     string          `json:"stage"`
	Verdict   receipt.Verdict `json:"verdict"`
	Proven    bool            `json:"proven"`
	Signed    bool            `json:"signed"`
	KeyID     string          `json:"keyid,omitempty"`
	Timestamp time.Time       `json:"timestamp"`
}

type receiptStatusOutput struct {
	Tool       string              `json:"tool"`
	Status     string              `json:"status"`
	Verified   bool                `json:"verified"`
	Worktree   string              `json:"worktree"`
	Sessions   []string            `json:"sessions"`
	Count      int                 `json:"count"`
	ByTool     map[string]int      `json:"by_tool"`
	ByVerdict  map[string]int      `json:"by_verdict"`
	Receipts   []receiptStatusItem `json:"receipts"`
	VerifyHint string              `json:"verify_hint"`
}

func handleReceipt(args []string) {
	code := runReceipt(args, os.Stdout, os.Stderr)
	if code != 0 {
		os.Exit(code)
	}
}

func runReceipt(args []string, stdout, stderr io.Writer) int {
	asJSON := false
	showWhy := false
	for _, a := range args {
		if a == "--json" {
			asJSON = true
		} else if a == "--why" {
			showWhy = true
		}
	}

	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		_, _ = fmt.Fprintln(stdout, `Usage:
  fabrial receipt verify [--session <id>] [--dir <path>] [--pubkey-b64 <b64>] [--pubkey <path>] [--socket <path>] [--json] [--why]
  fabrial receipt status [--session <id>] [--dir <path>] [--json] [--why]

Cryptographically verify or inspect local BLPR-v1 DSSE / in-toto Statement v1 receipts
stored under .fabrial/receipts/<session_id>/ (100% local workstation scope).`)
		return 0
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "verify":
		return runReceiptVerify(subArgs, stdout, stderr)
	case "status":
		return runReceiptStatus(subArgs, stdout, stderr)
	default:
		ffe := &ux.FixForwardError{
			Tool:           "fabrial",
			Code:           "FABRIAL_RECEIPT_UNKNOWN_SUBCOMMAND",
			Summary:        fmt.Sprintf("Unknown receipt subcommand %q", sub),
			RemediationCmd: "fabrial receipt verify",
			WhyOneLiner:    "Supported receipt subcommands are `verify` and `status`.",
			DeepWhy:        "Use `fabrial receipt verify` to validate DSSE Ed25519 signatures or `fabrial receipt status` for a read-only summary.",
			ExitCode:       1,
		}
		_ = ffe.Render(stderr, asJSON, showWhy)
		return ffe.ExitCode
	}
}

func runReceiptVerify(args []string, stdout, stderr io.Writer) int {
	asJSON := false
	showWhy := false
	sessionID := strings.TrimSpace(os.Getenv("FABRIAL_SESSION_ID"))
	targetDir := strings.TrimSpace(os.Getenv("FABRIAL_WORKTREE_ROOT"))
	if targetDir == "" {
		targetDir = "."
	}
	pubKeyB64 := ""
	pubKeyPath := ""
	socketPath := ""

	for _, a := range args {
		if a == "--json" {
			asJSON = true
		} else if a == "--why" {
			showWhy = true
		}
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--json":
			asJSON = true
		case "--why":
			showWhy = true
		case "--session":
			if i+1 >= len(args) {
				return emitReceiptError(stderr, asJSON, showWhy, 1, "FABRIAL_RECEIPT_MISSING_SESSION",
					"Flag --session requires a BLPR-v1 session ID", "fabrial receipt verify --session sess_...",
					"Specify a session ID matching ^sess_[0-9A-Za-z]+$ or omit --session to verify all sessions.", "")
			}
			sessionID = strings.TrimSpace(args[i+1])
			i++
		case "--dir", "-d":
			if i+1 >= len(args) {
				return emitReceiptError(stderr, asJSON, showWhy, 1, "FABRIAL_RECEIPT_MISSING_DIR",
					"Flag --dir requires a worktree directory path", "fabrial receipt verify --dir .",
					"Specify the local repository worktree containing .fabrial/receipts/.", "")
			}
			targetDir = args[i+1]
			i++
		case "--pubkey-b64":
			if i+1 >= len(args) {
				return emitReceiptError(stderr, asJSON, showWhy, 1, "FABRIAL_RECEIPT_MISSING_PUBKEY",
					"Flag --pubkey-b64 requires a base64-encoded Ed25519 public key", "fabrial receipt verify --pubkey-b64 <base64>",
					"Provide the 32-byte Ed25519 session public key in base64 or let fabrial query Locksmith over UDS.", "")
			}
			pubKeyB64 = strings.TrimSpace(args[i+1])
			i++
		case "--pubkey":
			if i+1 >= len(args) {
				return emitReceiptError(stderr, asJSON, showWhy, 1, "FABRIAL_RECEIPT_MISSING_PUBKEY_PATH",
					"Flag --pubkey requires a public key file path", "fabrial receipt verify --pubkey <path>",
					"Provide a regular file containing a raw or base64-encoded 32-byte Ed25519 public key.", "")
			}
			pubKeyPath = strings.TrimSpace(args[i+1])
			i++
		case "--socket":
			if i+1 >= len(args) {
				return emitReceiptError(stderr, asJSON, showWhy, 1, "FABRIAL_RECEIPT_MISSING_SOCKET",
					"Flag --socket requires a Locksmith UDS path", "fabrial receipt verify",
					"Defaults to LOCKSMITH_SOCKET or ~/.locksmith/locksmith.sock.", "")
			}
			socketPath = strings.TrimSpace(args[i+1])
			i++
		case "help", "-h", "--help":
			_, _ = fmt.Fprintln(stdout, "Usage: fabrial receipt verify [--session <id>] [--dir <path>] [--pubkey-b64 <b64>] [--pubkey <path>] [--socket <path>] [--json] [--why]")
			return 0
		default:
			if strings.HasPrefix(arg, "-") {
				return emitReceiptError(stderr, asJSON, showWhy, 1, "FABRIAL_RECEIPT_UNKNOWN_FLAG",
					fmt.Sprintf("Unrecognized flag %q for fabrial receipt verify", arg),
					"fabrial receipt verify --help",
					"Supported flags: --session, --dir, --pubkey-b64, --pubkey, --socket, --json, --why.", "")
			}
		}
	}

	store, err := receipt.NewStore(targetDir)
	if err != nil {
		return emitReceiptError(stderr, asJSON, showWhy, 1, "FABRIAL_RECEIPT_INVALID_DIR",
			fmt.Sprintf("Could not open worktree root: %v", err),
			"fabrial receipt verify --dir .",
			"Run fabrial receipt verify inside an accessible local repository worktree.", "")
	}

	var explicitPub ed25519.PublicKey
	if pubKeyB64 != "" {
		decoded, decErr := base64.StdEncoding.DecodeString(pubKeyB64)
		if decErr != nil || len(decoded) != ed25519.PublicKeySize {
			return emitReceiptError(stderr, asJSON, showWhy, receipt.ExitPolicyDeny, "FABRIAL_RECEIPT_INVALID_PUBKEY",
				"Invalid --pubkey-b64 value (expected base64-encoded 32-byte Ed25519 public key)",
				"fabrial receipt verify --pubkey-b64 <base64-ed25519-pubkey>",
				"Verification fails closed when the Ed25519 public key cannot be decoded.", "")
		}
		explicitPub = ed25519.PublicKey(decoded)
	} else if pubKeyPath != "" {
		pub, pErr := readPublicKeyFile(pubKeyPath)
		if pErr != nil {
			code := "FABRIAL_RECEIPT_INVALID_PUBKEY"
			if errors.Is(pErr, receipt.ErrSymlinkDetected) {
				code = "FABRIAL_RECEIPT_SYMLINK_REJECTED"
			}
			return emitReceiptError(stderr, asJSON, showWhy, receipt.ExitPolicyDeny, code,
				fmt.Sprintf("Could not load Ed25519 public key from %s", pubKeyPath),
				"fabrial receipt verify --pubkey-b64 <base64-ed25519-pubkey>",
				"Verification fails closed on unreadable, symlinked, or malformed public keys.",
				pErr.Error())
		}
		explicitPub = pub
	}

	var sessions []string
	if sessionID != "" {
		if !receipt.ValidateSessionID(sessionID) {
			return emitReceiptError(stderr, asJSON, showWhy, receipt.ExitPolicyDeny, "FABRIAL_RECEIPT_INVALID_SESSION",
				fmt.Sprintf("Invalid BLPR-v1 session ID %q", sessionID),
				"fabrial receipt verify",
				"BLPR-v1 session IDs must match ^sess_[0-9A-Za-z]+$ with no path traversal characters.", "")
		}
		sessions = []string{sessionID}
	} else {
		listed, lErr := store.ListSessions()
		if lErr != nil {
			return mapStoreError(stderr, asJSON, showWhy, lErr)
		}
		sessions = listed
	}

	if len(sessions) == 0 {
		return emitReceiptError(stderr, asJSON, showWhy, receipt.ExitPolicyDeny, "FABRIAL_RECEIPT_NONE_FOUND",
			"No BLPR-v1 receipt sessions found under .fabrial/receipts/",
			"fabrial session begin",
			"Verification fails closed when zero signed provenance receipts exist in the worktree.", "")
	}

	var allVerified []receipt.VerifiedReceipt
	for _, sid := range sessions {
		pub := explicitPub
		if pub == nil {
			signer, sErr := receipt.NewLocksmithUDSSigner(sid, socketPath)
			if sErr != nil {
				return emitReceiptError(stderr, asJSON, showWhy, receipt.ExitPolicyDeny, "FABRIAL_RECEIPT_PUBKEY_UNAVAILABLE",
					fmt.Sprintf("Failed to initialize Locksmith signer for session %s", sid),
					"fabrial receipt verify --pubkey-b64 <base64-ed25519-pubkey>",
					"Start Locksmith (`fabrial daemon start`) or supply --pubkey-b64 for offline verification.",
					sErr.Error())
			}
			fetchedPub, _, kErr := signer.GetSessionPubKey(context.Background())
			if kErr != nil {
				code := "FABRIAL_RECEIPT_PUBKEY_UNAVAILABLE"
				if errors.Is(kErr, receipt.ErrSymlinkDetected) {
					code = "FABRIAL_RECEIPT_SYMLINK_REJECTED"
				}
				return emitReceiptError(stderr, asJSON, showWhy, receipt.ExitPolicyDeny, code,
					fmt.Sprintf("Could not retrieve session public key for %s from Locksmith", sid),
					"fabrial receipt verify --pubkey-b64 <base64-ed25519-pubkey>",
					"Verification fails closed without an attested Ed25519 public key.",
					kErr.Error())
			}
			pub = fetchedPub
		}

		verified, vErr := store.VerifySession(sid, pub)
		if vErr != nil {
			return mapStoreError(stderr, asJSON, showWhy, vErr)
		}
		allVerified = append(allVerified, verified...)
	}

	if len(allVerified) == 0 {
		return emitReceiptError(stderr, asJSON, showWhy, receipt.ExitPolicyDeny, "FABRIAL_RECEIPT_NONE_FOUND",
			fmt.Sprintf("No BLPR-v1 receipts found for session(s): %s", strings.Join(sessions, ", ")),
			"fabrial receipt status",
			"Verification fails closed when the target session directory contains zero signed receipts.", "")
	}

	out := receiptVerifyOutput{
		Tool:          "fabrial",
		Status:        "verified",
		Worktree:      store.WorktreeRoot,
		Sessions:      sessions,
		VerifiedCount: len(allVerified),
		Receipts:      allVerified,
	}

	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(&out); err != nil {
			return 1
		}
		return 0
	}

	_, _ = fmt.Fprintf(stdout, "✓ fabrial: verified %d signed BLPR-v1 receipt(s) across %d session(s)\n",
		out.VerifiedCount, len(out.Sessions))
	_, _ = fmt.Fprintf(stdout, "  Next: fabrial receipt status\n")
	whyLine := "All DSSE Ed25519 signatures, SPIFFE session keyIDs, and in-toto Statement v1 schemas passed fail-closed verification."
	if !showWhy {
		whyLine += " (re-run with --why for receipt details)"
	}
	_, _ = fmt.Fprintf(stdout, "  Why:  %s\n", whyLine)

	if showWhy {
		_, _ = fmt.Fprintf(stdout, "\n  Deep Dive (--why):\n")
		for _, r := range out.Receipts {
			_, _ = fmt.Fprintf(stdout, "  • %s [%s/%s] verdict=%s proven=%v keyid=%s (%s)\n",
				ux.SanitizeTerminalText(r.ReceiptID),
				ux.SanitizeTerminalText(r.Tool),
				ux.SanitizeTerminalText(r.Stage),
				ux.SanitizeTerminalText(string(r.Verdict)),
				r.Proven,
				ux.SanitizeTerminalText(r.KeyID),
				ux.SanitizeTerminalText(r.Filename),
			)
		}
	}
	return 0
}

func runReceiptStatus(args []string, stdout, stderr io.Writer) int {
	asJSON := false
	showWhy := false
	sessionID := strings.TrimSpace(os.Getenv("FABRIAL_SESSION_ID"))
	targetDir := strings.TrimSpace(os.Getenv("FABRIAL_WORKTREE_ROOT"))
	if targetDir == "" {
		targetDir = "."
	}

	for _, a := range args {
		if a == "--json" {
			asJSON = true
		} else if a == "--why" {
			showWhy = true
		}
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--json":
			asJSON = true
		case "--why":
			showWhy = true
		case "--session":
			if i+1 >= len(args) {
				return emitReceiptError(stderr, asJSON, showWhy, 1, "FABRIAL_RECEIPT_MISSING_SESSION",
					"Flag --session requires a BLPR-v1 session ID", "fabrial receipt status",
					"Specify a session ID matching ^sess_[0-9A-Za-z]+$ or omit --session to inspect all sessions.", "")
			}
			sessionID = strings.TrimSpace(args[i+1])
			i++
		case "--dir", "-d":
			if i+1 >= len(args) {
				return emitReceiptError(stderr, asJSON, showWhy, 1, "FABRIAL_RECEIPT_MISSING_DIR",
					"Flag --dir requires a worktree directory path", "fabrial receipt status --dir .",
					"Specify the local repository worktree containing .fabrial/receipts/.", "")
			}
			targetDir = args[i+1]
			i++
		case "help", "-h", "--help":
			_, _ = fmt.Fprintln(stdout, "Usage: fabrial receipt status [--session <id>] [--dir <path>] [--json] [--why]")
			return 0
		default:
			if strings.HasPrefix(arg, "-") {
				return emitReceiptError(stderr, asJSON, showWhy, 1, "FABRIAL_RECEIPT_UNKNOWN_FLAG",
					fmt.Sprintf("Unrecognized flag %q for fabrial receipt status", arg),
					"fabrial receipt status --help",
					"Supported flags: --session, --dir, --json, --why.", "")
			}
		}
	}

	store, err := receipt.NewStore(targetDir)
	if err != nil {
		return emitReceiptError(stderr, asJSON, showWhy, 1, "FABRIAL_RECEIPT_INVALID_DIR",
			fmt.Sprintf("Could not open worktree root: %v", err),
			"fabrial receipt status --dir .",
			"Run fabrial receipt status inside an accessible local repository worktree.", "")
	}

	var sessions []string
	if sessionID != "" {
		if !receipt.ValidateSessionID(sessionID) {
			return emitReceiptError(stderr, asJSON, showWhy, receipt.ExitPolicyDeny, "FABRIAL_RECEIPT_INVALID_SESSION",
				fmt.Sprintf("Invalid BLPR-v1 session ID %q", sessionID),
				"fabrial receipt status",
				"BLPR-v1 session IDs must match ^sess_[0-9A-Za-z]+$.", "")
		}
		sessions = []string{sessionID}
	} else {
		listed, lErr := store.ListSessions()
		if lErr != nil {
			return mapStoreError(stderr, asJSON, showWhy, lErr)
		}
		sessions = listed
	}

	out := receiptStatusOutput{
		Tool:       "fabrial",
		Status:     "ok",
		Verified:   false,
		Worktree:   store.WorktreeRoot,
		Sessions:   sessions,
		ByTool:     make(map[string]int),
		ByVerdict:  make(map[string]int),
		Receipts:   make([]receiptStatusItem, 0),
		VerifyHint: "fabrial receipt verify",
	}

	for _, sid := range sessions {
		stored, rErr := store.ReadSession(sid)
		if rErr != nil {
			return mapStoreError(stderr, asJSON, showWhy, rErr)
		}
		for _, item := range stored {
			stmt, _, dErr := receipt.DecodeUnverified(item.Envelope)
			if dErr != nil {
				return mapStoreError(stderr, asJSON, showWhy, dErr)
			}
			keyID := ""
			if len(item.Envelope.Signatures) > 0 {
				keyID = item.Envelope.Signatures[0].KeyID
			}
			out.ByTool[stmt.Predicate.Producer.Tool]++
			out.ByVerdict[string(stmt.Predicate.Verdict)]++
			out.Receipts = append(out.Receipts, receiptStatusItem{
				SessionID: sid,
				Filename:  item.Filename,
				ReceiptID: stmt.Predicate.ReceiptID,
				Tool:      stmt.Predicate.Producer.Tool,
				Version:   stmt.Predicate.Producer.Version,
				Stage:     stmt.Predicate.Producer.Stage,
				Verdict:   stmt.Predicate.Verdict,
				Proven:    stmt.Predicate.Proven,
				Signed:    len(item.Envelope.Signatures) > 0,
				KeyID:     keyID,
				Timestamp: stmt.Predicate.Timestamp,
			})
		}
	}
	out.Count = len(out.Receipts)

	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(&out); err != nil {
			return 1
		}
		return 0
	}

	_, _ = fmt.Fprintf(stdout, "✓ fabrial: found %d BLPR-v1 receipt(s) across %d session(s) (read-only status; unverified)\n",
		out.Count, len(out.Sessions))
	_, _ = fmt.Fprintf(stdout, "  Next: fabrial receipt verify\n")
	whyLine := "Status reads local receipt structure only; run `fabrial receipt verify` to validate Ed25519 signatures."
	if !showWhy {
		whyLine += " (re-run with --why for receipt list)"
	}
	_, _ = fmt.Fprintf(stdout, "  Why:  %s\n", whyLine)

	if showWhy && len(out.Receipts) > 0 {
		_, _ = fmt.Fprintf(stdout, "\n  Deep Dive (--why):\n")
		for _, r := range out.Receipts {
			_, _ = fmt.Fprintf(stdout, "  • %s [%s/%s] verdict=%s signed=%v (%s)\n",
				ux.SanitizeTerminalText(r.ReceiptID),
				ux.SanitizeTerminalText(r.Tool),
				ux.SanitizeTerminalText(r.Stage),
				ux.SanitizeTerminalText(string(r.Verdict)),
				r.Signed,
				ux.SanitizeTerminalText(r.Filename),
			)
		}
	}
	return 0
}

func readPublicKeyFile(path string) (ed25519.PublicKey, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: pubkey path %s is a symlink", receipt.ErrSymlinkDetected, path)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("pubkey path %s is not a regular file", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	trimmed := strings.TrimSpace(string(raw))
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("pubkey file %s must contain 32 raw bytes or base64-encoded Ed25519 public key", path)
	}
	return ed25519.PublicKey(decoded), nil
}

func mapStoreError(stderr io.Writer, asJSON, showWhy bool, err error) int {
	if errors.Is(err, receipt.ErrSymlinkDetected) {
		return emitReceiptError(stderr, asJSON, showWhy, receipt.ExitPolicyDeny, "FABRIAL_RECEIPT_SYMLINK_REJECTED",
			"Refused symlinked receipt directory or file under .fabrial/receipts/",
			"fabrial receipt verify --why",
			"Symlinks in .fabrial/receipts/ are blocked fail-closed to prevent traversal outside the worktree.",
			err.Error())
	}
	if errors.Is(err, receipt.ErrSignatureFailed) || errors.Is(err, receipt.ErrInvalidEnvelope) {
		return emitReceiptError(stderr, asJSON, showWhy, receipt.ExitPolicyDeny, "FABRIAL_RECEIPT_VERIFY_FAILED",
			"BLPR-v1 receipt signature or schema verification failed (fail-closed)",
			"fabrial receipt verify --why",
			"A receipt was unsigned, tampered, or signed with a mismatched session SPIFFE keyID.",
			err.Error())
	}
	return emitReceiptError(stderr, asJSON, showWhy, receipt.ExitPolicyDeny, "FABRIAL_RECEIPT_ERROR",
		fmt.Sprintf("Receipt verification failed: %v", err),
		"fabrial receipt verify --why",
		"Resolve the receipt integrity or permission error before continuing.",
		err.Error())
}

func emitReceiptError(stderr io.Writer, asJSON, showWhy bool, exitCode int, code, summary, fix, why, deepWhy string) int {
	ffe := &ux.FixForwardError{
		Tool:           "fabrial",
		Code:           code,
		Summary:        summary,
		RemediationCmd: fix,
		WhyOneLiner:    why,
		DeepWhy:        deepWhy,
		References:     []string{"docs/use-cases/02-inter-tool-receipts-and-mcp-golden-path.md"},
		ExitCode:       exitCode,
	}
	_ = ffe.Render(stderr, asJSON, showWhy)
	return exitCode
}
