package receipt

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	StatementTypeV1     = "https://in-toto.io/Statement/v1"
	PredicateTypeV1     = "https://bonjoski.dev/attestation/paved-road/v1"
	DSSEPayloadType     = "application/vnd.in-toto+json"
	SchemaVersionV1     = "1.0.0"
	SPIFFESessionPrefix = "spiffe://bonjoski.local/session/"

	// ExitPolicyDeny is the deterministic UB-CLI-v2 / UB-MCP-v1 exit code for
	// tampered, unsigned, symlinked, or unverified receipts.
	ExitPolicyDeny = 10
)

// Verdict represents the outcome attested by a producer tool.
type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictDeny  Verdict = "deny"
	VerdictWarn  Verdict = "warn"
)

// ActorMode identifies whether a human (sdlc) or autonomous agent (aidlc) ran the step.
type ActorMode string

const (
	ActorModeSDLC  ActorMode = "sdlc"
	ActorModeAIDLC ActorMode = "aidlc"
)

// Stage identifies the paved-road lifecycle stage for a receipt.
type Stage string

const (
	StageIdeation          Stage = "ideation"
	StageScaffoldingDeps   Stage = "scaffolding_deps"
	StageCodingSecrets     Stage = "coding_secrets"
	StageTestingValidation Stage = "testing_validation"
	StageRelease           Stage = "release"
)

var (
	receiptIDRe      = regexp.MustCompile(`^rcpt_[0-9A-Za-z]+$`)
	sessionIDRe      = regexp.MustCompile(`^sess_[0-9A-Za-z]+$`)
	keyIDRe          = regexp.MustCompile(`^spiffe://bonjoski\.local/session/sess_[0-9A-Za-z]+$`)
	sha256HexRe      = regexp.MustCompile(`^[a-f0-9]{64}$`)
	extraDigestHexRe = regexp.MustCompile(`^[a-f0-9]{64,128}$`)
	headSHARe        = regexp.MustCompile(`^[a-f0-9]{7,64}$`)
	fixForwardCodeRe = regexp.MustCompile(`^[A-Z0-9_]+$`)

	validTools = map[string]struct{}{
		"coppermind": {},
		"argus":      {},
		"airlock":    {},
		"locksmith":  {},
		"aegisbox":   {},
		"soulcaster": {},
		"bomhound":   {},
		"conjoiner":  {},
		"halfshard":  {},
		"stormcage":  {},
		"flightdeck": {},
		"fabrial":    {},
	}

	validStages = map[string]struct{}{
		string(StageIdeation):          {},
		string(StageScaffoldingDeps):   {},
		string(StageCodingSecrets):     {},
		string(StageTestingValidation): {},
		string(StageRelease):           {},
	}

	validActorModes = map[string]struct{}{
		string(ActorModeSDLC):  {},
		string(ActorModeAIDLC): {},
	}

	validVerdicts = map[Verdict]struct{}{
		VerdictAllow: {},
		VerdictDeny:  {},
		VerdictWarn:  {},
	}
)

// Subject is an in-toto Statement v1 subject entry.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// SessionLineage captures the ambient session and repository HEAD context.
type SessionLineage struct {
	SessionID       string `json:"session_id"`
	ParentSessionID string `json:"parent_session_id,omitempty"`
	ActorMode       string `json:"actor_mode"`
	WorktreeHeadSHA string `json:"worktree_head_sha"`
}

// Producer identifies the bonjoski tool that emitted the receipt.
type Producer struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	Stage   string `json:"stage"`
}

// Predicate is the BLPR-v1 predicate body inside an in-toto Statement v1.
type Predicate struct {
	SchemaVersion  string          `json:"schema_version"`
	ReceiptID      string          `json:"receipt_id"`
	Timestamp      time.Time       `json:"timestamp"`
	Session        SessionLineage  `json:"session"`
	Producer       Producer        `json:"producer"`
	Verdict        Verdict         `json:"verdict"`
	Proven         bool            `json:"proven"`
	Claims         json.RawMessage `json:"claims"`
	ParentReceipts []string        `json:"parent_receipts,omitempty"`
	FixForwardCode string          `json:"fix_forward_code,omitempty"`
}

// Statement is a standards-compliant in-toto Statement v1 with a BLPR-v1 predicate.
type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

// DSSESignature is a single DSSE signature entry bound to a SPIFFE session keyID.
type DSSESignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// DSSEEnvelope is a Dead Simple Signing Envelope wrapping a base64-encoded Statement.
type DSSEEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []DSSESignature `json:"signatures"`
}

// SessionKeyID returns the canonical SPIFFE URI for a BLPR-v1 session ID.
func SessionKeyID(sessionID string) string {
	return SPIFFESessionPrefix + sessionID
}

// ValidateSessionID verifies session_id conforms to ^sess_[0-9A-Za-z]+$.
func ValidateSessionID(sessionID string) bool {
	return sessionIDRe.MatchString(sessionID)
}

// ValidateReceiptID verifies receipt_id conforms to ^rcpt_[0-9A-Za-z]+$.
func ValidateReceiptID(receiptID string) bool {
	return receiptIDRe.MatchString(receiptID)
}

// ValidateTool verifies tool is in the canonical blpr-v1.schema.json enum.
func ValidateTool(tool string) bool {
	_, ok := validTools[tool]
	return ok
}

// NewReceiptID generates a cryptographically random BLPR-v1 receipt identifier.
func NewReceiptID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate receipt id: %w", err)
	}
	return "rcpt_" + hex.EncodeToString(b), nil
}

// NewSessionID generates a cryptographically random BLPR-v1 session identifier.
func NewSessionID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate session id: %w", err)
	}
	return "sess_" + hex.EncodeToString(b), nil
}

// ValidateStatement enforces every structural constraint in blpr-v1.schema.json.
func ValidateStatement(stmt *Statement) error {
	if stmt == nil {
		return errors.New("statement is nil")
	}
	if stmt.Type != StatementTypeV1 {
		return fmt.Errorf("invalid statement _type %q (want %q)", stmt.Type, StatementTypeV1)
	}
	if stmt.PredicateType != PredicateTypeV1 {
		return fmt.Errorf("invalid predicateType %q (want %q)", stmt.PredicateType, PredicateTypeV1)
	}
	if len(stmt.Subject) == 0 {
		return errors.New("statement must contain at least one subject")
	}
	for i, sub := range stmt.Subject {
		if len(sub.Name) == 0 || len(sub.Name) > 512 {
			return fmt.Errorf("subject[%d].name length must be 1..512", i)
		}
		sha, ok := sub.Digest["sha256"]
		if !ok || !sha256HexRe.MatchString(sha) {
			return fmt.Errorf("subject[%d].digest.sha256 must be 64 lowercase hex chars", i)
		}
		for algo, val := range sub.Digest {
			if algo == "sha256" {
				continue
			}
			if !extraDigestHexRe.MatchString(val) {
				return fmt.Errorf("subject[%d].digest.%s must be 64..128 lowercase hex chars", i, algo)
			}
		}
	}

	p := &stmt.Predicate
	if p.SchemaVersion != SchemaVersionV1 {
		return fmt.Errorf("invalid predicate schema_version %q (want %q)", p.SchemaVersion, SchemaVersionV1)
	}
	if !receiptIDRe.MatchString(p.ReceiptID) {
		return fmt.Errorf("invalid predicate receipt_id %q", p.ReceiptID)
	}
	if p.Timestamp.IsZero() {
		return errors.New("predicate timestamp must not be zero")
	}

	if !sessionIDRe.MatchString(p.Session.SessionID) {
		return fmt.Errorf("invalid session.session_id %q", p.Session.SessionID)
	}
	if p.Session.ParentSessionID != "" && !sessionIDRe.MatchString(p.Session.ParentSessionID) {
		return fmt.Errorf("invalid session.parent_session_id %q", p.Session.ParentSessionID)
	}
	if _, ok := validActorModes[p.Session.ActorMode]; !ok {
		return fmt.Errorf("invalid session.actor_mode %q", p.Session.ActorMode)
	}
	if !headSHARe.MatchString(p.Session.WorktreeHeadSHA) {
		return fmt.Errorf("invalid session.worktree_head_sha %q", p.Session.WorktreeHeadSHA)
	}

	if _, ok := validTools[p.Producer.Tool]; !ok {
		return fmt.Errorf("invalid producer.tool %q", p.Producer.Tool)
	}
	if len(strings.TrimSpace(p.Producer.Version)) == 0 || len(p.Producer.Version) > 64 {
		return fmt.Errorf("invalid producer.version %q", p.Producer.Version)
	}
	if _, ok := validStages[p.Producer.Stage]; !ok {
		return fmt.Errorf("invalid producer.stage %q", p.Producer.Stage)
	}

	if _, ok := validVerdicts[p.Verdict]; !ok {
		return fmt.Errorf("invalid predicate verdict %q", p.Verdict)
	}

	trimmedClaims := bytes.TrimSpace(p.Claims)
	if len(trimmedClaims) == 0 || trimmedClaims[0] != '{' {
		return errors.New("predicate claims must be a JSON object")
	}
	var claimsObj map[string]interface{}
	if err := json.Unmarshal(trimmedClaims, &claimsObj); err != nil || claimsObj == nil {
		return fmt.Errorf("predicate claims must be a valid JSON object: %w", err)
	}

	for i, pr := range p.ParentReceipts {
		if !receiptIDRe.MatchString(pr) {
			return fmt.Errorf("invalid parent_receipts[%d] %q", i, pr)
		}
	}
	if p.FixForwardCode != "" && !fixForwardCodeRe.MatchString(p.FixForwardCode) {
		return fmt.Errorf("invalid fix_forward_code %q", p.FixForwardCode)
	}

	return nil
}

// ValidateEnvelope checks top-level DSSE envelope structure per blpr-v1.schema.json.
func ValidateEnvelope(env *DSSEEnvelope) error {
	if env == nil {
		return errors.New("DSSE envelope is nil")
	}
	if env.PayloadType != DSSEPayloadType {
		return fmt.Errorf("invalid DSSE payloadType %q (want %q)", env.PayloadType, DSSEPayloadType)
	}
	if strings.TrimSpace(env.Payload) == "" {
		return errors.New("DSSE payload is empty")
	}
	if len(env.Signatures) == 0 {
		return errors.New("DSSE envelope has zero signatures")
	}
	for i, s := range env.Signatures {
		if !keyIDRe.MatchString(s.KeyID) {
			return fmt.Errorf("signatures[%d].keyid %q does not match SPIFFE session pattern", i, s.KeyID)
		}
		if strings.TrimSpace(s.Sig) == "" {
			return fmt.Errorf("signatures[%d].sig is empty", i)
		}
	}
	return nil
}
