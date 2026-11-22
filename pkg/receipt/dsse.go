package receipt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

var (
	// ErrInvalidEnvelope indicates malformed, unsigned, or schema-invalid DSSE data.
	ErrInvalidEnvelope = errors.New("invalid or unsigned DSSE receipt envelope")
	// ErrSignatureFailed indicates Ed25519 signature or SPIFFE keyid verification failed.
	ErrSignatureFailed = errors.New("DSSE signature verification failed")
)

// Signer abstracts DSSE PAE Ed25519 signing (e.g., Locksmith UDS amortized session leaf key).
type Signer interface {
	SignDSSE(pae []byte) (keyID string, sig []byte, err error)
}

// LocalEd25519Signer is an in-memory Ed25519 DSSE signer bound to a single session SPIFFE URI.
type LocalEd25519Signer struct {
	KeyID string
	Priv  ed25519.PrivateKey
}

// NewLocalEd25519Signer constructs a LocalEd25519Signer for the given BLPR-v1 session ID.
func NewLocalEd25519Signer(sessionID string, priv ed25519.PrivateKey) (*LocalEd25519Signer, error) {
	if !ValidateSessionID(sessionID) {
		return nil, fmt.Errorf("invalid session ID %q", sessionID)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key length %d", len(priv))
	}
	return &LocalEd25519Signer{
		KeyID: SessionKeyID(sessionID),
		Priv:  priv,
	}, nil
}

// SignDSSE signs a DSSE PAE buffer with the local Ed25519 private key.
func (s *LocalEd25519Signer) SignDSSE(pae []byte) (string, []byte, error) {
	if s == nil || len(s.Priv) != ed25519.PrivateKeySize {
		return "", nil, errors.New("uninitialized Ed25519 signer")
	}
	if !keyIDRe.MatchString(s.KeyID) {
		return "", nil, fmt.Errorf("invalid SPIFFE keyid %q", s.KeyID)
	}
	sig := ed25519.Sign(s.Priv, pae)
	return s.KeyID, sig, nil
}

// PAE computes the DSSE Pre-Authentication Encoding per specification:
// "DSSEv1 " + len(type) + " " + type + " " + len(body) + " " + body
func PAE(payloadType string, payload []byte) []byte {
	prefix := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	out := make([]byte, 0, len(prefix)+len(payload))
	out = append(out, prefix...)
	out = append(out, payload...)
	return out
}

// SignEnvelope validates a BLPR-v1 Statement, serializes it, computes the DSSE PAE,
// and signs it with signer to produce a standards-compliant DSSEEnvelope.
func SignEnvelope(stmt *Statement, signer Signer) (*DSSEEnvelope, error) {
	if signer == nil {
		return nil, errors.New("signer is nil")
	}
	if err := ValidateStatement(stmt); err != nil {
		return nil, fmt.Errorf("validate statement: %w", err)
	}

	raw, err := json.Marshal(stmt)
	if err != nil {
		return nil, fmt.Errorf("marshal statement: %w", err)
	}

	pae := PAE(DSSEPayloadType, raw)
	keyID, sig, err := signer.SignDSSE(pae)
	if err != nil {
		return nil, fmt.Errorf("sign DSSE PAE: %w", err)
	}

	expectedKeyID := SessionKeyID(stmt.Predicate.Session.SessionID)
	if keyID != expectedKeyID || !keyIDRe.MatchString(keyID) {
		return nil, fmt.Errorf("signer keyid %q does not match statement session keyid %q", keyID, expectedKeyID)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("unexpected Ed25519 signature size %d", len(sig))
	}

	env := &DSSEEnvelope{
		PayloadType: DSSEPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(raw),
		Signatures: []DSSESignature{
			{
				KeyID: keyID,
				Sig:   base64.StdEncoding.EncodeToString(sig),
			},
		},
	}
	return env, nil
}

// ParseEnvelope strictly decodes JSON bytes into a DSSEEnvelope, rejecting unknown fields
// and trailing garbage per blpr-v1.schema.json (additionalProperties: false).
func ParseEnvelope(data []byte) (*DSSEEnvelope, error) {
	var env DSSEEnvelope
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data after JSON envelope", ErrInvalidEnvelope)
	}
	return &env, nil
}

// DecodeUnverified decodes and schema-validates the Statement inside a DSSEEnvelope
// WITHOUT verifying its cryptographic signature. Use ONLY for read-only inspection (status).
func DecodeUnverified(env *DSSEEnvelope) (*Statement, []byte, error) {
	if env == nil || env.PayloadType != DSSEPayloadType || env.Payload == "" {
		return nil, nil, ErrInvalidEnvelope
	}
	raw, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: decode payload: %v", ErrInvalidEnvelope, err)
	}
	var stmt Statement
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&stmt); err != nil {
		return nil, nil, fmt.Errorf("%w: unmarshal statement: %v", ErrInvalidEnvelope, err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, nil, fmt.Errorf("%w: trailing data in statement payload", ErrInvalidEnvelope)
	}
	if err := ValidateStatement(&stmt); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	return &stmt, raw, nil
}

// VerifyEnvelope strictly verifies a BLPR-v1 DSSEEnvelope against an Ed25519 public key:
//  1. Validates top-level envelope structure and payloadType.
//  2. Decodes and strictly schema-validates the embedded in-toto Statement v1.
//  3. Verifies that the signature's SPIFFE keyid matches the statement's session_id
//     (preventing keyid substitution attacks) and validates the Ed25519 signature over PAE.
func VerifyEnvelope(env *DSSEEnvelope, pub ed25519.PublicKey) (*Statement, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: invalid Ed25519 public key size %d", ErrSignatureFailed, len(pub))
	}
	if err := ValidateEnvelope(env); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}

	stmt, raw, err := DecodeUnverified(env)
	if err != nil {
		return nil, err
	}

	expectedKeyID := SessionKeyID(stmt.Predicate.Session.SessionID)
	pae := PAE(env.PayloadType, raw)

	verified := false
	for _, s := range env.Signatures {
		if s.KeyID != expectedKeyID {
			continue
		}
		sigBytes, decErr := base64.StdEncoding.DecodeString(s.Sig)
		if decErr != nil || len(sigBytes) != ed25519.SignatureSize {
			continue
		}
		if ed25519.Verify(pub, pae, sigBytes) {
			verified = true
			break
		}
	}

	if !verified {
		return nil, fmt.Errorf("%w: no valid Ed25519 signature matching %s", ErrSignatureFailed, expectedKeyID)
	}

	return stmt, nil
}
