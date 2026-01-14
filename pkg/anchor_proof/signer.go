// Copyright 2025 Certen Protocol
//
// Validator Attestation Signer - Creates and verifies validator attestations
// Validators sign attestations using Ed25519 to cryptographically endorse proofs

package anchor_proof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AttestationSigner creates validator attestations
type AttestationSigner struct {
	validatorID string
	privateKey  ed25519.PrivateKey
	publicKey   ed25519.PublicKey
}

// NewAttestationSigner creates a new signer with the given private key
func NewAttestationSigner(validatorID string, privateKey ed25519.PrivateKey) (*AttestationSigner, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d, got %d", ed25519.PrivateKeySize, len(privateKey))
	}

	return &AttestationSigner{
		validatorID: validatorID,
		privateKey:  privateKey,
		publicKey:   privateKey.Public().(ed25519.PublicKey),
	}, nil
}

// NewAttestationSignerFromHex creates a signer from a hex-encoded private key
func NewAttestationSignerFromHex(validatorID string, privateKeyHex string) (*AttestationSigner, error) {
	privateKey, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}
	return NewAttestationSigner(validatorID, privateKey)
}

// GetPublicKey returns the validator's public key
func (s *AttestationSigner) GetPublicKey() ed25519.PublicKey {
	return s.publicKey
}

// GetPublicKeyHex returns the validator's public key as hex
func (s *AttestationSigner) GetPublicKeyHex() string {
	return hex.EncodeToString(s.publicKey)
}

// GetValidatorID returns the validator ID
func (s *AttestationSigner) GetValidatorID() string {
	return s.validatorID
}

// =============================================================================
// Attestation Creation
// =============================================================================

// SignProof creates an attestation for a proof
func (s *AttestationSigner) SignProof(proof *CertenAnchorProof) (*ValidatorAttestation, error) {
	if proof == nil {
		return nil, fmt.Errorf("proof cannot be nil")
	}

	// Get the merkle root bytes
	merkleRoot, err := proof.GetMerkleRootBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to decode merkle root: %w", err)
	}

	// Create the attestation message
	message := createAttestationMessage(merkleRoot, proof.AnchorReference.TxHash)

	// Sign the message
	signature := ed25519.Sign(s.privateKey, message)

	return &ValidatorAttestation{
		AttestationID:      uuid.New(),
		ValidatorID:        s.validatorID,
		ValidatorPubkey:    s.publicKey,
		AttestedMerkleRoot: merkleRoot,
		AttestedAnchorTx:   proof.AnchorReference.TxHash,
		Signature:          signature,
		AttestedAt:         time.Now(),
	}, nil
}

// SignBatchProofs creates attestations for multiple proofs
func (s *AttestationSigner) SignBatchProofs(proofs []*CertenAnchorProof) ([]*ValidatorAttestation, error) {
	attestations := make([]*ValidatorAttestation, len(proofs))
	for i, proof := range proofs {
		att, err := s.SignProof(proof)
		if err != nil {
			return nil, fmt.Errorf("failed to sign proof %d: %w", i, err)
		}
		attestations[i] = att
	}
	return attestations, nil
}

// SignMerkleRoot creates an attestation for a merkle root and anchor tx
func (s *AttestationSigner) SignMerkleRoot(merkleRoot []byte, anchorTxHash string) (*ValidatorAttestation, error) {
	if len(merkleRoot) != 32 {
		return nil, fmt.Errorf("merkle root must be 32 bytes")
	}
	if anchorTxHash == "" {
		return nil, fmt.Errorf("anchor tx hash is required")
	}

	message := createAttestationMessage(merkleRoot, anchorTxHash)
	signature := ed25519.Sign(s.privateKey, message)

	return &ValidatorAttestation{
		AttestationID:      uuid.New(),
		ValidatorID:        s.validatorID,
		ValidatorPubkey:    s.publicKey,
		AttestedMerkleRoot: merkleRoot,
		AttestedAnchorTx:   anchorTxHash,
		Signature:          signature,
		AttestedAt:         time.Now(),
	}, nil
}

// =============================================================================
// Attestation Verification
// =============================================================================

// AttestationVerifier verifies validator attestations
type AttestationVerifier struct {
	// Known validators (pubkey -> validator ID)
	knownValidators map[string]string
}

// NewAttestationVerifier creates a new verifier
func NewAttestationVerifier() *AttestationVerifier {
	return &AttestationVerifier{
		knownValidators: make(map[string]string),
	}
}

// RegisterValidator adds a known validator
func (v *AttestationVerifier) RegisterValidator(validatorID string, pubkey ed25519.PublicKey) {
	keyHex := hex.EncodeToString(pubkey)
	v.knownValidators[keyHex] = validatorID
}

// RegisterValidatorHex adds a known validator with hex-encoded public key
func (v *AttestationVerifier) RegisterValidatorHex(validatorID, pubkeyHex string) error {
	pubkey, err := hex.DecodeString(pubkeyHex)
	if err != nil {
		return fmt.Errorf("invalid public key hex: %w", err)
	}
	if len(pubkey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: expected %d, got %d", ed25519.PublicKeySize, len(pubkey))
	}
	v.RegisterValidator(validatorID, pubkey)
	return nil
}

// VerifyAttestation verifies a single attestation
func (v *AttestationVerifier) VerifyAttestation(att *ValidatorAttestation) (*AttestationVerifyResult, error) {
	if att == nil {
		return nil, fmt.Errorf("attestation cannot be nil")
	}

	result := &AttestationVerifyResult{
		AttestationID: att.AttestationID,
		ValidatorID:   att.ValidatorID,
		VerifiedAt:    time.Now(),
	}

	// Check public key size
	if len(att.ValidatorPubkey) != ed25519.PublicKeySize {
		result.Valid = false
		result.Error = "invalid public key size"
		return result, nil
	}

	// Check signature size
	if len(att.Signature) != ed25519.SignatureSize {
		result.Valid = false
		result.Error = "invalid signature size"
		return result, nil
	}

	// Check if this is a known validator
	keyHex := hex.EncodeToString(att.ValidatorPubkey)
	knownID, isKnown := v.knownValidators[keyHex]
	result.IsKnownValidator = isKnown
	if isKnown && knownID != att.ValidatorID {
		result.Valid = false
		result.Error = "validator ID does not match known validator"
		return result, nil
	}

	// Recreate the message that was signed
	message := createAttestationMessage(att.AttestedMerkleRoot, att.AttestedAnchorTx)

	// Verify the signature
	result.Valid = ed25519.Verify(att.ValidatorPubkey, message, att.Signature)
	if !result.Valid {
		result.Error = "signature verification failed"
	}

	return result, nil
}

// VerifyAttestations verifies multiple attestations
func (v *AttestationVerifier) VerifyAttestations(attestations []ValidatorAttestation) (*BatchAttestationVerifyResult, error) {
	result := &BatchAttestationVerifyResult{
		Results:     make([]*AttestationVerifyResult, len(attestations)),
		TotalCount:  len(attestations),
		VerifiedAt:  time.Now(),
	}

	validatorsSeen := make(map[string]bool)

	for i, att := range attestations {
		attResult, err := v.VerifyAttestation(&att)
		if err != nil {
			return nil, fmt.Errorf("failed to verify attestation %d: %w", i, err)
		}
		result.Results[i] = attResult

		if attResult.Valid {
			result.ValidCount++
			if !validatorsSeen[att.ValidatorID] {
				validatorsSeen[att.ValidatorID] = true
				result.UniqueValidators++
			}
		} else {
			result.InvalidCount++
		}

		if attResult.IsKnownValidator {
			result.KnownValidatorCount++
		}
	}

	result.AllValid = result.ValidCount == result.TotalCount

	return result, nil
}

// VerifyProofAttestations verifies all attestations on a proof
func (v *AttestationVerifier) VerifyProofAttestations(proof *CertenAnchorProof) (*BatchAttestationVerifyResult, error) {
	return v.VerifyAttestations(proof.Attestations)
}

// =============================================================================
// Verification Results
// =============================================================================

// AttestationVerifyResult contains the result of verifying a single attestation
type AttestationVerifyResult struct {
	AttestationID    uuid.UUID `json:"attestation_id"`
	ValidatorID      string    `json:"validator_id"`
	Valid            bool      `json:"valid"`
	IsKnownValidator bool      `json:"is_known_validator"`
	Error            string    `json:"error,omitempty"`
	VerifiedAt       time.Time `json:"verified_at"`
}

// BatchAttestationVerifyResult contains the result of verifying multiple attestations
type BatchAttestationVerifyResult struct {
	Results             []*AttestationVerifyResult `json:"results"`
	TotalCount          int                        `json:"total_count"`
	ValidCount          int                        `json:"valid_count"`
	InvalidCount        int                        `json:"invalid_count"`
	KnownValidatorCount int                        `json:"known_validator_count"`
	UniqueValidators    int                        `json:"unique_validators"`
	AllValid            bool                       `json:"all_valid"`
	VerifiedAt          time.Time                  `json:"verified_at"`
}

// =============================================================================
// Helper Functions
// =============================================================================

// createAttestationMessage creates the canonical message to be signed
// Format: SHA256("CERTEN_ATTESTATION_V1" || merkle_root || anchor_tx_hash)
func createAttestationMessage(merkleRoot []byte, anchorTxHash string) []byte {
	// Create canonical message
	var buf bytes.Buffer
	buf.WriteString("CERTEN_ATTESTATION_V1")
	buf.Write(merkleRoot)
	buf.WriteString(anchorTxHash)

	// Hash the message (we sign the hash, not the raw message)
	hash := sha256.Sum256(buf.Bytes())
	return hash[:]
}

// ValidateAttestationSignature is a convenience function to verify a single attestation
func ValidateAttestationSignature(att *ValidatorAttestation) bool {
	if att == nil || len(att.ValidatorPubkey) != ed25519.PublicKeySize || len(att.Signature) != ed25519.SignatureSize {
		return false
	}
	message := createAttestationMessage(att.AttestedMerkleRoot, att.AttestedAnchorTx)
	return ed25519.Verify(att.ValidatorPubkey, message, att.Signature)
}

// =============================================================================
// Attestation Aggregation
// =============================================================================

// AttestationBundle represents a collection of attestations for a proof
type AttestationBundle struct {
	ProofID       uuid.UUID              `json:"proof_id"`
	MerkleRoot    []byte                 `json:"merkle_root"`
	AnchorTxHash  string                 `json:"anchor_tx_hash"`
	Attestations  []ValidatorAttestation `json:"attestations"`
	ValidCount    int                    `json:"valid_count"`
	TotalCount    int                    `json:"total_count"`
	IsSufficient  bool                   `json:"is_sufficient"`
	RequiredCount int                    `json:"required_count"`
	CreatedAt     time.Time              `json:"created_at"`
}

// NewAttestationBundle creates a new attestation bundle
func NewAttestationBundle(proofID uuid.UUID, merkleRoot []byte, anchorTxHash string, requiredCount int) *AttestationBundle {
	return &AttestationBundle{
		ProofID:       proofID,
		MerkleRoot:    merkleRoot,
		AnchorTxHash:  anchorTxHash,
		Attestations:  make([]ValidatorAttestation, 0),
		RequiredCount: requiredCount,
		CreatedAt:     time.Now(),
	}
}

// AddAttestation adds an attestation to the bundle after verification
func (b *AttestationBundle) AddAttestation(att *ValidatorAttestation) error {
	// Verify the attestation matches this bundle
	if !bytes.Equal(att.AttestedMerkleRoot, b.MerkleRoot) {
		return fmt.Errorf("attestation merkle root does not match bundle")
	}
	if att.AttestedAnchorTx != b.AnchorTxHash {
		return fmt.Errorf("attestation anchor tx does not match bundle")
	}

	// Verify the signature
	if !ValidateAttestationSignature(att) {
		return fmt.Errorf("attestation signature is invalid")
	}

	// Check for duplicate validator - check BOTH public key AND validator ID
	// to prevent the same key from attesting multiple times with different IDs
	for _, existing := range b.Attestations {
		// Check by public key (cryptographic identity) - primary check
		if bytes.Equal(existing.ValidatorPubkey, att.ValidatorPubkey) {
			return fmt.Errorf("duplicate attestation from public key (validator %s)", att.ValidatorID)
		}
		// Also check by validator ID for logical consistency
		if existing.ValidatorID == att.ValidatorID {
			return fmt.Errorf("duplicate attestation from validator %s", att.ValidatorID)
		}
	}

	b.Attestations = append(b.Attestations, *att)
	b.TotalCount = len(b.Attestations)
	b.ValidCount = b.TotalCount // All added attestations are valid (verified above)
	b.IsSufficient = b.ValidCount >= b.RequiredCount

	return nil
}

// ToJSON serializes the bundle to JSON
func (b *AttestationBundle) ToJSON() ([]byte, error) {
	return json.Marshal(b)
}

// GetValidatorIDs returns the IDs of all validators who have attested
func (b *AttestationBundle) GetValidatorIDs() []string {
	ids := make([]string, len(b.Attestations))
	for i, att := range b.Attestations {
		ids[i] = att.ValidatorID
	}
	return ids
}

// MerkleRootHex returns the Merkle root as a hex string
func (b *AttestationBundle) MerkleRootHex() string {
	return hex.EncodeToString(b.MerkleRoot)
}
