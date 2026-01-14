// Copyright 2025 Certen Protocol
//
// Phase 1: Proof Converter - Converts Go ProofBundle to Solidity CertenProof struct
// Per ANCHOR_V3_IMPLEMENTATION_PLAN.md Task 1.2
//
// This file provides the bridge between the validator's proof data structures and
// the CertenAnchorV3 contract's executeComprehensiveProof function.
//
// Key features:
// - Type-safe conversion from Go to Solidity-compatible structs
// - Validation to ensure all required fields are populated
// - Support for L1-L4 cryptographic proofs and G0-G2 governance proofs

package anchor

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// =============================================================================
// ProofBundle - Complete proof data for contract submission
// =============================================================================

// ProofBundle represents the complete proof data for a batch that will be
// submitted to the CertenAnchorV3 contract via executeComprehensiveProof.
// This is the Go-side representation of all proof components.
type ProofBundle struct {
	// Core identification
	BundleID    string    `json:"bundle_id"`
	BatchID     string    `json:"batch_id"`
	ValidatorID string    `json:"validator_id"`
	Timestamp   time.Time `json:"timestamp"`

	// Transaction identification
	TransactionHash [32]byte `json:"transaction_hash"`
	LeafHash        [32]byte `json:"leaf_hash"`

	// Merkle inclusion proof
	MerkleRoot  [32]byte   `json:"merkle_root"`
	ProofHashes [][32]byte `json:"proof_hashes"`

	// Commitment data (cryptographically derived from proof data)
	OperationCommitment  [32]byte `json:"operation_commitment"`
	CrossChainCommitment [32]byte `json:"cross_chain_commitment"`
	GovernanceRoot       [32]byte `json:"governance_root"`

	// Source chain information
	SourceChain       string   `json:"source_chain"`
	SourceBlockHeight uint64   `json:"source_block_height"`
	SourceTxHash      [32]byte `json:"source_tx_hash"`

	// Target chain information
	TargetChain   string         `json:"target_chain"`
	TargetAddress common.Address `json:"target_address"`

	// BLS ZK-SNARK proof (Groth16)
	BLSProof *BLSProofData `json:"bls_proof"`

	// Governance proof
	GovernanceProof *GovernanceProofData `json:"governance_proof"`

	// Proof expiration
	ExpirationTime time.Time `json:"expiration_time"`

	// Optional metadata
	Metadata []byte `json:"metadata,omitempty"`
}

// BLSProofData contains the BLS aggregate signature proof with ZK-SNARK verification data.
// This represents the multi-validator consensus on the anchor data.
type BLSProofData struct {
	// AggregateSignature is the BLS12-381 aggregate signature or ZK-SNARK proof bytes
	AggregateSignature []byte `json:"aggregate_signature"`

	// ValidatorAddresses are the Ethereum addresses of validators who signed
	ValidatorAddresses []common.Address `json:"validator_addresses"`

	// VotingPowers is the voting power of each validator
	VotingPowers []*big.Int `json:"voting_powers"`

	// TotalVotingPower is the total network voting power
	TotalVotingPower *big.Int `json:"total_voting_power"`

	// SignedVotingPower is the voting power that signed this proof
	SignedVotingPower *big.Int `json:"signed_voting_power"`

	// ThresholdMet indicates whether 2/3+ voting power signed
	ThresholdMet bool `json:"threshold_met"`

	// MessageHash is the hash of the message that was signed
	MessageHash [32]byte `json:"message_hash"`
}

// GovernanceProofData contains the governance authorization proof.
// This proves the transaction was authorized through the Accumulate governance system.
type GovernanceProofData struct {
	// KeyBookURL is the Accumulate URL of the KeyBook (e.g., "acc://example.acme/book")
	KeyBookURL string `json:"key_book_url"`

	// KeyBookRoot is the Merkle root of the KeyBook
	KeyBookRoot [32]byte `json:"key_book_root"`

	// KeyPageProofs is the Merkle proof path from authority to KeyBook root
	KeyPageProofs [][32]byte `json:"key_page_proofs"`

	// AuthorityAddress is the Ethereum address derived from the signing authority
	AuthorityAddress common.Address `json:"authority_address"`

	// AuthorityLevel is the governance level (0=G0, 1=G1, 2=G2)
	AuthorityLevel uint8 `json:"authority_level"`

	// Nonce is the authority's nonce for anti-replay protection
	Nonce *big.Int `json:"nonce"`

	// RequiredSignatures is the number of signatures required by the KeyPage
	RequiredSignatures *big.Int `json:"required_signatures"`

	// ProvidedSignatures is the number of signatures actually provided
	ProvidedSignatures *big.Int `json:"provided_signatures"`

	// ThresholdMet indicates whether the signature threshold was met
	ThresholdMet bool `json:"threshold_met"`
}

// =============================================================================
// Contract-Compatible Struct Types (matching Solidity structs)
// =============================================================================

// ContractCertenProof matches the Solidity CertenProof struct layout
type ContractCertenProof struct {
	TransactionHash [32]byte
	MerkleRoot      [32]byte
	ProofHashes     [][32]byte
	LeafHash        [32]byte
	GovernanceProof ContractGovernanceProofData
	BlsProof        ContractBLSProofData
	Commitments     ContractCommitmentData
	ExpirationTime  *big.Int
	Metadata        []byte
}

// ContractGovernanceProofData matches the Solidity GovernanceProofData struct
type ContractGovernanceProofData struct {
	KeyBookURL         string
	KeyBookRoot        [32]byte
	KeyPageProofs      [][32]byte
	AuthorityAddress   common.Address
	AuthorityLevel     uint8
	Nonce              *big.Int
	RequiredSignatures *big.Int
	ProvidedSignatures *big.Int
	ThresholdMet       bool
}

// ContractBLSProofData matches the Solidity BLSProofData struct
type ContractBLSProofData struct {
	AggregateSignature []byte
	ValidatorAddresses []common.Address
	VotingPowers       []*big.Int
	TotalVotingPower   *big.Int
	SignedVotingPower  *big.Int
	ThresholdMet       bool
	MessageHash        [32]byte
}

// ContractCommitmentData matches the Solidity CommitmentData struct
type ContractCommitmentData struct {
	OperationCommitment  [32]byte
	CrossChainCommitment [32]byte
	GovernanceRoot       [32]byte
	SourceChain          string
	SourceBlockHeight    *big.Int
	SourceTxHash         [32]byte
	TargetChain          string
	TargetAddress        common.Address
}

// =============================================================================
// ProofBundle Methods
// =============================================================================

// NewProofBundle creates a new ProofBundle with default values
func NewProofBundle(batchID, validatorID string) *ProofBundle {
	return &ProofBundle{
		BundleID:       GenerateBundleID(batchID, time.Now().Unix()),
		BatchID:        batchID,
		ValidatorID:    validatorID,
		Timestamp:      time.Now(),
		SourceChain:    "accumulate",
		TargetChain:    "ethereum",
		ExpirationTime: time.Now().Add(24 * time.Hour), // Default 24h expiration
		BLSProof:       &BLSProofData{},
		GovernanceProof: &GovernanceProofData{
			Nonce:              big.NewInt(0),
			RequiredSignatures: big.NewInt(1),
			ProvidedSignatures: big.NewInt(1),
		},
	}
}

// Validate ensures all required proof data is properly populated.
// Returns an error describing what is missing or invalid.
func (b *ProofBundle) Validate() error {
	if b == nil {
		return errors.New("proof bundle is nil")
	}

	// Validate core identification
	if b.BundleID == "" {
		return errors.New("bundle_id is required")
	}
	if b.BatchID == "" {
		return errors.New("batch_id is required")
	}
	if b.ValidatorID == "" {
		return errors.New("validator_id is required")
	}

	// Validate commitments are not zero (cryptographic binding requirement)
	if b.OperationCommitment == [32]byte{} {
		return errors.New("operation_commitment is required (32 bytes)")
	}
	if b.CrossChainCommitment == [32]byte{} {
		return errors.New("cross_chain_commitment is required (32 bytes)")
	}
	if b.GovernanceRoot == [32]byte{} {
		return errors.New("governance_root is required (32 bytes)")
	}

	// Validate Merkle proof
	if b.MerkleRoot == [32]byte{} {
		return errors.New("merkle_root is required (32 bytes)")
	}
	if b.LeafHash == [32]byte{} {
		return errors.New("leaf_hash is required (32 bytes)")
	}

	// Validate BLS proof
	if b.BLSProof == nil {
		return errors.New("bls_proof is required")
	}
	if len(b.BLSProof.AggregateSignature) == 0 {
		return errors.New("bls_proof.aggregate_signature is required")
	}
	if b.BLSProof.TotalVotingPower == nil || b.BLSProof.TotalVotingPower.Sign() <= 0 {
		return errors.New("bls_proof.total_voting_power must be positive")
	}
	if b.BLSProof.SignedVotingPower == nil || b.BLSProof.SignedVotingPower.Sign() <= 0 {
		return errors.New("bls_proof.signed_voting_power must be positive")
	}

	// Validate governance proof
	if b.GovernanceProof == nil {
		return errors.New("governance_proof is required")
	}
	if b.GovernanceProof.RequiredSignatures == nil {
		return errors.New("governance_proof.required_signatures is required")
	}
	if b.GovernanceProof.ProvidedSignatures == nil {
		return errors.New("governance_proof.provided_signatures is required")
	}

	// Validate expiration
	if b.ExpirationTime.Before(time.Now()) {
		return errors.New("proof has expired")
	}

	return nil
}

// ToContractProof converts the ProofBundle to the contract-compatible struct format.
// This is the primary method for preparing proof data for contract submission.
func (b *ProofBundle) ToContractProof() *ContractCertenProof {
	if b == nil {
		return nil
	}

	// Convert BLS proof
	blsProof := ContractBLSProofData{
		ThresholdMet: false,
	}
	if b.BLSProof != nil {
		blsProof = ContractBLSProofData{
			AggregateSignature: b.BLSProof.AggregateSignature,
			ValidatorAddresses: b.BLSProof.ValidatorAddresses,
			VotingPowers:       b.BLSProof.VotingPowers,
			TotalVotingPower:   b.BLSProof.TotalVotingPower,
			SignedVotingPower:  b.BLSProof.SignedVotingPower,
			ThresholdMet:       b.BLSProof.ThresholdMet,
			MessageHash:        b.BLSProof.MessageHash,
		}
		// Ensure non-nil slices
		if blsProof.ValidatorAddresses == nil {
			blsProof.ValidatorAddresses = []common.Address{}
		}
		if blsProof.VotingPowers == nil {
			blsProof.VotingPowers = []*big.Int{}
		}
		if blsProof.TotalVotingPower == nil {
			blsProof.TotalVotingPower = big.NewInt(0)
		}
		if blsProof.SignedVotingPower == nil {
			blsProof.SignedVotingPower = big.NewInt(0)
		}
	}

	// Convert governance proof
	govProof := ContractGovernanceProofData{
		Nonce:              big.NewInt(0),
		RequiredSignatures: big.NewInt(1),
		ProvidedSignatures: big.NewInt(1),
		ThresholdMet:       true,
	}
	if b.GovernanceProof != nil {
		govProof = ContractGovernanceProofData{
			KeyBookURL:         b.GovernanceProof.KeyBookURL,
			KeyBookRoot:        b.GovernanceProof.KeyBookRoot,
			KeyPageProofs:      b.GovernanceProof.KeyPageProofs,
			AuthorityAddress:   b.GovernanceProof.AuthorityAddress,
			AuthorityLevel:     b.GovernanceProof.AuthorityLevel,
			Nonce:              b.GovernanceProof.Nonce,
			RequiredSignatures: b.GovernanceProof.RequiredSignatures,
			ProvidedSignatures: b.GovernanceProof.ProvidedSignatures,
			ThresholdMet:       b.GovernanceProof.ThresholdMet,
		}
		// Ensure non-nil values
		if govProof.KeyPageProofs == nil {
			govProof.KeyPageProofs = [][32]byte{}
		}
		if govProof.Nonce == nil {
			govProof.Nonce = big.NewInt(0)
		}
		if govProof.RequiredSignatures == nil {
			govProof.RequiredSignatures = big.NewInt(1)
		}
		if govProof.ProvidedSignatures == nil {
			govProof.ProvidedSignatures = big.NewInt(1)
		}
	}

	// Build commitment data
	commitments := ContractCommitmentData{
		OperationCommitment:  b.OperationCommitment,
		CrossChainCommitment: b.CrossChainCommitment,
		GovernanceRoot:       b.GovernanceRoot,
		SourceChain:          b.SourceChain,
		SourceBlockHeight:    big.NewInt(int64(b.SourceBlockHeight)),
		SourceTxHash:         b.SourceTxHash,
		TargetChain:          b.TargetChain,
		TargetAddress:        b.TargetAddress,
	}

	// Ensure non-nil proof hashes
	proofHashes := b.ProofHashes
	if proofHashes == nil {
		proofHashes = [][32]byte{}
	}

	// Ensure non-nil metadata
	metadata := b.Metadata
	if metadata == nil {
		metadata = []byte{}
	}

	// CRITICAL FIX: The contract's merkleRoot is keccak256(op || cc || gov),
	// NOT the Merkle inclusion proof root. We MUST compute this to match
	// what createAnchor() stored in the contract.
	// b.MerkleRoot is the BPT/inclusion proof root - NOT what the contract expects!
	contractMerkleRoot := b.ComputeExpectedMerkleRoot()

	return &ContractCertenProof{
		TransactionHash: b.TransactionHash,
		MerkleRoot:      contractMerkleRoot, // FIXED: Use computed keccak256(op||cc||gov)
		ProofHashes:     proofHashes,
		LeafHash:        b.LeafHash,
		GovernanceProof: govProof,
		BlsProof:        blsProof,
		Commitments:     commitments,
		ExpirationTime:  big.NewInt(b.ExpirationTime.Unix()),
		Metadata:        metadata,
	}
}

// ComputeExpectedMerkleRoot computes the merkle root as the contract does:
// keccak256(operationCommitment || crossChainCommitment || governanceRoot)
// This can be used to verify the contract will compute the expected value.
// Per Phase 5 Task 5.4: Uses REAL Keccak256 (not a placeholder)
func (b *ProofBundle) ComputeExpectedMerkleRoot() [32]byte {
	// Match Solidity: keccak256(abi.encodePacked(op, cc, gov))
	data := make([]byte, 96) // 32 + 32 + 32
	copy(data[0:32], b.OperationCommitment[:])
	copy(data[32:64], b.CrossChainCommitment[:])
	copy(data[64:96], b.GovernanceRoot[:])

	// Use real Keccak256 from go-ethereum/crypto (defined in anchor_manager.go)
	return Keccak256(data)
}

// SetCommitments sets the three canonical commitments
func (b *ProofBundle) SetCommitments(op, cc, gov [32]byte) {
	b.OperationCommitment = op
	b.CrossChainCommitment = cc
	b.GovernanceRoot = gov
}

// SetMerkleProof sets the Merkle inclusion proof data
func (b *ProofBundle) SetMerkleProof(root [32]byte, leafHash [32]byte, path [][32]byte) {
	b.MerkleRoot = root
	b.LeafHash = leafHash
	b.ProofHashes = path
}

// SetBLSProof sets the BLS aggregate signature proof
func (b *ProofBundle) SetBLSProof(
	signature []byte,
	validators []common.Address,
	powers []*big.Int,
	totalPower *big.Int,
	signedPower *big.Int,
	messageHash [32]byte,
) {
	// Calculate if threshold met (2/3+ required)
	thresholdMet := false
	if totalPower != nil && totalPower.Sign() > 0 && signedPower != nil {
		// 2/3 threshold: signedPower * 3 >= totalPower * 2
		signedTimes3 := new(big.Int).Mul(signedPower, big.NewInt(3))
		totalTimes2 := new(big.Int).Mul(totalPower, big.NewInt(2))
		thresholdMet = signedTimes3.Cmp(totalTimes2) >= 0
	}

	b.BLSProof = &BLSProofData{
		AggregateSignature: signature,
		ValidatorAddresses: validators,
		VotingPowers:       powers,
		TotalVotingPower:   totalPower,
		SignedVotingPower:  signedPower,
		ThresholdMet:       thresholdMet,
		MessageHash:        messageHash,
	}
}

// SetGovernanceProof sets the governance authorization proof
func (b *ProofBundle) SetGovernanceProof(
	keyBookURL string,
	keyBookRoot [32]byte,
	keyPageProofs [][32]byte,
	authorityAddr common.Address,
	level uint8,
	nonce *big.Int,
	required *big.Int,
	provided *big.Int,
) {
	thresholdMet := false
	if required != nil && provided != nil {
		thresholdMet = provided.Cmp(required) >= 0
	}

	b.GovernanceProof = &GovernanceProofData{
		KeyBookURL:         keyBookURL,
		KeyBookRoot:        keyBookRoot,
		KeyPageProofs:      keyPageProofs,
		AuthorityAddress:   authorityAddr,
		AuthorityLevel:     level,
		Nonce:              nonce,
		RequiredSignatures: required,
		ProvidedSignatures: provided,
		ThresholdMet:       thresholdMet,
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

// GenerateBundleID creates a unique bundle ID using SHA256 hash of batchID and timestamp.
// This prevents collision by including timestamp in the hash.
func GenerateBundleID(batchID string, timestamp int64) string {
	data := make([]byte, 0, len(batchID)+8)
	data = append(data, []byte(batchID)...)
	data = binary.BigEndian.AppendUint64(data, uint64(timestamp))
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// GenerateBundleIDBytes32 creates a bytes32 bundle ID for contract calls
func GenerateBundleIDBytes32(batchID string, timestamp int64) [32]byte {
	data := make([]byte, 0, len(batchID)+8)
	data = append(data, []byte(batchID)...)
	data = binary.BigEndian.AppendUint64(data, uint64(timestamp))
	return sha256.Sum256(data)
}

// NOTE: Keccak256Hash is defined in anchor_manager.go using go-ethereum's crypto.Keccak256
// Per Phase 5 Task 5.4: Removed placeholder implementation, using real Keccak256

// HexToBytes32 converts a hex string to [32]byte
func HexToBytes32(hexStr string) ([32]byte, error) {
	var result [32]byte

	// Remove 0x prefix if present
	if len(hexStr) >= 2 && hexStr[:2] == "0x" {
		hexStr = hexStr[2:]
	}

	if len(hexStr) != 64 {
		return result, fmt.Errorf("hex string must be 64 characters, got %d", len(hexStr))
	}

	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return result, fmt.Errorf("invalid hex string: %w", err)
	}

	copy(result[:], decoded)
	return result, nil
}

// Bytes32ToHex converts [32]byte to hex string with 0x prefix
func Bytes32ToHex(b [32]byte) string {
	return "0x" + hex.EncodeToString(b[:])
}

// =============================================================================
// ProofBundle Builder Pattern
// =============================================================================

// ProofBundleBuilder provides a fluent API for building ProofBundles
type ProofBundleBuilder struct {
	bundle *ProofBundle
}

// NewProofBundleBuilder creates a new builder
func NewProofBundleBuilder(batchID, validatorID string) *ProofBundleBuilder {
	return &ProofBundleBuilder{
		bundle: NewProofBundle(batchID, validatorID),
	}
}

// WithTransactionHash sets the transaction hash
func (pb *ProofBundleBuilder) WithTransactionHash(hash [32]byte) *ProofBundleBuilder {
	pb.bundle.TransactionHash = hash
	return pb
}

// WithMerkleProof sets the Merkle proof data
func (pb *ProofBundleBuilder) WithMerkleProof(root, leaf [32]byte, path [][32]byte) *ProofBundleBuilder {
	pb.bundle.SetMerkleProof(root, leaf, path)
	return pb
}

// WithCommitments sets the three canonical commitments
func (pb *ProofBundleBuilder) WithCommitments(op, cc, gov [32]byte) *ProofBundleBuilder {
	pb.bundle.SetCommitments(op, cc, gov)
	return pb
}

// WithSourceInfo sets source chain information
func (pb *ProofBundleBuilder) WithSourceInfo(chain string, height uint64, txHash [32]byte) *ProofBundleBuilder {
	pb.bundle.SourceChain = chain
	pb.bundle.SourceBlockHeight = height
	pb.bundle.SourceTxHash = txHash
	return pb
}

// WithTargetInfo sets target chain information
func (pb *ProofBundleBuilder) WithTargetInfo(chain string, addr common.Address) *ProofBundleBuilder {
	pb.bundle.TargetChain = chain
	pb.bundle.TargetAddress = addr
	return pb
}

// WithExpiration sets the proof expiration time
func (pb *ProofBundleBuilder) WithExpiration(t time.Time) *ProofBundleBuilder {
	pb.bundle.ExpirationTime = t
	return pb
}

// WithMetadata sets optional metadata
func (pb *ProofBundleBuilder) WithMetadata(data []byte) *ProofBundleBuilder {
	pb.bundle.Metadata = data
	return pb
}

// Build validates and returns the ProofBundle
func (pb *ProofBundleBuilder) Build() (*ProofBundle, error) {
	if err := pb.bundle.Validate(); err != nil {
		return nil, fmt.Errorf("proof bundle validation failed: %w", err)
	}
	return pb.bundle, nil
}

// BuildUnsafe returns the ProofBundle without validation (for testing)
func (pb *ProofBundleBuilder) BuildUnsafe() *ProofBundle {
	return pb.bundle
}
