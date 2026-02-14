// Copyright 2025 Certen Protocol
//
// CertenAnchorV4 Go Bindings - Unified Anchor Contract
// Per Gap Analysis Step 4: Consolidates all features from Creation + Verification
//
// This file provides wrapper types and convenience functions for the abigen-generated bindings.
// The actual bindings are in anchor_v4_generated.go
//
// Generated from CertenAnchorV4.sol using:
//   1. Compile: npx hardhat compile
//   2. Generate: abigen --abi CertenAnchorV4.abi --bin CertenAnchorV4.bin --pkg contracts --type CertenAnchorV4 --out anchor_v4_generated.go

package contracts

import (
	"context"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// =============================================================================
// TYPE ALIASES - Map to generated types
// =============================================================================

// CertenProof is the unified proof structure
type CertenProof = CertenAnchorV4CertenProof

// GovernanceProof contains governance authorization data
type GovernanceProof = CertenAnchorV4GovernanceProofData

// BLSProof contains BLS aggregated signature data
type BLSProof = CertenAnchorV4BLSProofData

// Commitment contains cross-chain commitment information
type Commitment = CertenAnchorV4CommitmentData

// =============================================================================
// EXTENDED ANCHOR TYPES - Additional fields beyond generated types
// =============================================================================

// Anchor represents stored anchor data from the V4 contract
type Anchor struct {
	BundleId              [32]byte       `json:"bundleId"`
	MerkleRoot            [32]byte       `json:"merkleRoot"`
	OperationCommitment   [32]byte       `json:"operationCommitment"`
	CrossChainCommitment  [32]byte       `json:"crossChainCommitment"`
	GovernanceRoot        [32]byte       `json:"governanceRoot"`
	AccumulateBlockHeight *big.Int       `json:"accumulateBlockHeight"`
	Timestamp             *big.Int       `json:"timestamp"`
	Validator             common.Address `json:"validator"`
	Valid                 bool           `json:"valid"`
	ProofExecuted         bool           `json:"proofExecuted"`
}

// VerificationResult contains detailed verification results
type VerificationResult struct {
	MerkleVerified     bool `json:"merkleVerified"`
	GovernanceVerified bool `json:"governanceVerified"`
	BLSVerified        bool `json:"blsVerified"`
	CommitmentVerified bool `json:"commitmentVerified"`
	TimestampValid     bool `json:"timestampValid"`
	NonceValid         bool `json:"nonceValid"`
}

// ValidatorInfo contains validator registration info
type ValidatorInfo struct {
	Registered   bool     `json:"registered"`
	VotingPower  *big.Int `json:"votingPower"`
	BLSPublicKey []byte   `json:"blsPublicKey"`
	RegisteredAt *big.Int `json:"registeredAt"`
}

// =============================================================================
// V4 CONTRACT WRAPPER - Provides convenience methods over generated bindings
// =============================================================================

// CertenAnchorWrapper wraps the generated CertenAnchorV4 with additional convenience methods
type CertenAnchorWrapper struct {
	*CertenAnchorV4
	address common.Address
}

// NewCertenAnchorWrapper creates a new V4 contract wrapper instance
func NewCertenAnchorWrapper(address common.Address, backend bind.ContractBackend) (*CertenAnchorWrapper, error) {
	contract, err := NewCertenAnchorV4(address, backend)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorWrapper{
		CertenAnchorV4: contract,
		address:        address,
	}, nil
}

// GetAddress returns the contract address
func (w *CertenAnchorWrapper) GetAddress() common.Address {
	return w.address
}

// =============================================================================
// CONVENIENCE METHODS - Simplified interface for common operations
// =============================================================================

// CreateAnchorSimple creates a new anchor using direct parameters (simplified interface)
// V4 UPDATE: Now requires adiURLHash to bind anchor to specific Accumulate data account
func (w *CertenAnchorWrapper) CreateAnchorSimple(
	opts *bind.TransactOpts,
	bundleId [32]byte,
	adiURLHash [32]byte,
	operationCommitment [32]byte,
	crossChainCommitment [32]byte,
	governanceRoot [32]byte,
	accumulateBlockHeight *big.Int,
) (*types.Transaction, error) {
	return w.CertenAnchorV4Transactor.CreateAnchor(opts, bundleId, adiURLHash, operationCommitment, crossChainCommitment, governanceRoot, accumulateBlockHeight)
}

// ExecuteComprehensiveProofSimple executes comprehensive proof verification
func (w *CertenAnchorWrapper) ExecuteComprehensiveProofSimple(
	opts *bind.TransactOpts,
	anchorId [32]byte,
	proof CertenProof,
) (*types.Transaction, error) {
	return w.CertenAnchorV4Transactor.ExecuteComprehensiveProof(opts, anchorId, proof)
}

// ExecuteWithGovernanceSimple executes governance-authorized operation on target
// Per Gap Analysis: This is the MISSING step after executeComprehensiveProof
// REQUIRES: anchor.proofExecuted == true, caller must be operator
// EXECUTES: target.call{value: value}(data)
// EMITS: GovernanceExecuted(anchorId, target, value, success, timestamp)
func (w *CertenAnchorWrapper) ExecuteWithGovernanceSimple(
	opts *bind.TransactOpts,
	anchorId [32]byte,
	target common.Address,
	value *big.Int,
	data []byte,
) (*types.Transaction, error) {
	return w.CertenAnchorV4Transactor.ExecuteWithGovernance(opts, anchorId, target, value, data)
}

// GetAnchorFull retrieves full anchor data as Anchor struct
func (w *CertenAnchorWrapper) GetAnchorFull(opts *bind.CallOpts, anchorId [32]byte) (*Anchor, error) {
	result, err := w.CertenAnchorV4Caller.Anchors(opts, anchorId)
	if err != nil {
		return nil, err
	}
	return &Anchor{
		BundleId:              result.BundleId,
		MerkleRoot:            result.MerkleRoot,
		OperationCommitment:   result.OperationCommitment,
		CrossChainCommitment:  result.CrossChainCommitment,
		GovernanceRoot:        result.GovernanceRoot,
		AccumulateBlockHeight: result.AccumulateBlockHeight,
		Timestamp:             result.Timestamp,
		Validator:             result.Validator,
		Valid:                 result.Valid,
		ProofExecuted:         result.ProofExecuted,
	}, nil
}

// GetValidatorInfo retrieves validator information as ValidatorInfo
func (w *CertenAnchorWrapper) GetValidatorInfo(opts *bind.CallOpts, validator common.Address) (*ValidatorInfo, error) {
	registered, votingPower, err := w.CertenAnchorV4Caller.GetBLSValidatorInfo(opts, validator)
	if err != nil {
		return nil, err
	}
	return &ValidatorInfo{
		Registered:  registered,
		VotingPower: votingPower,
	}, nil
}

// VerifyMerkleProof verifies a merkle proof against the anchor
func (w *CertenAnchorWrapper) VerifyMerkleProof(
	opts *bind.CallOpts,
	anchorId [32]byte,
	merkleProof [][32]byte,
	leaf [32]byte,
) (bool, error) {
	return w.CertenAnchorV4Caller.VerifyProof(opts, anchorId, merkleProof, leaf)
}

// VerifyBLSSignature verifies a BLS signature
func (w *CertenAnchorWrapper) VerifyBLSSignature(
	opts *bind.CallOpts,
	signature []byte,
	messageHash [32]byte,
) (bool, error) {
	return w.CertenAnchorV4Caller.VerifyBLSSignature(opts, signature, messageHash)
}

// GetThresholdInfo returns BLS threshold configuration
func (w *CertenAnchorWrapper) GetThresholdInfo(opts *bind.CallOpts) (numerator, denominator, totalPower *big.Int, err error) {
	return w.CertenAnchorV4Caller.GetBLSThresholdInfo(opts)
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// WaitForConfirmation waits for a transaction to be confirmed
func WaitForConfirmation(
	ctx context.Context,
	tx *types.Transaction,
	client bind.DeployBackend,
) (*types.Receipt, error) {
	return bind.WaitMined(ctx, client, tx)
}

// BuildCertenProof creates a CertenProof from components
func BuildCertenProof(
	txHash [32]byte,
	merkleRoot [32]byte,
	proofHashes [][32]byte,
	leafHash [32]byte,
	govProof GovernanceProof,
	blsProof BLSProof,
	commitments Commitment,
	expirationTime *big.Int,
	metadata []byte,
) CertenProof {
	return CertenProof{
		TransactionHash: txHash,
		MerkleRoot:      merkleRoot,
		ProofHashes:     proofHashes,
		LeafHash:        leafHash,
		GovernanceProof: govProof,
		BlsProof:        blsProof,
		Commitments:     commitments,
		ExpirationTime:  expirationTime,
		Metadata:        metadata,
	}
}

// BuildDefaultGovernanceProof creates a governance proof with sensible defaults
func BuildDefaultGovernanceProof(
	keyBookURL string,
	keyBookRoot [32]byte,
	authorityAddress common.Address,
	nonce *big.Int,
) GovernanceProof {
	return GovernanceProof{
		KeyBookURL:         keyBookURL,
		KeyBookRoot:        keyBookRoot,
		KeyPageProofs:      [][32]byte{},
		AuthorityAddress:   authorityAddress,
		AuthorityLevel:     0,
		Nonce:              nonce,
		RequiredSignatures: big.NewInt(1),
		ProvidedSignatures: big.NewInt(1),
		ThresholdMet:       true,
	}
}

// BuildDefaultBLSProof creates a BLS proof with sensible defaults
func BuildDefaultBLSProof(
	aggregateSignature []byte,
	validatorAddresses []common.Address,
	votingPowers []*big.Int,
	messageHash [32]byte,
) BLSProof {
	totalPower := big.NewInt(0)
	for _, power := range votingPowers {
		totalPower.Add(totalPower, power)
	}
	return BLSProof{
		AggregateSignature: aggregateSignature,
		ValidatorAddresses: validatorAddresses,
		VotingPowers:       votingPowers,
		TotalVotingPower:   totalPower,
		SignedVotingPower:  totalPower, // All validators signed
		ThresholdMet:       true,
		MessageHash:        messageHash,
	}
}

// BuildDefaultCommitment creates a commitment with sensible defaults
func BuildDefaultCommitment(
	operationCommitment [32]byte,
	crossChainCommitment [32]byte,
	governanceRoot [32]byte,
	sourceBlockHeight *big.Int,
	sourceTxHash [32]byte,
	targetAddress common.Address,
) Commitment {
	return Commitment{
		OperationCommitment:  operationCommitment,
		CrossChainCommitment: crossChainCommitment,
		GovernanceRoot:       governanceRoot,
		SourceChain:          "accumulate",
		SourceBlockHeight:    sourceBlockHeight,
		SourceTxHash:         sourceTxHash,
		TargetChain:          "ethereum",
		TargetAddress:        targetAddress,
	}
}

// DefaultExpirationTime returns expiration time 1 hour from now
func DefaultExpirationTime() *big.Int {
	return big.NewInt(time.Now().Add(time.Hour).Unix())
}

// ConvertFromExtended converts ComprehensiveCertenProof to CertenProof
func ConvertFromExtended(proof ComprehensiveCertenProof) CertenProof {
	return CertenProof{
		TransactionHash: proof.TransactionHash,
		MerkleRoot:      proof.MerkleRoot,
		ProofHashes:     proof.ProofHashes,
		LeafHash:        proof.LeafHash,
		GovernanceProof: GovernanceProof{
			KeyBookURL:         proof.GovernanceProof.KeyBookURL,
			KeyBookRoot:        proof.GovernanceProof.KeyBookRoot,
			KeyPageProofs:      proof.GovernanceProof.KeyPageProofs,
			AuthorityAddress:   proof.GovernanceProof.AuthorityAddress,
			AuthorityLevel:     proof.GovernanceProof.AuthorityLevel,
			Nonce:              proof.GovernanceProof.Nonce,
			RequiredSignatures: proof.GovernanceProof.RequiredSignatures,
			ProvidedSignatures: proof.GovernanceProof.ProvidedSignatures,
			ThresholdMet:       proof.GovernanceProof.ThresholdMet,
		},
		BlsProof: BLSProof{
			AggregateSignature: proof.BLSProof.AggregateSignature,
			ValidatorAddresses: proof.BLSProof.ValidatorAddresses,
			VotingPowers:       proof.BLSProof.VotingPowers,
			TotalVotingPower:   proof.BLSProof.TotalVotingPower,
			SignedVotingPower:  proof.BLSProof.SignedVotingPower,
			ThresholdMet:       proof.BLSProof.ThresholdMet,
			MessageHash:        proof.BLSProof.MessageHash,
			PubkeyCommitment:   proof.BLSProof.PubkeyCommitment,
		},
		Commitments: Commitment{
			OperationCommitment:  proof.Commitments.OperationCommitment,
			CrossChainCommitment: proof.Commitments.CrossChainCommitment,
			GovernanceRoot:       proof.Commitments.GovernanceRoot,
			SourceChain:          proof.Commitments.SourceChain,
			SourceBlockHeight:    proof.Commitments.SourceBlockHeight,
			SourceTxHash:         proof.Commitments.SourceTxHash,
			TargetChain:          proof.Commitments.TargetChain,
			TargetAddress:        proof.Commitments.TargetAddress,
		},
		ExpirationTime: proof.ExpirationTime,
		Metadata:       proof.Metadata,
	}
}
