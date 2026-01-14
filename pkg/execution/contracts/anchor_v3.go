// Copyright 2025 Certen Protocol
//
// CertenAnchorV3 Go Bindings - Unified Anchor Contract
// Per Gap Analysis Step 4: Consolidates all features from Creation + Verification V2
//
// This file provides wrapper types and convenience functions for the abigen-generated bindings.
// The actual bindings are in anchor_v3_generated.go
//
// Generated from CertenAnchorV3.sol using:
//   1. Compile: npx hardhat compile
//   2. Generate: abigen --abi CertenAnchorV3.abi --bin CertenAnchorV3.bin --pkg contracts --type CertenAnchorV3 --out anchor_v3_generated.go

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
// TYPE ALIASES - Map to generated types for backward compatibility
// =============================================================================

// CertenProofV3 is the unified proof structure for V3 contract
// Alias to the abigen-generated type for backward compatibility
type CertenProofV3 = CertenAnchorV3CertenProof

// GovernanceProofV3 contains governance authorization data
type GovernanceProofV3 = CertenAnchorV3GovernanceProofData

// BLSProofV3 contains BLS aggregated signature data
type BLSProofV3 = CertenAnchorV3BLSProofData

// CommitmentV3 contains cross-chain commitment information
type CommitmentV3 = CertenAnchorV3CommitmentData

// =============================================================================
// EXTENDED ANCHOR TYPES - Additional fields beyond generated types
// =============================================================================

// AnchorV3 represents stored anchor data from the V3 contract
// Extended version with additional helper fields
type AnchorV3 struct {
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

// VerificationResultV3 contains detailed verification results
type VerificationResultV3 struct {
	MerkleVerified     bool `json:"merkleVerified"`
	GovernanceVerified bool `json:"governanceVerified"`
	BLSVerified        bool `json:"blsVerified"`
	CommitmentVerified bool `json:"commitmentVerified"`
	TimestampValid     bool `json:"timestampValid"`
	NonceValid         bool `json:"nonceValid"`
}

// ValidatorInfoV3 contains validator registration info
type ValidatorInfoV3 struct {
	Registered   bool     `json:"registered"`
	VotingPower  *big.Int `json:"votingPower"`
	BLSPublicKey []byte   `json:"blsPublicKey"`
	RegisteredAt *big.Int `json:"registeredAt"`
}

// =============================================================================
// V3 CONTRACT WRAPPER - Provides convenience methods over generated bindings
// =============================================================================

// CertenAnchorV3Wrapper wraps the generated CertenAnchorV3 with additional convenience methods
type CertenAnchorV3Wrapper struct {
	*CertenAnchorV3
	address common.Address
}

// NewCertenAnchorV3Wrapper creates a new V3 contract wrapper instance
func NewCertenAnchorV3Wrapper(address common.Address, backend bind.ContractBackend) (*CertenAnchorV3Wrapper, error) {
	contract, err := NewCertenAnchorV3(address, backend)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV3Wrapper{
		CertenAnchorV3: contract,
		address:        address,
	}, nil
}

// GetAddress returns the contract address
func (w *CertenAnchorV3Wrapper) GetAddress() common.Address {
	return w.address
}

// =============================================================================
// CONVENIENCE METHODS - Simplified interface for common operations
// =============================================================================

// CreateAnchorSimple creates a new anchor using direct parameters (simplified interface)
func (w *CertenAnchorV3Wrapper) CreateAnchorSimple(
	opts *bind.TransactOpts,
	bundleId [32]byte,
	operationCommitment [32]byte,
	crossChainCommitment [32]byte,
	governanceRoot [32]byte,
	accumulateBlockHeight *big.Int,
) (*types.Transaction, error) {
	return w.CertenAnchorV3Transactor.CreateAnchor(opts, bundleId, operationCommitment, crossChainCommitment, governanceRoot, accumulateBlockHeight)
}

// ExecuteComprehensiveProofSimple executes comprehensive proof verification
func (w *CertenAnchorV3Wrapper) ExecuteComprehensiveProofSimple(
	opts *bind.TransactOpts,
	anchorId [32]byte,
	proof CertenProofV3,
) (*types.Transaction, error) {
	return w.CertenAnchorV3Transactor.ExecuteComprehensiveProof(opts, anchorId, proof)
}

// ExecuteWithGovernanceSimple executes governance-authorized operation on target
// Per Gap Analysis: This is the MISSING step after executeComprehensiveProof
// REQUIRES: anchor.proofExecuted == true, caller must be operator
// EXECUTES: target.call{value: value}(data)
// EMITS: GovernanceExecuted(anchorId, target, value, success, timestamp)
func (w *CertenAnchorV3Wrapper) ExecuteWithGovernanceSimple(
	opts *bind.TransactOpts,
	anchorId [32]byte,
	target common.Address,
	value *big.Int,
	data []byte,
) (*types.Transaction, error) {
	return w.CertenAnchorV3Transactor.ExecuteWithGovernance(opts, anchorId, target, value, data)
}

// GetAnchorFull retrieves full anchor data as AnchorV3 struct
func (w *CertenAnchorV3Wrapper) GetAnchorFull(opts *bind.CallOpts, anchorId [32]byte) (*AnchorV3, error) {
	result, err := w.CertenAnchorV3Caller.Anchors(opts, anchorId)
	if err != nil {
		return nil, err
	}
	return &AnchorV3{
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

// GetValidatorInfo retrieves validator information as ValidatorInfoV3
func (w *CertenAnchorV3Wrapper) GetValidatorInfo(opts *bind.CallOpts, validator common.Address) (*ValidatorInfoV3, error) {
	registered, votingPower, err := w.CertenAnchorV3Caller.GetBLSValidatorInfo(opts, validator)
	if err != nil {
		return nil, err
	}
	return &ValidatorInfoV3{
		Registered:  registered,
		VotingPower: votingPower,
	}, nil
}

// VerifyProofDetailed returns detailed verification results as VerificationResultV3
func (w *CertenAnchorV3Wrapper) VerifyProofDetailed(
	opts *bind.CallOpts,
	anchorId [32]byte,
	proof CertenProofV3,
) (*VerificationResultV3, error) {
	result, err := w.CertenAnchorV3Caller.VerifyCertenProofDetailed(opts, anchorId, proof)
	if err != nil {
		return nil, err
	}
	return &VerificationResultV3{
		MerkleVerified:     result[0],
		GovernanceVerified: result[1],
		BLSVerified:        result[2],
		CommitmentVerified: result[3],
		TimestampValid:     result[4],
		NonceValid:         result[5],
	}, nil
}

// GetThresholdInfo returns BLS threshold configuration
func (w *CertenAnchorV3Wrapper) GetThresholdInfo(opts *bind.CallOpts) (numerator, denominator, totalPower *big.Int, err error) {
	return w.CertenAnchorV3Caller.GetBLSThresholdInfo(opts)
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

// BuildCertenProofV3 creates a CertenProofV3 from components
func BuildCertenProofV3(
	txHash [32]byte,
	merkleRoot [32]byte,
	proofHashes [][32]byte,
	leafHash [32]byte,
	govProof GovernanceProofV3,
	blsProof BLSProofV3,
	commitments CommitmentV3,
	expirationTime *big.Int,
	metadata []byte,
) CertenProofV3 {
	return CertenProofV3{
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
) GovernanceProofV3 {
	return GovernanceProofV3{
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
) BLSProofV3 {
	totalPower := big.NewInt(0)
	for _, power := range votingPowers {
		totalPower.Add(totalPower, power)
	}
	return BLSProofV3{
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
) CommitmentV3 {
	return CommitmentV3{
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

// ConvertFromExtended converts ComprehensiveCertenProof to CertenProofV3
// Compatibility shim for existing code
func ConvertFromExtended(proof ComprehensiveCertenProof) CertenProofV3 {
	return CertenProofV3{
		TransactionHash: proof.TransactionHash,
		MerkleRoot:      proof.MerkleRoot,
		ProofHashes:     proof.ProofHashes,
		LeafHash:        proof.LeafHash,
		GovernanceProof: GovernanceProofV3{
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
		BlsProof: BLSProofV3{
			AggregateSignature: proof.BLSProof.AggregateSignature,
			ValidatorAddresses: proof.BLSProof.ValidatorAddresses,
			VotingPowers:       proof.BLSProof.VotingPowers,
			TotalVotingPower:   proof.BLSProof.TotalVotingPower,
			SignedVotingPower:  proof.BLSProof.SignedVotingPower,
			ThresholdMet:       proof.BLSProof.ThresholdMet,
			MessageHash:        proof.BLSProof.MessageHash,
		},
		Commitments: CommitmentV3{
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
