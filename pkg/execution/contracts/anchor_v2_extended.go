// Copyright 2025 Certen Protocol
//
// Extended CertenAnchorV2 bindings with all contract functions
// This file supplements anchor_v2.go with missing functions from the deployed contract

package contracts

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// =============================================================================
// Extended Proof Structures matching deployed Solidity contract
// =============================================================================

// ComprehensiveCertenProof is the full proof structure expected by executeComprehensiveProof
// This matches the Solidity CertenProof struct in the deployed contract
type ComprehensiveCertenProof struct {
	// Core transaction identification
	TransactionHash [32]byte `json:"transactionHash"`
	MerkleRoot      [32]byte `json:"merkleRoot"`

	// Merkle proof path
	ProofHashes [][32]byte `json:"proofHashes"`
	LeafHash    [32]byte   `json:"leafHash"`

	// Governance proof data
	GovernanceProof GovernanceProofData `json:"governanceProof"`

	// BLS signature data
	BLSProof BLSProofData `json:"blsProof"`

	// Commitment data for cross-chain verification
	Commitments CommitmentData `json:"commitments"`

	// Timing and metadata
	ExpirationTime *big.Int `json:"expirationTime"`
	Metadata       []byte   `json:"metadata"`
}

// GovernanceProofData contains governance authorization data
type GovernanceProofData struct {
	// Key book hierarchy
	KeyBookURL  string   `json:"keyBookURL"`
	KeyBookRoot [32]byte `json:"keyBookRoot"`

	// Key page proofs
	KeyPageProofs [][32]byte `json:"keyPageProofs"`

	// Authorization tracking
	AuthorityAddress common.Address `json:"authorityAddress"`
	AuthorityLevel   uint8          `json:"authorityLevel"`
	Nonce            *big.Int       `json:"nonce"`

	// Threshold requirements
	RequiredSignatures *big.Int `json:"requiredSignatures"`
	ProvidedSignatures *big.Int `json:"providedSignatures"`
	ThresholdMet       bool     `json:"thresholdMet"`
}

// BLSProofData contains BLS aggregated signature data
type BLSProofData struct {
	// Aggregated BLS signature
	AggregateSignature []byte `json:"aggregateSignature"`

	// Validator information
	ValidatorAddresses []common.Address `json:"validatorAddresses"`
	VotingPowers       []*big.Int       `json:"votingPowers"`

	// Threshold tracking
	TotalVotingPower  *big.Int `json:"totalVotingPower"`
	SignedVotingPower *big.Int `json:"signedVotingPower"`
	ThresholdMet      bool     `json:"thresholdMet"`

	// Message that was signed
	MessageHash [32]byte `json:"messageHash"`
}

// CommitmentData contains cross-chain commitment information
type CommitmentData struct {
	// Operation commitment (from intent 4-blob hash)
	OperationCommitment [32]byte `json:"operationCommitment"`

	// Cross-chain commitment (from BPT root)
	CrossChainCommitment [32]byte `json:"crossChainCommitment"`

	// Governance root (from BLS aggregate)
	GovernanceRoot [32]byte `json:"governanceRoot"`

	// Source chain information
	SourceChain       string   `json:"sourceChain"`
	SourceBlockHeight *big.Int `json:"sourceBlockHeight"`
	SourceTxHash      [32]byte `json:"sourceTxHash"`

	// Target chain information
	TargetChain   string         `json:"targetChain"`
	TargetAddress common.Address `json:"targetAddress"`
}

// AnchorData represents stored anchor data from the contract
type AnchorData struct {
	BundleId              [32]byte       `json:"bundleId"`
	MerkleRoot            [32]byte       `json:"merkleRoot"`
	OperationCommitment   [32]byte       `json:"operationCommitment"`
	CrossChainCommitment  [32]byte       `json:"crossChainCommitment"`
	GovernanceRoot        [32]byte       `json:"governanceRoot"`
	AccumulateBlockHeight *big.Int       `json:"accumulateBlockHeight"`
	Timestamp             *big.Int       `json:"timestamp"`
	Validator             common.Address `json:"validator"`
	Valid                 bool           `json:"valid"`
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

// =============================================================================
// Extended Contract Interface
// =============================================================================

// CertenAnchorV2Extended provides access to all contract functions
type CertenAnchorV2Extended struct {
	*CertenAnchorV2
	address common.Address
	backend bind.ContractBackend
}

// NewCertenAnchorV2Extended creates an extended contract instance
func NewCertenAnchorV2Extended(address common.Address, backend bind.ContractBackend) (*CertenAnchorV2Extended, error) {
	base, err := NewCertenAnchorV2(address, backend)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV2Extended{
		CertenAnchorV2: base,
		address:        address,
		backend:        backend,
	}, nil
}

// =============================================================================
// Execute Functions (State-Modifying)
// =============================================================================

// ExecuteComprehensiveProof executes comprehensive proof verification and records on-chain
// This is the main function for submitting validated proofs to the anchor contract
func (c *CertenAnchorV2Extended) ExecuteComprehensiveProof(
	opts *bind.TransactOpts,
	anchorId [32]byte,
	proof ComprehensiveCertenProof,
) (*types.Transaction, error) {
	// Convert to legacy AnchorProof format for current contract
	// The contract accepts the simpler AnchorProof struct
	legacyProof := AnchorProof{
		TransactionHash:     proof.TransactionHash,
		MerkleRoot:          proof.MerkleRoot,
		ProofHashes:         proof.ProofHashes,
		LeafHash:            proof.LeafHash,
		ValidatorSignatures: proof.BLSProof.AggregateSignature,
		Timestamp:           proof.ExpirationTime,
	}

	// Use the raw transactor to call executeComprehensiveProof
	return c.CertenAnchorV2Transactor.contract.Transact(
		opts,
		"executeComprehensiveProof",
		anchorId,
		legacyProof,
	)
}

// CreateAnchorWithCommitments creates an anchor with the 5-parameter format
func (c *CertenAnchorV2Extended) CreateAnchorWithCommitments(
	opts *bind.TransactOpts,
	bundleId [32]byte,
	operationCommitment [32]byte,
	crossChainCommitment [32]byte,
	governanceRoot [32]byte,
	accumulateBlockHeight *big.Int,
) (*types.Transaction, error) {
	return c.CertenAnchorV2Transactor.contract.Transact(
		opts,
		"createAnchor",
		bundleId,
		operationCommitment,
		crossChainCommitment,
		governanceRoot,
		accumulateBlockHeight,
	)
}

// InvalidateAnchor marks an anchor as invalid
func (c *CertenAnchorV2Extended) InvalidateAnchor(
	opts *bind.TransactOpts,
	anchorId [32]byte,
) (*types.Transaction, error) {
	return c.CertenAnchorV2Transactor.contract.Transact(
		opts,
		"invalidateAnchor",
		anchorId,
	)
}

// =============================================================================
// Verification Functions (View)
// =============================================================================

// VerifyCertenProofDetailed returns detailed verification results
func (c *CertenAnchorV2Extended) VerifyCertenProofDetailed(
	opts *bind.CallOpts,
	anchorId [32]byte,
	proof AnchorProof,
) (VerificationResult, error) {
	var out []interface{}
	err := c.CertenAnchorV2Caller.contract.Call(opts, &out, "verifyCertenProofDetailed", anchorId, proof)
	if err != nil {
		return VerificationResult{}, err
	}

	// Parse the bool[6] result
	results := out[0].([6]bool)
	return VerificationResult{
		MerkleVerified:     results[0],
		GovernanceVerified: results[1],
		BLSVerified:        results[2],
		CommitmentVerified: results[3],
		TimestampValid:     results[4],
		NonceValid:         results[5],
	}, nil
}

// VerifyBLSSignature verifies a BLS signature against a message hash
func (c *CertenAnchorV2Extended) VerifyBLSSignature(
	opts *bind.CallOpts,
	signature []byte,
	messageHash [32]byte,
) (bool, error) {
	var out []interface{}
	err := c.CertenAnchorV2Caller.contract.Call(opts, &out, "verifyBLSSignature", signature, messageHash)
	if err != nil {
		return false, err
	}
	return out[0].(bool), nil
}

// VerifyProof verifies a Merkle proof
func (c *CertenAnchorV2Extended) VerifyProof(
	opts *bind.CallOpts,
	anchorId [32]byte,
	proof [][32]byte,
	leaf [32]byte,
) (bool, error) {
	var out []interface{}
	err := c.CertenAnchorV2Caller.contract.Call(opts, &out, "verifyProof", anchorId, proof, leaf)
	if err != nil {
		return false, err
	}
	return out[0].(bool), nil
}

// =============================================================================
// Query Functions (View)
// =============================================================================

// GetAnchor retrieves full anchor data
func (c *CertenAnchorV2Extended) GetAnchor(
	opts *bind.CallOpts,
	anchorId [32]byte,
) (AnchorData, error) {
	var out []interface{}
	err := c.CertenAnchorV2Caller.contract.Call(opts, &out, "getAnchor", anchorId)
	if err != nil {
		return AnchorData{}, err
	}

	// Parse struct fields
	return AnchorData{
		BundleId:              out[0].([32]byte),
		MerkleRoot:            out[1].([32]byte),
		OperationCommitment:   out[2].([32]byte),
		CrossChainCommitment:  out[3].([32]byte),
		GovernanceRoot:        out[4].([32]byte),
		AccumulateBlockHeight: out[5].(*big.Int),
		Timestamp:             out[6].(*big.Int),
		Validator:             out[7].(common.Address),
		Valid:                 out[8].(bool),
	}, nil
}

// AnchorExists checks if an anchor exists
func (c *CertenAnchorV2Extended) AnchorExists(
	opts *bind.CallOpts,
	anchorId [32]byte,
) (bool, error) {
	var out []interface{}
	err := c.CertenAnchorV2Caller.contract.Call(opts, &out, "anchorExists", anchorId)
	if err != nil {
		return false, err
	}
	return out[0].(bool), nil
}

// GetBLSValidatorInfo returns validator info
func (c *CertenAnchorV2Extended) GetBLSValidatorInfo(
	opts *bind.CallOpts,
	validator common.Address,
) (bool, *big.Int, error) {
	var out []interface{}
	err := c.CertenAnchorV2Caller.contract.Call(opts, &out, "getBLSValidatorInfo", validator)
	if err != nil {
		return false, nil, err
	}
	return out[0].(bool), out[1].(*big.Int), nil
}

// GetBLSThresholdInfo returns BLS threshold configuration
func (c *CertenAnchorV2Extended) GetBLSThresholdInfo(
	opts *bind.CallOpts,
) (*big.Int, *big.Int, *big.Int, error) {
	var out []interface{}
	err := c.CertenAnchorV2Caller.contract.Call(opts, &out, "getBLSThresholdInfo")
	if err != nil {
		return nil, nil, nil, err
	}
	return out[0].(*big.Int), out[1].(*big.Int), out[2].(*big.Int), nil
}

// GetVerificationStats returns verification statistics for an anchor
func (c *CertenAnchorV2Extended) GetVerificationStats(
	opts *bind.CallOpts,
	anchorId [32]byte,
) (*big.Int, *big.Int, error) {
	var out []interface{}
	err := c.CertenAnchorV2Caller.contract.Call(opts, &out, "getVerificationStats", anchorId)
	if err != nil {
		return nil, nil, err
	}
	return out[0].(*big.Int), out[1].(*big.Int), nil
}

// IsCommitmentUsed checks if a commitment has been used (anti-replay)
func (c *CertenAnchorV2Extended) IsCommitmentUsed(
	opts *bind.CallOpts,
	commitmentHash [32]byte,
) (bool, error) {
	var out []interface{}
	err := c.CertenAnchorV2Caller.contract.Call(opts, &out, "isCommitmentUsed", commitmentHash)
	if err != nil {
		return false, err
	}
	return out[0].(bool), nil
}

// IsNonceUsed checks if a governance nonce has been used
func (c *CertenAnchorV2Extended) IsNonceUsed(
	opts *bind.CallOpts,
	authority common.Address,
	nonce *big.Int,
) (bool, error) {
	var out []interface{}
	err := c.CertenAnchorV2Caller.contract.Call(opts, &out, "isNonceUsed", authority, nonce)
	if err != nil {
		return false, err
	}
	return out[0].(bool), nil
}

// GetValidatorAnchorCount returns number of anchors created by a validator
func (c *CertenAnchorV2Extended) GetValidatorAnchorCount(
	opts *bind.CallOpts,
	validator common.Address,
) (*big.Int, error) {
	var out []interface{}
	err := c.CertenAnchorV2Caller.contract.Call(opts, &out, "getValidatorAnchorCount", validator)
	if err != nil {
		return nil, err
	}
	return out[0].(*big.Int), nil
}

// =============================================================================
// Helper Functions
// =============================================================================

// BuildComprehensiveProof creates a ComprehensiveCertenProof from components
func BuildComprehensiveProof(
	txHash [32]byte,
	merkleRoot [32]byte,
	proofHashes [][32]byte,
	leafHash [32]byte,
	govProof GovernanceProofData,
	blsProof BLSProofData,
	commitments CommitmentData,
	expirationTime *big.Int,
	metadata []byte,
) ComprehensiveCertenProof {
	return ComprehensiveCertenProof{
		TransactionHash: txHash,
		MerkleRoot:      merkleRoot,
		ProofHashes:     proofHashes,
		LeafHash:        leafHash,
		GovernanceProof: govProof,
		BLSProof:        blsProof,
		Commitments:     commitments,
		ExpirationTime:  expirationTime,
		Metadata:        metadata,
	}
}

// ToLegacyAnchorProof converts ComprehensiveCertenProof to legacy AnchorProof
func (p *ComprehensiveCertenProof) ToLegacyAnchorProof() AnchorProof {
	return AnchorProof{
		TransactionHash:     p.TransactionHash,
		MerkleRoot:          p.MerkleRoot,
		ProofHashes:         p.ProofHashes,
		LeafHash:            p.LeafHash,
		ValidatorSignatures: p.BLSProof.AggregateSignature,
		Timestamp:           p.ExpirationTime,
	}
}

// GetAddress returns the contract address
func (c *CertenAnchorV2Extended) GetAddress() common.Address {
	return c.address
}

// WaitForConfirmation waits for a transaction to be confirmed
// Caller should use bind.WaitMined with their ethclient.Client directly
func (c *CertenAnchorV2Extended) WaitForConfirmation(
	ctx context.Context,
	tx *types.Transaction,
	client bind.DeployBackend,
) (*types.Receipt, error) {
	return bind.WaitMined(ctx, client, tx)
}
