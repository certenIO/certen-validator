// Copyright 2025 Certen Protocol
//
// Anchor Proof Builder - Constructs CertenAnchorProof from components
// This builder integrates:
// - Batch Merkle inclusion proofs
// - External chain anchor references
// - State proofs (L1-L3)
// - Governance proofs (G0-G2)

package anchor_proof

import (
	"fmt"
	"time"

	"github.com/certen/independant-validator/pkg/merkle"
	"github.com/google/uuid"
)

// Builder constructs CertenAnchorProof instances
type Builder struct {
	// Core identification
	proofID     uuid.UUID
	accumTxHash string
	accountURL  string
	batchID     uuid.UUID
	batchType   string

	// Component 1: Transaction Inclusion
	merkleProof *merkle.InclusionProof
	merkleRoot  []byte

	// Component 2: Anchor Reference
	anchorChain     AnchorChain
	anchorTxHash    string
	anchorBlockNum  int64
	anchorBlockHash string
	anchorTimestamp time.Time
	chainID         string
	networkID       string
	contractAddr    string
	confirmations   int
	reqConfirms     int

	// Component 3: State Proof
	stateProofIncluded bool
	stateProofBVN      string
	stateProofHeight   int64

	// Component 4: Authority Proof
	authorityProofIncluded bool
	authorityProofLevel    GovernanceLevel

	// Metadata
	validatorID string
	createdAt   time.Time

	// Errors during building
	errors []error
}

// NewBuilder creates a new proof builder
func NewBuilder() *Builder {
	return &Builder{
		proofID:     uuid.New(),
		createdAt:   time.Now(),
		reqConfirms: 12, // Default: 12 confirmations for Ethereum
	}
}

// WithTransactionInfo sets the original transaction information
func (b *Builder) WithTransactionInfo(accumTxHash, accountURL string) *Builder {
	b.accumTxHash = accumTxHash
	b.accountURL = accountURL
	return b
}

// WithBatchInfo sets the batch information
func (b *Builder) WithBatchInfo(batchID uuid.UUID, batchType string) *Builder {
	b.batchID = batchID
	b.batchType = batchType
	return b
}

// WithMerkleProof sets the Merkle inclusion proof (Component 1)
func (b *Builder) WithMerkleProof(proof *merkle.InclusionProof, merkleRoot []byte) *Builder {
	b.merkleProof = proof
	b.merkleRoot = merkleRoot
	return b
}

// WithAnchorReference sets the anchor reference (Component 2)
func (b *Builder) WithAnchorReference(
	chain AnchorChain,
	txHash string,
	blockNum int64,
	blockHash string,
	confirmations int,
) *Builder {
	b.anchorChain = chain
	b.anchorTxHash = txHash
	b.anchorBlockNum = blockNum
	b.anchorBlockHash = blockHash
	b.confirmations = confirmations
	return b
}

// WithAnchorChainDetails sets additional chain details
func (b *Builder) WithAnchorChainDetails(chainID, networkID, contractAddr string) *Builder {
	b.chainID = chainID
	b.networkID = networkID
	b.contractAddr = contractAddr
	return b
}

// WithAnchorTimestamp sets the anchor timestamp
func (b *Builder) WithAnchorTimestamp(ts time.Time) *Builder {
	b.anchorTimestamp = ts
	return b
}

// WithRequiredConfirmations sets the required confirmation count
func (b *Builder) WithRequiredConfirmations(count int) *Builder {
	b.reqConfirms = count
	return b
}

// WithStateProof marks that a state proof is included (Component 3)
func (b *Builder) WithStateProof(included bool, bvn string, blockHeight int64) *Builder {
	b.stateProofIncluded = included
	b.stateProofBVN = bvn
	b.stateProofHeight = blockHeight
	return b
}

// WithAuthorityProof marks that an authority proof is included (Component 4)
func (b *Builder) WithAuthorityProof(included bool, level GovernanceLevel) *Builder {
	b.authorityProofIncluded = included
	b.authorityProofLevel = level
	return b
}

// WithValidatorID sets the validator ID
func (b *Builder) WithValidatorID(validatorID string) *Builder {
	b.validatorID = validatorID
	return b
}

// Build constructs the final CertenAnchorProof
func (b *Builder) Build() (*CertenAnchorProof, error) {
	// Validate required fields
	if err := b.validate(); err != nil {
		return nil, err
	}

	proof := &CertenAnchorProof{
		ProofID:          b.proofID,
		ProofVersion:     ProofVersion,
		AccumulateTxHash: b.accumTxHash,
		AccountURL:       b.accountURL,
		BatchID:          b.batchID,
		BatchType:        b.batchType,
		CreatedAt:        b.createdAt,
		UpdatedAt:        b.createdAt,
	}

	// Build Component 1: Transaction Inclusion Proof
	proof.TransactionInclusion = b.buildMerkleInclusion()

	// Build Component 2: Anchor Reference
	proof.AnchorReference = b.buildAnchorReference()

	// Build Component 3: State Proof
	proof.StateProof = b.buildStateProof()

	// Build Component 4: Authority Proof
	proof.AuthorityProof = b.buildAuthorityProof()

	return proof, nil
}

// validate checks that all required fields are set
func (b *Builder) validate() error {
	if b.accumTxHash == "" {
		return fmt.Errorf("accumulate transaction hash is required")
	}
	if b.accountURL == "" {
		return fmt.Errorf("account URL is required")
	}
	if b.batchID == uuid.Nil {
		return fmt.Errorf("batch ID is required")
	}
	if b.merkleProof == nil {
		return fmt.Errorf("merkle proof is required")
	}
	if b.anchorTxHash == "" {
		return fmt.Errorf("anchor transaction hash is required")
	}
	return nil
}

// buildMerkleInclusion constructs Component 1
func (b *Builder) buildMerkleInclusion() MerkleInclusionProof {
	inclusion := MerkleInclusionProof{
		LeafHash:   b.merkleProof.LeafHash,
		LeafIndex:  b.merkleProof.LeafIndex,
		MerkleRoot: b.merkleProof.MerkleRoot,
		TreeSize:   b.merkleProof.TreeSize,
		Path:       make([]MerkleNode, len(b.merkleProof.Path)),
	}

	// Convert merkle path
	for i, node := range b.merkleProof.Path {
		pos := "left"
		if node.Position == merkle.Right {
			pos = "right"
		}
		inclusion.Path[i] = MerkleNode{
			Hash:     node.Hash,
			Position: pos,
		}
	}

	return inclusion
}

// buildAnchorReference constructs Component 2
func (b *Builder) buildAnchorReference() AnchorReference {
	return AnchorReference{
		Chain:                 b.anchorChain,
		ChainID:               b.chainID,
		NetworkID:             b.networkID,
		TxHash:                b.anchorTxHash,
		BlockNumber:           b.anchorBlockNum,
		BlockHash:             b.anchorBlockHash,
		Timestamp:             b.anchorTimestamp,
		ContractAddress:       b.contractAddr,
		Confirmations:         b.confirmations,
		RequiredConfirmations: b.reqConfirms,
		IsFinal:               b.confirmations >= b.reqConfirms,
	}
}

// buildStateProof constructs Component 3
func (b *Builder) buildStateProof() StateProofReference {
	return StateProofReference{
		Included:    b.stateProofIncluded,
		BVN:         b.stateProofBVN,
		BlockHeight: b.stateProofHeight,
	}
}

// buildAuthorityProof constructs Component 4
func (b *Builder) buildAuthorityProof() AuthorityProofReference {
	return AuthorityProofReference{
		Included: b.authorityProofIncluded,
		Level:    b.authorityProofLevel,
	}
}

// =============================================================================
// Batch Builder (for building multiple proofs efficiently)
// =============================================================================

// BatchBuilder builds multiple proofs for a batch
type BatchBuilder struct {
	batchID     uuid.UUID
	batchType   string
	merkleRoot  []byte
	anchorRef   *AnchorReference
	validatorID string
	proofs      []*CertenAnchorProof
}

// NewBatchBuilder creates a builder for batch proof creation
func NewBatchBuilder(batchID uuid.UUID, batchType string, merkleRoot []byte) *BatchBuilder {
	return &BatchBuilder{
		batchID:    batchID,
		batchType:  batchType,
		merkleRoot: merkleRoot,
		proofs:     make([]*CertenAnchorProof, 0),
	}
}

// WithAnchorReference sets the anchor reference for all proofs in the batch
func (bb *BatchBuilder) WithAnchorReference(ref *AnchorReference) *BatchBuilder {
	bb.anchorRef = ref
	return bb
}

// WithValidatorID sets the validator ID for all proofs
func (bb *BatchBuilder) WithValidatorID(id string) *BatchBuilder {
	bb.validatorID = id
	return bb
}

// AddTransaction adds a transaction to the batch
func (bb *BatchBuilder) AddTransaction(
	accumTxHash, accountURL string,
	merkleProof *merkle.InclusionProof,
) error {
	builder := NewBuilder().
		WithTransactionInfo(accumTxHash, accountURL).
		WithBatchInfo(bb.batchID, bb.batchType).
		WithMerkleProof(merkleProof, bb.merkleRoot).
		WithValidatorID(bb.validatorID)

	if bb.anchorRef != nil {
		builder.WithAnchorReference(
			bb.anchorRef.Chain,
			bb.anchorRef.TxHash,
			bb.anchorRef.BlockNumber,
			bb.anchorRef.BlockHash,
			bb.anchorRef.Confirmations,
		).WithAnchorChainDetails(
			bb.anchorRef.ChainID,
			bb.anchorRef.NetworkID,
			bb.anchorRef.ContractAddress,
		).WithRequiredConfirmations(bb.anchorRef.RequiredConfirmations)
	}

	proof, err := builder.Build()
	if err != nil {
		return fmt.Errorf("failed to build proof for %s: %w", accumTxHash, err)
	}

	bb.proofs = append(bb.proofs, proof)
	return nil
}

// Build returns all proofs for the batch
func (bb *BatchBuilder) Build() []*CertenAnchorProof {
	return bb.proofs
}

// Count returns the number of proofs in the batch
func (bb *BatchBuilder) Count() int {
	return len(bb.proofs)
}
