// Copyright 2025 Certen Protocol
//
// Proof Helpers - Convenience functions for integrating proofs with batch collector
// This bridges the pkg/proof types with the batch TransactionData format.
//
// Per Whitepaper Section 3.4.1:
// - Component 3: State Proof (ChainedProof L1-L3)
// - Component 4: Authority Proof (GovernanceProof G0-G2)

package batch

import (
	"encoding/json"
	"fmt"

	"github.com/certen/independant-validator/pkg/proof"
	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
)

// TransactionDataFromProofBundle creates a TransactionData from a proof bundle
// This is the primary way to add a transaction with proofs to a batch
func TransactionDataFromProofBundle(bundle *proof.TransactionProofBundle, txHash []byte) (*TransactionData, error) {
	if bundle == nil {
		return nil, fmt.Errorf("proof bundle cannot be nil")
	}
	if len(txHash) != 32 {
		return nil, fmt.Errorf("txHash must be 32 bytes")
	}

	td := &TransactionData{
		AccumTxHash: bundle.AccumTxHash,
		AccountURL:  bundle.AccountURL,
		TxHash:      txHash,
	}

	// Add ChainedProof if present
	if bundle.ChainedProof != nil {
		chainedJSON, err := bundle.ChainedProof.ToJSON()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize chained proof: %w", err)
		}
		td.ChainedProof = chainedJSON
	}

	// Add GovernanceProof if present
	if bundle.GovernanceProof != nil {
		govJSON, err := bundle.GovernanceProof.ToJSON()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize governance proof: %w", err)
		}
		td.GovProof = govJSON
		td.GovLevel = bundle.GetGovernanceLevel()
	}

	return td, nil
}

// TransactionDataWithChainedProof creates TransactionData with just a ChainedProof
func TransactionDataWithChainedProof(
	accumTxHash, accountURL string,
	txHash []byte,
	chainedProof *chained_proof.ChainedProof,
	validatorID, environment string,
) (*TransactionData, error) {
	if len(txHash) != 32 {
		return nil, fmt.Errorf("txHash must be 32 bytes")
	}

	td := &TransactionData{
		AccumTxHash: accumTxHash,
		AccountURL:  accountURL,
		TxHash:      txHash,
	}

	if chainedProof != nil {
		wrapper := proof.NewChainedProofWrapper(chainedProof, validatorID, environment)
		chainedJSON, err := wrapper.ToJSON()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize chained proof: %w", err)
		}
		td.ChainedProof = chainedJSON
	}

	return td, nil
}

// TransactionDataWithGovernanceProof creates TransactionData with just a GovernanceProof
func TransactionDataWithGovernanceProof(
	accumTxHash, accountURL string,
	txHash []byte,
	govProof *proof.GovernanceProof,
	validatorID, environment string,
) (*TransactionData, error) {
	if len(txHash) != 32 {
		return nil, fmt.Errorf("txHash must be 32 bytes")
	}

	td := &TransactionData{
		AccumTxHash: accumTxHash,
		AccountURL:  accountURL,
		TxHash:      txHash,
	}

	if govProof != nil {
		wrapper := proof.NewGovernanceProofWrapper(govProof, validatorID, environment)
		govJSON, err := wrapper.ToJSON()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize governance proof: %w", err)
		}
		td.GovProof = govJSON
		td.GovLevel = string(govProof.Level)
	}

	return td, nil
}

// TransactionDataWithBothProofs creates TransactionData with both proofs
func TransactionDataWithBothProofs(
	accumTxHash, accountURL string,
	txHash []byte,
	chainedProof *chained_proof.ChainedProof,
	govProof *proof.GovernanceProof,
	validatorID, environment string,
) (*TransactionData, error) {
	if len(txHash) != 32 {
		return nil, fmt.Errorf("txHash must be 32 bytes")
	}

	td := &TransactionData{
		AccumTxHash: accumTxHash,
		AccountURL:  accountURL,
		TxHash:      txHash,
	}

	if chainedProof != nil {
		wrapper := proof.NewChainedProofWrapper(chainedProof, validatorID, environment)
		chainedJSON, err := wrapper.ToJSON()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize chained proof: %w", err)
		}
		td.ChainedProof = chainedJSON
	}

	if govProof != nil {
		wrapper := proof.NewGovernanceProofWrapper(govProof, validatorID, environment)
		govJSON, err := wrapper.ToJSON()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize governance proof: %w", err)
		}
		td.GovProof = govJSON
		td.GovLevel = string(govProof.Level)
	}

	return td, nil
}

// SimpleTransactionData creates a minimal TransactionData without proofs
// Use this when proofs will be attached later or for testing
func SimpleTransactionData(accumTxHash, accountURL string, txHash []byte) (*TransactionData, error) {
	if len(txHash) != 32 {
		return nil, fmt.Errorf("txHash must be 32 bytes")
	}

	return &TransactionData{
		AccumTxHash: accumTxHash,
		AccountURL:  accountURL,
		TxHash:      txHash,
	}, nil
}

// ExtractChainedProof extracts and deserializes the ChainedProof from TransactionData
func ExtractChainedProof(td *TransactionData) (*proof.ChainedProofWrapper, error) {
	if td == nil || len(td.ChainedProof) == 0 {
		return nil, nil
	}
	return proof.ChainedProofFromJSON(td.ChainedProof)
}

// ExtractGovernanceProof extracts and deserializes the GovernanceProof from TransactionData
func ExtractGovernanceProof(td *TransactionData) (*proof.GovernanceProofWrapper, error) {
	if td == nil || len(td.GovProof) == 0 {
		return nil, nil
	}
	return proof.GovernanceProofWrapperFromJSON(td.GovProof)
}

// ValidateTransactionData validates that TransactionData has required fields
func ValidateTransactionData(td *TransactionData) error {
	if td == nil {
		return fmt.Errorf("transaction data cannot be nil")
	}
	if td.AccumTxHash == "" {
		return fmt.Errorf("accumulate transaction hash is required")
	}
	if td.AccountURL == "" {
		return fmt.Errorf("account URL is required")
	}
	if len(td.TxHash) != 32 {
		return ErrInvalidTxHash
	}
	return nil
}

// ProofSummary provides a summary of proofs in a TransactionData
type ProofSummary struct {
	HasChainedProof    bool   `json:"has_chained_proof"`
	HasGovernanceProof bool   `json:"has_governance_proof"`
	GovernanceLevel    string `json:"governance_level,omitempty"`
	ChainedComplete    bool   `json:"chained_complete"`
	GovernanceValid    bool   `json:"governance_valid"`
}

// GetProofSummary extracts a summary of proofs from TransactionData
func GetProofSummary(td *TransactionData) (*ProofSummary, error) {
	summary := &ProofSummary{
		HasChainedProof:    len(td.ChainedProof) > 0,
		HasGovernanceProof: len(td.GovProof) > 0,
		GovernanceLevel:    td.GovLevel,
	}

	// Try to extract and validate chained proof
	if summary.HasChainedProof {
		wrapper, err := ExtractChainedProof(td)
		if err == nil && wrapper != nil {
			summary.ChainedComplete = wrapper.IsComplete()
		}
	}

	// Try to extract and validate governance proof
	if summary.HasGovernanceProof {
		wrapper, err := ExtractGovernanceProof(td)
		if err == nil && wrapper != nil {
			summary.GovernanceValid = wrapper.Verified
		}
	}

	return summary, nil
}

// BatchProofStats provides statistics about proofs in a batch
type BatchProofStats struct {
	TotalTransactions     int            `json:"total_transactions"`
	WithChainedProof      int            `json:"with_chained_proof"`
	WithGovernanceProof   int            `json:"with_governance_proof"`
	ChainedComplete       int            `json:"chained_complete"`
	GovernanceValid       int            `json:"governance_valid"`
	GovernanceLevelCounts map[string]int `json:"governance_level_counts"`
}

// ComputeBatchProofStats computes proof statistics for a batch
func ComputeBatchProofStats(transactions []*TransactionData) *BatchProofStats {
	stats := &BatchProofStats{
		TotalTransactions:     len(transactions),
		GovernanceLevelCounts: make(map[string]int),
	}

	for _, tx := range transactions {
		summary, err := GetProofSummary(tx)
		if err != nil {
			continue
		}

		if summary.HasChainedProof {
			stats.WithChainedProof++
		}
		if summary.ChainedComplete {
			stats.ChainedComplete++
		}
		if summary.HasGovernanceProof {
			stats.WithGovernanceProof++
		}
		if summary.GovernanceValid {
			stats.GovernanceValid++
		}
		if summary.GovernanceLevel != "" {
			stats.GovernanceLevelCounts[summary.GovernanceLevel]++
		}
	}

	return stats
}

// TransactionDataBuilder provides a fluent interface for building TransactionData
type TransactionDataBuilder struct {
	td          *TransactionData
	validatorID string
	environment string
	err         error
}

// NewTransactionDataBuilder creates a new builder
func NewTransactionDataBuilder(accumTxHash, accountURL string, txHash []byte) *TransactionDataBuilder {
	builder := &TransactionDataBuilder{
		validatorID: "validator-default",
		environment: "production",
	}

	if len(txHash) != 32 {
		builder.err = ErrInvalidTxHash
		return builder
	}

	builder.td = &TransactionData{
		AccumTxHash: accumTxHash,
		AccountURL:  accountURL,
		TxHash:      txHash,
	}

	return builder
}

// WithValidatorID sets the validator ID for proof wrappers
func (b *TransactionDataBuilder) WithValidatorID(id string) *TransactionDataBuilder {
	b.validatorID = id
	return b
}

// WithEnvironment sets the environment for proof wrappers
func (b *TransactionDataBuilder) WithEnvironment(env string) *TransactionDataBuilder {
	b.environment = env
	return b
}

// WithChainedProof adds a ChainedProof
func (b *TransactionDataBuilder) WithChainedProof(cp *chained_proof.ChainedProof) *TransactionDataBuilder {
	if b.err != nil || b.td == nil || cp == nil {
		return b
	}

	wrapper := proof.NewChainedProofWrapper(cp, b.validatorID, b.environment)
	jsonData, err := wrapper.ToJSON()
	if err != nil {
		b.err = fmt.Errorf("failed to serialize chained proof: %w", err)
		return b
	}
	b.td.ChainedProof = jsonData
	return b
}

// WithGovernanceProof adds a GovernanceProof
func (b *TransactionDataBuilder) WithGovernanceProof(gp *proof.GovernanceProof) *TransactionDataBuilder {
	if b.err != nil || b.td == nil || gp == nil {
		return b
	}

	wrapper := proof.NewGovernanceProofWrapper(gp, b.validatorID, b.environment)
	jsonData, err := wrapper.ToJSON()
	if err != nil {
		b.err = fmt.Errorf("failed to serialize governance proof: %w", err)
		return b
	}
	b.td.GovProof = jsonData
	b.td.GovLevel = string(gp.Level)
	return b
}

// WithIntent adds intent data
func (b *TransactionDataBuilder) WithIntent(intentType string, intentData interface{}) *TransactionDataBuilder {
	if b.err != nil || b.td == nil {
		return b
	}

	b.td.IntentType = intentType
	if intentData != nil {
		jsonData, err := json.Marshal(intentData)
		if err != nil {
			b.err = fmt.Errorf("failed to serialize intent data: %w", err)
			return b
		}
		b.td.IntentData = jsonData
	}
	return b
}

// Build returns the constructed TransactionData
func (b *TransactionDataBuilder) Build() (*TransactionData, error) {
	if b.err != nil {
		return nil, b.err
	}
	if b.td == nil {
		return nil, fmt.Errorf("no transaction data built")
	}
	return b.td, nil
}
