// Copyright 2025 Certen Protocol
//
// Batch Adapter - Integrates proof systems with batch transaction processing
// This adapter bridges ChainedProof (L1-L3) and GovernanceProof (G0-G2)
// with the batch collector for database storage.
//
// Per Whitepaper Section 3.4.1:
// - Component 3: State Proof (ChainedProof L1-L3)
// - Component 4: Authority Proof (GovernanceProof G0-G2)

package proof

import (
	"encoding/json"
	"fmt"
	"time"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
)

// =============================================================================
// ChainedProof Adapter
// =============================================================================

// ChainedProofWrapper wraps the working-proof ChainedProof for batch integration
type ChainedProofWrapper struct {
	// The underlying ChainedProof from working-proof package
	Proof *chained_proof.ChainedProof `json:"proof"`

	// Metadata for batch processing
	GeneratedAt time.Time `json:"generated_at"`
	ValidatorID string    `json:"validator_id"`
	Environment string    `json:"environment"` // devnet, testnet, mainnet

	// Verification status
	Verified       bool   `json:"verified"`
	Layer1Valid    bool   `json:"layer1_valid"`
	Layer2Valid    bool   `json:"layer2_valid"`
	Layer3Valid    bool   `json:"layer3_valid"`
	VerifyError    string `json:"verify_error,omitempty"`
	VerificationMs int64  `json:"verification_ms"`
}

// NewChainedProofWrapper creates a wrapper around a ChainedProof
func NewChainedProofWrapper(proof *chained_proof.ChainedProof, validatorID, environment string) *ChainedProofWrapper {
	return &ChainedProofWrapper{
		Proof:       proof,
		GeneratedAt: time.Now(),
		ValidatorID: validatorID,
		Environment: environment,
		Verified:    false,
	}
}

// ToJSON serializes the wrapper to JSON for database storage
func (w *ChainedProofWrapper) ToJSON() (json.RawMessage, error) {
	return json.Marshal(w)
}

// ChainedProofFromJSON deserializes a ChainedProofWrapper from JSON
func ChainedProofFromJSON(data json.RawMessage) (*ChainedProofWrapper, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var wrapper ChainedProofWrapper
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("failed to unmarshal chained proof: %w", err)
	}
	return &wrapper, nil
}

// GetTxHash returns the transaction hash from the proof input
func (w *ChainedProofWrapper) GetTxHash() string {
	if w.Proof == nil {
		return ""
	}
	return w.Proof.Input.TxHash
}

// GetAccount returns the account URL from the proof input
func (w *ChainedProofWrapper) GetAccount() string {
	if w.Proof == nil {
		return ""
	}
	return w.Proof.Input.Account
}

// GetBVN returns the BVN from the proof input
func (w *ChainedProofWrapper) GetBVN() string {
	if w.Proof == nil {
		return ""
	}
	return w.Proof.Input.BVN
}

// IsComplete returns whether all layers are present
func (w *ChainedProofWrapper) IsComplete() bool {
	if w.Proof == nil {
		return false
	}
	// Check Layer1 has required fields
	if w.Proof.Layer1.BVNRootChainAnchor == "" {
		return false
	}
	// Check Layer2 has required fields
	if w.Proof.Layer2.DNRootChainAnchor == "" {
		return false
	}
	// Check Layer3 has required fields
	if w.Proof.Layer3.DNStateTreeAnchor == "" {
		return false
	}
	return true
}

// SetVerificationResult sets the verification status
func (w *ChainedProofWrapper) SetVerificationResult(l1Valid, l2Valid, l3Valid bool, verifyErr error, durationMs int64) {
	w.Layer1Valid = l1Valid
	w.Layer2Valid = l2Valid
	w.Layer3Valid = l3Valid
	w.Verified = l1Valid && l2Valid && l3Valid
	w.VerificationMs = durationMs
	if verifyErr != nil {
		w.VerifyError = verifyErr.Error()
	}
}

// =============================================================================
// Governance Proof Adapter
// =============================================================================

// GovernanceProofWrapper wraps GovernanceProof for batch integration
type GovernanceProofWrapper struct {
	// The governance proof
	Proof *GovernanceProof `json:"proof"`

	// Metadata for batch processing
	GeneratedAt time.Time `json:"generated_at"`
	ValidatorID string    `json:"validator_id"`
	Environment string    `json:"environment"` // devnet, testnet, mainnet

	// Verification status
	Verified       bool   `json:"verified"`
	VerifyError    string `json:"verify_error,omitempty"`
	VerificationMs int64  `json:"verification_ms"`
}

// NewGovernanceProofWrapper creates a wrapper around a GovernanceProof
func NewGovernanceProofWrapper(proof *GovernanceProof, validatorID, environment string) *GovernanceProofWrapper {
	return &GovernanceProofWrapper{
		Proof:       proof,
		GeneratedAt: time.Now(),
		ValidatorID: validatorID,
		Environment: environment,
		Verified:    proof != nil && proof.IsValid(),
	}
}

// ToJSON serializes the wrapper to JSON for database storage
func (w *GovernanceProofWrapper) ToJSON() (json.RawMessage, error) {
	return json.Marshal(w)
}

// GovernanceProofWrapperFromJSON deserializes a GovernanceProofWrapper from JSON
func GovernanceProofWrapperFromJSON(data json.RawMessage) (*GovernanceProofWrapper, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var wrapper GovernanceProofWrapper
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("failed to unmarshal governance proof: %w", err)
	}
	return &wrapper, nil
}

// GetLevel returns the governance level
func (w *GovernanceProofWrapper) GetLevel() GovernanceLevel {
	if w.Proof == nil {
		return ""
	}
	return w.Proof.Level
}

// GetTxHash returns the transaction hash from the proof
func (w *GovernanceProofWrapper) GetTxHash() string {
	if w.Proof == nil {
		return ""
	}
	switch w.Proof.Level {
	case GovLevelG0:
		if w.Proof.G0 != nil {
			return w.Proof.G0.TxHash
		}
	case GovLevelG1:
		if w.Proof.G1 != nil {
			return w.Proof.G1.TxHash
		}
	case GovLevelG2:
		if w.Proof.G2 != nil {
			return w.Proof.G2.TxHash
		}
	}
	return ""
}

// GetScope returns the transaction scope from the proof
func (w *GovernanceProofWrapper) GetScope() string {
	if w.Proof == nil {
		return ""
	}
	switch w.Proof.Level {
	case GovLevelG0:
		if w.Proof.G0 != nil {
			return w.Proof.G0.Scope
		}
	case GovLevelG1:
		if w.Proof.G1 != nil {
			return w.Proof.G1.Scope
		}
	case GovLevelG2:
		if w.Proof.G2 != nil {
			return w.Proof.G2.Scope
		}
	}
	return ""
}

// SetVerificationResult sets the verification status
func (w *GovernanceProofWrapper) SetVerificationResult(verified bool, verifyErr error, durationMs int64) {
	w.Verified = verified
	w.VerificationMs = durationMs
	if verifyErr != nil {
		w.VerifyError = verifyErr.Error()
	}
}

// =============================================================================
// Combined Proof Bundle for Batch Transactions
// =============================================================================

// TransactionProofBundle contains all proofs for a transaction
// This is what gets attached to each batch transaction
type TransactionProofBundle struct {
	// Transaction identification
	AccumTxHash string `json:"accumulate_tx_hash"`
	AccountURL  string `json:"account_url"`

	// Component 3: State Proof (ChainedProof L1-L3)
	ChainedProof *ChainedProofWrapper `json:"chained_proof,omitempty"`

	// Component 4: Authority Proof (GovernanceProof G0-G2)
	GovernanceProof *GovernanceProofWrapper `json:"governance_proof,omitempty"`

	// Bundle metadata
	GeneratedAt time.Time `json:"generated_at"`
	ValidatorID string    `json:"validator_id"`
	Environment string    `json:"environment"`

	// Overall status
	ChainedValid    bool   `json:"chained_valid"`
	GovernanceValid bool   `json:"governance_valid"`
	BundleComplete  bool   `json:"bundle_complete"`
	BundleError     string `json:"bundle_error,omitempty"`
}

// NewTransactionProofBundle creates a new proof bundle for a transaction
func NewTransactionProofBundle(accumTxHash, accountURL, validatorID, environment string) *TransactionProofBundle {
	return &TransactionProofBundle{
		AccumTxHash: accumTxHash,
		AccountURL:  accountURL,
		GeneratedAt: time.Now(),
		ValidatorID: validatorID,
		Environment: environment,
	}
}

// SetChainedProof sets the chained proof component
func (b *TransactionProofBundle) SetChainedProof(proof *chained_proof.ChainedProof) {
	b.ChainedProof = NewChainedProofWrapper(proof, b.ValidatorID, b.Environment)
	b.ChainedValid = b.ChainedProof.IsComplete()
	b.updateBundleStatus()
}

// SetChainedProofWrapper sets the chained proof wrapper directly
func (b *TransactionProofBundle) SetChainedProofWrapper(wrapper *ChainedProofWrapper) {
	b.ChainedProof = wrapper
	b.ChainedValid = wrapper != nil && wrapper.Verified
	b.updateBundleStatus()
}

// SetGovernanceProof sets the governance proof component
func (b *TransactionProofBundle) SetGovernanceProof(proof *GovernanceProof) {
	b.GovernanceProof = NewGovernanceProofWrapper(proof, b.ValidatorID, b.Environment)
	b.GovernanceValid = b.GovernanceProof.Verified
	b.updateBundleStatus()
}

// SetGovernanceProofWrapper sets the governance proof wrapper directly
func (b *TransactionProofBundle) SetGovernanceProofWrapper(wrapper *GovernanceProofWrapper) {
	b.GovernanceProof = wrapper
	b.GovernanceValid = wrapper != nil && wrapper.Verified
	b.updateBundleStatus()
}

// updateBundleStatus updates the overall bundle status
func (b *TransactionProofBundle) updateBundleStatus() {
	// Bundle is complete if we have at least one valid proof
	// (ChainedProof is required, GovernanceProof is optional based on level)
	b.BundleComplete = b.ChainedValid
}

// ToJSON serializes the bundle to JSON
func (b *TransactionProofBundle) ToJSON() (json.RawMessage, error) {
	return json.Marshal(b)
}

// TransactionProofBundleFromJSON deserializes a bundle from JSON
func TransactionProofBundleFromJSON(data json.RawMessage) (*TransactionProofBundle, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var bundle TransactionProofBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("failed to unmarshal proof bundle: %w", err)
	}
	return &bundle, nil
}

// GetChainedProofJSON returns the chained proof as JSON for database storage
func (b *TransactionProofBundle) GetChainedProofJSON() (json.RawMessage, error) {
	if b.ChainedProof == nil {
		return nil, nil
	}
	return b.ChainedProof.ToJSON()
}

// GetGovernanceProofJSON returns the governance proof as JSON for database storage
func (b *TransactionProofBundle) GetGovernanceProofJSON() (json.RawMessage, error) {
	if b.GovernanceProof == nil {
		return nil, nil
	}
	return b.GovernanceProof.ToJSON()
}

// GetGovernanceLevel returns the governance level as a string for database storage
func (b *TransactionProofBundle) GetGovernanceLevel() string {
	if b.GovernanceProof == nil {
		return ""
	}
	return string(b.GovernanceProof.GetLevel())
}

// =============================================================================
// Database Conversion Helpers
// =============================================================================

// ToDBGovernanceLevel converts GovernanceLevel to database format
func ToDBGovernanceLevel(level GovernanceLevel) string {
	return string(level)
}

// FromDBGovernanceLevel converts database format to GovernanceLevel
func FromDBGovernanceLevel(level string) GovernanceLevel {
	switch level {
	case "G0":
		return GovLevelG0
	case "G1":
		return GovLevelG1
	case "G2":
		return GovLevelG2
	default:
		return ""
	}
}
