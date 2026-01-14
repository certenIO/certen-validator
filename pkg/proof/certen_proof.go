// Copyright 2025 Certen Protocol
//
// Lite-Client-Only Proof Generation for Certen Validator
// Cleaned up to remove all unimplemented validation paths

package proof

import (
	"context"
	"fmt"
	"time"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/api"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof"
)

// ProofGenerator handles lite-client-only proof generation
type ProofGenerator struct {
	liteClientProofGen *LiteClientProofGenerator
	config             *ProofConfig
}

// ProofConfig contains configuration for proof generation
type ProofConfig struct {
	EnableRealProofs  bool          `json:"enable_real_proofs"`
	BatchSize         int           `json:"batch_size"`
	ProcessingTimeout time.Duration `json:"processing_timeout"`
	CacheEnabled      bool          `json:"cache_enabled"`
	Environment       string        `json:"environment"`
	ValidatorID       string        `json:"validator_id"`
}

// ProofRequest represents a simplified proof request
type ProofRequest struct {
	RequestID       string `json:"request_id"`
	ProofType       string `json:"proof_type"`        // "transaction", "account"
	TransactionHash string `json:"transaction_hash,omitempty"`
	AccountURL      string `json:"account_url,omitempty"`
}

// CertenProof represents the lite-client-only proof format
type CertenProof struct {
	// Basic identification
	ProofID         string    `json:"proof_id"`
	ProofVersion    string    `json:"proof_version"`
	ProofType       string    `json:"proof_type"`
	GeneratedAt     time.Time `json:"generated_at"`
	ValidatorID     string    `json:"validator_id"`
	Environment     string    `json:"environment"`

	// Target information
	TransactionHash string `json:"transaction_hash,omitempty"`
	AccountURL      string `json:"account_url,omitempty"`
	BlockHeight     uint64 `json:"block_height,omitempty"`

	// Real lite client proof components
	LiteClientProof *LiteClientProofData `json:"lite_client_proof"`

	// BFT consensus components for ValidatorBlock building
	BLSAggregateSignature string   `json:"bls_aggregate_signature,omitempty"` // From governance authorization
	ValidatorSignatures   []string `json:"validator_signatures,omitempty"`   // From BFT consensus pre-execution

	// Accumulate anchor reference from lite client proof
	AccumulateAnchor *AccumulateAnchorData `json:"accumulate_anchor,omitempty"`

	// Verification status
	VerificationStatus *VerificationStatusData `json:"verification_status"`

	// Performance metadata
	ProcessingTime time.Duration           `json:"processing_time"`
	Metrics        *ProofGenerationMetrics `json:"metrics,omitempty"`
}

// AccumulateAnchorData contains anchor reference data from Accumulate blockchain
type AccumulateAnchorData struct {
	BlockHash   string `json:"block_hash"`
	BlockHeight uint64 `json:"block_height"`
	TxHash      string `json:"tx_hash"`
}

// LiteClientProofData contains real proof data from Accumulate lite client
type LiteClientProofData struct {
	// Complete proof chain from lite client
	CompleteProof *proof.CompleteProof `json:"complete_proof"`

	// Layer-specific components
	AccountHash []byte `json:"account_hash"`
	BPTRoot     []byte `json:"bpt_root"`
	BlockHash   []byte `json:"block_hash"`

	// Consensus proof (when available)
	ConsensusProof *proof.ConsensusProof `json:"consensus_proof,omitempty"`

	// Raw account data from lite client
	AccountData *api.AccountInfo `json:"account_data,omitempty"`
	ReceiptData *api.ReceiptInfo `json:"receipt_data,omitempty"`

	// Proof validation status
	ProofValid      bool   `json:"proof_valid"`
	ValidationLevel string `json:"validation_level"` // "account", "bpt", "block", "consensus"
}

// VerificationStatusData contains verification status information
type VerificationStatusData struct {
	OverallValid      bool              `json:"overall_valid"`
	Confidence        float64           `json:"confidence"`
	VerificationLevel string            `json:"verification_level"`
	ComponentStatus   map[string]bool   `json:"component_status"`
	VerifiedAt        time.Time         `json:"verified_at"`
	ProcessingTime    time.Duration     `json:"processing_time,omitempty"`
	Details           map[string]string `json:"details,omitempty"`
}

// VerificationStep represents a step in verification
type VerificationStep struct {
	StepName  string        `json:"step_name"`
	StepType  string        `json:"step_type"`
	Valid     bool          `json:"valid"`
	Duration  time.Duration `json:"duration"`
	Error     string        `json:"error,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// ProofGenerationMetrics contains metrics about proof generation
type ProofGenerationMetrics struct {
	TotalTime    time.Duration `json:"total_time"`
	ProofSize    int           `json:"proof_size"`
	CacheHits    int           `json:"cache_hits"`
	CacheMisses  int           `json:"cache_misses"`
	Steps        []VerificationStep `json:"steps,omitempty"`
}

// NewProofGenerator creates a new proof generator
func NewProofGenerator(liteClientAdapter *LiteClientProofGenerator, config *ProofConfig) (*ProofGenerator, error) {
	if liteClientAdapter == nil {
		return nil, fmt.Errorf("lite client adapter cannot be nil")
	}
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	return &ProofGenerator{
		liteClientProofGen: liteClientAdapter,
		config:             config,
	}, nil
}

// GenerateProof generates a proof using only the lite client
func (pg *ProofGenerator) GenerateProof(ctx context.Context, req *ProofRequest) (*CertenProof, error) {
	if req == nil {
		return nil, fmt.Errorf("proof request cannot be nil")
	}

	// Enforce required AccountURL
	accountURL := req.AccountURL
	if accountURL == "" {
		return nil, fmt.Errorf("AccountURL must be provided for proof generation (no derivation from tx hash)")
	}

	startTime := time.Now()

	// Generate lite client proof
	completeProof, err := pg.liteClientProofGen.GenerateAccumulateProof(ctx, accountURL)
	if err != nil {
		return nil, fmt.Errorf("lite client proof generation failed: %w", err)
	}

	// Verify the proof
	verificationPassed := false
	if err := pg.liteClientProofGen.VerifyProof(completeProof); err == nil {
		verificationPassed = true
	}

	// Create adapter and convert to CertenProof
	adapter := NewCertenProofAdapter(completeProof, req, pg.config.ValidatorID)
	certenProof := adapter.ToCertenProof()
	if certenProof == nil {
		return nil, fmt.Errorf("failed to convert CompleteProof to CertenProof")
	}

	// Set verification status
	if certenProof.VerificationStatus == nil {
		certenProof.VerificationStatus = &VerificationStatusData{
			ComponentStatus: make(map[string]bool),
			VerifiedAt:      time.Now(),
		}
	}

	// Set lite client component status
	certenProof.VerificationStatus.ComponentStatus["lite_client"] = verificationPassed
	pg.calculateOverallStatus(certenProof)

	// Set processing time
	certenProof.ProcessingTime = time.Since(startTime)

	return certenProof, nil
}

// calculateOverallStatus calculates the overall verification status
func (pg *ProofGenerator) calculateOverallStatus(certenProof *CertenProof) {
	if certenProof.VerificationStatus == nil {
		return
	}

	// For lite-client-only mode, overall status is just the lite client status
	liteClientValid, exists := certenProof.VerificationStatus.ComponentStatus["lite_client"]
	if !exists {
		certenProof.VerificationStatus.OverallValid = false
		certenProof.VerificationStatus.Confidence = 0.0
		certenProof.VerificationStatus.VerificationLevel = "failed"
		return
	}

	certenProof.VerificationStatus.OverallValid = liteClientValid
	if liteClientValid {
		certenProof.VerificationStatus.Confidence = 1.0
		certenProof.VerificationStatus.VerificationLevel = "complete"
	} else {
		certenProof.VerificationStatus.Confidence = 0.0
		certenProof.VerificationStatus.VerificationLevel = "failed"
	}
}

// calculateProofSize calculates the size of the proof in bytes
func (pg *ProofGenerator) calculateProofSize(certenProof *CertenProof) int {
	if certenProof == nil || certenProof.LiteClientProof == nil {
		return 0
	}
	return len(fmt.Sprintf("%+v", certenProof.LiteClientProof.CompleteProof))
}