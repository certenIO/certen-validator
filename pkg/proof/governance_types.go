// Copyright 2025 Certen Protocol
//
// Portable Governance Proof Types for Certen Validator
// These types mirror the consolidated_governance-proof types for importability.
// Based on CERTEN Governance Proof Specification v3-governance-kpsw-exec-4.0
//
// Per Whitepaper Section 3.4.1:
// - G0: Inclusion and Finality Only
// - G1: Governance Correctness (Authority Validated)
// - G2: Governance + Outcome Binding

package proof

import (
	"encoding/json"
	"time"
)

// GovernanceLevel defines the governance proof level
type GovernanceLevel string

const (
	// GovLevelG0 - Inclusion and Finality Only (No Governance)
	GovLevelG0 GovernanceLevel = "G0"
	// GovLevelG1 - Governance Correctness (Default)
	GovLevelG1 GovernanceLevel = "G1"
	// GovLevelG2 - Governance Correctness + Outcome Binding
	GovLevelG2 GovernanceLevel = "G2"
)

// GovernanceSpecVersion is the CERTEN specification version
const GovernanceSpecVersion = "v3-governance-kpsw-exec-4.0"

// =============================================================================
// Core Execution Types
// =============================================================================

// ExecTerms represents execution witness terms
type ExecTerms struct {
	MBI     int64  `json:"mbi"`     // Major Block Index
	Witness string `json:"witness"` // Execution witness (receipt anchor)
}

// ExecutionContext represents execution context from G1 authority snapshot
type ExecutionContext struct {
	Scope             string `json:"scope"`
	TxHash            string `json:"tx_hash"`
	ExecMBI           int64  `json:"exec_mbi"`
	ExecWitness       string `json:"exec_witness"`
	AuthorityVerified bool   `json:"authority_verified"`
}

// =============================================================================
// Receipt Types
// =============================================================================

// GovReceiptData represents Accumulate receipt information
type GovReceiptData struct {
	Start          string     `json:"start"`          // Receipt start hash
	Anchor         string     `json:"anchor"`         // Receipt anchor hash
	LocalBlock     int64      `json:"localBlock"`     // Local block number
	LocalBlockTime *time.Time `json:"localBlockTime"` // Local block time (optional)
	MajorBlock     *int64     `json:"majorBlock"`     // Major block number (optional)
	End            *string    `json:"end"`            // Receipt end hash (optional)
}

// =============================================================================
// Signature and Authorization Types
// =============================================================================

// SignatureData represents Ed25519 signature information
type SignatureData struct {
	Type            string    `json:"type"`            // Should be "ed25519"
	PublicKey       string    `json:"publicKey"`       // 32-byte hex
	Signature       string    `json:"signature"`       // 64-byte hex
	Signer          string    `json:"signer"`          // acc://...
	SignerVersion   int64     `json:"signerVersion"`   // Key page version
	Timestamp       *int64    `json:"timestamp"`       // Optional signature timestamp
	TransactionHash string    `json:"transactionHash"` // TX_HASH
	TXID            string    `json:"txID"`            // MSGID format
	SecurityLevel   string    `json:"securityLevel"`   // Enhanced security level
	VerifiedTime    time.Time `json:"verifiedTime"`    // When verification occurred
}

// ValidatedSignature represents a signature with cryptographic validation
type ValidatedSignature struct {
	MessageID                 string         `json:"messageID"`                 // MSGID
	MessageHash               string         `json:"messageHash"`               // Entry hash
	Receipt                   GovReceiptData `json:"receipt"`                   // Timing receipt
	Signature                 SignatureData  `json:"signature"`                 // Signature data
	TimingVerified            bool           `json:"timingVerified"`            // localBlock <= EXEC_MBI
	TransactionHashVerified   bool           `json:"transactionHashVerified"`   // signature.transactionHash == TX_HASH
	CryptographicallyVerified bool           `json:"cryptographicallyVerified"` // Ed25519 verified
	SecurityLevel             string         `json:"securityLevel"`             // Security verification level
	VerificationTime          time.Time      `json:"verificationTime"`          // When verification occurred
	IntegrityHash             string         `json:"integrityHash"`             // Artifact integrity hash
}

// =============================================================================
// Authority and Key Page Types
// =============================================================================

// KeyPageState represents key page state at a specific version
type KeyPageState struct {
	Version   uint64   `json:"version"`   // Key page version
	Keys      []string `json:"keys"`      // List of key hashes (SHA256)
	Threshold uint64   `json:"threshold"` // Required signature threshold
}

// GenesisEvent represents the syntheticCreateIdentity event
type GenesisEvent struct {
	EntryHash  string         `json:"entryHash"`  // Entry hash of genesis transaction
	LocalBlock int64          `json:"localBlock"` // Genesis block number
	Receipt    GovReceiptData `json:"receipt"`    // Genesis receipt
	TxType     string         `json:"txType"`     // Should be "syntheticCreateIdentity"
	PageState  KeyPageState   `json:"pageState"`  // Initial key page state
}

// MutationEvent represents an updateKeyPage mutation
type MutationEvent struct {
	EntryHash     string         `json:"entryHash"`     // Entry hash of mutation transaction
	LocalBlock    int64          `json:"localBlock"`    // Mutation block number
	Receipt       GovReceiptData `json:"receipt"`       // Mutation receipt
	TxType        string         `json:"txType"`        // Should be "updateKeyPage"
	PreviousState KeyPageState   `json:"previousState"` // State before mutation
	NewState      KeyPageState   `json:"newState"`      // State after mutation
}

// ValidationSummary provides validation summary for authority snapshot
type ValidationSummary struct {
	GenesisFound     bool   `json:"genesisFound"`     // Genesis event located
	MutationsApplied int    `json:"mutationsApplied"` // Number of mutations applied
	TotalEntries     int    `json:"totalEntries"`     // Total P#main entries examined
	FinalVersion     uint64 `json:"finalVersion"`     // Final key page version
	FinalThreshold   uint64 `json:"finalThreshold"`   // Final threshold
	FinalKeyCount    int    `json:"finalKeyCount"`    // Final number of keys
}

// AuthoritySnapshot represents complete authority snapshot at execution time
type AuthoritySnapshot struct {
	Page       string            `json:"page"`       // Key page URL
	ExecTerms  ExecTerms         `json:"execTerms"`  // Execution terms
	StateExec  KeyPageState      `json:"stateExec"`  // Key page state at execution
	Genesis    GenesisEvent      `json:"genesis"`    // Genesis event
	Mutations  []MutationEvent   `json:"mutations"`  // All mutations <= EXEC_MBI
	Validation ValidationSummary `json:"validation"` // Validation summary
}

// =============================================================================
// G2 Payload and Effect Verification Types
// =============================================================================

// PayloadVerification represents result of payload verification
type PayloadVerification struct {
	Verified            bool                   `json:"verified"`            // Payload verification result
	ComputedTxHash      string                 `json:"computedTxHash"`      // Hash computed by Go verifier
	ExpectedTxHash      string                 `json:"expectedTxHash"`      // Expected TX_HASH
	GoVerifierOutput    string                 `json:"goVerifierOutput"`    // Raw Go verifier stdout
	GoVerifierErrors    string                 `json:"goVerifierErrors"`    // Raw Go verifier stderr
	VerificationDetails map[string]interface{} `json:"verificationDetails"` // Additional details
}

// EffectVerification represents result of transaction effect verification
type EffectVerification struct {
	EffectType    string                 `json:"effectType"`    // Transaction effect type
	Verified      bool                   `json:"verified"`      // Effect verification result
	ExpectedValue *string                `json:"expectedValue"` // Expected effect value
	ComputedValue *string                `json:"computedValue"` // Computed effect value
	Details       map[string]interface{} `json:"details"`       // Additional details
}

// VerificationResult represents a generic verification result
type VerificationResult struct {
	Verified bool   `json:"verified"` // Verification result
	Details  string `json:"details"`  // Verification details
}

// OutcomeLeaf represents G2 outcome leaf with payload and effect verification
type OutcomeLeaf struct {
	PayloadBinding     PayloadVerification `json:"payloadBinding"`     // Payload authenticity
	ReceiptBinding     VerificationResult  `json:"receiptBinding"`     // Receipt binding
	WitnessConsistency VerificationResult  `json:"witnessConsistency"` // Witness consistency
	Effect             EffectVerification  `json:"effect"`             // Effect verification
}

// =============================================================================
// Security Report Type
// =============================================================================

// SecurityReport provides comprehensive security information
type SecurityReport struct {
	Level             string    `json:"level"`
	TotalVerified     int64     `json:"totalVerified"`
	TotalFailed       int64     `json:"totalFailed"`
	AuditEventsCount  int       `json:"auditEventsCount"`
	CustodyChainValid bool      `json:"custodyChainValid"`
	GeneratedAt       time.Time `json:"generatedAt"`
}

// =============================================================================
// Governance Proof Result Types
// =============================================================================

// G0Result represents G0 proof result (Inclusion and Finality Only)
type G0Result struct {
	EntryHashExec     string         `json:"entry_hash_exec"`     // Execution entry hash (TXID)
	TXID              string         `json:"txid"`                // Message ID hash
	TxHash            string         `json:"tx_hash"`             // Canonical transaction hash
	ExecMBI           int64          `json:"exec_mbi"`            // Execution MBI
	ExecWitness       string         `json:"exec_witness"`        // Execution witness (receipt anchor)
	Scope             string         `json:"scope"`               // Transaction scope
	Chain             string         `json:"chain"`               // Chain name (typically "main")
	ExpandedMessageID string         `json:"expanded_message_id"` // Expanded message.id for binding
	Principal         string         `json:"principal"`           // Extracted principal
	Receipt           GovReceiptData `json:"receipt"`             // Execution receipt
	G0ProofComplete   bool           `json:"g0_proof_complete"`   // G0 proof completion flag
}

// G1Result represents G1 proof result with cryptographic verification
type G1Result struct {
	G0Result                          // Inherit all G0 results
	AuthoritySnapshot   AuthoritySnapshot    `json:"authority_snapshot"`    // KPSW-EXEC snapshot
	ValidatedSignatures []ValidatedSignature `json:"validated_signatures"`  // All validated signatures
	UniqueValidKeys     int                  `json:"unique_valid_keys"`     // Unique valid key count
	RequiredThreshold   uint64               `json:"required_threshold"`    // Required threshold
	ThresholdSatisfied  bool                 `json:"threshold_satisfied"`   // Threshold satisfaction
	ExecutionSuccess    bool                 `json:"execution_success"`     // Execution success
	TimingValid         bool                 `json:"timing_valid"`          // Timing validation
	G1ProofComplete     bool                 `json:"g1_proof_complete"`     // G1 proof complete
	ConcurrencyEnabled  bool                 `json:"concurrency_enabled"`   // Concurrency was used
	WorkerCount         int                  `json:"worker_count"`          // Number of workers used
	ProcessingTimeMs    int64                `json:"processing_time_ms"`    // Total processing time

	// Enhanced cryptographic security fields
	CryptographicSecurity bool            `json:"cryptographic_security"` // Enhanced crypto enabled
	SecurityReport        *SecurityReport `json:"security_report"`        // Comprehensive security report
	Ed25519Verified       int64           `json:"ed25519_verified"`       // Number of Ed25519 verifications
	AuditTrailEvents      int             `json:"audit_trail_events"`     // Number of audit events
	BundleIntegrityHash   string          `json:"bundle_integrity_hash"`  // Bundle integrity hash
}

// G2Result represents G2 proof result (Governance + Outcome Binding)
type G2Result struct {
	G1Result                         // Inherit all G1 results
	OutcomeLeaf     OutcomeLeaf `json:"outcome_leaf"`      // Outcome leaf with payload binding
	PayloadVerified bool        `json:"payload_verified"`  // Payload authenticity verified
	EffectVerified  bool        `json:"effect_verified"`   // Transaction effect verified
	G2ProofComplete bool        `json:"g2_proof_complete"` // G2 proof completion flag
	SecurityLevel   string      `json:"security_level"`    // Security level description
}

// =============================================================================
// Governance Proof Wrapper
// =============================================================================

// GovernanceProof wraps the governance proof with level information
type GovernanceProof struct {
	Level       GovernanceLevel `json:"level"`
	SpecVersion string          `json:"spec_version"`
	GeneratedAt time.Time       `json:"generated_at"`

	// Level-specific results (only one will be populated based on Level)
	G0 *G0Result `json:"g0,omitempty"`
	G1 *G1Result `json:"g1,omitempty"`
	G2 *G2Result `json:"g2,omitempty"`
}

// IsValid returns whether the governance proof is valid at its level
func (gp *GovernanceProof) IsValid() bool {
	switch gp.Level {
	case GovLevelG0:
		return gp.G0 != nil && gp.G0.G0ProofComplete
	case GovLevelG1:
		return gp.G1 != nil && gp.G1.G1ProofComplete
	case GovLevelG2:
		return gp.G2 != nil && gp.G2.G2ProofComplete
	default:
		return false
	}
}

// ToJSON serializes the governance proof to JSON
func (gp *GovernanceProof) ToJSON() (json.RawMessage, error) {
	return json.Marshal(gp)
}

// GovernanceProofFromJSON deserializes a governance proof from JSON
func GovernanceProofFromJSON(data json.RawMessage) (*GovernanceProof, error) {
	var gp GovernanceProof
	if err := json.Unmarshal(data, &gp); err != nil {
		return nil, err
	}
	return &gp, nil
}

// NewG0GovernanceProof creates a new G0 governance proof
func NewG0GovernanceProof(g0 *G0Result) *GovernanceProof {
	return &GovernanceProof{
		Level:       GovLevelG0,
		SpecVersion: GovernanceSpecVersion,
		GeneratedAt: time.Now(),
		G0:          g0,
	}
}

// NewG1GovernanceProof creates a new G1 governance proof
func NewG1GovernanceProof(g1 *G1Result) *GovernanceProof {
	return &GovernanceProof{
		Level:       GovLevelG1,
		SpecVersion: GovernanceSpecVersion,
		GeneratedAt: time.Now(),
		G1:          g1,
	}
}

// NewG2GovernanceProof creates a new G2 governance proof
func NewG2GovernanceProof(g2 *G2Result) *GovernanceProof {
	return &GovernanceProof{
		Level:       GovLevelG2,
		SpecVersion: GovernanceSpecVersion,
		GeneratedAt: time.Now(),
		G2:          g2,
	}
}
