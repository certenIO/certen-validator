// Copyright 2025 Certen Protocol
//
// Canonical Intent Data Model - RFC 8785 Compliant JSON Processing
// Implements deterministic intent processing with raw message preservation

package consensus

import (
	"encoding/json"
	"fmt"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof"
	certenproof "github.com/certen/independant-validator/pkg/proof"
)

// CertenIntent represents an intent that needs to be processed - canonical definition
// This is the single source of truth for CertenIntent across the entire codebase.
//
// ARCHITECTURE: This type should ONLY be referenced via intent.CertenIntent alias in other packages.
// Do NOT import consensus.CertenIntent directly - always use intent.CertenIntent to ensure
// consistent type usage and prevent import cycles.
//
// IMPORTANT: The 4 data fields (IntentData, CrossChainData, GovernanceData, ReplayData) are
// **raw (non-canonical)** JSON bytes as extracted from the Accumulate transaction. These are NOT:
//   - Canonicalized (deterministic field ordering)
//   - Hashed or committed to
//   - Validated beyond basic JSON parsing
//
// Canonicalization, hashing, and cryptographic commitment are handled downstream in the
// commitment/proof pipeline during consensus processing, NOT at this intent discovery layer.
//
// This separation allows:
//   - Clean intent discovery focused on extraction and routing
//   - Deterministic consensus processing with canonical form
//   - Flexible proof generation with proper cryptographic commitments
type CertenIntent struct {
	IntentID        string `json:"intentId"`
	TransactionHash string `json:"transactionHash"`
	AccountURL      string `json:"accountUrl"`      // Principal account URL (where TX lives): .../data
	OrganizationADI string `json:"organizationAdi"` // Organization ADI (for policy/routing): org ADI only
	Partition       string `json:"partition"`       // BVN partition name (e.g., "bvn1") for L1-L3 proof generation
	IntentData      []byte `json:"intentData"`      // Raw JSON blob - canonicalized later in commitment pipeline
	CrossChainData  []byte `json:"crossChainData"`  // Raw JSON blob - canonicalized later in commitment pipeline
	GovernanceData  []byte `json:"governanceData"`  // Raw JSON blob - canonicalized later in commitment pipeline
	ReplayData      []byte `json:"replayData"`      // Raw JSON blob - canonicalized later in commitment pipeline

	// CRITICAL: Proof class determines execution routing per FIRST_PRINCIPLES 2.5
	// On-demand vs on-cadence proofs are NEVER interchangeable
	ProofClass      string `json:"proofClass"` // "on_demand" | "on_cadence" - extracted from IntentData
}

// IntentData represents the parsed intent data blob
type IntentData struct {
	Kind                     string                 `json:"kind"`           // "CERTEN_INTENT"
	Version                  string                 `json:"version"`        // "1.0"
	IntentType               string                 `json:"intentType"`     // "single_leg_cross_chain_transfer"
	Description              string                 `json:"description"`
	OrganizationAdi          string                 `json:"organizationAdi"`
	IntentID                 string                 `json:"intent_id"`
	CreatedBy                string                 `json:"created_by"`
	CreatedAt                string                 `json:"created_at"`
	IntentClass              string                 `json:"intent_class"`
	RegulatoryJurisdiction   string                 `json:"regulatory_jurisdiction"`
	Tags                     []string               `json:"tags"`
	Initiator                map[string]interface{} `json:"initiator"`
	Priority                 string                 `json:"priority"`
	RiskLevel                string                 `json:"risk_level"`
	ComplianceRequired       bool                   `json:"compliance_required"`

	// CRITICAL: ProofClass determines execution routing - never interchangeable
	ProofClass               string                 `json:"proof_class"` // "on_demand" | "on_cadence"
	EstimatedGas             string                 `json:"estimated_gas"`
	EstimatedFees            map[string]interface{} `json:"estimated_fees"`

	// OrganizationADI is a legacy field; OrganizationAdi is canonical.
	OrganizationADI          string                 `json:"organizationADI,omitempty"`
}

// CrossChainEnvelope represents the parsed cross-chain data blob
type CrossChainEnvelope struct {
	Protocol               string                 `json:"protocol"`        // "CERTEN"
	Version                string                 `json:"version"`         // "1.0"
	OperationGroupId       string                 `json:"operationGroupId"`
	Legs                   []CCLeg                `json:"legs"`
	Atomicity              map[string]interface{} `json:"atomicity"`
	ExecutionConstraints   map[string]interface{} `json:"execution_constraints"`
	CrossChainRouting      map[string]interface{} `json:"cross_chain_routing"`

	// OperationGroup is a legacy field; OperationGroupId is canonical.
	OperationGroup         string                 `json:"operationGroup,omitempty"`
}

// CCLeg represents a single cross-chain operation leg
type CCLeg struct {
	LegID   string `json:"legId"`
	Role    string `json:"role"`    // "source" or "destination"
	Chain   string `json:"chain"`   // "ethereum"
	ChainID uint64 `json:"chainId"` // 11155111 for Sepolia
	Network string `json:"network"` // "sepolia"

	Asset struct {
		Symbol   string `json:"symbol"`   // "ETH"
		Decimals uint8  `json:"decimals"` // 18
		Native   bool   `json:"native"`   // true
	} `json:"asset"`

	From      string `json:"from"`      // Source address
	To        string `json:"to"`        // Destination address
	AmountEth string `json:"amountEth"` // "0.005"
	AmountWei string `json:"amountWei"` // "5000000000000000"

	AnchorContract struct {
		Address          string `json:"address"`          // Contract address
		FunctionSelector string `json:"functionSelector"` // Function selector
	} `json:"anchorContract"`

	GasPolicy struct {
		MaxFeePerGasGwei        string `json:"maxFeePerGasGwei"`
		MaxPriorityFeePerGasGwei string `json:"maxPriorityFeePerGasGwei"`
		GasLimit                uint64 `json:"gasLimit"`
		Payer                   string `json:"payer"`
	} `json:"gasPolicy"`
}

// GovernanceData represents the parsed governance data blob
type GovernanceData struct {
	OrganizationAdi string `json:"organizationAdi"`

	Authorization struct {
		RequiredKeyBook      string   `json:"required_key_book"`
		RequiredKeyPage      string   `json:"required_key_page"`
		SignatureThreshold   int      `json:"signature_threshold"`
		RequiredSigners      []string `json:"required_signers"`
		AuthorizationHash    string   `json:"authorization_hash"`

		// Optional: explicit role mapping
		Roles []struct {
			Role    string `json:"role"`
			KeyPage string `json:"keyPage"`
		} `json:"roles"`
	} `json:"authorization"`

	ValidationRules   map[string]interface{} `json:"validation_rules"`
	ComplianceChecks  map[string]interface{} `json:"compliance_checks"`

	// OrganizationADI is a legacy field; OrganizationAdi is canonical.
	OrganizationADI   string                 `json:"organizationADI,omitempty"`
}

// ReplayData represents the parsed replay protection data blob
type ReplayData struct {
	Nonce                    string                 `json:"nonce"`
	CreatedAt                int64                  `json:"created_at"`  // Unix timestamp in SECONDS (not ms) since epoch
	ExpiresAt                int64                  `json:"expires_at"`  // Unix timestamp in SECONDS (not ms) since epoch
	IntentHash               string                 `json:"intent_hash"`
	ChainNonces              map[string]interface{} `json:"chain_nonces"`
	ExecutionWindow          map[string]interface{} `json:"execution_window"`
	Security                 map[string]interface{} `json:"security"`

	// Legacy fields for backward compatibility
	ClientOperationID        string `json:"clientOperationId,omitempty"`
	ClientNonce              int64  `json:"clientNonce,omitempty"`
	NotBefore                string `json:"notBefore,omitempty"`  // ISO-8601
	MaxExecutionDelaySeconds int64  `json:"maxExecutionDelaySeconds,omitempty"`
	ReplayProtection         map[string]interface{} `json:"replayProtection,omitempty"`
}

// BuilderInputs represents the inputs needed for validator block building
type BuilderInputs struct {
	Intent       *CertenIntent
	Governance   GovernanceInputs
	Execution    ExecutionInputs
	AnchorRef    AccumulateAnchorReference
	SyntheticTxs []SyntheticTx
	ResultAtts   []ResultAttestation
	BlockHeight  uint64

	// Lite client proof - complete cryptographic proof chain
	// from account state to network consensus via the Accumulate lite client
	LiteClientProof *proof.CompleteProof `json:"lite_client_proof,omitempty"`
}

// GovernanceInputs are supplied from chain state & signatures
// Per CERTEN spec v3-governance-kpsw-exec-4.0, governance proofs are generated
// AFTER L1-L4 lite client proof completes (dependency chain)
type GovernanceInputs struct {
	// === LEGACY FIELDS (backward compatibility) ===
	Leaves                []AuthorizationLeaf
	BLSAggregateSignature string

	// === FULL GOVERNANCE PROOF ARTIFACTS (G0/G1/G2) ===
	// Generated AFTER L1-L4 lite client proof completes

	// G0Proof: Inclusion & Finality - uses L1-L4 as foundation
	G0Proof *certenproof.G0Result `json:"g0_proof,omitempty"`

	// G1Proof: Authority Validated - uses G0 + key page authority
	G1Proof *certenproof.G1Result `json:"g1_proof,omitempty"`

	// G2Proof: Outcome Binding - uses G1 + effect verification (post-execution)
	G2Proof *certenproof.G2Result `json:"g2_proof,omitempty"`

	// GovernanceLevel: highest proof level achieved ("G0", "G1", "G2")
	GovernanceLevel string `json:"governance_level,omitempty"`
}

// ExecutionInputs captures current execution stage (pre or post)
type ExecutionInputs struct {
	Stage               string                // "pre-execution" or "post-execution"
	ValidatorSignatures []string
	ExternalResults     []ExternalChainResult

	// CRITICAL: ProofClass routing per FIRST_PRINCIPLES 2.5
	ProofClass          string                // "on_demand" | "on_cadence" - flows to ExecutionProof
}

// AccumulateAnchorReference represents the Accumulate blockchain anchor
type AccumulateAnchorReference struct {
	BlockHash   string `json:"block_hash"`
	BlockHeight uint64 `json:"block_height"`
	TxHash      string `json:"tx_hash"`
	AccountURL  string `json:"account_url,omitempty"` // Source Accumulate account URL
}

// IntentMetadata represents strongly typed metadata used in BFT pipeline
// This replaces raw map[string]interface{} for better type safety
type IntentMetadata struct {
	AccountURL string `json:"account_url,omitempty"`
	// Add other fields as needed for BFT operations
}

// OperationID returns the canonical operation ID computed from the 4 blob hashes
// This is the ONLY function that should compute operation commitments.
// Returns the operationID with the "0x" prefix.
func (ci *CertenIntent) OperationID() (string, error) {
	_, opHex, err := certenproof.ComputeCanonical4BlobHash(
		ci.IntentData,
		ci.CrossChainData,
		ci.GovernanceData,
		ci.ReplayData,
	)
	if err != nil {
		return "", fmt.Errorf("compute canonical 4-blob hash: %w", err)
	}
	return "0x" + opHex, nil
}

// ParseCrossChain returns the typed cross-chain envelope from the raw JSON blob
func (ci *CertenIntent) ParseCrossChain() (*CrossChainEnvelope, error) {
	var env CrossChainEnvelope
	if err := json.Unmarshal(ci.CrossChainData, &env); err != nil {
		return nil, fmt.Errorf("parse cross-chain data: %w", err)
	}
	return &env, nil
}

// ParseReplay returns the typed replay data from the raw JSON blob
func (ci *CertenIntent) ParseReplay() (*ReplayData, error) {
	var rd ReplayData
	if err := json.Unmarshal(ci.ReplayData, &rd); err != nil {
		return nil, fmt.Errorf("parse replay data: %w", err)
	}
	return &rd, nil
}

// ParseGovernance returns the typed governance data from the raw JSON blob
func (ci *CertenIntent) ParseGovernance() (*GovernanceData, error) {
	var gd GovernanceData
	if err := json.Unmarshal(ci.GovernanceData, &gd); err != nil {
		return nil, fmt.Errorf("parse governance data: %w", err)
	}
	return &gd, nil
}

// ParseIntentData returns the typed intent data from the raw JSON blob
func (ci *CertenIntent) ParseIntentData() (*IntentData, error) {
	var id IntentData
	if err := json.Unmarshal(ci.IntentData, &id); err != nil {
		return nil, fmt.Errorf("parse intent data: %w", err)
	}
	return &id, nil
}

// ExtractAndSetProofClass extracts the proof class from IntentData and sets it on the CertenIntent
// This ensures proof class is visible throughout the consensus pipeline per FIRST_PRINCIPLES 2.5
func (ci *CertenIntent) ExtractAndSetProofClass() error {
	if ci.ProofClass != "" {
		return nil // Already set
	}

	// Parse IntentData to extract proof class
	intentData, err := ci.ParseIntentData()
	if err != nil {
		return fmt.Errorf("parse intent data for proof class: %w", err)
	}

	// Extract proof class from canonical IntentData
	if intentData.ProofClass != "" {
		ci.ProofClass = intentData.ProofClass
	} else {
		// Fallback: infer from priority or other fields if not explicitly set
		// High priority typically indicates on-demand
		if intentData.Priority == "high" || intentData.Priority == "urgent" {
			ci.ProofClass = "on_demand"
		} else {
			ci.ProofClass = "on_cadence"
		}
	}

	// Validate proof class
	if ci.ProofClass != "on_demand" && ci.ProofClass != "on_cadence" {
		return fmt.Errorf("invalid proof class '%s' - must be 'on_demand' or 'on_cadence'", ci.ProofClass)
	}

	return nil
}

// GetProofClass returns the proof class, ensuring it's set
func (ci *CertenIntent) GetProofClass() (string, error) {
	if err := ci.ExtractAndSetProofClass(); err != nil {
		return "", err
	}
	return ci.ProofClass, nil
}

// Validate performs comprehensive validation of the CertenIntent structure
// F.1.1 remediation: Input validation before processing
// This should be called before any intent processing to ensure data integrity
func (ci *CertenIntent) Validate() error {
	// Required field: IntentID
	if ci.IntentID == "" {
		return fmt.Errorf("intent validation failed: empty intent ID")
	}

	// Required field: TransactionHash
	if ci.TransactionHash == "" {
		return fmt.Errorf("intent validation failed: empty transaction hash")
	}
	// Transaction hash should be 64 hex characters (32 bytes)
	if len(ci.TransactionHash) != 64 {
		return fmt.Errorf("intent validation failed: invalid transaction hash length: expected 64, got %d", len(ci.TransactionHash))
	}

	// Required field: IntentData blob
	if len(ci.IntentData) == 0 {
		return fmt.Errorf("intent validation failed: empty intent data")
	}

	// Required field: CrossChainData blob
	if len(ci.CrossChainData) == 0 {
		return fmt.Errorf("intent validation failed: empty cross-chain data")
	}

	// Required field: GovernanceData blob
	if len(ci.GovernanceData) == 0 {
		return fmt.Errorf("intent validation failed: empty governance data")
	}

	// Required field: ReplayData blob
	if len(ci.ReplayData) == 0 {
		return fmt.Errorf("intent validation failed: empty replay data")
	}

	// Validate each blob is valid JSON
	var temp interface{}
	if err := json.Unmarshal(ci.IntentData, &temp); err != nil {
		return fmt.Errorf("intent validation failed: invalid JSON in intent data: %w", err)
	}
	if err := json.Unmarshal(ci.CrossChainData, &temp); err != nil {
		return fmt.Errorf("intent validation failed: invalid JSON in cross-chain data: %w", err)
	}
	if err := json.Unmarshal(ci.GovernanceData, &temp); err != nil {
		return fmt.Errorf("intent validation failed: invalid JSON in governance data: %w", err)
	}
	if err := json.Unmarshal(ci.ReplayData, &temp); err != nil {
		return fmt.Errorf("intent validation failed: invalid JSON in replay data: %w", err)
	}

	// Validate proof class if set
	if ci.ProofClass != "" {
		if ci.ProofClass != "on_demand" && ci.ProofClass != "on_cadence" {
			return fmt.Errorf("intent validation failed: invalid proof class '%s' - must be 'on_demand' or 'on_cadence'", ci.ProofClass)
		}
	}

	// Optional: Validate AccountURL format if provided
	if ci.AccountURL != "" {
		if len(ci.AccountURL) < 6 || ci.AccountURL[:6] != "acc://" {
			return fmt.Errorf("intent validation failed: invalid account URL format (must start with 'acc://')")
		}
	}

	return nil
}

// ValidateForExecution performs additional validation required before execution
// This is stricter than basic Validate() and ensures execution readiness
func (ci *CertenIntent) ValidateForExecution(blockHeight uint64) error {
	// First run basic validation
	if err := ci.Validate(); err != nil {
		return err
	}

	// Block height must be non-zero
	if blockHeight == 0 {
		return fmt.Errorf("intent validation for execution failed: zero block height")
	}

	// AccountURL is required for execution routing
	if ci.AccountURL == "" {
		return fmt.Errorf("intent validation for execution failed: empty account URL")
	}

	// OrganizationADI is required for governance
	if ci.OrganizationADI == "" {
		return fmt.Errorf("intent validation for execution failed: empty organization ADI")
	}

	// Proof class must be extractable
	if _, err := ci.GetProofClass(); err != nil {
		return fmt.Errorf("intent validation for execution failed: %w", err)
	}

	// Parse and validate cross-chain data has at least one leg
	ccData, err := ci.ParseCrossChain()
	if err != nil {
		return fmt.Errorf("intent validation for execution failed: %w", err)
	}
	if len(ccData.Legs) == 0 {
		return fmt.Errorf("intent validation for execution failed: no cross-chain legs defined")
	}

	// Validate replay data for expiration
	replayData, err := ci.ParseReplay()
	if err != nil {
		return fmt.Errorf("intent validation for execution failed: %w", err)
	}
	if replayData.ExpiresAt > 0 {
		// Note: Time validation should be done by caller with current time
		// This just ensures the field is present if set
		if replayData.CreatedAt <= 0 {
			return fmt.Errorf("intent validation for execution failed: expires_at set but created_at missing")
		}
	}

	return nil
}
