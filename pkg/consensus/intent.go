// Copyright 2025 Certen Protocol
//
// Canonical Intent Data Model - RFC 8785 Compliant JSON Processing
// Implements deterministic intent processing with raw message preservation

package consensus

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof"
	certenproof "github.com/certen/independant-validator/pkg/proof"
)

// HIGH-002: Package-level replay store for persistent nonce tracking.
// Set via SetReplayStore() during initialization. Falls back to in-memory
// map if no persistent store is configured (development mode only).
var (
	globalReplayStore   ReplayStore
	globalReplayStoreMu sync.RWMutex

	// Fallback in-memory map for when no persistent store is configured
	fallbackNonces   = make(map[string]bool)
	fallbackNoncesMu sync.Mutex
)

// SetReplayStore sets the package-level persistent replay store.
// Must be called during initialization before any intents are processed.
func SetReplayStore(store ReplayStore) {
	globalReplayStoreMu.Lock()
	defer globalReplayStoreMu.Unlock()
	globalReplayStore = store
}

// getReplayStore returns the current replay store (or nil if not set).
func getReplayStore() ReplayStore {
	globalReplayStoreMu.RLock()
	defer globalReplayStoreMu.RUnlock()
	return globalReplayStore
}

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
	UserID          string `json:"userId,omitempty"` // User who created the intent (from intent_data.created_by)
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
	Version                string                 `json:"version"`         // "1.0" (single-leg) or "2.0" (multi-leg)
	OperationGroupId       string                 `json:"operationGroupId"`
	Legs                   []CCLeg                `json:"legs"`            // 1-N legs for multi-leg support
	Atomicity              map[string]interface{} `json:"atomicity"`
	ExecutionConstraints   map[string]interface{} `json:"execution_constraints"`
	CrossChainRouting      map[string]interface{} `json:"cross_chain_routing"`

	// Multi-leg coordination (Version 2.0+)
	// ExecutionMode determines how legs are executed:
	// - "sequential": Legs execute in sequence_order, one chain group at a time
	// - "parallel": All chain groups execute simultaneously
	// - "atomic": All legs must succeed or all are rolled back
	ExecutionMode          string                 `json:"execution_mode,omitempty"`

	// LegDependencies explicitly define which legs depend on others
	LegDependencies        []LegDependency        `json:"leg_dependencies,omitempty"`

	// RollbackPolicy defines behavior when a leg fails in atomic mode
	RollbackPolicy         *RollbackPolicy        `json:"rollback_policy,omitempty"`

	// TimeoutPolicy defines global timeout behavior for multi-leg intent
	TimeoutPolicy          *TimeoutPolicy         `json:"timeout_policy,omitempty"`

	// OperationGroup is a legacy field; OperationGroupId is canonical.
	OperationGroup         string                 `json:"operationGroup,omitempty"`
}

// LegDependency defines an explicit dependency between legs
type LegDependency struct {
	LegID          string `json:"leg_id"`           // The leg that has the dependency
	DependsOnLegID string `json:"depends_on_leg_id"` // The leg it depends on
	ConditionType  string `json:"condition_type"`    // "success", "completion", "confirmation"
}

// RollbackPolicy defines rollback behavior for atomic multi-leg intents
type RollbackPolicy struct {
	Enabled           bool   `json:"enabled"`             // Whether rollback is enabled
	RollbackOnFailure bool   `json:"rollback_on_failure"` // Rollback all legs if one fails
	RollbackOnTimeout bool   `json:"rollback_on_timeout"` // Rollback if timeout exceeded
	MaxRollbackLegs   int    `json:"max_rollback_legs"`   // Maximum legs to attempt rollback (0 = all)
}

// TimeoutPolicy defines timeout behavior for multi-leg execution
type TimeoutPolicy struct {
	GlobalTimeoutSeconds int `json:"global_timeout_seconds"` // Max time for entire intent
	PerLegTimeoutSeconds int `json:"per_leg_timeout_seconds"` // Max time per leg
	PerChainTimeoutSeconds int `json:"per_chain_timeout_seconds"` // Max time per chain group
}

// CCLeg represents a single cross-chain operation leg
type CCLeg struct {
	LegID   string `json:"legId"`
	Role    string `json:"role"`    // "source", "destination", or "intermediate"
	Chain   string `json:"chain"`   // "ethereum"
	ChainID int64  `json:"chainId"` // 11155111 for Sepolia, -3 for TON Testnet
	Network string `json:"network"` // "sepolia"

	Asset struct {
		Symbol   string `json:"symbol"`   // "ETH"
		Decimals uint8  `json:"decimals"` // 18
		Native   bool   `json:"native"`   // true
		Address  string `json:"address,omitempty"` // Token contract address (for non-native)
	} `json:"asset"`

	From      string `json:"from"`      // Source address
	To        string `json:"to"`        // Destination address
	AmountEth string `json:"amountEth"` // "0.005"
	AmountWei string `json:"amountWei"` // "5000000000000000"

	AnchorContract struct {
		// EVM
		Address          string `json:"address,omitempty"`          // EVM contract address
		FunctionSelector string `json:"functionSelector,omitempty"` // EVM function selector
		// Non-EVM identifiers (only one will be set per chain type)
		Type             string `json:"type,omitempty"`             // "evm_contract", "solana_program", "near_contract", etc.
		ProgramID        string `json:"programId,omitempty"`        // Solana program ID
		ContractID       string `json:"contractId,omitempty"`       // NEAR contract ID
		ModuleAddress    string `json:"moduleAddress,omitempty"`    // Aptos module address
	} `json:"anchorContract"`

	GasPolicy struct {
		MaxFeePerGasGwei         string `json:"maxFeePerGasGwei"`
		MaxPriorityFeePerGasGwei string `json:"maxPriorityFeePerGasGwei"`
		GasLimit                 uint64 `json:"gasLimit"`
		Payer                    string `json:"payer"`
	} `json:"gasPolicy"`

	// Multi-leg execution fields (Version 2.0+)
	// SequenceOrder determines execution order for sequential mode (0-indexed)
	SequenceOrder int `json:"sequence_order,omitempty"`

	// DependsOnLegs lists leg IDs that must complete before this leg executes
	DependsOnLegs []string `json:"depends_on_legs,omitempty"`

	// MaxRetries is the maximum number of retry attempts for this leg
	MaxRetries int `json:"max_retries,omitempty"`

	// Priority allows per-leg priority override (higher = more urgent)
	Priority int `json:"priority,omitempty"`

	// SlippageTolerance is the maximum acceptable slippage (e.g. "0.5%")
	SlippageTolerance string `json:"slippage_tolerance,omitempty"`

	// DeadlineTimestamp is the unix timestamp deadline for this leg
	DeadlineTimestamp int64 `json:"deadline_timestamp,omitempty"`

	// CRITICAL-003: ExecutionPayload binding from user-signed Blob 1.
	// Commits the exact on-chain execution params (target, value, calldata hash)
	// into the intent before it's signed and written to Accumulate.
	ExecutionPayload *ExecutionPayload `json:"executionPayload,omitempty"`
}

// ExecutionPayload contains the pre-computed execution commitment from the API bridge.
// CRITICAL-003: This is included in the user-signed crossChainData blob and binds
// the exact runtime parameters that the destination-chain contract will execute.
type ExecutionPayload struct {
	Target              string `json:"target"`              // Destination address (checksummed)
	Value               string `json:"value"`               // Native value in wei (string)
	CallData            string `json:"callData"`            // RB-0/RB-1: raw calldata (0x-hex); "0x"/absent = native transfer
	DataHash            string `json:"dataHash"`            // keccak256 of calldata
	ChainID             int64  `json:"chainId"`             // Target chain ID
	ExecutionCommitment string `json:"executionCommitment"` // keccak256(abi.encodePacked(chainId, target, value, dataHash))
	// RB-4: events the contract call must emit for the validator to attest success.
	ExpectedEvents []ExpectedEventPayload `json:"expectedEvents,omitempty"`
	// RB-5: storage-slot effects the call must produce, proven against stateRoot.
	ExpectedState []ExpectedStatePayload `json:"expectedState,omitempty"`
}

// ExpectedEventPayload is a committed event the call must emit (RB-4).
type ExpectedEventPayload struct {
	Contract string `json:"contract"`
	Topic0   string `json:"topic0"`
	DataHash string `json:"dataHash,omitempty"`
}

// ExpectedStatePayload is a committed storage-slot effect (RB-5).
type ExpectedStatePayload struct {
	Account string `json:"account"`
	Slot    string `json:"slot"`
	Value   string `json:"value"`
}

// ChainKey returns a unique key for this leg's target chain (e.g., "base-sepolia").
// Uses NormalizeChainKey for consistent key format across the entire multi-leg pipeline.
func (leg *CCLeg) ChainKey() string {
	return NormalizeChainKey(leg.Chain)
}

// ParseSlippageTolerance parses the "X%" string to a float64 (e.g. "0.5%" -> 0.5).
// Returns an error if the format is invalid or the value is out of range [0, 100].
func (leg *CCLeg) ParseSlippageTolerance() (float64, error) {
	if leg.SlippageTolerance == "" {
		return 0, nil // No slippage set
	}

	s := leg.SlippageTolerance
	if s[len(s)-1] != '%' {
		return 0, fmt.Errorf("slippage_tolerance must end with '%%', got '%s'", s)
	}

	var val float64
	_, err := fmt.Sscanf(s[:len(s)-1], "%f", &val)
	if err != nil {
		return 0, fmt.Errorf("invalid slippage_tolerance '%s': %w", s, err)
	}

	if val < 0 || val > 100 {
		return 0, fmt.Errorf("slippage_tolerance %.2f%% out of range [0, 100]", val)
	}

	return val, nil
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

// GetTargetChain extracts the target chain from cross-chain data legs
// Per Unified Multi-Chain Architecture: Extract target_chain from intent legs[].chain
// Returns the chain name (e.g., "ethereum", "sepolia", "solana") and chain ID
func (ci *CertenIntent) GetTargetChain() (chainName string, chainID int64, err error) {
	// Parse cross-chain data
	ccEnvelope, err := ci.ParseCrossChain()
	if err != nil {
		return "", 0, fmt.Errorf("parse cross-chain data for target chain: %w", err)
	}

	if len(ccEnvelope.Legs) == 0 {
		return "", 0, fmt.Errorf("no cross-chain legs found in intent")
	}

	// Find the destination leg (role="destination") or use the first leg
	var targetLeg *CCLeg
	for i := range ccEnvelope.Legs {
		leg := &ccEnvelope.Legs[i]
		if leg.Role == "destination" {
			targetLeg = leg
			break
		}
	}

	// Fallback to first leg if no destination found
	if targetLeg == nil {
		targetLeg = &ccEnvelope.Legs[0]
	}

	// Extract chain information
	chainName = targetLeg.Chain
	if chainName == "" {
		chainName = targetLeg.Network // Fallback to network name
	}

	chainID = targetLeg.ChainID

	// Normalize chain name to lowercase
	if chainName != "" {
		chainName = normalizeChainName(chainName)
	}

	return chainName, chainID, nil
}

// normalizeChainName converts chain names to the canonical format
func normalizeChainName(chain string) string {
	// Convert to lowercase and normalize common names
	switch chain {
	case "Ethereum", "ETHEREUM", "ethereum":
		return "ethereum"
	case "Sepolia", "SEPOLIA", "sepolia":
		return "sepolia"
	case "Solana", "SOLANA", "solana":
		return "solana"
	case "Near", "NEAR", "near":
		return "near"
	case "TON", "ton", "Ton":
		return "ton"
	default:
		return chain
	}
}

// NormalizeChainKey creates a canonical chain key from a chain name string.
// This is the ONLY function that should construct chain keys for use across the
// multi-leg pipeline (GAP 15: chain key normalization).
// Format: lowercase, spaces replaced with hyphens (e.g., "base-sepolia").
// This matches the format used by bft_integration.go for parseMultiChainTxHashes output keys.
func NormalizeChainKey(chain string) string {
	return strings.ToLower(strings.ReplaceAll(chain, " ", "-"))
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

	// Validate replay data for expiration and timing
	replayData, err := ci.ParseReplay()
	if err != nil {
		return fmt.Errorf("intent validation for execution failed: %w", err)
	}
	if replayData.ExpiresAt > 0 {
		if replayData.CreatedAt <= 0 {
			return fmt.Errorf("intent validation for execution failed: expires_at set but created_at missing")
		}
		// Enforce deadline: reject expired intents
		if time.Now().Unix() > replayData.ExpiresAt {
			return fmt.Errorf("intent expired at %d, current time %d", replayData.ExpiresAt, time.Now().Unix())
		}
		// Sanity: created_at must be before expires_at
		if replayData.CreatedAt >= replayData.ExpiresAt {
			return fmt.Errorf("created_at (%d) must be before expires_at (%d)", replayData.CreatedAt, replayData.ExpiresAt)
		}
	}

	// Validate nonce for replay protection
	if err := ci.ValidateNonce(replayData); err != nil {
		return fmt.Errorf("intent validation for execution failed: %w", err)
	}

	return nil
}

// ValidateNonce checks the replay data nonce for uniqueness to prevent replay attacks.
// HIGH-002: Uses persistent ReplayStore if configured, falls back to in-memory map.
// Once validated, the nonce is recorded so duplicate intents are rejected.
func (ci *CertenIntent) ValidateNonce(replayData *ReplayData) error {
	if replayData.Nonce == "" {
		return fmt.Errorf("replay nonce is empty")
	}

	// HIGH-002: Use persistent replay store if available
	if store := getReplayStore(); store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		exists, err := store.HasNonce(ctx, replayData.Nonce)
		if err != nil {
			return fmt.Errorf("replay store check failed: %w", err)
		}
		if exists {
			return fmt.Errorf("duplicate nonce '%s': intent already processed (persistent)", replayData.Nonce)
		}

		if err := store.MarkNonce(ctx, replayData.Nonce, replayData.ExpiresAt); err != nil {
			return fmt.Errorf("replay store mark failed: %w", err)
		}
		return nil
	}

	// Fallback: in-memory map (development mode — logs warning)
	fallbackNoncesMu.Lock()
	defer fallbackNoncesMu.Unlock()

	if fallbackNonces[replayData.Nonce] {
		return fmt.Errorf("duplicate nonce '%s': intent already processed", replayData.Nonce)
	}
	fallbackNonces[replayData.Nonce] = true
	return nil
}

// =============================================================================
// Multi-Leg Intent Support Methods
// =============================================================================

// GetLegsGroupedByChain groups all legs by their target chain for efficient anchoring.
// Returns a map where keys are chain keys (e.g., "ethereum:1", "polygon:137")
// and values are slices of legs targeting that chain.
// This enables one anchor call per chain group.
func (ci *CertenIntent) GetLegsGroupedByChain() (map[string][]CCLeg, error) {
	ccEnvelope, err := ci.ParseCrossChain()
	if err != nil {
		return nil, fmt.Errorf("parse cross-chain data for leg grouping: %w", err)
	}

	grouped := make(map[string][]CCLeg)
	for _, leg := range ccEnvelope.Legs {
		key := leg.ChainKey()
		grouped[key] = append(grouped[key], leg)
	}

	return grouped, nil
}

// GetLegCount returns the number of legs in this intent
func (ci *CertenIntent) GetLegCount() (int, error) {
	ccEnvelope, err := ci.ParseCrossChain()
	if err != nil {
		return 0, fmt.Errorf("parse cross-chain data for leg count: %w", err)
	}
	return len(ccEnvelope.Legs), nil
}

// GetExecutionMode returns the execution mode for this intent
// Defaults to "sequential" for backward compatibility
func (ci *CertenIntent) GetExecutionMode() (string, error) {
	ccEnvelope, err := ci.ParseCrossChain()
	if err != nil {
		return "", fmt.Errorf("parse cross-chain data for execution mode: %w", err)
	}

	// Check explicit execution_mode field first
	if ccEnvelope.ExecutionMode != "" {
		return ccEnvelope.ExecutionMode, nil
	}

	// Check execution_constraints map (legacy/alternative location)
	if mode, ok := ccEnvelope.ExecutionConstraints["mode"].(string); ok && mode != "" {
		return mode, nil
	}

	// Default to sequential for backward compatibility
	return "sequential", nil
}

// DetectIntentVersion returns the intent version based on structure analysis:
// - "1.0": Single-leg (legacy) - 1 leg, no execution mode
// - "1.1": Multi-leg sequential default - >1 legs, no explicit mode
// - "2.0": Multi-leg with coordination - >1 legs, explicit execution mode
func (ci *CertenIntent) DetectIntentVersion() (string, error) {
	ccEnvelope, err := ci.ParseCrossChain()
	if err != nil {
		return "", fmt.Errorf("parse cross-chain data for version detection: %w", err)
	}

	legCount := len(ccEnvelope.Legs)

	// Single-leg is always version 1.0
	if legCount <= 1 {
		return "1.0", nil
	}

	// Check for explicit execution mode (indicates v2.0)
	if ccEnvelope.ExecutionMode != "" {
		return "2.0", nil
	}

	// Check execution_constraints for mode
	if _, hasMode := ccEnvelope.ExecutionConstraints["mode"]; hasMode {
		return "2.0", nil
	}

	// Check for leg dependencies (indicates v2.0)
	if len(ccEnvelope.LegDependencies) > 0 {
		return "2.0", nil
	}

	// Check for individual leg ordering
	for _, leg := range ccEnvelope.Legs {
		if leg.SequenceOrder > 0 || len(leg.DependsOnLegs) > 0 {
			return "2.0", nil
		}
	}

	// Multi-leg without explicit coordination is v1.1
	return "1.1", nil
}

// IsMultiLeg returns true if this intent has more than one leg
func (ci *CertenIntent) IsMultiLeg() (bool, error) {
	count, err := ci.GetLegCount()
	if err != nil {
		return false, err
	}
	return count > 1, nil
}

// GetLegByID returns a specific leg by its LegID
func (ci *CertenIntent) GetLegByID(legID string) (*CCLeg, error) {
	ccEnvelope, err := ci.ParseCrossChain()
	if err != nil {
		return nil, fmt.Errorf("parse cross-chain data for leg lookup: %w", err)
	}

	for i := range ccEnvelope.Legs {
		if ccEnvelope.Legs[i].LegID == legID {
			return &ccEnvelope.Legs[i], nil
		}
	}

	return nil, fmt.Errorf("leg not found: %s", legID)
}

// GetLegByIndex returns a leg by its index (0-indexed)
func (ci *CertenIntent) GetLegByIndex(index int) (*CCLeg, error) {
	ccEnvelope, err := ci.ParseCrossChain()
	if err != nil {
		return nil, fmt.Errorf("parse cross-chain data for leg index lookup: %w", err)
	}

	if index < 0 || index >= len(ccEnvelope.Legs) {
		return nil, fmt.Errorf("leg index out of range: %d (have %d legs)", index, len(ccEnvelope.Legs))
	}

	return &ccEnvelope.Legs[index], nil
}

// GetUniqueChains returns a list of unique chain keys across all legs
func (ci *CertenIntent) GetUniqueChains() ([]string, error) {
	grouped, err := ci.GetLegsGroupedByChain()
	if err != nil {
		return nil, err
	}

	chains := make([]string, 0, len(grouped))
	for chainKey := range grouped {
		chains = append(chains, chainKey)
	}

	return chains, nil
}

// GetLegsForChain returns all legs targeting a specific chain
func (ci *CertenIntent) GetLegsForChain(chainKey string) ([]CCLeg, error) {
	grouped, err := ci.GetLegsGroupedByChain()
	if err != nil {
		return nil, err
	}

	legs, ok := grouped[chainKey]
	if !ok {
		return nil, fmt.Errorf("no legs found for chain: %s", chainKey)
	}

	return legs, nil
}

// LegOperationID computes an operation ID specific to a leg within the intent.
// This is derived from the main OperationID plus the leg index.
func (ci *CertenIntent) LegOperationID(legIndex int) (string, error) {
	mainOpID, err := ci.OperationID()
	if err != nil {
		return "", err
	}

	// For multi-leg, append leg index to create unique per-leg operation ID
	return fmt.Sprintf("%s-leg%d", mainOpID, legIndex), nil
}

// ValidateMultiLeg performs validation specific to multi-leg intents
func (ci *CertenIntent) ValidateMultiLeg() error {
	// First run basic validation
	if err := ci.Validate(); err != nil {
		return err
	}

	ccEnvelope, err := ci.ParseCrossChain()
	if err != nil {
		return fmt.Errorf("multi-leg validation failed: %w", err)
	}

	legCount := len(ccEnvelope.Legs)
	if legCount == 0 {
		return fmt.Errorf("multi-leg validation failed: no legs defined")
	}

	// Validate execution mode if set
	execMode, err := ci.GetExecutionMode()
	if err != nil {
		return fmt.Errorf("multi-leg validation failed: %w", err)
	}
	if execMode != "sequential" && execMode != "parallel" && execMode != "atomic" {
		return fmt.Errorf("multi-leg validation failed: invalid execution mode '%s'", execMode)
	}

	// Validate each leg
	seenLegIDs := make(map[string]bool)
	for i, leg := range ccEnvelope.Legs {
		// Check for duplicate leg IDs
		if leg.LegID != "" {
			if seenLegIDs[leg.LegID] {
				return fmt.Errorf("multi-leg validation failed: duplicate leg ID '%s'", leg.LegID)
			}
			seenLegIDs[leg.LegID] = true
		}

		// Validate chain info
		if leg.Chain == "" {
			return fmt.Errorf("multi-leg validation failed: leg %d has empty chain", i)
		}

		// Validate role
		if leg.Role != "source" && leg.Role != "destination" && leg.Role != "intermediate" {
			return fmt.Errorf("multi-leg validation failed: leg %d has invalid role '%s'", i, leg.Role)
		}

		// Validate slippage tolerance if set
		if leg.SlippageTolerance != "" {
			if _, err := leg.ParseSlippageTolerance(); err != nil {
				return fmt.Errorf("multi-leg validation failed: leg %d: %w", i, err)
			}
		}

		// Validate dependencies reference existing legs
		for _, depLegID := range leg.DependsOnLegs {
			found := false
			for _, otherLeg := range ccEnvelope.Legs {
				if otherLeg.LegID == depLegID {
					found = true
					break
				}
			}
			if !found && depLegID != "" {
				return fmt.Errorf("multi-leg validation failed: leg %d depends on unknown leg '%s'", i, depLegID)
			}
		}
	}

	// Validate explicit leg dependencies
	for _, dep := range ccEnvelope.LegDependencies {
		if !seenLegIDs[dep.LegID] {
			return fmt.Errorf("multi-leg validation failed: dependency references unknown leg '%s'", dep.LegID)
		}
		if !seenLegIDs[dep.DependsOnLegID] {
			return fmt.Errorf("multi-leg validation failed: dependency references unknown depends_on_leg '%s'", dep.DependsOnLegID)
		}
		if dep.LegID == dep.DependsOnLegID {
			return fmt.Errorf("multi-leg validation failed: leg '%s' cannot depend on itself", dep.LegID)
		}
	}

	// Check for circular dependencies using DFS cycle detection (GAP 11)
	if err := detectCircularDependencies(ccEnvelope); err != nil {
		return fmt.Errorf("multi-leg validation failed: %w", err)
	}

	return nil
}

// detectCircularDependencies performs DFS-based cycle detection on the leg dependency graph.
// Returns an error if any circular dependency is found (e.g., A->B->C->A).
func detectCircularDependencies(envelope *CrossChainEnvelope) error {
	// Build adjacency list: legID -> list of legIDs it depends on
	adj := make(map[string][]string)
	for _, leg := range envelope.Legs {
		if leg.LegID == "" {
			continue
		}
		adj[leg.LegID] = append(adj[leg.LegID], leg.DependsOnLegs...)
	}
	for _, dep := range envelope.LegDependencies {
		adj[dep.LegID] = append(adj[dep.LegID], dep.DependsOnLegID)
	}

	// DFS states: 0=unvisited, 1=in-progress (on stack), 2=done
	const (
		unvisited  = 0
		inProgress = 1
		done       = 2
	)
	state := make(map[string]int)

	var dfs func(node string) error
	dfs = func(node string) error {
		state[node] = inProgress
		for _, dep := range adj[node] {
			if dep == "" {
				continue
			}
			switch state[dep] {
			case inProgress:
				return fmt.Errorf("circular dependency detected: %s -> %s", node, dep)
			case unvisited:
				if err := dfs(dep); err != nil {
					return err
				}
			}
		}
		state[node] = done
		return nil
	}

	for _, leg := range envelope.Legs {
		if leg.LegID == "" {
			continue
		}
		if state[leg.LegID] == unvisited {
			if err := dfs(leg.LegID); err != nil {
				return err
			}
		}
	}
	return nil
}
