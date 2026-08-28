// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"strings"
	"time"

	"github.com/certen/certen-protocol/services/validator/accumulate-lite-client-2/liteclient/proof/govreceipt"
)

// CERTEN Governance Proof Types
// This file contains all type definitions for the consolidated governance proof system
// implementing CERTEN Governance Proof Specification v3-governance-kpsw-exec-4.0

// =============================================================================
// Proof Levels and Constants
// =============================================================================

// ProofLevel defines the governance proof level
type ProofLevel string

const (
	// ProofLevelG0 - Inclusion and Finality Only (No Governance)
	ProofLevelG0 ProofLevel = "G0"
	// ProofLevelG1 - Governance Correctness (Default)
	ProofLevelG1 ProofLevel = "G1"
	// ProofLevelG2 - Governance Correctness + Outcome Binding
	ProofLevelG2 ProofLevel = "G2"
)

// Specification version for CERTEN compliance
const (
	SpecVersion = "v3-governance-kpsw-exec-4.0"
)

// =============================================================================
// Core Execution Types
// =============================================================================

// ExecTerms represents execution witness terms
// Direct translation of Python ExecTerms dataclass
type ExecTerms struct {
	MBI     int64  `json:"mbi"`     // Major Block Index
	Witness string `json:"witness"` // Execution witness (receipt anchor)
}

// ExecutionContext represents execution context from G1 authority snapshot
// Direct translation of Python ExecutionContext dataclass
type ExecutionContext struct {
	Scope             string `json:"scope"`
	TxHash            string `json:"tx_hash"`
	ExecMBI           int64  `json:"exec_mbi"`
	ExecWitness       string `json:"exec_witness"`
	AuthorityVerified bool   `json:"authority_verified"`
}

// =============================================================================
// Signature and Authorization Types
// =============================================================================

// SignatureData represents Ed25519 signature information with enhanced cryptographic security
// Contains all signature fields from v3 message result plus security enhancements
type SignatureData struct {
	Type string `json:"type"` // "ed25519" or "delegated"

	// Chain is the delegation path, OUTERMOST FIRST, and it is part of the
	// signature rather than context about it: DelegatedSignature.Metadata()
	// recurses, so every Delegator URL here is inside the bytes the inner key
	// signed. Empty for a bare ed25519 signature. See delegation.go.
	Chain []SignerLink `json:"chain,omitempty"`

	// DigestForm records which of the two accepted digests this signature was
	// actually made over, once it has been verified. It is recorded rather than
	// discarded so the distribution is observable - if the merkle form never
	// appears that is worth knowing, and if it does, defect D4 was rejecting
	// real signatures.
	DigestForm string `json:"digestForm,omitempty"`

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

// ValidatedSignature represents a signature with superior cryptographic validation
// Enhanced version with comprehensive security verification
type ValidatedSignature struct {
	MessageID                 string        `json:"messageID"`                 // MSGID
	MessageHash               string        `json:"messageHash"`               // Entry hash
	Receipt                   ReceiptData   `json:"receipt"`                   // Timing receipt
	Signature                 SignatureData `json:"signature"`                 // Signature data
	TimingVerified            bool          `json:"timingVerified"`            // localBlock <= EXEC_MBI
	TransactionHashVerified   bool          `json:"transactionHashVerified"`   // signature.transactionHash == TX_HASH
	CryptographicallyVerified bool          `json:"cryptographicallyVerified"` // Ed25519 verified
	SecurityLevel             string        `json:"securityLevel"`             // Security verification level
	VerificationTime          time.Time     `json:"verificationTime"`          // When verification occurred
	IntegrityHash             string        `json:"integrityHash"`             // Artifact integrity hash
}

// SignatureSetData represents extracted signature set information with enhanced security tracking
// Enhanced version with cryptographic integrity verification
type SignatureSetData struct {
	MessageIDs        []string  `json:"messageIDs"`        // Canonical signatureSet message IDs
	KeyPage           string    `json:"keyPage"`           // Key page URL
	TxScope           string    `json:"txScope"`           // Transaction scope
	SignatureCount    int       `json:"signatureCount"`    // Number of signatures
	SecurityLevel     string    `json:"securityLevel"`     // Security verification level
	ExtractionTime    time.Time `json:"extractionTime"`    // When signatures were extracted
	IntegrityVerified bool      `json:"integrityVerified"` // Bundle integrity verified
}

// =============================================================================
// Authority and Key Page Types
// =============================================================================

// KeyPageState represents key page state at a specific version
// Direct translation of Python KeyPageState dataclass
type KeyPageState struct {
	Version uint64 `json:"version"` // Key page version

	// Entries is the page's authority: every KeySpec on it, key entries and
	// delegated ones alike. It is what the threshold counts.
	//
	// Keys below is the key-hash SUBSET of this, kept because everything that
	// already reads it keeps meaning what it meant. Entries is the authority;
	// Keys is a view. A page whose entries are all delegates has an empty Keys
	// and is still a perfectly good authority - which is precisely the case the
	// old model could not represent at all. See authority_entries.go.
	Entries []KeyPageEntry `json:"entries,omitempty"`

	Keys      []string `json:"keys"`      // List of key hashes (SHA256)
	Threshold uint64   `json:"threshold"` // Required signature threshold
}

// EntrySet returns the page's entries, reconstructing them from Keys if a state
// was built before entries existed.
//
// The fallback is not a compatibility shim for its own sake: a state carrying
// only key hashes is one whose delegate entries were never parsed, and treating
// its key list as the whole page would silently understate the entry count and
// let a threshold be met that the real page does not consider met.
func (s KeyPageState) EntrySet() []KeyPageEntry {
	if len(s.Entries) > 0 {
		return s.Entries
	}
	out := make([]KeyPageEntry, 0, len(s.Keys))
	for _, k := range s.Keys {
		out = append(out, KeyPageEntry{KeyHash: strings.ToLower(k)})
	}
	return out
}

// GenesisEvent represents the syntheticCreateIdentity event
type GenesisEvent struct {
	EntryHash  string       `json:"entryHash"`  // Entry hash of genesis transaction
	LocalBlock int64        `json:"localBlock"` // Genesis block number
	Receipt    ReceiptData  `json:"receipt"`    // Genesis receipt
	TxType     string       `json:"txType"`     // Should be "syntheticCreateIdentity"
	PageState  KeyPageState `json:"pageState"`  // Initial key page state
}

// MutationEvent represents an updateKeyPage mutation
type MutationEvent struct {
	EntryHash     string       `json:"entryHash"`     // Entry hash of mutation transaction
	LocalBlock    int64        `json:"localBlock"`    // Mutation block number
	Receipt       ReceiptData  `json:"receipt"`       // Mutation receipt
	TxType        string       `json:"txType"`        // Should be "updateKeyPage"
	PreviousState KeyPageState `json:"previousState"` // State before mutation
	NewState      KeyPageState `json:"newState"`      // State after mutation
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
// Direct translation of Python AuthoritySnapshot dataclass
type AuthoritySnapshot struct {
	Page       string            `json:"page"`       // Key page URL
	ExecTerms  ExecTerms         `json:"execTerms"`  // Execution terms
	StateExec  KeyPageState      `json:"stateExec"`  // Key page state at execution
	Genesis    GenesisEvent      `json:"genesis"`    // Genesis event
	Mutations  []MutationEvent   `json:"mutations"`  // All mutations <= EXEC_MBI
	Validation ValidationSummary `json:"validation"` // Validation summary
}

// AuthorizationResult represents final G1 authorization result
// Direct translation of Python AuthorizationResult dataclass
type AuthorizationResult struct {
	TxScope             string               `json:"txScope"`             // Transaction scope
	TxHash              string               `json:"txHash"`              // TX_HASH
	KeyPage             string               `json:"keyPage"`             // Key page URL
	AuthoritySnapshot   AuthoritySnapshot    `json:"authoritySnapshot"`   // Complete snapshot
	ValidatedSignatures []ValidatedSignature `json:"validatedSignatures"` // Valid signatures
	UniqueValidKeys     int                  `json:"uniqueValidKeys"`     // Unique valid key count
	ThresholdSatisfied  bool                 `json:"thresholdSatisfied"`  // Threshold >= requirement
	ExecutionSuccess    bool                 `json:"executionSuccess"`    // Transaction exists
	TimingValid         bool                 `json:"timingValid"`         // All signatures before execution
	G1ProofComplete     bool                 `json:"g1ProofComplete"`     // G1 proof complete
}

// =============================================================================
// G2 Payload and Effect Verification Types
// =============================================================================

// PayloadVerification represents result of Go verifier payload verification
// Direct translation of Python PayloadVerification dataclass
type PayloadVerification struct {
	Verified            bool                   `json:"verified"`            // Payload verification result
	ComputedTxHash      string                 `json:"computedTxHash"`      // Hash computed by Go verifier
	ExpectedTxHash      string                 `json:"expectedTxHash"`      // Expected TX_HASH
	GoVerifierOutput    string                 `json:"goVerifierOutput"`    // Raw Go verifier stdout
	GoVerifierErrors    string                 `json:"goVerifierErrors"`    // Raw Go verifier stderr
	VerificationDetails map[string]interface{} `json:"verificationDetails"` // Additional details
}

// EffectVerification represents result of transaction effect verification
// Direct translation of Python EffectVerification dataclass
type EffectVerification struct {
	EffectType    string                 `json:"effectType"`    // Transaction effect type
	Verified      bool                   `json:"verified"`      // Effect verification result
	ExpectedValue *string                `json:"expectedValue"` // Expected effect value
	ComputedValue *string                `json:"computedValue"` // Computed effect value
	Details       map[string]interface{} `json:"details"`       // Additional details
}

// OutcomeLeaf represents G2 outcome leaf with payload and effect verification
type OutcomeLeaf struct {
	PayloadBinding     PayloadVerification `json:"payloadBinding"`     // Payload authenticity
	ReceiptBinding     VerificationResult  `json:"receiptBinding"`     // Receipt binding
	WitnessConsistency VerificationResult  `json:"witnessConsistency"` // Witness consistency
	Effect             EffectVerification  `json:"effect"`             // Effect verification
}

// G2ProofResult represents complete G2 proof result
// Direct translation of Python G2ProofResult dataclass
type G2ProofResult struct {
	TxHash                     string              `json:"txHash"`                     // TX_HASH
	ExecScope                  string              `json:"execScope"`                  // Execution scope
	ExecEntry                  string              `json:"execEntry"`                  // Execution entry
	ExecutionContext           ExecutionContext    `json:"executionContext"`           // Execution context
	PayloadVerification        PayloadVerification `json:"payloadVerification"`        // Payload verification
	EffectVerification         EffectVerification  `json:"effectVerification"`         // Effect verification
	ReceiptBindingVerified     bool                `json:"receiptBindingVerified"`     // Receipt binding OK
	WitnessConsistencyVerified bool                `json:"witnessConsistencyVerified"` // Witness consistency OK
	G2ProofComplete            bool                `json:"g2ProofComplete"`            // G2 proof complete
	SecurityLevel              string              `json:"securityLevel"`              // Security level description
}

// =============================================================================
// RPC and Receipt Types
// =============================================================================

// ReceiptData represents Accumulate receipt information
// Contains all receipt fields with proper types
type ReceiptData struct {
	Start          string     `json:"start"`          // Receipt start hash (the leaf)
	Anchor         string     `json:"anchor"`         // Receipt anchor hash (the root)
	LocalBlock     int64      `json:"localBlock"`     // Local block number
	LocalBlockTime *time.Time `json:"localBlockTime"` // Local block time (optional)
	MajorBlock     *int64     `json:"majorBlock"`     // Major block number (optional)
	End            *string    `json:"end"`            // Receipt end hash (optional)

	// Entries is the merkle path from Start to Anchor.
	//
	// It was previously discarded during parsing, so no governance receipt
	// could ever be recomputed and "receipt binding" could only compare
	// start/anchor values that came from the same response. See
	// VerifyReceiptMerkle.
	Entries []ReceiptStep `json:"entries"`
}

// ReceiptStep is one step of a receipt's merkle path. Right reports that the
// sibling is on the right, matching Accumulate's encoding, which omits the
// field when false.
//
// STAGE 2: a type ALIAS rather than its own declaration. It was a structurally
// identical copy of the chained-proof step, and two identical declarations are
// two things that can drift — a receipt stored by the validator and a fixture
// read by the offline verifier have to be the same document, not merely the same
// shape today. govreceipt.Step is itself an alias of
// chained_proof.ReceiptStep, so all three names now denote one type.
type ReceiptStep = govreceipt.Step

// VerificationResult represents a generic verification result
type VerificationResult struct {
	Verified bool   `json:"verified"` // Verification result
	Details  string `json:"details"`  // Verification details
}

// RPCArtifact represents saved RPC artifact with integrity hash
// Implements CERTEN Section 4.2 Bundle Integrity requirements
type RPCArtifact struct {
	Label          string `json:"label"`               // Artifact label
	Endpoint       string `json:"endpoint"`            // RPC endpoint
	SHA256Response string `json:"sha256_response_raw"` // SHA256 of raw response bytes
	Timestamp      int64  `json:"ts_unix"`             // Unix timestamp
}

// IntegrityManifest represents bundle integrity manifest
type IntegrityManifest struct {
	BundleHash      string                 `json:"bundle_hash"`      // Overall bundle hash
	ArtifactHashes  map[string]string      `json:"artifact_hashes"`  // Individual artifact hashes
	VerifiedAt      time.Time              `json:"verified_at"`      // Verification timestamp
	VerificationLog []VerificationLogEntry `json:"verification_log"` // Verification log
}

// VerificationLogEntry represents a single verification log entry
type VerificationLogEntry struct {
	Timestamp time.Time `json:"timestamp"` // Log entry timestamp
	Level     string    `json:"level"`     // Log level (INFO, ERROR, etc.)
	Message   string    `json:"message"`   // Log message
}

// ArtifactBundle represents complete proof bundle with integrity
type ArtifactBundle struct {
	WorkDir     string            `json:"workdir"`      // Working directory
	ProofLevel  ProofLevel        `json:"proof_level"`  // Proof level achieved
	SpecVersion string            `json:"spec_version"` // CERTEN spec version
	Artifacts   []RPCArtifact     `json:"artifacts"`    // All RPC artifacts
	Integrity   IntegrityManifest `json:"integrity"`    // Integrity manifest
}

// =============================================================================
// Result Types for Each Proof Level
// =============================================================================

// G0Result represents G0 proof result (Inclusion and Finality Only)
type G0Result struct {
	EntryHashExec     string      `json:"entry_hash_exec"`     // Execution entry hash (TXID)
	TXID              string      `json:"txid"`                // Message ID hash (same as entry_hash_exec)
	TxHash            string      `json:"tx_hash"`             // Canonical transaction hash
	ExecMBI           int64       `json:"exec_mbi"`            // Execution MBI
	ExecWitness       string      `json:"exec_witness"`        // Execution witness (receipt anchor)
	Scope             string      `json:"scope"`               // Transaction scope
	Chain             string      `json:"chain"`               // Chain name (typically "main")
	ExpandedMessageID string      `json:"expanded_message_id"` // Expanded message.id for binding
	Principal         string      `json:"principal"`           // Extracted principal
	Receipt           ReceiptData `json:"receipt"`             // Execution receipt
	G0ProofComplete   bool        `json:"g0_proof_complete"`   // G0 proof completion flag
}

// G1Result represents G1 proof result with superior cryptographic verification
type G1Result struct {
	G0Result                                 // Inherit all G0 results
	AuthoritySnapshot   AuthoritySnapshot    `json:"authority_snapshot"`   // KPSW-EXEC snapshot
	ValidatedSignatures []ValidatedSignature `json:"validated_signatures"` // All validated signatures
	UniqueValidKeys     int                  `json:"unique_valid_keys"`    // Unique valid key count
	RequiredThreshold   uint64               `json:"required_threshold"`   // Required threshold
	ThresholdSatisfied  bool                 `json:"threshold_satisfied"`  // Threshold satisfaction
	ExecutionSuccess    bool                 `json:"execution_success"`    // Execution success
	TimingValid         bool                 `json:"timing_valid"`         // Timing validation
	G1ProofComplete     bool                 `json:"g1_proof_complete"`    // G1 proof complete
	ConcurrencyEnabled  bool                 `json:"concurrency_enabled"`  // Concurrency was used
	WorkerCount         int                  `json:"worker_count"`         // Number of workers used
	ProcessingTimeMs    int64                `json:"processing_time_ms"`   // Total processing time
	// Enhanced cryptographic security fields
	CryptographicSecurity bool            `json:"cryptographic_security"` // Enhanced crypto enabled
	SecurityReport        *SecurityReport `json:"security_report"`        // Comprehensive security report
	Ed25519Verified       int64           `json:"ed25519_verified"`       // Number of Ed25519 verifications
	AuditTrailEvents      int             `json:"audit_trail_events"`     // Number of audit events
	BundleIntegrityHash   string          `json:"bundle_integrity_hash"`  // Bundle integrity hash

	// SignatureRouteStatus records which extraction routes ran, whether they
	// agreed, and whether coverage was degraded. It is a pointer so that a
	// result built without it is distinguishable from one where both routes
	// ran and agreed - "never recorded" must not read as "agreed".
	SignatureRouteStatus *RouteStatus `json:"signatureRouteStatus,omitempty"`

	// TimingBasis says, PER COUNTED SIGNATURE, how its ordering before
	// execution was established: re-derived locally (localBlock <= execMBI) or
	// inherited from the fact of execution because the two block indices count
	// different chains.
	//
	// A TOP-LEVEL ARRAY, deliberately, and NOT a field of ValidatedSignature.
	// ValidatedSignature is inside the shape the validator hashes into the
	// govRoot; this must never be able to reach that shape. It travels beside
	// it, in the same relationship GovReceiptEvidence has to the receipt
	// summary, and the validator lifts it with a side read into a wrapper no
	// canonical hash reaches. Correlate to validated_signatures by messageID.
	//
	// See g1_timing_basis.go for why the distinction is worth recording.
	TimingBasis []SignatureTimingBasis `json:"timingBasis,omitempty"`

	// UnverifiedPageRules names, PER PAGE, every threshold the page carries
	// that this proof did not re-derive: reject, response and block.
	//
	// G1 re-derives the ACCEPT threshold. A page that sets one of the other
	// three demands more than that, and until this field a reader of
	// "threshold satisfied: true" had no way to learn it. Each note says which
	// of three distinct things it is - a rule that could have changed the
	// answer, one that could not, and one the protocol does not enforce at all
	// - because collapsing them would put a load-bearing omission and a moot
	// one behind the same words.
	//
	// A TOP-LEVEL ARRAY for the same reason TimingBasis is one: KeyPageState is
	// reachable from this struct through AuthoritySnapshot.StateExec, and this
	// struct is what the validator hashes into the govRoot. Carrying the
	// thresholds on KeyPageState would widen that preimage and move every
	// govRoot ever signed.
	//
	// Empty - and so absent, via omitempty - for every page in the corpus and
	// in production, none of which set any of the three.
	//
	// See g1_page_rules.go for what each rule means and why each was recorded
	// rather than re-derived.
	UnverifiedPageRules []PageRuleNote `json:"unverifiedPageRules,omitempty"`
}

// G2Result represents G2 proof result (Governance + Outcome Binding)
type G2Result struct {
	G1Result                    // Inherit all G1 results
	OutcomeLeaf     OutcomeLeaf `json:"outcome_leaf"`      // Outcome leaf with payload binding
	PayloadVerified bool        `json:"payload_verified"`  // Payload authenticity verified
	EffectVerified  bool        `json:"effect_verified"`   // Transaction effect verified
	G2ProofComplete bool        `json:"g2_proof_complete"` // G2 proof completion flag
	SecurityLevel   string      `json:"security_level"`    // Security level description

	// OutcomeBinding is the evidence for G2's defining claim. It is a pointer
	// so a result built without it is distinguishable from one that verified;
	// its zero state is NotRun, which is never a pass.
	OutcomeBinding *OutcomeBinding `json:"outcomeBinding,omitempty"`
}

// =============================================================================
// Error Types
// =============================================================================

// ProofError represents a governance proof error
type ProofError struct {
	Msg string
}

func (e ProofError) Error() string {
	return e.Msg
}

// ValidationError represents a validation error
type ValidationError struct {
	Msg string
}

func (e ValidationError) Error() string {
	return e.Msg
}

// RPCError represents an RPC communication error
type RPCError struct {
	Msg string
}

func (e RPCError) Error() string {
	return e.Msg
}

// =============================================================================
// Request Types for CLI and API
// =============================================================================

// G0Request represents a request for G0 proof
type G0Request struct {
	Account         string  `json:"account"`           // Account scope
	TxHash          string  `json:"txhash"`            // Transaction hash
	CanonicalTxHash *string `json:"tx_hash,omitempty"` // Optional canonical TX_HASH
	Chain           string  `json:"chain"`             // Chain name (default: "main")
	V3Endpoint      string  `json:"v3_endpoint"`       // v3 RPC endpoint
	WorkDir         string  `json:"workdir"`           // Working directory
}

// G1Request represents a request for G1 proof
type G1Request struct {
	G0Request            // Inherit G0 request
	KeyPage       string `json:"key_page"`       // Key page URL
	SigningDomain string `json:"signing_domain"` // Signing domain (default: "accumulate_ed25519")
}

// G2Request represents a request for G2 proof
type G2Request struct {
	G1Request               // Inherit G1 request
	GoModDir        *string `json:"gomoddir,omitempty"`          // Go module directory
	SigbytesPath    *string `json:"sigbytes_path,omitempty"`     // Path to sigbytes tool
	ExpectEntryHash *string `json:"expect_entry_hash,omitempty"` // Expected entry hash for effect verification
}

// SecurityReport is the shape the `security_report` slot of G1Result carries.
//
// # WHY IT SURVIVED THE DELETION OF THE FILE THAT DEFINED IT
//
// Phase 8 item 4 deleted g1_enhanced_crypto.go, which invented a digest -
// sha256("accumulate/" || txHash || version || timestamp) - that is not the
// Accumulate digest and never was. The only producer of a SecurityReport was
// generateSecurityReport in that file, so nothing populates this any more and
// the slot is always null.
//
// The TYPE stays because G1Result is hashed into the governance root
// (SetG1FromJSON), the field carries no omitempty, and every G1Result ever
// serialized therefore contains `"security_report": null`. Removing the field
// would remove that key, change the preimage, and move govRoot - which
// runbook rule 4 forbids and which no fleet upgrade could roll out atomically
// against proofs already anchored on chain.
//
// It holds no digest and no verification logic, so rule 10 - one
// implementation of a digest - is satisfied by the deletion that left it here.
type SecurityReport struct {
	SecurityLevel     string    `json:"securityLevel"`
	CryptographicHash string    `json:"cryptographicHash"`
	BundleHash        string    `json:"bundleHash"`
	AuditEvents       int       `json:"auditEvents"`
	CustodyEvents     int       `json:"custodyEvents"`
	VerificationTime  time.Time `json:"verificationTime"`
	IntegrityVerified bool      `json:"integrityVerified"`
	Ed25519Verified   int64     `json:"ed25519Verified"`
	FailedCount       int64     `json:"failedCount"`
}
