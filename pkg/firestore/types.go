// Copyright 2025 Certen Protocol
//
// Firestore Document Types
// Types for syncing proof cycle progress to Firestore for real-time UI updates

package firestore

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// ProofStage represents the 9 stages of the proof lifecycle
type ProofStage int

const (
	StageIntentCreation     ProofStage = 1 // User creates intent in Firestore
	StageSignatureCollection ProofStage = 2 // Signatures collected on Accumulate
	StageIntentDiscovery    ProofStage = 3 // Validator discovers intent
	StageProofGeneration    ProofStage = 4 // L1-L3 and G0-G2 proofs generated
	StageBatchConsensus     ProofStage = 5 // Batch closed, merkle root computed
	StageEthereumAnchoring  ProofStage = 6 // Anchor submitted to Ethereum
	StageConfirmationTracking ProofStage = 7 // Ethereum confirmations tracked
	StageBLSAttestation     ProofStage = 8 // BLS aggregate signatures
	StageWriteBack          ProofStage = 9 // Result written back to Accumulate
)

// StageNames maps stage numbers to human-readable names
var StageNames = map[ProofStage]string{
	StageIntentCreation:      "Intent Creation",
	StageSignatureCollection: "Signature Collection",
	StageIntentDiscovery:     "Intent Discovery",
	StageProofGeneration:     "Proof Generation",
	StageBatchConsensus:      "Batch Consensus",
	StageEthereumAnchoring:   "Ethereum Anchoring",
	StageConfirmationTracking: "Confirmation Tracking",
	StageBLSAttestation:      "BLS Attestation",
	StageWriteBack:           "Write Back",
}

// SnapshotStatus represents the status of a stage
type SnapshotStatus string

const (
	StatusPending    SnapshotStatus = "pending"
	StatusInProgress SnapshotStatus = "in_progress"
	StatusCompleted  SnapshotStatus = "completed"
	StatusFailed     SnapshotStatus = "failed"
)

// StatusSnapshot represents a proof cycle status update in Firestore
// Path: /users/{uid}/transactionIntents/{intentId}/statusSnapshots/{snapshotId}
type StatusSnapshot struct {
	// Firestore document ID (auto-generated or specified)
	SnapshotID string `json:"snapshotId" firestore:"-"`

	// Stage information
	Stage     ProofStage     `json:"stage" firestore:"stage"`
	StageName string         `json:"stageName" firestore:"stageName"`
	Status    SnapshotStatus `json:"status" firestore:"status"`

	// Timestamps
	Timestamp time.Time  `json:"timestamp" firestore:"timestamp"`
	StartedAt *time.Time `json:"startedAt,omitempty" firestore:"startedAt,omitempty"`
	EndedAt   *time.Time `json:"endedAt,omitempty" firestore:"endedAt,omitempty"`

	// Source attribution
	Source      string `json:"source" firestore:"source"`           // "validator", "user", "system"
	ValidatorID string `json:"validatorId" firestore:"validatorId"` // Which validator created this

	// Stage-specific data (varies by stage)
	Data map[string]interface{} `json:"data" firestore:"data"`

	// Chain integrity
	PreviousSnapshotID string `json:"previousSnapshotId,omitempty" firestore:"previousSnapshotId,omitempty"`
	SnapshotHash       string `json:"snapshotHash" firestore:"snapshotHash"`

	// Error information (for failed status)
	ErrorMessage string `json:"errorMessage,omitempty" firestore:"errorMessage,omitempty"`
	ErrorCode    string `json:"errorCode,omitempty" firestore:"errorCode,omitempty"`
}

// Stage-specific data structures

// Stage3Data contains data for Intent Discovery stage
type Stage3Data struct {
	AccumTxHash      string `json:"accumTxHash"`
	AccountURL       string `json:"accountUrl"`
	BlockHeight      int64  `json:"blockHeight"`
	DiscoveryTime    string `json:"discoveryTime"`
	ProofClass       string `json:"proofClass"` // "on_cadence" or "on_demand"
	IntentType       string `json:"intentType,omitempty"`
	TargetChain      string `json:"targetChain,omitempty"`
}

// Stage4Data contains data for Proof Generation stage
type Stage4Data struct {
	ProofID        string `json:"proofId"`
	ChainedLayers  int    `json:"chainedLayers"`  // Number of L layers generated (1-3)
	GovernanceLevels int  `json:"governanceLevels"` // Number of G levels generated (0-2)
	L1Generated    bool   `json:"l1Generated"`
	L2Generated    bool   `json:"l2Generated"`
	L3Generated    bool   `json:"l3Generated"`
	G0Generated    bool   `json:"g0Generated"`
	G1Generated    bool   `json:"g1Generated"`
	G2Generated    bool   `json:"g2Generated"`
	ProofHash      string `json:"proofHash,omitempty"`
}

// Stage5Data contains data for Batch Consensus stage
type Stage5Data struct {
	BatchID       string `json:"batchId"`
	BatchPosition int    `json:"batchPosition"`
	MerkleRoot    string `json:"merkleRoot"`
	LeafHash      string `json:"leafHash"`
	BatchSize     int    `json:"batchSize"`
	ProofClass    string `json:"proofClass"`
}

// Stage6Data contains data for Ethereum Anchoring stage
type Stage6Data struct {
	AnchorTxHash   string `json:"anchorTxHash"`
	BlockNumber    int64  `json:"blockNumber"`
	ContractAddress string `json:"contractAddress"`
	GasUsed        int64  `json:"gasUsed,omitempty"`
	NetworkName    string `json:"networkName"` // "sepolia", "mainnet", etc.
}

// Stage7Data contains data for Confirmation Tracking stage
type Stage7Data struct {
	AnchorTxHash       string `json:"anchorTxHash"`
	CurrentConfirmations int  `json:"currentConfirmations"`
	RequiredConfirmations int `json:"requiredConfirmations"`
	IsConfirmed        bool   `json:"isConfirmed"`
	BlockNumber        int64  `json:"blockNumber"`
}

// Stage8Data contains data for BLS Attestation stage
type Stage8Data struct {
	AttestationID      string   `json:"attestationId"`
	ValidatorCount     int      `json:"validatorCount"`
	ParticipatingValidators []string `json:"participatingValidators"`
	TotalWeight        int64    `json:"totalWeight"`
	AchievedWeight     int64    `json:"achievedWeight"`
	ThresholdMet       bool     `json:"thresholdMet"`
	AggregateSignature string   `json:"aggregateSignature,omitempty"`
}

// Stage9Data contains data for Write Back stage
type Stage9Data struct {
	WriteBackTxHash    string `json:"writeBackTxHash"`
	AccumulateURL      string `json:"accumulateUrl"`
	ResultStatus       string `json:"resultStatus"` // "success", "failed"
	ExecutionProof     string `json:"executionProof,omitempty"`
	CompletionTime     string `json:"completionTime"`
}

// AuditTrailEntry represents an audit trail entry in Firestore
// Path: /users/{uid}/auditTrail/{entryId}
type AuditTrailEntry struct {
	// Firestore document ID
	EntryID string `json:"entryId" firestore:"-"`

	// Reference to transaction
	TransactionID string `json:"transactionId" firestore:"transactionId"` // Intent ID from Firestore
	AccumTxHash   string `json:"accumTxHash,omitempty" firestore:"accumTxHash,omitempty"`

	// Event classification
	Phase  string `json:"phase" firestore:"phase"`   // "discovered", "proof_generated", "batched", "anchored", "attested", "executed", "completed"
	Action string `json:"action" firestore:"action"` // Human-readable action description

	// Actor information
	Actor     string `json:"actor" firestore:"actor"`         // "validator-{id}", "system", "user"
	ActorType string `json:"actorType" firestore:"actorType"` // "service", "user", "system"

	// Timestamps
	Timestamp time.Time `json:"timestamp" firestore:"timestamp"`

	// Chain integrity (append-only audit log)
	PreviousHash string `json:"previousHash" firestore:"previousHash"`
	EntryHash    string `json:"entryHash" firestore:"entryHash"`

	// Additional details
	Details map[string]interface{} `json:"details,omitempty" firestore:"details,omitempty"`

	// Proof reference (links to proof service data)
	ProofID  string `json:"proofId,omitempty" firestore:"proofId,omitempty"`
	BatchID  string `json:"batchId,omitempty" firestore:"batchId,omitempty"`
	AnchorID string `json:"anchorId,omitempty" firestore:"anchorId,omitempty"`
}

// AuditPhases defines valid audit trail phases
var AuditPhases = map[string]string{
	"discovered":      "Intent Discovered",
	"proof_generated": "Proof Generated",
	"batched":         "Added to Batch",
	"anchored":        "Anchored on Ethereum",
	"attested":        "BLS Attestation Complete",
	"executed":        "Execution Verified",
	"completed":       "Proof Cycle Complete",
}

// IntentMetadata represents metadata stored with intent for linking
type IntentMetadata struct {
	// User reference
	UserID   string `json:"userId" firestore:"userId"`
	IntentID string `json:"intentId" firestore:"intentId"`

	// Accumulate reference
	AccumTxHash string `json:"accumTxHash" firestore:"accumTxHash"`
	AccountURL  string `json:"accountUrl" firestore:"accountUrl"`

	// Status
	CurrentStage ProofStage `json:"currentStage" firestore:"currentStage"`
	LastUpdated  time.Time  `json:"lastUpdated" firestore:"lastUpdated"`

	// Links to proof service data
	ProofID  *uuid.UUID `json:"proofId,omitempty" firestore:"proofId,omitempty"`
	BatchID  *uuid.UUID `json:"batchId,omitempty" firestore:"batchId,omitempty"`
	AnchorID *uuid.UUID `json:"anchorId,omitempty" firestore:"anchorId,omitempty"`
}

// TransactionIntentUpdate represents fields to update on a transaction intent
type TransactionIntentUpdate struct {
	Status               string                 `json:"status,omitempty" firestore:"status,omitempty"`
	CurrentStage         *int                   `json:"currentStage,omitempty" firestore:"currentStage,omitempty"`
	LastUpdated          *time.Time             `json:"lastUpdated,omitempty" firestore:"lastUpdated,omitempty"`
	ProofID              string                 `json:"proofId,omitempty" firestore:"proofId,omitempty"`
	BatchID              string                 `json:"batchId,omitempty" firestore:"batchId,omitempty"`
	AnchorTxHash         string                 `json:"anchorTxHash,omitempty" firestore:"anchorTxHash,omitempty"`
	EthereumConfirmations *int                  `json:"ethereumConfirmations,omitempty" firestore:"ethereumConfirmations,omitempty"`
	CompletedAt          *time.Time             `json:"completedAt,omitempty" firestore:"completedAt,omitempty"`
	Error                string                 `json:"error,omitempty" firestore:"error,omitempty"`
	Metadata             map[string]interface{} `json:"metadata,omitempty" firestore:"metadata,omitempty"`
}

// FirestoreEvent represents an event to sync to Firestore
type FirestoreEvent struct {
	// Event identification
	EventID   string    `json:"eventId"`
	EventType string    `json:"eventType"` // "status_snapshot", "audit_entry", "intent_update"
	Timestamp time.Time `json:"timestamp"`

	// Target document path components
	UserID    string `json:"userId"`
	IntentID  string `json:"intentId"`

	// Event payload (one of these will be set)
	StatusSnapshot *StatusSnapshot           `json:"statusSnapshot,omitempty"`
	AuditEntry     *AuditTrailEntry          `json:"auditEntry,omitempty"`
	IntentUpdate   *TransactionIntentUpdate  `json:"intentUpdate,omitempty"`

	// Processing status
	Processed bool       `json:"processed"`
	ProcessedAt *time.Time `json:"processedAt,omitempty"`
	RetryCount int        `json:"retryCount"`
	LastError  string     `json:"lastError,omitempty"`
}

// ToJSON converts a StatusSnapshot to JSON for hashing
func (s *StatusSnapshot) ToJSON() ([]byte, error) {
	return json.Marshal(s)
}

// ToJSON converts an AuditTrailEntry to JSON for hashing
func (a *AuditTrailEntry) ToJSON() ([]byte, error) {
	return json.Marshal(a)
}
