// Copyright 2025 Certen Protocol
//
// Business-Level Types - Cleaned of Consensus Overlay
// Contains validator metadata, request types, and utilities that remain useful
// after migrating consensus logic to pure CometBFT architecture.

package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// Business-level types for validator operations, proof requests, and utilities

// ValidatorRole defines the role of a validator in the network
type ValidatorRole string

const (
	RoleValidator ValidatorRole = "validator" // All nodes are full validators
	RoleObserver  ValidatorRole = "observer"
)

// ValidatorInfo contains information about a validator in the network
type ValidatorInfo struct {
	ValidatorID     string        `json:"validator_id"`
	PublicKey       string        `json:"public_key"`
	NetworkAddress  string        `json:"network_address"`
	VotingPower     int64         `json:"voting_power"`
	Role            ValidatorRole `json:"role"`
	LastHeartbeat   time.Time     `json:"last_heartbeat"`
	IsActive        bool          `json:"is_active"`
	JoinedAt        time.Time     `json:"joined_at"`
	Reputation      float64       `json:"reputation"`
}

// ProofBundle represents a complete bundle of proofs for business processing
type ProofBundle struct {
	BundleID         string                     `json:"bundle_id"`
	CreatedAt        time.Time                  `json:"created_at"`
	IntentRequests   []*ProofVerificationRequest `json:"intent_requests"`
	ValidatorProofs  []string                   `json:"validator_proofs"`
	SyntheticTxs     []string                   `json:"synthetic_txs"`
	TargetChainResults []string                 `json:"target_chain_results"`
	BundleHash       string                     `json:"bundle_hash"`
}

// ProofVerificationRequest represents a business-level request for proof verification
type ProofVerificationRequest struct {
	RequestID       string                 `json:"request_id"`
	ProofType       string                 `json:"proof_type"`       // includes "certen_intent"
	AccountURL      string                 `json:"account_url"`
	ProofData       interface{}            `json:"proof_data"`
	RequesterID     string                 `json:"requester_id"`
	Priority        string                 `json:"priority"`
	TimeoutSeconds  int64                  `json:"timeout_seconds"`
	IntentID        string                 `json:"intent_id,omitempty"`
	TransactionHash string                 `json:"transaction_hash,omitempty"`
	BlockHeight     uint64                 `json:"block_height,omitempty"`
	DiscoveryTime   time.Time              `json:"discovery_time,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// AuthorityValidationRequest represents a business-level request for authority validation
type AuthorityValidationRequest struct {
	RequestID       string                 `json:"request_id"`
	ValidationType  string                 `json:"validation_type"`
	KeyBookURL      string                 `json:"key_book_url"`
	KeyPageURL      string                 `json:"key_page_url"`
	RequiredSigs    int                    `json:"required_signatures"`
	ProvidedSigs    []string               `json:"provided_signatures"`
	TransactionData interface{}            `json:"transaction_data"`
	RequesterID     string                 `json:"requester_id"`
	Priority        Priority               `json:"priority"`
	Timeout         time.Duration          `json:"timeout"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// Priority defines the priority level for business requests
type Priority string

const (
	PriorityLow      Priority = "low"
	PriorityNormal   Priority = "normal"
	PriorityHigh     Priority = "high"
	PriorityCritical Priority = "critical"
)

// Utility functions for validator operations

// GenerateRequestID creates a unique identifier for business requests
func GenerateRequestID(requestType, requester string) string {
	timestamp := time.Now().UnixNano()
	data := fmt.Sprintf("%s_%s_%d", requestType, requester, timestamp)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8]) // Use first 8 bytes for readability
}

// ValidateThreshold checks if a threshold percentage is met
func ValidateThreshold(approveCount, totalCount int, threshold float64) bool {
	if totalCount == 0 {
		return false
	}
	return float64(approveCount)/float64(totalCount) >= threshold
}

// CalculateRequiredCount calculates minimum count needed for threshold
func CalculateRequiredCount(total int, threshold float64) int {
	required := int(float64(total) * threshold)
	if required == 0 && total > 0 {
		required = 1 // At least one required
	}
	return required
}

// IsByzantineFaultTolerant checks if the validator set can tolerate Byzantine faults
func IsByzantineFaultTolerant(totalValidators, maxFaults int) bool {
	// For Byzantine fault tolerance: n >= 3f + 1
	return totalValidators >= 3*maxFaults + 1
}
