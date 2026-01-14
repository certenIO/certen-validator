// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package interfaces defines comprehensive interfaces for the production proof system
package interfaces

import (
	"context"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
)

// ProofBuilder defines the interface for generating cryptographic proofs
type ProofBuilder interface {
	// Core proof generation
	GenerateAccountProof(ctx context.Context, accountURL *url.URL) (*CompleteProof, error)
	GenerateBPTProof(ctx context.Context, accountURL string) (*BPTProof, error)

	// Receipt chain building
	BuildReceiptChain(ctx context.Context, start, end []byte) (*merkle.Receipt, error)
	BuildCompleteChain(ctx context.Context, accountURL string) (*CompleteChain, error)

	// Verification
	VerifyCompleteProof(proof *CompleteProof) error
	VerifyBPTProof(proof *BPTProof) error
}

// ProofVerifier defines the interface for proof verification
type ProofVerifier interface {
	// Verify individual proof components
	VerifyAccountState(accountURL *url.URL, proof *AccountProof) error
	VerifyBPTInclusion(accountHash []byte, proof *BPTProof) error
	VerifyReceiptChain(receipt *merkle.Receipt) error

	// Verify complete proof chain
	VerifyCompleteProof(proof *CompleteProof) error

	// Layer-specific verification
	VerifyLayer1(accountURL *url.URL) (*Layer1Result, error)
	VerifyLayer2(bptRoot string, blockHeight int64) (*Layer2Result, error)
	VerifyLayer3(blockHash string, blockHeight int64) (*Layer3Result, error)
}

// ProofCollector gathers all necessary proof components
type ProofCollector interface {
	// Collect proof data for an account
	CollectAccountProofData(ctx context.Context, accountURL string) (*ProofData, error)

	// Collect specific proof components
	CollectBPTProof(ctx context.Context, partition string, accountHash []byte) (*BPTProof, error)
	CollectReceipts(ctx context.Context, requests []ReceiptRequest) ([]*merkle.Receipt, error)
	CollectValidatorSets(ctx context.Context, partitions []string) (map[string][]ValidatorInfo, error)

	// Collect anchor proofs
	CollectAnchorProofs(ctx context.Context, anchors []AnchorRequest) ([]*AnchorProof, error)
}

// ProofCache manages caching of proof components for performance
type ProofCache interface {
	// Cache proof components
	StoreAccountProof(accountURL string, proof *CompleteProof) error
	StoreBPTProof(partition string, hash []byte, proof *BPTProof) error
	StoreReceipt(key []byte, receipt *merkle.Receipt) error

	// Retrieve cached proofs
	GetAccountProof(accountURL string) (*CompleteProof, bool)
	GetBPTProof(partition string, hash []byte) (*BPTProof, bool)
	GetReceipt(key []byte) (*merkle.Receipt, bool)

	// Cache management
	InvalidateAccountProof(accountURL string) error
	ClearProofCache() error
	GetProofCacheMetrics() *ProofCacheMetrics
}

// ProofManager coordinates all proof operations with advanced functionality
type ProofManager interface {
	// Initialize proof system
	Initialize(backend DataBackend) error

	// Generate proof with strategy
	GenerateProof(ctx context.Context, accountURL string, strategy ProofStrategy) (*CompleteProof, error)

	// Batch proof generation for performance
	GenerateBatchProof(ctx context.Context, accountURLs []string) (map[string]*CompleteProof, error)

	// Verify proof
	VerifyProof(proof *CompleteProof) error

	// Get proof requirements
	GetRequirements(accountURL string) *ProofRequirements

	// Cache management
	GetCache() ProofCache

	// Metrics and monitoring
	GetMetrics() *ProofSystemMetrics

	// Configuration
	UpdateConfig(config *ProofConfig) error
	GetConfig() *ProofConfig

	// Debug and diagnostics
	SetDebugMode(enabled bool)
	GetDebugInfo(accountURL string) (*DebugInfo, error)
}

// ProofSerializer handles proof serialization for persistence and transport
type ProofSerializer interface {
	// Serialize proof to bytes
	SerializeProof(proof *CompleteProof) ([]byte, error)

	// Deserialize proof from bytes
	DeserializeProof(data []byte) (*CompleteProof, error)

	// Export proof to JSON
	ExportToJSON(proof *CompleteProof) ([]byte, error)

	// Import proof from JSON
	ImportFromJSON(data []byte) (*CompleteProof, error)

	// Compress/decompress for efficient storage
	CompressProof(proof *CompleteProof) ([]byte, error)
	DecompressProof(data []byte) (*CompleteProof, error)
}

// ConsensusVerifier verifies consensus requirements
type ConsensusVerifier interface {
	// Verify validator set
	VerifyValidatorSet(validators []ValidatorInfo, expectedHash []byte) error

	// Verify threshold signatures
	VerifyThresholdSignatures(signatures []ValidatorSignature, validators []ValidatorInfo, threshold float64) error

	// Get current validator set
	GetCurrentValidators(ctx context.Context, partition string) ([]ValidatorInfo, error)

	// Verify state transition
	VerifyStateTransition(oldState, newState []byte, validators []ValidatorInfo) error
}

// Data structures

// ProofStrategy defines different proof generation strategies
type ProofStrategy int

const (
	// StrategyMinimal generates minimal proof for verification
	StrategyMinimal ProofStrategy = iota

	// StrategyComplete generates complete proof with all components
	StrategyComplete

	// StrategyOptimized generates optimized proof based on cache
	StrategyOptimized

	// StrategyBatch generates proof for multiple accounts efficiently
	StrategyBatch

	// StrategyDebug generates proof with debug information
	StrategyDebug
)

// ProofConfig contains configuration for proof system
type ProofConfig struct {
	// Cache configuration
	EnableCache bool
	CacheSize   int
	CacheTTL    time.Duration

	// Strategy configuration
	DefaultStrategy ProofStrategy
	BatchSize       int
	ParallelWorkers int

	// Verification configuration
	StrictMode       bool // Fail on any verification error
	RequireConsensus bool // Require consensus verification
	MinValidators    int  // Minimum validators for consensus

	// Performance configuration
	Timeout    time.Duration
	MaxRetries int
	RetryDelay time.Duration

	// Debug configuration
	DebugMode   bool
	VerboseMode bool
	LogLevel    string

	// Endpoint configuration
	APIEndpoint   string
	CometEndpoint string
}

// ProofSystemMetrics contains overall proof system metrics
type ProofSystemMetrics struct {
	ProofsGenerated     int64
	ProofsVerified      int64
	AverageProofTime    time.Duration
	CacheMetrics        *ProofCacheMetrics
	FailureCount        int64
	LastError           error
	Layer1SuccessRate   float64
	Layer2SuccessRate   float64
	Layer3SuccessRate   float64
	BatchProofsGenerated int64
	TotalUptime          time.Duration
}

// ProofCacheMetrics contains cache performance metrics
type ProofCacheMetrics struct {
	TotalEntries      int
	AccountProofs     int
	BPTProofs         int
	Receipts          int
	HitRate           float64
	MissRate          float64
	EvictionCount     int64
	AverageProofAge   time.Duration
	CacheSize         int64
	MaxCacheSize      int64
	LastCleanupTime   time.Time
}

// DebugInfo contains debug information for proof generation
type DebugInfo struct {
	AccountURL     string
	GenerationTime time.Duration
	LayerTimes     map[string]time.Duration
	CacheHits      map[string]bool
	Errors         []string
	Warnings       []string
	ProofSize      int64
	VerificationSteps []VerificationStep
}

// VerificationStep represents a single step in proof verification
type VerificationStep struct {
	Layer       string
	Description string
	Duration    time.Duration
	Success     bool
	Error       error
	Details     map[string]interface{}
}

// ProofRequirements defines what data the proof system needs
type ProofRequirements interface {
	// What data the proof system needs from backend
	GetRequiredReceipts(accountURL string) []ReceiptRequest
	GetRequiredValidators(partition string) []ValidatorInfo
	GetRequiredAnchors(accountURL string) []AnchorRequest

	// Check if proof data is complete
	ValidateProofData(data *ProofData) error
	HasSufficientData(accountURL string, data *ProofData) bool
}

// Supporting data structures

// CompleteProof represents a complete cryptographic proof chain
type CompleteProof struct {
	// Layer 1: Account → BPT
	AccountHash []byte          `json:"accountHash"`
	BPTProof    *merkle.Receipt `json:"bptProof"`

	// Layer 2: BPT → Block
	BPTRoot     []byte `json:"bptRoot"`
	BlockHeight uint64 `json:"blockHeight"`
	BlockHash   []byte `json:"blockHash"`

	// Layer 3: Block → Validators
	ValidatorProof *ConsensusProof `json:"validatorProof,omitempty"`

	// Layer 4: Validators → Genesis (future)
	TrustChain []ValidatorTransition `json:"trustChain,omitempty"`

	// Metadata
	GeneratedAt time.Time `json:"generatedAt"`
	Strategy    ProofStrategy `json:"strategy"`
	TrustLevel  string `json:"trustLevel"`

	// Combined proof receipt
	CombinedReceipt *merkle.Receipt `json:"combinedReceipt"`

	// Proof path components
	MainChainProof *merkle.Receipt  `json:"mainChainProof"`
	BVNAnchorProof *PartitionAnchor `json:"bvnAnchorProof"`
	DNAnchorProof  *PartitionAnchor `json:"dnAnchorProof"`
}

// ConsensusProof represents Layer 3 consensus verification
type ConsensusProof struct {
	BlockHeight uint64               `json:"blockHeight"`
	BlockHash   []byte               `json:"blockHash"`
	ChainID     string               `json:"chainId"`
	Round       int32                `json:"round"`
	Validators  []ValidatorInfo      `json:"validators"`
	Signatures  []ValidatorSignature `json:"signatures"`
	TotalPower  int64                `json:"totalPower"`
	SignedPower int64                `json:"signedPower"`
	Timestamp   time.Time            `json:"timestamp"`
}

// ValidatorInfo represents a validator's public information
type ValidatorInfo struct {
	Address     []byte `json:"address"`
	PublicKey   []byte `json:"publicKey"`
	VotingPower int64  `json:"votingPower"`
	Verified    bool   `json:"verified"`
}

// ValidatorSignature represents a validator's signature on a block
type ValidatorSignature struct {
	ValidatorAddress []byte    `json:"validatorAddress"`
	Signature        []byte    `json:"signature"`
	Timestamp        time.Time `json:"timestamp"`
	Verified         bool      `json:"verified"`
}

// ValidatorTransition represents a validator set change
type ValidatorTransition struct {
	FromHeight    uint64          `json:"fromHeight"`
	ToHeight      uint64          `json:"toHeight"`
	OldValidators []ValidatorInfo `json:"oldValidators"`
	NewValidators []ValidatorInfo `json:"newValidators"`
	Approvals     int64           `json:"approvals"`
	TransitionHash []byte         `json:"transitionHash"`
}

// PartitionAnchor represents an anchor between partitions
type PartitionAnchor struct {
	SourcePartition string          `json:"sourcePartition"`
	TargetPartition string          `json:"targetPartition"`
	AnchorHash      []byte          `json:"anchorHash"`
	Receipt         *merkle.Receipt `json:"receipt"`
	Height          int64           `json:"height"`
}

// BPTProof represents a proof of inclusion in the BPT
type BPTProof struct {
	AccountHash []byte          `json:"accountHash"`
	BPTRoot     []byte          `json:"bptRoot"`
	Proof       *merkle.Receipt `json:"proof"`
	Partition   string          `json:"partition"`
}

// AccountProof represents proof for an account state
type AccountProof struct {
	AccountURL  string    `json:"accountURL"`
	AccountHash []byte    `json:"accountHash"`
	StateRoot   []byte    `json:"stateRoot"`
	BlockHeight int64     `json:"blockHeight"`
	Timestamp   time.Time `json:"timestamp"`
}

// CompleteChain represents a complete proof chain
type CompleteChain struct {
	AccountProof   *AccountProof     `json:"accountProof"`
	BPTProof       *BPTProof         `json:"bptProof"`
	MainChainProof *merkle.Receipt   `json:"mainChainProof"`
	BVNAnchorProof *merkle.Receipt   `json:"bvnAnchorProof"`
	DNAnchorProof  *merkle.Receipt   `json:"dnAnchorProof"`
	Validators     []ValidatorSignature `json:"validators"`
	ChainID        string            `json:"chainId"`
}

// ReceiptRequest specifies a receipt needed for proof
type ReceiptRequest struct {
	Type      string `json:"type"` // "main-chain", "bvn-anchor", "dn-anchor"
	Partition string `json:"partition"`
	Start     []byte `json:"start"`
	End       []byte `json:"end"`
	Height    int64  `json:"height"`
}

// AnchorRequest specifies an anchor proof needed
type AnchorRequest struct {
	SourcePartition string `json:"sourcePartition"`
	TargetPartition string `json:"targetPartition"`
	AnchorHash      []byte `json:"anchorHash"`
	Height          int64  `json:"height"`
}

// AnchorProof contains proof for an anchor
type AnchorProof struct {
	Request   AnchorRequest   `json:"request"`
	Receipt   *merkle.Receipt `json:"receipt"`
	Validated bool           `json:"validated"`
	Timestamp time.Time      `json:"timestamp"`
}

// ProofData contains all data needed for proof generation
type ProofData struct {
	Account      *AccountData             `json:"account"`
	BPTProof     *BPTProof               `json:"bptProof"`
	Receipts     []*merkle.Receipt       `json:"receipts"`
	Validators   map[string][]ValidatorInfo `json:"validators"`
	AnchorProofs []*AnchorProof          `json:"anchorProofs"`
	CollectedAt  time.Time               `json:"collectedAt"`
	Version      string                  `json:"version"`
}

// Layer verification result types

// Layer1Result contains results from Layer 1 verification
type Layer1Result struct {
	Verified     bool   `json:"verified"`
	AccountURL   string `json:"accountUrl"`
	AccountHash  string `json:"accountHash"`
	BPTRoot      string `json:"bptRoot"`
	ProofEntries int    `json:"proofEntries"`
	BlockIndex   uint64 `json:"blockIndex"`
	BlockTime    uint64 `json:"blockTime,omitempty"`
	Error        string `json:"error,omitempty"`
}

// Layer2Result contains results from Layer 2 verification
type Layer2Result struct {
	Verified      bool   `json:"verified"`
	BPTRoot       string `json:"bptRoot"`
	BlockHeight   int64  `json:"blockHeight"`
	BlockHash     string `json:"blockHash,omitempty"`
	AppHash       string `json:"appHash,omitempty"`
	BlockTime     string `json:"blockTime,omitempty"`
	ChainID       string `json:"chainId,omitempty"`
	TrustRequired string `json:"trustRequired,omitempty"`
	Error         string `json:"error,omitempty"`
}

// Layer3Result contains results from Layer 3 verification
type Layer3Result struct {
	Verified            bool   `json:"verified"`
	BlockHash           string `json:"blockHash"`
	BlockHeight         int64  `json:"blockHeight"`
	ChainID             string `json:"chainId"`
	Round               int32  `json:"round"`
	TotalValidators     int    `json:"totalValidators"`
	SignedValidators    int    `json:"signedValidators"`
	TotalPower          int64  `json:"totalPower"`
	SignedPower         int64  `json:"signedPower"`
	ThresholdMet        bool   `json:"thresholdMet"`
	Status              string `json:"status,omitempty"`
	APILimitation       bool   `json:"apiLimitation,omitempty"`
	Error               string `json:"error,omitempty"`
}

// Backend interfaces

// DataBackend provides data access for proof operations
type DataBackend interface {
	QueryAccount(url *url.URL) (interface{}, error)
	QueryBlock(height int64) (interface{}, error)
	QueryValidators(height int64) (interface{}, error)
}

// AccountData represents account information for proof generation
type AccountData struct {
	URL         string      `json:"url"`
	Type        string      `json:"type"`
	Data        interface{} `json:"data"`
	StateHash   []byte      `json:"stateHash"`
	LastUpdated time.Time   `json:"lastUpdated"`
}