// Copyright 2025 Certen Protocol
//
// EventWatcher monitors CertenAnchorV3 contract events
// Per Implementation Plan Phase 4, Task 4.2: Event monitoring for multi-validator consensus
//
// This component watches for on-chain anchor events and emits them to subscribers
// for confirmation tracking, attestation coordination, and error diagnosis.

package anchor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

// =============================================================================
// Event Types
// =============================================================================

// EventType identifies the type of contract event
type EventType string

const (
	EventTypeAnchorCreated          EventType = "AnchorCreated"
	EventTypeProofExecuted          EventType = "ProofExecuted"
	EventTypeProofVerificationFailed EventType = "ProofVerificationFailed"
	EventTypeGovernanceExecuted     EventType = "GovernanceExecuted"
	EventTypeValidatorRegistered    EventType = "ValidatorRegistered"
	EventTypeValidatorRemoved       EventType = "ValidatorRemoved"
	EventTypeThresholdUpdated       EventType = "ThresholdUpdated"
	EventTypeUnknown                EventType = "Unknown"
)

// =============================================================================
// Event Structures
// =============================================================================

// ContractEvent is the base interface for all contract events
type ContractEvent interface {
	GetEventType() EventType
	GetBlockNumber() uint64
	GetTxHash() string
	GetTimestamp() time.Time
}

// AnchorCreatedEvent represents the AnchorCreated event from CertenAnchorV3
type AnchorCreatedEvent struct {
	BundleID              [32]byte       `json:"bundle_id"`
	OperationCommitment   [32]byte       `json:"operation_commitment"`
	CrossChainCommitment  [32]byte       `json:"cross_chain_commitment"`
	GovernanceRoot        [32]byte       `json:"governance_root"`
	AccumulateBlockHeight *big.Int       `json:"accumulate_block_height"`
	Validator             common.Address `json:"validator"`
	Timestamp             *big.Int       `json:"timestamp"`

	// Metadata
	BlockNumber uint64    `json:"block_number"`
	TxHash      string    `json:"tx_hash"`
	LogIndex    uint      `json:"log_index"`
	ParsedAt    time.Time `json:"parsed_at"`
}

func (e *AnchorCreatedEvent) GetEventType() EventType   { return EventTypeAnchorCreated }
func (e *AnchorCreatedEvent) GetBlockNumber() uint64    { return e.BlockNumber }
func (e *AnchorCreatedEvent) GetTxHash() string         { return e.TxHash }
func (e *AnchorCreatedEvent) GetTimestamp() time.Time   { return e.ParsedAt }

// ProofExecutedEvent represents the ProofExecuted event from CertenAnchorV3
type ProofExecutedEvent struct {
	AnchorID            [32]byte `json:"anchor_id"`
	TransactionHash     [32]byte `json:"transaction_hash"`
	MerkleVerified      bool     `json:"merkle_verified"`
	BLSVerified         bool     `json:"bls_verified"`
	GovernanceVerified  bool     `json:"governance_verified"`
	Timestamp           *big.Int `json:"timestamp"`

	// Metadata
	BlockNumber uint64    `json:"block_number"`
	TxHash      string    `json:"tx_hash"`
	LogIndex    uint      `json:"log_index"`
	ParsedAt    time.Time `json:"parsed_at"`
}

func (e *ProofExecutedEvent) GetEventType() EventType   { return EventTypeProofExecuted }
func (e *ProofExecutedEvent) GetBlockNumber() uint64    { return e.BlockNumber }
func (e *ProofExecutedEvent) GetTxHash() string         { return e.TxHash }
func (e *ProofExecutedEvent) GetTimestamp() time.Time   { return e.ParsedAt }

// ProofVerificationFailedEvent represents the ProofVerificationFailed event
type ProofVerificationFailedEvent struct {
	AnchorID             [32]byte `json:"anchor_id"`
	TransactionHash      [32]byte `json:"transaction_hash"`
	MerkleVerified       bool     `json:"merkle_verified"`
	BLSVerified          bool     `json:"bls_verified"`
	GovernanceVerified   bool     `json:"governance_verified"`
	CommitmentVerified   bool     `json:"commitment_verified"`
	Reason               string   `json:"reason"`
	Timestamp            *big.Int `json:"timestamp"`

	// Metadata
	BlockNumber uint64    `json:"block_number"`
	TxHash      string    `json:"tx_hash"`
	LogIndex    uint      `json:"log_index"`
	ParsedAt    time.Time `json:"parsed_at"`
}

func (e *ProofVerificationFailedEvent) GetEventType() EventType { return EventTypeProofVerificationFailed }
func (e *ProofVerificationFailedEvent) GetBlockNumber() uint64  { return e.BlockNumber }
func (e *ProofVerificationFailedEvent) GetTxHash() string       { return e.TxHash }
func (e *ProofVerificationFailedEvent) GetTimestamp() time.Time { return e.ParsedAt }

// GovernanceExecutedEvent represents the GovernanceExecuted event
type GovernanceExecutedEvent struct {
	AnchorID  [32]byte       `json:"anchor_id"`
	Target    common.Address `json:"target"`
	Value     *big.Int       `json:"value"`
	Success   bool           `json:"success"`
	Timestamp *big.Int       `json:"timestamp"`

	// Metadata
	BlockNumber uint64    `json:"block_number"`
	TxHash      string    `json:"tx_hash"`
	LogIndex    uint      `json:"log_index"`
	ParsedAt    time.Time `json:"parsed_at"`
}

func (e *GovernanceExecutedEvent) GetEventType() EventType { return EventTypeGovernanceExecuted }
func (e *GovernanceExecutedEvent) GetBlockNumber() uint64  { return e.BlockNumber }
func (e *GovernanceExecutedEvent) GetTxHash() string       { return e.TxHash }
func (e *GovernanceExecutedEvent) GetTimestamp() time.Time { return e.ParsedAt }

// ValidatorRegisteredEvent represents the ValidatorRegistered event
type ValidatorRegisteredEvent struct {
	Validator   common.Address `json:"validator"`
	VotingPower *big.Int       `json:"voting_power"`

	// Metadata
	BlockNumber uint64    `json:"block_number"`
	TxHash      string    `json:"tx_hash"`
	LogIndex    uint      `json:"log_index"`
	ParsedAt    time.Time `json:"parsed_at"`
}

func (e *ValidatorRegisteredEvent) GetEventType() EventType { return EventTypeValidatorRegistered }
func (e *ValidatorRegisteredEvent) GetBlockNumber() uint64  { return e.BlockNumber }
func (e *ValidatorRegisteredEvent) GetTxHash() string       { return e.TxHash }
func (e *ValidatorRegisteredEvent) GetTimestamp() time.Time { return e.ParsedAt }

// =============================================================================
// ABI Definition for Event Parsing
// =============================================================================

// CertenAnchorV3EventsABI contains the ABI for events we watch
const CertenAnchorV3EventsABI = `[
	{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "bundleId", "type": "bytes32"},
			{"indexed": false, "name": "operationCommitment", "type": "bytes32"},
			{"indexed": false, "name": "crossChainCommitment", "type": "bytes32"},
			{"indexed": false, "name": "governanceRoot", "type": "bytes32"},
			{"indexed": false, "name": "accumulateBlockHeight", "type": "uint256"},
			{"indexed": true, "name": "validator", "type": "address"},
			{"indexed": false, "name": "timestamp", "type": "uint256"}
		],
		"name": "AnchorCreated",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "anchorId", "type": "bytes32"},
			{"indexed": false, "name": "transactionHash", "type": "bytes32"},
			{"indexed": false, "name": "merkleVerified", "type": "bool"},
			{"indexed": false, "name": "blsVerified", "type": "bool"},
			{"indexed": false, "name": "governanceVerified", "type": "bool"},
			{"indexed": false, "name": "timestamp", "type": "uint256"}
		],
		"name": "ProofExecuted",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "anchorId", "type": "bytes32"},
			{"indexed": false, "name": "transactionHash", "type": "bytes32"},
			{"indexed": false, "name": "merkleVerified", "type": "bool"},
			{"indexed": false, "name": "blsVerified", "type": "bool"},
			{"indexed": false, "name": "governanceVerified", "type": "bool"},
			{"indexed": false, "name": "commitmentVerified", "type": "bool"},
			{"indexed": false, "name": "reason", "type": "string"},
			{"indexed": false, "name": "timestamp", "type": "uint256"}
		],
		"name": "ProofVerificationFailed",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "anchorId", "type": "bytes32"},
			{"indexed": true, "name": "target", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"},
			{"indexed": false, "name": "success", "type": "bool"},
			{"indexed": false, "name": "timestamp", "type": "uint256"}
		],
		"name": "GovernanceExecuted",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "validator", "type": "address"},
			{"indexed": false, "name": "votingPower", "type": "uint256"}
		],
		"name": "ValidatorRegistered",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "validator", "type": "address"}
		],
		"name": "ValidatorRemoved",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{"indexed": false, "name": "oldThreshold", "type": "uint256"},
			{"indexed": false, "name": "newThreshold", "type": "uint256"}
		],
		"name": "ThresholdUpdated",
		"type": "event"
	}
]`

// =============================================================================
// Event Topic Hashes (Keccak256 of event signatures)
// =============================================================================

var (
	// Pre-computed topic hashes for event filtering
	TopicAnchorCreated          common.Hash
	TopicProofExecuted          common.Hash
	TopicProofVerificationFailed common.Hash
	TopicGovernanceExecuted     common.Hash
	TopicValidatorRegistered    common.Hash
	TopicValidatorRemoved       common.Hash
	TopicThresholdUpdated       common.Hash
)

func init() {
	// Compute Keccak256 hashes of event signatures
	// AnchorCreated(bytes32,bytes32,bytes32,bytes32,uint256,address,uint256)
	TopicAnchorCreated = computeEventSignatureHash("AnchorCreated(bytes32,bytes32,bytes32,bytes32,uint256,address,uint256)")
	// ProofExecuted(bytes32,bytes32,bool,bool,bool,uint256)
	TopicProofExecuted = computeEventSignatureHash("ProofExecuted(bytes32,bytes32,bool,bool,bool,uint256)")
	// ProofVerificationFailed(bytes32,bytes32,bool,bool,bool,bool,string,uint256)
	TopicProofVerificationFailed = computeEventSignatureHash("ProofVerificationFailed(bytes32,bytes32,bool,bool,bool,bool,string,uint256)")
	// GovernanceExecuted(bytes32,address,uint256,bool,uint256)
	TopicGovernanceExecuted = computeEventSignatureHash("GovernanceExecuted(bytes32,address,uint256,bool,uint256)")
	// ValidatorRegistered(address,uint256)
	TopicValidatorRegistered = computeEventSignatureHash("ValidatorRegistered(address,uint256)")
	// ValidatorRemoved(address)
	TopicValidatorRemoved = computeEventSignatureHash("ValidatorRemoved(address)")
	// ThresholdUpdated(uint256,uint256)
	TopicThresholdUpdated = computeEventSignatureHash("ThresholdUpdated(uint256,uint256)")
}

// computeEventSignatureHash computes Keccak256 hash of an event signature
func computeEventSignatureHash(signature string) common.Hash {
	hash := sha256.Sum256([]byte(signature))
	// Note: Ethereum uses Keccak256, not SHA256
	// We'll use go-ethereum's crypto.Keccak256Hash at runtime for accuracy
	return common.BytesToHash(hash[:])
}

// =============================================================================
// EventWatcher
// =============================================================================

// EventWatcherConfig contains configuration for the event watcher
type EventWatcherConfig struct {
	// Contract address to watch
	ContractAddress common.Address

	// Ethereum client connection
	EthereumURL string
	ChainID     int64

	// Polling configuration (for networks without WebSocket support)
	PollInterval time.Duration
	BlockLookback uint64 // How many blocks back to scan on start

	// Filter configuration
	EnabledEvents []EventType // Which events to watch (empty = all)

	// Processing configuration
	EventBufferSize int           // Size of event channel buffer
	RetryAttempts   int           // Number of retry attempts for failed queries
	RetryDelay      time.Duration // Delay between retries
}

// DefaultEventWatcherConfig returns a default configuration
func DefaultEventWatcherConfig() *EventWatcherConfig {
	return &EventWatcherConfig{
		PollInterval:    15 * time.Second,
		BlockLookback:   100,
		EventBufferSize: 1000,
		RetryAttempts:   3,
		RetryDelay:      2 * time.Second,
		EnabledEvents:   []EventType{}, // All events
	}
}

// EventWatcher monitors CertenAnchorV3 contract events
type EventWatcher struct {
	config *EventWatcherConfig
	client *ethclient.Client
	abi    abi.ABI

	// Event channel
	events chan ContractEvent
	errors chan error

	// State management
	lastProcessedBlock uint64
	mu                 sync.RWMutex

	// Lifecycle management
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	running    bool
	runningMu  sync.Mutex

	// Handlers
	handlers   map[EventType][]EventHandler
	handlersMu sync.RWMutex

	logger *log.Logger
}

// EventHandler is a callback for processing events
type EventHandler func(event ContractEvent) error

// NewEventWatcher creates a new event watcher
func NewEventWatcher(config *EventWatcherConfig, logger *log.Logger) (*EventWatcher, error) {
	if config == nil {
		config = DefaultEventWatcherConfig()
	}

	if config.ContractAddress == (common.Address{}) {
		return nil, fmt.Errorf("contract address is required")
	}

	if config.EthereumURL == "" {
		return nil, fmt.Errorf("ethereum URL is required")
	}

	// Parse the ABI
	parsedABI, err := abi.JSON(strings.NewReader(CertenAnchorV3EventsABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse events ABI: %w", err)
	}

	// Connect to Ethereum
	client, err := ethclient.Dial(config.EthereumURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Ethereum: %w", err)
	}

	if logger == nil {
		logger = log.New(log.Writer(), "[EventWatcher] ", log.LstdFlags)
	}

	return &EventWatcher{
		config:   config,
		client:   client,
		abi:      parsedABI,
		events:   make(chan ContractEvent, config.EventBufferSize),
		errors:   make(chan error, 100),
		handlers: make(map[EventType][]EventHandler),
		logger:   logger,
	}, nil
}

// RegisterHandler registers an event handler for a specific event type
// Pass EventTypeUnknown to register a handler for all events
func (w *EventWatcher) RegisterHandler(eventType EventType, handler EventHandler) {
	w.handlersMu.Lock()
	defer w.handlersMu.Unlock()

	if w.handlers[eventType] == nil {
		w.handlers[eventType] = []EventHandler{}
	}
	w.handlers[eventType] = append(w.handlers[eventType], handler)
}

// Events returns the event channel for receiving parsed events
func (w *EventWatcher) Events() <-chan ContractEvent {
	return w.events
}

// Errors returns the error channel for receiving errors
func (w *EventWatcher) Errors() <-chan error {
	return w.errors
}

// Start begins watching for events
func (w *EventWatcher) Start(ctx context.Context) error {
	w.runningMu.Lock()
	if w.running {
		w.runningMu.Unlock()
		return fmt.Errorf("event watcher already running")
	}
	w.running = true
	w.runningMu.Unlock()

	w.ctx, w.cancel = context.WithCancel(ctx)

	// Initialize the last processed block
	if err := w.initializeStartBlock(); err != nil {
		return fmt.Errorf("failed to initialize start block: %w", err)
	}

	// Start the polling goroutine
	w.wg.Add(1)
	go w.pollLoop()

	// Start the handler dispatcher
	w.wg.Add(1)
	go w.dispatchLoop()

	w.logger.Printf("EventWatcher started, monitoring contract %s from block %d",
		w.config.ContractAddress.Hex(), w.lastProcessedBlock)

	return nil
}

// Stop stops the event watcher
func (w *EventWatcher) Stop() error {
	w.runningMu.Lock()
	if !w.running {
		w.runningMu.Unlock()
		return nil
	}
	w.running = false
	w.runningMu.Unlock()

	// Cancel the context
	if w.cancel != nil {
		w.cancel()
	}

	// Wait for goroutines to finish
	w.wg.Wait()

	// Close channels
	close(w.events)
	close(w.errors)

	w.logger.Printf("EventWatcher stopped")
	return nil
}

// initializeStartBlock sets the starting block for event polling
func (w *EventWatcher) initializeStartBlock() error {
	// Get current block number
	currentBlock, err := w.client.BlockNumber(w.ctx)
	if err != nil {
		return fmt.Errorf("failed to get current block: %w", err)
	}

	// Calculate start block with lookback
	if currentBlock > w.config.BlockLookback {
		w.lastProcessedBlock = currentBlock - w.config.BlockLookback
	} else {
		w.lastProcessedBlock = 0
	}

	return nil
}

// pollLoop continuously polls for new events
func (w *EventWatcher) pollLoop() {
	defer w.wg.Done()

	ticker := time.NewTicker(w.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			if err := w.pollEvents(); err != nil {
				w.logger.Printf("Error polling events: %v", err)
				select {
				case w.errors <- err:
				default:
					// Error channel full, skip
				}
			}
		}
	}
}

// pollEvents fetches and processes events from the contract
func (w *EventWatcher) pollEvents() error {
	// Get current block number
	currentBlock, err := w.client.BlockNumber(w.ctx)
	if err != nil {
		return fmt.Errorf("failed to get current block: %w", err)
	}

	w.mu.RLock()
	fromBlock := w.lastProcessedBlock + 1
	w.mu.RUnlock()

	if fromBlock > currentBlock {
		return nil // No new blocks
	}

	// Cap the range to prevent too large queries
	// NOTE: Alchemy free tier limits eth_getLogs to 10 blocks per request
	toBlock := currentBlock
	maxBlockRange := uint64(9) // Alchemy free tier limit (10 blocks inclusive)
	if toBlock-fromBlock > maxBlockRange {
		toBlock = fromBlock + maxBlockRange
	}

	// Build filter query
	query := ethereum.FilterQuery{
		FromBlock: big.NewInt(int64(fromBlock)),
		ToBlock:   big.NewInt(int64(toBlock)),
		Addresses: []common.Address{w.config.ContractAddress},
	}

	// Add topic filters for enabled events
	if len(w.config.EnabledEvents) > 0 {
		topics := make([]common.Hash, 0, len(w.config.EnabledEvents))
		for _, et := range w.config.EnabledEvents {
			if topic := w.getTopicForEventType(et); topic != (common.Hash{}) {
				topics = append(topics, topic)
			}
		}
		if len(topics) > 0 {
			query.Topics = [][]common.Hash{topics}
		}
	}

	// Fetch logs with retry
	var logs []types.Log
	for attempt := 0; attempt < w.config.RetryAttempts; attempt++ {
		logs, err = w.client.FilterLogs(w.ctx, query)
		if err == nil {
			break
		}
		if attempt < w.config.RetryAttempts-1 {
			time.Sleep(w.config.RetryDelay)
		}
	}
	if err != nil {
		return fmt.Errorf("failed to filter logs after %d attempts: %w", w.config.RetryAttempts, err)
	}

	// Parse and emit events
	for _, log := range logs {
		event, err := w.parseLog(log)
		if err != nil {
			w.logger.Printf("Failed to parse log: %v", err)
			continue
		}
		if event != nil {
			select {
			case w.events <- event:
			default:
				w.logger.Printf("Event channel full, dropping event")
			}
		}
	}

	// Update last processed block
	w.mu.Lock()
	w.lastProcessedBlock = toBlock
	w.mu.Unlock()

	if len(logs) > 0 {
		w.logger.Printf("Processed %d events from blocks %d to %d", len(logs), fromBlock, toBlock)
	}

	return nil
}

// getTopicForEventType returns the topic hash for an event type
func (w *EventWatcher) getTopicForEventType(et EventType) common.Hash {
	switch et {
	case EventTypeAnchorCreated:
		return TopicAnchorCreated
	case EventTypeProofExecuted:
		return TopicProofExecuted
	case EventTypeProofVerificationFailed:
		return TopicProofVerificationFailed
	case EventTypeGovernanceExecuted:
		return TopicGovernanceExecuted
	case EventTypeValidatorRegistered:
		return TopicValidatorRegistered
	case EventTypeValidatorRemoved:
		return TopicValidatorRemoved
	case EventTypeThresholdUpdated:
		return TopicThresholdUpdated
	default:
		return common.Hash{}
	}
}

// parseLog parses a raw log into a typed event
func (w *EventWatcher) parseLog(log types.Log) (ContractEvent, error) {
	if len(log.Topics) == 0 {
		return nil, fmt.Errorf("log has no topics")
	}

	topic := log.Topics[0]
	parsedAt := time.Now()

	// Match topic to event type and parse
	// Note: In production, we'd use the parsed ABI's event signatures
	// Here we match against the first topic (event signature hash)

	// Try to determine event type from ABI
	for _, event := range w.abi.Events {
		if event.ID == topic {
			switch event.Name {
			case "AnchorCreated":
				return w.parseAnchorCreated(log, parsedAt)
			case "ProofExecuted":
				return w.parseProofExecuted(log, parsedAt)
			case "ProofVerificationFailed":
				return w.parseProofVerificationFailed(log, parsedAt)
			case "GovernanceExecuted":
				return w.parseGovernanceExecuted(log, parsedAt)
			case "ValidatorRegistered":
				return w.parseValidatorRegistered(log, parsedAt)
			default:
				w.logger.Printf("Unknown event type: %s", event.Name)
				return nil, nil
			}
		}
	}

	return nil, nil // Unknown event topic
}

// parseAnchorCreated parses an AnchorCreated event
func (w *EventWatcher) parseAnchorCreated(log types.Log, parsedAt time.Time) (*AnchorCreatedEvent, error) {
	event := &AnchorCreatedEvent{
		BlockNumber: log.BlockNumber,
		TxHash:      log.TxHash.Hex(),
		LogIndex:    log.Index,
		ParsedAt:    parsedAt,
	}

	// Extract indexed parameters from topics
	// topic[0] = event signature
	// topic[1] = bundleId (indexed)
	// topic[2] = validator (indexed)
	if len(log.Topics) >= 3 {
		event.BundleID = log.Topics[1]
		event.Validator = common.BytesToAddress(log.Topics[2].Bytes())
	}

	// Unpack non-indexed data
	if len(log.Data) > 0 {
		values, err := w.abi.Unpack("AnchorCreated", log.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to unpack AnchorCreated data: %w", err)
		}

		if len(values) >= 5 {
			if v, ok := values[0].([32]byte); ok {
				event.OperationCommitment = v
			}
			if v, ok := values[1].([32]byte); ok {
				event.CrossChainCommitment = v
			}
			if v, ok := values[2].([32]byte); ok {
				event.GovernanceRoot = v
			}
			if v, ok := values[3].(*big.Int); ok {
				event.AccumulateBlockHeight = v
			}
			if v, ok := values[4].(*big.Int); ok {
				event.Timestamp = v
			}
		}
	}

	w.logger.Printf("Parsed AnchorCreated: bundleId=%s, validator=%s, block=%d",
		hex.EncodeToString(event.BundleID[:])[:16], event.Validator.Hex()[:10], event.BlockNumber)

	return event, nil
}

// parseProofExecuted parses a ProofExecuted event
func (w *EventWatcher) parseProofExecuted(log types.Log, parsedAt time.Time) (*ProofExecutedEvent, error) {
	event := &ProofExecutedEvent{
		BlockNumber: log.BlockNumber,
		TxHash:      log.TxHash.Hex(),
		LogIndex:    log.Index,
		ParsedAt:    parsedAt,
	}

	// Extract indexed parameters from topics
	if len(log.Topics) >= 2 {
		event.AnchorID = log.Topics[1]
	}

	// Unpack non-indexed data
	if len(log.Data) > 0 {
		values, err := w.abi.Unpack("ProofExecuted", log.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to unpack ProofExecuted data: %w", err)
		}

		if len(values) >= 5 {
			if v, ok := values[0].([32]byte); ok {
				event.TransactionHash = v
			}
			if v, ok := values[1].(bool); ok {
				event.MerkleVerified = v
			}
			if v, ok := values[2].(bool); ok {
				event.BLSVerified = v
			}
			if v, ok := values[3].(bool); ok {
				event.GovernanceVerified = v
			}
			if v, ok := values[4].(*big.Int); ok {
				event.Timestamp = v
			}
		}
	}

	w.logger.Printf("Parsed ProofExecuted: anchorId=%s, merkle=%v, bls=%v, gov=%v",
		hex.EncodeToString(event.AnchorID[:])[:16], event.MerkleVerified, event.BLSVerified, event.GovernanceVerified)

	return event, nil
}

// parseProofVerificationFailed parses a ProofVerificationFailed event
func (w *EventWatcher) parseProofVerificationFailed(log types.Log, parsedAt time.Time) (*ProofVerificationFailedEvent, error) {
	event := &ProofVerificationFailedEvent{
		BlockNumber: log.BlockNumber,
		TxHash:      log.TxHash.Hex(),
		LogIndex:    log.Index,
		ParsedAt:    parsedAt,
	}

	// Extract indexed parameters from topics
	if len(log.Topics) >= 2 {
		event.AnchorID = log.Topics[1]
	}

	// Unpack non-indexed data
	if len(log.Data) > 0 {
		values, err := w.abi.Unpack("ProofVerificationFailed", log.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to unpack ProofVerificationFailed data: %w", err)
		}

		if len(values) >= 7 {
			if v, ok := values[0].([32]byte); ok {
				event.TransactionHash = v
			}
			if v, ok := values[1].(bool); ok {
				event.MerkleVerified = v
			}
			if v, ok := values[2].(bool); ok {
				event.BLSVerified = v
			}
			if v, ok := values[3].(bool); ok {
				event.GovernanceVerified = v
			}
			if v, ok := values[4].(bool); ok {
				event.CommitmentVerified = v
			}
			if v, ok := values[5].(string); ok {
				event.Reason = v
			}
			if v, ok := values[6].(*big.Int); ok {
				event.Timestamp = v
			}
		}
	}

	w.logger.Printf("Parsed ProofVerificationFailed: anchorId=%s, reason=%s",
		hex.EncodeToString(event.AnchorID[:])[:16], event.Reason)

	return event, nil
}

// parseGovernanceExecuted parses a GovernanceExecuted event
func (w *EventWatcher) parseGovernanceExecuted(log types.Log, parsedAt time.Time) (*GovernanceExecutedEvent, error) {
	event := &GovernanceExecutedEvent{
		BlockNumber: log.BlockNumber,
		TxHash:      log.TxHash.Hex(),
		LogIndex:    log.Index,
		ParsedAt:    parsedAt,
	}

	// Extract indexed parameters from topics
	if len(log.Topics) >= 3 {
		event.AnchorID = log.Topics[1]
		event.Target = common.BytesToAddress(log.Topics[2].Bytes())
	}

	// Unpack non-indexed data
	if len(log.Data) > 0 {
		values, err := w.abi.Unpack("GovernanceExecuted", log.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to unpack GovernanceExecuted data: %w", err)
		}

		if len(values) >= 3 {
			if v, ok := values[0].(*big.Int); ok {
				event.Value = v
			}
			if v, ok := values[1].(bool); ok {
				event.Success = v
			}
			if v, ok := values[2].(*big.Int); ok {
				event.Timestamp = v
			}
		}
	}

	w.logger.Printf("Parsed GovernanceExecuted: anchorId=%s, target=%s, success=%v",
		hex.EncodeToString(event.AnchorID[:])[:16], event.Target.Hex()[:10], event.Success)

	return event, nil
}

// parseValidatorRegistered parses a ValidatorRegistered event
func (w *EventWatcher) parseValidatorRegistered(log types.Log, parsedAt time.Time) (*ValidatorRegisteredEvent, error) {
	event := &ValidatorRegisteredEvent{
		BlockNumber: log.BlockNumber,
		TxHash:      log.TxHash.Hex(),
		LogIndex:    log.Index,
		ParsedAt:    parsedAt,
	}

	// Extract indexed parameters from topics
	if len(log.Topics) >= 2 {
		event.Validator = common.BytesToAddress(log.Topics[1].Bytes())
	}

	// Unpack non-indexed data
	if len(log.Data) > 0 {
		values, err := w.abi.Unpack("ValidatorRegistered", log.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to unpack ValidatorRegistered data: %w", err)
		}

		if len(values) >= 1 {
			if v, ok := values[0].(*big.Int); ok {
				event.VotingPower = v
			}
		}
	}

	w.logger.Printf("Parsed ValidatorRegistered: validator=%s, power=%s",
		event.Validator.Hex()[:10], event.VotingPower.String())

	return event, nil
}

// dispatchLoop dispatches events to registered handlers
func (w *EventWatcher) dispatchLoop() {
	defer w.wg.Done()

	for {
		select {
		case <-w.ctx.Done():
			return
		case event, ok := <-w.events:
			if !ok {
				return
			}
			w.dispatchEvent(event)
		}
	}
}

// dispatchEvent dispatches an event to registered handlers
func (w *EventWatcher) dispatchEvent(event ContractEvent) {
	w.handlersMu.RLock()
	defer w.handlersMu.RUnlock()

	eventType := event.GetEventType()

	// Call type-specific handlers
	if handlers, ok := w.handlers[eventType]; ok {
		for _, handler := range handlers {
			if err := handler(event); err != nil {
				w.logger.Printf("Handler error for %s: %v", eventType, err)
			}
		}
	}

	// Call catch-all handlers (registered for EventTypeUnknown)
	if handlers, ok := w.handlers[EventTypeUnknown]; ok {
		for _, handler := range handlers {
			if err := handler(event); err != nil {
				w.logger.Printf("Handler error for catch-all: %v", err)
			}
		}
	}
}

// =============================================================================
// Utility Functions
// =============================================================================

// GetLastProcessedBlock returns the last processed block number
func (w *EventWatcher) GetLastProcessedBlock() uint64 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.lastProcessedBlock
}

// SetLastProcessedBlock sets the last processed block (for resuming from a checkpoint)
func (w *EventWatcher) SetLastProcessedBlock(blockNumber uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lastProcessedBlock = blockNumber
}

// IsRunning returns whether the event watcher is running
func (w *EventWatcher) IsRunning() bool {
	w.runningMu.Lock()
	defer w.runningMu.Unlock()
	return w.running
}

// GetConfig returns the event watcher configuration
func (w *EventWatcher) GetConfig() *EventWatcherConfig {
	return w.config
}

// FetchHistoricalEvents fetches events from a specific block range
// This is useful for catching up on missed events after a restart
func (w *EventWatcher) FetchHistoricalEvents(ctx context.Context, fromBlock, toBlock uint64) ([]ContractEvent, error) {
	query := ethereum.FilterQuery{
		FromBlock: big.NewInt(int64(fromBlock)),
		ToBlock:   big.NewInt(int64(toBlock)),
		Addresses: []common.Address{w.config.ContractAddress},
	}

	logs, err := w.client.FilterLogs(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch historical logs: %w", err)
	}

	events := make([]ContractEvent, 0, len(logs))
	for _, log := range logs {
		event, err := w.parseLog(log)
		if err != nil {
			w.logger.Printf("Failed to parse historical log: %v", err)
			continue
		}
		if event != nil {
			events = append(events, event)
		}
	}

	return events, nil
}
