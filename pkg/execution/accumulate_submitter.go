// Copyright 2025 Certen Protocol
//
// AccumulateSubmitter Implementation - Write-back to Accumulate Network
// Per CERTEN_COMPLETE_PROOF_CYCLE_SPEC.md Phase 9
//
// This implements the AccumulateSubmitter interface for submitting
// WriteData transactions back to the Accumulate network using proper
// Accumulate protocol types and binary-encoded signatures.

package execution

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/certen/independant-validator/pkg/accumulate"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// =============================================================================
// ACCUMULATE SUBMITTER IMPLEMENTATION
// =============================================================================

// AccumulateSubmitterImpl implements AccumulateSubmitter for real Accumulate network interaction
type AccumulateSubmitterImpl struct {
	mu sync.RWMutex

	// Accumulate client for network interaction
	client *accumulate.LiteClientAdapter

	// Signing credentials
	signingKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey

	// Account configuration
	accountURL   string // Principal account for write-back (e.g., "acc://certen.acme/proof-results")
	signerURL    string // Key page URL for signing (e.g., "acc://certen.acme/book/1")
	keyPageIndex uint64 // Key page index (signer version)
	keyIndex     uint64 // Key index within the page

	// Nonce and credit management
	nonceTracker  *NonceTracker
	creditChecker *CreditChecker

	// Configuration
	confirmationTimeout time.Duration
	maxRetries          int
	retryDelay          time.Duration

	// Logging
	logger *log.Logger
}

// AccumulateSubmitterConfig contains configuration for AccumulateSubmitter
type AccumulateSubmitterConfig struct {
	// Client configuration
	Client *accumulate.LiteClientAdapter

	// Signing credentials - must be valid Ed25519 key
	PrivateKey ed25519.PrivateKey

	// Account configuration
	AccountURL   string // Data account for write-back
	SignerURL    string // Key page URL
	KeyPageIndex uint64
	KeyIndex     uint64

	// Timing configuration
	ConfirmationTimeout time.Duration
	MaxRetries          int
	RetryDelay          time.Duration

	// Logger
	Logger *log.Logger
}

// NewAccumulateSubmitter creates a new AccumulateSubmitter implementation
func NewAccumulateSubmitter(cfg *AccumulateSubmitterConfig) (*AccumulateSubmitterImpl, error) {
	if cfg.Client == nil {
		return nil, fmt.Errorf("accumulate client is required")
	}

	if len(cfg.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key: expected %d bytes, got %d", ed25519.PrivateKeySize, len(cfg.PrivateKey))
	}

	if cfg.AccountURL == "" {
		return nil, fmt.Errorf("account URL is required")
	}

	if cfg.SignerURL == "" {
		return nil, fmt.Errorf("signer URL is required")
	}

	// Extract public key from private key
	publicKey := cfg.PrivateKey.Public().(ed25519.PublicKey)

	// Set defaults
	confirmationTimeout := cfg.ConfirmationTimeout
	if confirmationTimeout == 0 {
		confirmationTimeout = 2 * time.Minute
	}

	maxRetries := cfg.MaxRetries
	if maxRetries == 0 {
		maxRetries = 3
	}

	retryDelay := cfg.RetryDelay
	if retryDelay == 0 {
		retryDelay = 5 * time.Second
	}

	logger := cfg.Logger
	if logger == nil {
		logger = log.New(log.Writer(), "[AccSubmitter] ", log.LstdFlags)
	}

	// Create nonce tracker
	nonceTracker := NewNonceTracker(cfg.SignerURL, cfg.Client, logger)

	// Create credit checker
	creditChecker := NewCreditChecker(cfg.SignerURL, cfg.Client, logger)

	submitter := &AccumulateSubmitterImpl{
		client:              cfg.Client,
		signingKey:          cfg.PrivateKey,
		publicKey:           publicKey,
		accountURL:          cfg.AccountURL,
		signerURL:           cfg.SignerURL,
		keyPageIndex:        cfg.KeyPageIndex,
		keyIndex:            cfg.KeyIndex,
		nonceTracker:        nonceTracker,
		creditChecker:       creditChecker,
		confirmationTimeout: confirmationTimeout,
		maxRetries:          maxRetries,
		retryDelay:          retryDelay,
		logger:              logger,
	}

	return submitter, nil
}

// SubmitTransaction submits a synthetic transaction to Accumulate
// Returns the transaction hash on success
func (s *AccumulateSubmitterImpl) SubmitTransaction(ctx context.Context, tx *SyntheticTransaction) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Printf("📤 Submitting WriteData transaction: %s", tx.ToHex())

	// Step 1: Check credit balance
	hasCredits, balance, err := s.creditChecker.HasSufficientCredits(ctx, MinCreditsForWriteData)
	if err != nil {
		return "", fmt.Errorf("failed to check credits: %w", err)
	}
	if !hasCredits {
		return "", fmt.Errorf("insufficient credits: have %d, need %d", balance, MinCreditsForWriteData)
	}
	s.logger.Printf("✅ Credit check passed: %d credits available", balance)

	// Step 2: Create the Accumulate Transaction with proper protocol types
	accTx, err := s.createAccumulateTransaction(tx)
	if err != nil {
		return "", fmt.Errorf("failed to create Accumulate transaction: %w", err)
	}

	// Step 3: Create and sign the signature using proper Accumulate signing
	timestamp := uint64(time.Now().UnixMicro())
	sig, err := s.createAndSignSignature(accTx, timestamp)
	if err != nil {
		return "", fmt.Errorf("failed to create signature: %w", err)
	}

	// Step 4: Create the envelope
	envelope := &messaging.Envelope{
		Transaction: []*protocol.Transaction{accTx},
		Signatures:  []protocol.Signature{sig},
	}

	// Step 5: Submit to Accumulate network via JSON-RPC
	txHash, err := s.submitEnvelope(ctx, envelope)
	if err != nil {
		return "", fmt.Errorf("failed to submit envelope: %w", err)
	}

	s.logger.Printf("✅ Transaction submitted: %s", txHash)
	return txHash, nil
}

// createAccumulateTransaction creates a proper Accumulate protocol Transaction
func (s *AccumulateSubmitterImpl) createAccumulateTransaction(tx *SyntheticTransaction) (*protocol.Transaction, error) {
	// Parse the account URL
	principal, err := url.Parse(s.accountURL)
	if err != nil {
		return nil, fmt.Errorf("invalid account URL: %w", err)
	}

	// Convert CertenDataEntry to Accumulate DoubleHashDataEntry format
	dataEntries := tx.Body.DataEntry.ToDoubleHashFormat()

	// Create the WriteData body with DoubleHashDataEntry
	writeDataBody := &protocol.WriteData{
		Entry: &protocol.DoubleHashDataEntry{
			Data: dataEntries,
		},
	}

	// Create the transaction (initiator will be set when we sign)
	accTx := &protocol.Transaction{
		Header: protocol.TransactionHeader{
			Principal: principal,
		},
		Body: writeDataBody,
	}

	s.logger.Printf("📝 Created WriteData transaction with %d data entries", len(dataEntries))
	return accTx, nil
}

// createAndSignSignature creates and signs an ED25519 signature using Accumulate protocol
func (s *AccumulateSubmitterImpl) createAndSignSignature(tx *protocol.Transaction, timestamp uint64) (*protocol.ED25519Signature, error) {
	// Parse the signer URL
	signerURL, err := url.Parse(s.signerURL)
	if err != nil {
		return nil, fmt.Errorf("invalid signer URL: %w", err)
	}

	// Create the signature object (without the actual signature bytes yet)
	sig := &protocol.ED25519Signature{
		PublicKey:     s.publicKey,
		Signer:        signerURL,
		SignerVersion: s.keyPageIndex,
		Timestamp:     timestamp,
	}

	// Compute the initiator hash from the signature metadata
	// This uses Accumulate's internal Initiator() method which does proper binary encoding
	initiatorHasher, err := sig.Initiator()
	if err != nil {
		return nil, fmt.Errorf("failed to compute initiator: %w", err)
	}
	initiatorHash := initiatorHasher.MerkleHash()

	// Set the transaction's initiator to the signature metadata hash
	copy(tx.Header.Initiator[:], initiatorHash)

	// Get the transaction hash (computed using Accumulate's binary encoding)
	txHash := tx.GetHash()

	// Sign using Accumulate's protocol signing function
	// SignED25519 computes: sign(SHA256(sigMetadataHash + txHash))
	protocol.SignED25519(sig, s.signingKey, nil, txHash)

	// Set the transaction hash in the signature
	sig.TransactionHash = *(*[32]byte)(txHash)

	s.logger.Printf("🔐 Signed transaction with ED25519 (initiator: %x...)", initiatorHash[:8])
	return sig, nil
}

// submitEnvelope submits the envelope to Accumulate via JSON-RPC
func (s *AccumulateSubmitterImpl) submitEnvelope(ctx context.Context, envelope *messaging.Envelope) (string, error) {
	// Serialize the envelope to JSON for the JSON-RPC call
	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("failed to marshal envelope: %w", err)
	}

	s.logger.Printf("🔍 [V3-SUBMIT] Submitting envelope to Accumulate")

	// Submit using the client's SubmitEnvelope method
	txHash, err := s.client.SubmitEnvelope(ctx, envelopeJSON)
	if err != nil {
		return "", fmt.Errorf("failed to submit to network: %w", err)
	}

	return txHash, nil
}

// GetTransactionStatus queries the status of a submitted transaction
func (s *AccumulateSubmitterImpl) GetTransactionStatus(ctx context.Context, txHash string) (string, error) {
	s.logger.Printf("🔍 Checking transaction status: %s", txHash)

	// Query transaction status from Accumulate
	status, err := s.client.GetTransactionStatus(ctx, txHash)
	if err != nil {
		return "", fmt.Errorf("failed to get transaction status: %w", err)
	}

	// Map Accumulate status to our standard status strings
	switch status {
	case "pending":
		return "pending", nil
	case "delivered":
		return "confirmed", nil
	case "failed":
		return "failed", nil
	default:
		return status, nil
	}
}

// =============================================================================
// DATA ENTRY FORMAT CONVERSION
// =============================================================================

// ToDoubleHashFormat converts CertenDataEntry to Accumulate's DoubleHashDataEntry format
// Returns [][]byte where each entry is the raw bytes of the data in "key=value" format
// This is the COMPREHENSIVE format with all proof data for independent verification
func (e *CertenDataEntry) ToDoubleHashFormat() [][]byte {
	entries := make([][]byte, 0, 51)

	// Helper to create labeled entries
	labeled := func(key, value string) []byte {
		return []byte(fmt.Sprintf("%s=%s", key, value))
	}

	// ==========================================================================
	// ENTRY IDENTIFICATION (Entries 0-2)
	// ==========================================================================
	entries = append(entries, labeled("entry_type", e.EntryType))     // 0
	entries = append(entries, labeled("version", e.Version))          // 1
	entries = append(entries, labeled("format", "certen_proof_v2"))   // 2

	// ==========================================================================
	// INTENT REFERENCE (Entries 3-6)
	// ==========================================================================
	entries = append(entries, labeled("intent_id", e.IntentID))                          // 3
	entries = append(entries, labeled("intent_hash", e.IntentHash))                      // 4
	entries = append(entries, labeled("intent_tx_hash", e.IntentTxHash))                 // 5
	entries = append(entries, labeled("intent_block", fmt.Sprintf("%d", e.IntentBlock))) // 6

	// ==========================================================================
	// EXECUTION COMMITMENT (Entries 7-12)
	// ==========================================================================
	entries = append(entries, labeled("operation_id", e.OperationID))       // 7
	entries = append(entries, labeled("bundle_id", e.BundleID))             // 8
	entries = append(entries, labeled("commitment_hash", e.CommitmentHash)) // 9
	entries = append(entries, labeled("anchor_contract", e.AnchorContract)) // 10
	entries = append(entries, labeled("function_selector", e.FunctionSelector)) // 11
	entries = append(entries, labeled("expected_value", e.ExpectedValue))   // 12

	// ==========================================================================
	// 3-STEP TRANSACTION DETAILS (Entries 13-21)
	// ==========================================================================
	entries = append(entries, labeled("step1_selector", e.Step1Selector))       // 13
	entries = append(entries, labeled("step1_contract", e.Step1Contract))       // 14
	entries = append(entries, labeled("step1_intent_hash", e.Step1IntentHash))  // 15
	entries = append(entries, labeled("step2_selector", e.Step2Selector))       // 16
	entries = append(entries, labeled("step2_contract", e.Step2Contract))       // 17
	entries = append(entries, labeled("step3_selector", e.Step3Selector))       // 18
	entries = append(entries, labeled("step3_contract", e.Step3Contract))       // 19
	entries = append(entries, labeled("step3_final_target", e.Step3FinalTarget)) // 20
	entries = append(entries, labeled("step3_final_value", e.Step3FinalValue))   // 21

	// ==========================================================================
	// ACTUAL EXECUTION RESULT (Entries 22-29)
	// ==========================================================================
	entries = append(entries, labeled("chain_name", e.ChainName))                      // 22
	entries = append(entries, labeled("chain_id", fmt.Sprintf("%d", e.ChainID)))       // 23
	entries = append(entries, labeled("tx_hash", e.TxHash))                            // 24
	entries = append(entries, labeled("block_number", fmt.Sprintf("%d", e.BlockNumber))) // 25
	entries = append(entries, labeled("block_hash", e.BlockHash))                       // 26
	entries = append(entries, labeled("success", fmt.Sprintf("%t", e.Success)))         // 27
	entries = append(entries, labeled("gas_used", fmt.Sprintf("%d", e.GasUsed)))        // 28
	entries = append(entries, labeled("tx_from", e.TxFrom))                             // 29

	// ==========================================================================
	// EVENT VERIFICATION (Entries 30-33)
	// ==========================================================================
	entries = append(entries, labeled("events_hash", e.EventsHash))                       // 30
	entries = append(entries, labeled("event_count", fmt.Sprintf("%d", e.EventCount)))    // 31
	entries = append(entries, labeled("transfer_executed_hash", e.TransferExecutedHash))  // 32
	entries = append(entries, labeled("events_verified", fmt.Sprintf("%t", e.EventsVerified))) // 33

	// ==========================================================================
	// STATE BINDING (Entries 34-36)
	// ==========================================================================
	entries = append(entries, labeled("state_root", e.StateRoot))             // 34
	entries = append(entries, labeled("receipts_root", e.ReceiptsRoot))       // 35
	entries = append(entries, labeled("transactions_root", e.TransactionsRoot)) // 36

	// ==========================================================================
	// GOVERNANCE PROOF (Entries 37-40)
	// ==========================================================================
	entries = append(entries, labeled("validator_count", fmt.Sprintf("%d", e.ValidatorCount))) // 37
	entries = append(entries, labeled("signed_power", e.SignedPower))                          // 38
	entries = append(entries, labeled("governance_proof_ref", e.GovernanceProofRef))          // 39
	entries = append(entries, labeled("threshold_met", fmt.Sprintf("%t", e.ThresholdMet)))    // 40

	// ==========================================================================
	// AUDIT REFERENCES (Entries 41-44)
	// ==========================================================================
	entries = append(entries, labeled("proof_artifact_id", e.ProofArtifactID))             // 41
	entries = append(entries, labeled("anchor_proof_hash", e.AnchorProofHash))             // 42
	entries = append(entries, labeled("previous_result_hash", e.PreviousResultHash))       // 43
	entries = append(entries, labeled("sequence_number", fmt.Sprintf("%d", e.SequenceNumber))) // 44

	// ==========================================================================
	// RESULT HASHES (Entries 45-47)
	// ==========================================================================
	entries = append(entries, labeled("result_hash", e.ResultHash))         // 45
	entries = append(entries, labeled("proof_cycle_hash", e.ProofCycleHash)) // 46
	entries = append(entries, labeled("schema_version", "2.0"))              // 47

	// ==========================================================================
	// FINALIZATION (Entries 48-50)
	// ==========================================================================
	entries = append(entries, labeled("confirmation_blocks", fmt.Sprintf("%d", e.ConfirmationBlocks))) // 48
	entries = append(entries, labeled("timestamp", fmt.Sprintf("%d", e.Timestamp)))                    // 49
	entries = append(entries, labeled("finalized_at", fmt.Sprintf("%d", e.FinalizedAt)))               // 50

	return entries
}

// ToAccumulateFormat converts CertenDataEntry to hex-encoded strings (for compatibility)
// This is the legacy format - prefer ToDoubleHashFormat for new code
func (e *CertenDataEntry) ToAccumulateFormat() []string {
	rawEntries := e.ToDoubleHashFormat()
	hexEntries := make([]string, len(rawEntries))
	for i, entry := range rawEntries {
		hexEntries[i] = hex.EncodeToString(entry)
	}
	return hexEntries
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// GetAccountURL returns the account URL for write-back
func (s *AccumulateSubmitterImpl) GetAccountURL() string {
	return s.accountURL
}

// GetPublicKey returns the public key used for signing
func (s *AccumulateSubmitterImpl) GetPublicKey() ed25519.PublicKey {
	return s.publicKey
}

// GetPublicKeyHex returns the hex-encoded public key
func (s *AccumulateSubmitterImpl) GetPublicKeyHex() string {
	return hex.EncodeToString(s.publicKey)
}

// =============================================================================
// NULL SUBMITTER FOR TESTING
// =============================================================================

// NullAccumulateSubmitter is a no-op implementation for testing
type NullAccumulateSubmitter struct {
	logger *log.Logger
}

// NewNullAccumulateSubmitter creates a null submitter that logs but doesn't submit
func NewNullAccumulateSubmitter(logger *log.Logger) *NullAccumulateSubmitter {
	if logger == nil {
		logger = log.New(log.Writer(), "[NullSubmitter] ", log.LstdFlags)
	}
	return &NullAccumulateSubmitter{logger: logger}
}

// SubmitTransaction logs the transaction but doesn't submit
func (s *NullAccumulateSubmitter) SubmitTransaction(ctx context.Context, tx *SyntheticTransaction) (string, error) {
	s.logger.Printf("⚠️ [NULL] Would submit transaction: %s (write-back disabled)", tx.ToHex())
	// Return a fake hash for testing
	return fmt.Sprintf("null-tx-%s", tx.ToHex()[:16]), nil
}

// GetTransactionStatus always returns confirmed for null submitter
func (s *NullAccumulateSubmitter) GetTransactionStatus(ctx context.Context, txHash string) (string, error) {
	s.logger.Printf("⚠️ [NULL] Would check status for: %s", txHash)
	return "confirmed", nil
}
