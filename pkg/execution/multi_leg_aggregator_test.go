package execution

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/google/uuid"
)

// mockSubmitter is a test implementation of AccumulateSubmitter
type mockSubmitter struct {
	submitted []*SyntheticTransaction
	mu        sync.Mutex
}

func (m *mockSubmitter) SubmitTransaction(ctx context.Context, tx *SyntheticTransaction) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.submitted = append(m.submitted, tx)
	return fmt.Sprintf("mock-receipt-%s", tx.ToHex()[:8]), nil
}

func (m *mockSubmitter) GetTransactionStatus(ctx context.Context, txHash string) (string, error) {
	return "confirmed", nil
}

// TestMultiLegAggregator_4ChainIntent simulates a 4-chain intent where each chain group
// completes its proof cycle independently, and verifies the aggregator produces a unified write-back.
func TestMultiLegAggregator_4ChainIntent(t *testing.T) {
	// Create mock submitter
	submitter := &mockSubmitter{}

	// Create tx builder
	txBuilder := NewSyntheticTxBuilder(
		"acc://certen.acme/proof-results",
		"validator-1",
		make([]byte, 32), // dummy key
	)

	// Create aggregator
	resultChains := make(map[string]*ResultHashChain)
	var resultChainsLock sync.RWMutex

	agg := NewMultiLegAggregator(&MultiLegAggregatorConfig{
		TxBuilder:        txBuilder,
		Submitter:        submitter,
		ResultChains:     resultChains,
		ResultChainsLock: &resultChainsLock,
		WriteBackTimeout: 30 * time.Second,
		ValidatorID:      "validator-1",
	})

	// Define 4-leg intent across 4 chains
	intentID := "intent-multi-4"
	legMapping := map[int]LegChainInfo{
		0: {ChainKey: "ethereum:11155111", ChainName: "ethereum-sepolia", ChainID: 11155111, LegID: "leg-eth"},
		1: {ChainKey: "base:84532", ChainName: "base-sepolia", ChainID: 84532, LegID: "leg-base"},
		2: {ChainKey: "aptos:2", ChainName: "aptos-testnet", ChainID: 2, LegID: "leg-aptos"},
		3: {ChainKey: "solana:0", ChainName: "solana-devnet", ChainID: 0, LegID: "leg-sol"},
	}

	// Register intent
	agg.RegisterMultiLegIntent(intentID, "op-123", 4, "parallel", legMapping)

	// Track unified write-back
	var writeBackIntentID, writeBackTxHash string
	agg.SetOnUnifiedWriteBack(func(id string, txHash string) {
		writeBackIntentID = id
		writeBackTxHash = txHash
	})

	// Simulate chain groups completing in arbitrary order
	chains := []struct {
		chainKey string
		txHash   string
		block    uint64
		chainID  string
	}{
		{"base:84532", "0xbase_tx_001", 200, "84532"},
		{"aptos:2", "0xaptos_tx_001", 300, "2"},
		{"solana:0", "sol_tx_001_base58", 400, "0"},
		{"ethereum:11155111", "0xeth_tx_001", 100, "11155111"},
	}

	for i, c := range chains {
		result := &UnifiedProofCycleResult{
			CycleID:   fmt.Sprintf("cycle-%s", c.chainKey),
			ProofID:   uuid.New(),
			Success:   true,
			ChainID:   c.chainID,
			StartedAt: time.Now(),
			ObservationResults: []*chain.ObservationResult{
				{
					TxHash:              c.txHash,
					BlockNumber:         c.block,
					BlockHash:           fmt.Sprintf("block_%s", c.chainKey),
					Status:              1,
					Confirmations:       12,
					IsFinalized:         true,
					GasUsed:             uint64(21000 + i*1000),
					ObserverValidatorID: "validator-1",
					TxFrom:              "0xexecutor",
					ChainName:           legMapping[i].ChainName,
					ChainIDNumeric:      legMapping[i].ChainID,
				},
			},
			AggregatedAttestation: &attestation.AggregatedAttestation{
				ParticipantCount: 3,
				TotalWeight:      3,
				AchievedWeight:   3,
				ThresholdMet:     true,
				Verified:         true,
			},
		}

		err := agg.OnChainGroupCycleComplete(intentID, c.chainKey, result)
		if err != nil {
			t.Fatalf("OnChainGroupCycleComplete failed for %s: %v", c.chainKey, err)
		}
	}

	// Verify a write-back was submitted
	submitter.mu.Lock()
	submittedCount := len(submitter.submitted)
	submitter.mu.Unlock()

	if submittedCount != 1 {
		t.Fatalf("Expected 1 submitted transaction, got %d", submittedCount)
	}

	// Verify callback was called
	if writeBackIntentID != intentID {
		t.Errorf("Expected write-back intent ID %s, got %s", intentID, writeBackIntentID)
	}
	if writeBackTxHash == "" {
		t.Error("Expected non-empty write-back tx hash")
	}

	// Verify the submitted transaction has multi-leg data
	submitter.mu.Lock()
	tx := submitter.submitted[0]
	submitter.mu.Unlock()

	if tx.Body == nil {
		t.Fatal("Expected non-nil transaction body")
	}

	dataEntry := tx.Body.DataEntry
	if dataEntry.LegCount != 4 {
		t.Errorf("Expected LegCount=4, got %d", dataEntry.LegCount)
	}

	if dataEntry.MultiLegResultHash == "" {
		t.Error("Expected non-empty MultiLegResultHash")
	}

	if len(dataEntry.LegProofs) != 4 {
		t.Fatalf("Expected 4 LegProofs, got %d", len(dataEntry.LegProofs))
	}

	// Verify leg ordering (should be sorted by leg index, not arrival order)
	expectedChains := []string{"ethereum-sepolia", "base-sepolia", "aptos-testnet", "solana-devnet"}
	for i, expected := range expectedChains {
		if dataEntry.LegProofs[i].ChainName != expected {
			t.Errorf("Leg %d: expected chain %s, got %s", i, expected, dataEntry.LegProofs[i].ChainName)
		}
	}

	// Verify the multi_leg_result_hash is deterministic
	var legResults []LegResult
	for _, lp := range dataEntry.LegProofs {
		var eventsHash [32]byte
		if decoded, err := hex.DecodeString(lp.EventsHash); err == nil && len(decoded) >= 32 {
			copy(eventsHash[:], decoded[:32])
		}
		legResults = append(legResults, LegResult{
			LegIndex: lp.LegIndex,
			Chain:    lp.ChainName,
			ChainID:  lp.ChainID,
			TxHash:   lp.TxHash,
		})
	}

	// Verify no pending intents remain
	if agg.GetPendingCount() != 0 {
		t.Errorf("Expected 0 pending intents, got %d", agg.GetPendingCount())
	}
}

// TestMultiLegAggregator_PartialCompletion verifies behavior when not all chain groups complete.
func TestMultiLegAggregator_PartialCompletion(t *testing.T) {
	submitter := &mockSubmitter{}
	txBuilder := NewSyntheticTxBuilder("acc://test", "v1", make([]byte, 32))

	resultChains := make(map[string]*ResultHashChain)
	var resultChainsLock sync.RWMutex

	agg := NewMultiLegAggregator(&MultiLegAggregatorConfig{
		TxBuilder:        txBuilder,
		Submitter:        submitter,
		ResultChains:     resultChains,
		ResultChainsLock: &resultChainsLock,
	})

	legMapping := map[int]LegChainInfo{
		0: {ChainKey: "ethereum:1", ChainName: "ethereum", ChainID: 1},
		1: {ChainKey: "solana:0", ChainName: "solana", ChainID: 0},
	}

	agg.RegisterMultiLegIntent("intent-partial", "op-456", 2, "parallel", legMapping)

	// Only complete one chain group
	result := &UnifiedProofCycleResult{
		CycleID: "cycle-eth",
		ProofID: uuid.New(),
		Success: true,
		ChainID: "1",
		ObservationResults: []*chain.ObservationResult{
			{TxHash: "0xeth", BlockNumber: 100, Status: 1, IsFinalized: true},
		},
		AggregatedAttestation: &attestation.AggregatedAttestation{
			ParticipantCount: 1, ThresholdMet: true, Verified: true,
		},
	}

	err := agg.OnChainGroupCycleComplete("intent-partial", "ethereum:1", result)
	if err != nil {
		t.Fatalf("OnChainGroupCycleComplete failed: %v", err)
	}

	// Should NOT have submitted anything (still waiting for solana)
	submitter.mu.Lock()
	if len(submitter.submitted) != 0 {
		t.Errorf("Expected 0 submitted (partial), got %d", len(submitter.submitted))
	}
	submitter.mu.Unlock()

	// Should still have 1 pending
	if agg.GetPendingCount() != 1 {
		t.Errorf("Expected 1 pending intent, got %d", agg.GetPendingCount())
	}
}

// TestMultiLegAggregator_DuplicateRegistration verifies idempotent registration.
func TestMultiLegAggregator_DuplicateRegistration(t *testing.T) {
	agg := NewMultiLegAggregator(&MultiLegAggregatorConfig{})

	legMapping := map[int]LegChainInfo{
		0: {ChainKey: "ethereum:1"},
	}

	agg.RegisterMultiLegIntent("intent-dup", "op-1", 1, "parallel", legMapping)
	agg.RegisterMultiLegIntent("intent-dup", "op-1", 1, "parallel", legMapping) // Duplicate

	if agg.GetPendingCount() != 1 {
		t.Errorf("Expected 1 pending (deduped), got %d", agg.GetPendingCount())
	}
}
