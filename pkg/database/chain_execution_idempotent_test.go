package database

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// RB4-F55. A proof cycle persists the settlement it observed, then goes on to attest, prove and write back. A
// restart between the two (production, 2026-09-29: the fleet was redeployed 57 s after validator-6 persisted
// base-sepolia tx 0xc409fa0a… for multi-leg intent 000ac79a) re-runs the cycle, which observes the same
// transaction and inserted it again: "duplicate key value violates unique constraint
// chain_execution_results_chain_id_tx_hash_key". The cycle failed on its own earlier write and the intent sat in
// `settling` for good. Recording the same observation again must answer with the row already there; recording a
// DIFFERENT observation of the same transaction is a contradiction and is refused by name.

func newChainExecutionInput(cycleID, txHash string) *NewChainExecutionResult {
	blockNumber := int64(47451715)
	blockTime := time.Date(2026, 9, 29, 8, 48, 38, 0, time.UTC)
	step := WorkflowStep(1)
	required := 2
	submitted := blockTime
	return &NewChainExecutionResult{
		CycleID:               cycleID,
		ChainPlatform:         ChainPlatform("evm"),
		ChainID:               "84532",
		NetworkName:           "base-sepolia",
		TxHash:                txHash,
		BlockNumber:           &blockNumber,
		BlockHash:             "0xb33fedde436515945f23f7fda80e34c004640d39d36e3c3ce992ba2d59cb13d3",
		BlockTimestamp:        &blockTime,
		Status:                ExecutionStatus(1),
		Confirmations:         12,
		RequiredConfirmations: &required,
		IsFinalized:           true,
		ResultHash:            hash32("result:" + txHash),
		StateRoot:             hash32("state:" + txHash),
		TransactionsRoot:      hash32("txs:" + txHash),
		ReceiptsRoot:          hash32("receipts:" + txHash),
		RawReceipt:            []byte("null"),
		Logs:                  []byte("[]"),
		PlatformData:          []byte("{}"),
		ObserverValidatorID:   "validator-6",
		WorkflowStep:          &step,
		AnchorID:              hash32("anchor:" + txHash),
		SubmittedAt:           &submitted,
	}
}

func testTxHash() string {
	return "0x" + strings.ReplaceAll(uuid.New().String(), "-", "") + strings.ReplaceAll(uuid.New().String(), "-", "")
}

func TestChainExecutionRecordedTwiceByARestartedCycleIsTheSameRow(t *testing.T) {
	requireTestDB(t)
	ctx := context.Background()
	repo := NewUnifiedRepository(testDB)
	tx := testTxHash()
	t.Cleanup(func() {
		_, _ = testDB.ExecContext(context.Background(), `DELETE FROM chain_execution_results WHERE tx_hash = $1`, tx)
	})

	first, err := repo.CreateChainExecutionResult(ctx, newChainExecutionInput("cycle-before-restart", tx))
	if err != nil {
		t.Fatalf("first record: %v", err)
	}
	// The restarted cycle has a new cycle id and observes the very same settlement.
	second, err := repo.CreateChainExecutionResult(ctx, newChainExecutionInput("cycle-after-restart", tx))
	if err != nil {
		t.Fatalf("THE regression: a restarted cycle recording its own settlement again failed: %v", err)
	}
	if second != first {
		t.Fatalf("the same observation must answer with the row already recorded: got %s, want %s", second, first)
	}

	row, err := repo.GetChainExecutionResultByTxHash(ctx, "84532", tx)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if row.CycleID != "cycle-before-restart" {
		t.Fatalf("the recorded row is history and is not rewritten: cycle_id %q", row.CycleID)
	}
}

func TestChainExecutionRecordedDifferentlyIsRefusedByName(t *testing.T) {
	requireTestDB(t)
	ctx := context.Background()
	repo := NewUnifiedRepository(testDB)
	tx := testTxHash()
	t.Cleanup(func() {
		_, _ = testDB.ExecContext(context.Background(), `DELETE FROM chain_execution_results WHERE tx_hash = $1`, tx)
	})

	if _, err := repo.CreateChainExecutionResult(ctx, newChainExecutionInput("cycle-a", tx)); err != nil {
		t.Fatalf("first record: %v", err)
	}

	for name, mutate := range map[string]func(*NewChainExecutionResult){
		"another block (a reorg)": func(in *NewChainExecutionResult) { in.BlockHash = "0x" + strings.Repeat("ab", 32) },
		"another status":          func(in *NewChainExecutionResult) { in.Status = ExecutionStatus(2) },
		"another receipts root":   func(in *NewChainExecutionResult) { in.ReceiptsRoot = hash32("other receipts") },
		"another observer":        func(in *NewChainExecutionResult) { in.ObserverValidatorID = "validator-3" },
		"another result hash":     func(in *NewChainExecutionResult) { in.ResultHash = hash32("other result") },
		"another block number":    func(in *NewChainExecutionResult) { n := int64(47451716); in.BlockNumber = &n },
	} {
		in := newChainExecutionInput("cycle-b", tx)
		mutate(in)
		_, err := repo.CreateChainExecutionResult(ctx, in)
		if !errors.Is(err, ErrChainExecutionContradicts) {
			t.Fatalf("%s: want ErrChainExecutionContradicts, got %v", name, err)
		}
	}

	row, err := repo.GetChainExecutionResultByTxHash(ctx, "84532", tx)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if row.CycleID != "cycle-a" || row.Status != ExecutionStatus(1) {
		t.Fatalf("a refused contradiction must leave the recorded row untouched: %+v", row)
	}
}
