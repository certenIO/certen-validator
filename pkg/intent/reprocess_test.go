// Copyright 2026 Certen Protocol

package intent

import (
	"context"
	"errors"
	"io"
	"log"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/accumulate"
	"github.com/certen/independant-validator/pkg/consensus"
)

// RB4-F55 repair: one intent is processed again exactly as discovery processes it - from its Directory Network
// block, converted from the same transaction - so the round a repair needs is re-derived and checked against the
// committed block (consensus.ArmMemberRepair). Nothing else in the block is touched, an intent being processed now
// is not processed twice, and an intent named by the wrong transaction is refused.

type blockClient struct {
	accumulate.Client
	txs []*accumulate.CertenTransaction
}

func (c *blockClient) SearchCertenTransactions(_ context.Context, h int64) ([]*accumulate.CertenTransaction, error) {
	var out []*accumulate.CertenTransaction
	for _, tx := range c.txs {
		if tx.BlockHeight == h {
			out = append(out, tx)
		}
	}
	return out, nil
}

func blockTx(hash, intentID string, height int64) *accumulate.CertenTransaction {
	return &accumulate.CertenTransaction{
		Hash: hash, AccountURL: "acc://harbor.acme/data", BlockHeight: height,
		Partition: "acc://dn.acme", ProofPartition: "bvn1", ProofBlockIndex: 8270001,
		IntentData: map[string]interface{}{
			"intentData":     map[string]interface{}{"intent_id": intentID, "proof_class": "on_demand"},
			"crossChainData": map[string]interface{}{},
			"governanceData": map[string]interface{}{"organizationAdi": "acc://harbor.acme"},
			"replayData":     map[string]interface{}{"expires_at": 1790600000},
		},
	}
}

func reprocessDiscovery(t *testing.T, txs ...*accumulate.CertenTransaction) (*IntentDiscovery, *[]*CertenIntent) {
	t.Helper()
	id := &IntentDiscovery{client: &blockClient{txs: txs}, logger: log.New(io.Discard, "", 0), intentStatus: map[string]IntentStatus{}}
	var processed []*CertenIntent
	id.reprocess = func(ci *CertenIntent, height uint64) (consensus.TargetChainOutcome, error) {
		processed = append(processed, ci)
		return consensus.TargetChainPending, nil
	}
	return id, &processed
}

func intentIDOf(t *testing.T, tx *accumulate.CertenTransaction) string {
	t.Helper()
	ci, err := (&IntentDiscovery{logger: log.New(io.Discard, "", 0)}).convertCertenTransactionToIntent(tx)
	if err != nil {
		t.Fatal(err)
	}
	return ci.IntentID
}

func TestReprocessingAnIntentTouchesOnlyThatIntent(t *testing.T) {
	target := blockTx(strings.Repeat("db", 32), "repair-target", 10007772)
	other := blockTx(strings.Repeat("0e", 32), "repair-other", 10007772)
	id, processed := reprocessDiscovery(t, other, target)
	want := intentIDOf(t, target)
	if err := id.ReprocessIntent(context.Background(), 10007772, target.Hash, want); err != nil {
		t.Fatal(err)
	}
	if len(*processed) != 1 || (*processed)[0].IntentID != want || (*processed)[0].TransactionHash != target.Hash {
		t.Fatalf("processed %d intents; want exactly the named one", len(*processed))
	}
	if (*processed)[0].ProofPartition != "bvn1" {
		t.Fatalf("the intent was not converted as discovery converts it: partition %q", (*processed)[0].ProofPartition)
	}
	if id.getIntentStatus(want) != IntentStatusCompleted {
		t.Fatalf("status after: %v", id.getIntentStatus(want))
	}
}

func TestReprocessingRefusesWhatItCannotName(t *testing.T) {
	target := blockTx(strings.Repeat("db", 32), "repair-target", 10007772)
	want := intentIDOf(t, target)
	ctx := context.Background()

	id, processed := reprocessDiscovery(t, target)
	if err := id.ReprocessIntent(ctx, 10007773, target.Hash, want); err == nil || !strings.Contains(err.Error(), "not in") {
		t.Fatalf("an intent looked for in the wrong block: %v", err)
	}
	if err := id.ReprocessIntent(ctx, 10007772, target.Hash, "another-intent"); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("a transaction carrying another intent than the one named: %v", err)
	}
	id.intentStatus[want] = IntentStatusInProgress
	if err := id.ReprocessIntent(ctx, 10007772, target.Hash, want); err == nil || !strings.Contains(err.Error(), "being processed") {
		t.Fatalf("an intent being processed now: %v", err)
	}
	id.intentStatus[want] = IntentStatusFailedPermanent
	if err := id.ReprocessIntent(ctx, 10007772, target.Hash, want); err == nil || !strings.Contains(err.Error(), "permanently invalid") {
		t.Fatalf("a permanently invalid intent: %v", err)
	}
	if len(*processed) != 0 {
		t.Fatalf("a refused reprocess processed %d intents", len(*processed))
	}
}

func TestAReprocessingFailureIsReturned(t *testing.T) {
	target := blockTx(strings.Repeat("db", 32), "repair-target", 10007772)
	id, _ := reprocessDiscovery(t, target)
	want := intentIDOf(t, target)
	boom := errors.New("committed as another block")
	id.reprocess = func(*CertenIntent, uint64) (consensus.TargetChainOutcome, error) {
		return consensus.TargetChainPending, boom
	}
	if err := id.ReprocessIntent(context.Background(), 10007772, target.Hash, want); !errors.Is(err, boom) {
		t.Fatalf("the round's failure was not returned: %v", err)
	}
	if id.getIntentStatus(want) != IntentStatusFailed {
		t.Fatalf("status after a failure: %v", id.getIntentStatus(want))
	}
}
