package execution

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/proof"
)

// The AGT-0 scene-1 anchor on Base Sepolia, as its receipt and header state it (chain-check evm receipt, 2026-11-18).
const (
	scene1AnchorTx    = "0x43766439c30deea319debe031b6f00d90ef1cede7735b8969e3ba15212a0f1ad"
	scene1AnchorBlock = 60397757
	scene1AnchorHash  = "0x4d4e949bf7d9c6967dd8fa126d04f08a59c9caefacf31a5284d3e77d6721d07d"
)

var scene1AnchorTime = time.Date(2026, 11, 18, 11, 30, 20, 0, time.UTC)

func scene1Receipt() *chain.ObservationResult {
	return &chain.ObservationResult{TxHash: scene1AnchorTx, BlockNumber: scene1AnchorBlock, BlockHash: scene1AnchorHash,
		BlockTimestamp: scene1AnchorTime, Confirmations: 5316, Status: 1}
}

func scene1Layer() *Layer5 {
	return &Layer5{ChainID: 84532, Network: "base-sepolia", AnchorTx: scene1AnchorTx, BlockNumber: scene1AnchorBlock}
}

// AGT-F11: the anchor block's hash and time come from the anchor transaction's own receipt block, and the settlement's
// block (another block, another hash, another time) is never used.
func TestAnchorBlockIsTheAnchorReceiptsBlockNeverTheSettlements(t *testing.T) {
	settlement := &chain.ObservationResult{TxHash: "0x79bd698007f4426eb2b412a61f23b63a385335cff560c43d0636a159420f5238",
		BlockNumber: 60397816, BlockHash: "0x" + strings.Repeat("ab", 32), BlockTimestamp: scene1AnchorTime.Add(12 * time.Second)}
	l5 := scene1Layer()
	if err := completeAnchorBlock(l5, scene1AnchorBlock, scene1Receipt()); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if l5.BlockHash != scene1AnchorHash || !l5.BlockTime.Equal(scene1AnchorTime) || l5.BlockNumber != scene1AnchorBlock || l5.AnchorBlock != "" {
		t.Fatalf("layer states block %d %s at %s (state %q)", l5.BlockNumber, l5.BlockHash, l5.BlockTime, l5.AnchorBlock)
	}
	if l5.BlockHash == settlement.BlockHash || l5.BlockTime.Equal(settlement.BlockTimestamp) {
		t.Fatal("the settlement's block was stated as the anchor's")
	}
	// A reading of the settlement transaction is not a reading of the anchor.
	other := scene1Layer()
	if err := completeAnchorBlock(other, 0, settlement); !errors.Is(err, ErrAnchorBlockUnread) || other.BlockHash != "" {
		t.Fatalf("a reading of another transaction was used: %v %q", err, other.BlockHash)
	}
	if err := anchorBlockComplete(l5); err != nil {
		t.Fatalf("a fully read layer is not complete: %v", err)
	}
}

// A receipt in another block than the one recorded is refused by name; neither block is picked.
func TestAnchorBlockReceiptMismatchIsANamedRefusal(t *testing.T) {
	l5 := scene1Layer()
	l5.BlockNumber = 0
	err := completeAnchorBlock(l5, scene1AnchorBlock+1, scene1Receipt())
	if !errors.Is(err, ErrAnchorBlockMismatch) || !strings.Contains(err.Error(), "anchor_block_mismatch") {
		t.Fatalf("mismatch not refused by name: %v", err)
	}
	if l5.BlockHash != "" || !l5.BlockTime.IsZero() {
		t.Fatalf("a mismatched block was stated: %q %s", l5.BlockHash, l5.BlockTime)
	}
}

// Until the block is read the layer is in the named state anchor_block_unread, never a finished-looking reference.
func TestAnchorBlockUnreadIsANamedState(t *testing.T) {
	cases := map[string]*chain.ObservationResult{
		"not read":     nil,
		"no hash":      {TxHash: scene1AnchorTx, BlockNumber: scene1AnchorBlock, BlockTimestamp: scene1AnchorTime},
		"no time":      {TxHash: scene1AnchorTx, BlockNumber: scene1AnchorBlock, BlockHash: scene1AnchorHash},
		"no block num": {TxHash: scene1AnchorTx, BlockHash: scene1AnchorHash, BlockTimestamp: scene1AnchorTime},
	}
	for name, obs := range cases {
		l5 := scene1Layer()
		err := completeAnchorBlock(l5, scene1AnchorBlock, obs)
		if !errors.Is(err, ErrAnchorBlockUnread) || l5.AnchorBlock != AnchorBlockUnread {
			t.Fatalf("%s: %v, state %q", name, err, l5.AnchorBlock)
		}
		if anchorBlockComplete(l5) == nil {
			t.Fatalf("%s: an unread layer counts as complete", name)
		}
		raw, _ := json.Marshal(l5)
		if !strings.Contains(string(raw), `"anchorBlock":"anchor_block_unread"`) {
			t.Fatalf("%s: the stored layer does not state its state: %s", name, raw)
		}
	}
}

// No anchor reference is written from a layer whose block was not read (the repository is never reached).
func TestNoAnchorReferenceIsWrittenWithoutTheAnchorBlock(t *testing.T) {
	l5 := scene1Layer()
	_ = completeAnchorBlock(l5, scene1AnchorBlock, nil)
	o := &UnifiedOrchestrator{config: &UnifiedOrchestratorConfig{}} // no repositories: any write would fail
	settled := &chain.ObservationResult{TxHash: "0x" + strings.Repeat("cd", 32), BlockNumber: scene1AnchorBlock + 59, IsFinalized: true,
		BlockHash: "0x" + strings.Repeat("ef", 32), BlockTimestamp: scene1AnchorTime.Add(time.Minute)}
	if err := o.writeAnchorReference(context.Background(), uuid.New(), &UnifiedProofCycleResult{ChainID: "84532"}, l5, settled); err != nil {
		t.Fatalf("an unread layer must yield no reference, not an error: %v", err)
	}
}

// End to end offline: the bundle anchor component built from the scene-1 anchor's receipt states the block hash and
// anchored_at that chain-check bundle verify requires ("anchor reference is well-formed").
func TestScene1AnchorReferenceCarriesBlockHashAndTime(t *testing.T) {
	l5 := scene1Layer()
	if err := completeAnchorBlock(l5, scene1AnchorBlock, scene1Receipt()); err != nil {
		t.Fatal(err)
	}
	ref := &proof.AnchorReferenceProof{TargetChain: "84532", AnchorTxHash: l5.AnchorTx, AnchorBlockNumber: l5.BlockNumber,
		AnchorBlockHash: l5.BlockHash, Confirmations: 5316, RequiredConfs: 2, AnchoredAt: l5.BlockTime}
	raw, err := json.Marshal(ref)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if m["anchor_block_hash"] != scene1AnchorHash || m["anchored_at"] != "2026-11-18T11:30:20Z" {
		t.Fatalf("anchor reference %s", raw)
	}
}
