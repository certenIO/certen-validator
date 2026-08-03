package execution

import (
	"encoding/json"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

type jsonCodec struct{}

func (jsonCodec) Encode(v interface{}) (json.RawMessage, error) { return json.Marshal(v) }
func (jsonCodec) Decode(r json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	err := json.Unmarshal(r, &m)
	return m, err
}

func member(id string, h uint64, chain int64) *PendingBatchIntent {
	return &PendingBatchIntent{
		IntentID: id, ADIURL: "acc://" + id + ".acme", ChainID: chain,
		Account:     common.HexToAddress("0x32b4687bE3c02d52e2d94Dc1cFAF03a0E5af0C8B"),
		OperationID: opid(byte(len(id))),
		Legs: []LegExecution{{
			LegID: "l0", ChainID: chain, Target: tgt(9), Value: big.NewInt(1), Data: []byte{0xde, 0xad},
		}},
		CommitHeight: h,
		Attestation:  map[string]interface{}{"intent": id},
	}
}

// THE durability property: a member queued before a restart must be present after one, in the
// SAME period, so it forms the identical tree it would have.
func TestMempoolStore_SurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "batch", "mempool.json")
	st, err := NewBatchMempoolStore(path, jsonCodec{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	before := NewBatchMempool(BatchMempoolConfig{MinBatchSize: 1, MaxBatchSize: 64})
	before.SetStore(st, nil)
	for _, m := range []*PendingBatchIntent{member("alpha", 6259279, 11155111), member("beta", 6259282, 11155111)} {
		if err := before.Add(m); err != nil {
			t.Fatal(err)
		}
	}

	// A brand-new process: fresh mempool, same file.
	st2, err := NewBatchMempoolStore(path, jsonCodec{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	after := NewBatchMempool(BatchMempoolConfig{MinBatchSize: 1, MaxBatchSize: 64})
	after.SetStore(st2, nil)

	if got := after.PendingCount(); got != 2 {
		t.Fatalf("restored %d members, want 2 — a restart would have stranded intents the round "+
			"already reported as batch_queued", got)
	}

	// Same period, same order, same leaf inputs => same root and bundleId.
	pa := before.PeekForPeriod(11155111, 6259200, 100)
	pb := after.PeekForPeriod(11155111, 6259200, 100)
	if len(pa) != 2 || len(pb) != 2 {
		t.Fatalf("period selection differs after restart: %d vs %d", len(pa), len(pb))
	}
	for i := range pa {
		if pa[i].IntentID != pb[i].IntentID || pa[i].CommitHeight != pb[i].CommitHeight {
			t.Fatalf("member %d differs after restart: %s@%d vs %s@%d",
				i, pa[i].IntentID, pa[i].CommitHeight, pb[i].IntentID, pb[i].CommitHeight)
		}
		la, errA := pa[i].LeafInput()
		lb, errB := pb[i].LeafInput()
		if errA != nil || errB != nil {
			t.Fatalf("leaf input error: %v / %v", errA, errB)
		}
		if ComputeBatchLeaf(11155111, la) != ComputeBatchLeaf(11155111, lb) {
			t.Fatalf("member %s produces a DIFFERENT leaf after restart — the restored batch "+
				"would derive another bundleId and no peer would attest it", pa[i].IntentID)
		}
	}
	if pb[0].Attestation == nil {
		t.Fatal("attestation snapshot lost; the member could settle but its proof cycle would never replay")
	}
}

// Taking a period must be reflected on disk, or a restart would resurrect members that have
// already been anchored and attested.
func TestMempoolStore_TakeIsPersisted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mempool.json")
	st, _ := NewBatchMempoolStore(path, jsonCodec{}, nil)
	m := NewBatchMempool(BatchMempoolConfig{MinBatchSize: 1, MaxBatchSize: 64})
	m.SetStore(st, nil)
	if err := m.Add(member("gamma", 100, 11155111)); err != nil {
		t.Fatal(err)
	}
	if n := len(m.TakeForPeriod(11155111, 100, 100)); n != 1 {
		t.Fatalf("took %d, want 1", n)
	}

	st2, _ := NewBatchMempoolStore(path, jsonCodec{}, nil)
	after := NewBatchMempool(BatchMempoolConfig{MinBatchSize: 1, MaxBatchSize: 64})
	after.SetStore(st2, nil)
	if got := after.PendingCount(); got != 0 {
		t.Fatalf("%d member(s) resurrected after being taken; they would be re-anchored", got)
	}
}

// A missing snapshot must not be fatal — re-derivation remains the backstop.
func TestMempoolStore_MissingFileIsNotFatal(t *testing.T) {
	st, err := NewBatchMempoolStore(filepath.Join(t.TempDir(), "absent.json"), jsonCodec{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	m := NewBatchMempool(BatchMempoolConfig{MinBatchSize: 1, MaxBatchSize: 64})
	m.SetStore(st, nil) // must not panic or block
	if m.PendingCount() != 0 {
		t.Fatal("unexpected members")
	}
}
