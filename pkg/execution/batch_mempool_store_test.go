package execution

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
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
	return certifiedForTest(&PendingBatchIntent{AccumulateSetRoot: testAccSet, GovernanceCommitment: testGov,
		IntentID: id, ADIURL: "acc://" + id + ".acme", ChainID: chain,
		Account:     common.HexToAddress("0x32b4687bE3c02d52e2d94Dc1cFAF03a0E5af0C8B"),
		OperationID: opid(byte(len(id))),
		Legs: []LegExecution{{
			LegID: "l0", ChainID: chain, Target: tgt(9), Value: big.NewInt(1), Data: []byte{0xde, 0xad},
		}},
		CommitHeight: h,
		Attestation:  map[string]interface{}{"intent": id},
	})
}

// THE durability property: a member queued before a restart must be present after one, in the
// SAME period, so it forms the identical tree it would have.
func TestMempoolStore_SurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "batch", "mempool.json")
	st, err := NewBatchMempoolStore(path, jsonCodec{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	before := newTestMempool(BatchMempoolConfig{MaxBatchSize: 64})
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
	after := newTestMempool(BatchMempoolConfig{MaxBatchSize: 64})
	after.SetStore(st2, nil)

	if got := after.PendingCount(); got != 2 {
		t.Fatalf("restored %d members, want 2 — a restart would have stranded intents the round "+
			"already reported as batch_queued", got)
	}

	// Same period, same order, same leaf inputs => same root and bundleId.
	pa := before.PeriodMembers(11155111, 6259200, 100)
	pb := after.PeriodMembers(11155111, 6259200, 100)
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

// A member's outcome must be reflected on disk, or a restart would resurrect as pending a member that
// has already settled, and settle it again.
func TestMempoolStore_OutcomeIsPersisted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mempool.json")
	st, _ := NewBatchMempoolStore(path, jsonCodec{}, nil)
	m := newTestMempool(BatchMempoolConfig{MaxBatchSize: 64})
	m.SetStore(st, nil)
	if err := m.Add(member("gamma", 100, 11155111)); err != nil {
		t.Fatal(err)
	}
	m.MarkOutcome(m.PeriodMembers(11155111, 100, 100), MemberSettled)

	st2, _ := NewBatchMempoolStore(path, jsonCodec{}, nil)
	after := newTestMempool(BatchMempoolConfig{MaxBatchSize: 64})
	after.SetStore(st2, nil)
	if got := after.PendingCount(); got != 0 {
		t.Fatalf("%d member(s) resurrected as pending after they settled; they would be settled again", got)
	}
	// Still in its period, with its outcome: the period's trees are unchanged by the restart.
	if got := after.PeriodMembers(11155111, 100, 100); len(got) != 1 || got[0].Outcome != MemberSettled {
		t.Fatalf("restored period = %+v, want the member with outcome settled", got)
	}
}

// A missing snapshot must not be fatal — re-derivation remains the backstop.
func TestMempoolStore_MissingFileIsNotFatal(t *testing.T) {
	st, err := NewBatchMempoolStore(filepath.Join(t.TempDir(), "absent.json"), jsonCodec{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	m := newTestMempool(BatchMempoolConfig{MaxBatchSize: 64})
	m.SetStore(st, nil) // must not panic or block
	if m.PendingCount() != 0 {
		t.Fatal("unexpected members")
	}
}

// A member written without an Accumulate validator set root was admitted for the retired V8.1 anchor, which its intent
// still declares. It cannot settle on V8.2, so the restore refuses it by name - the node does not start until the batch
// path is drained - rather than restoring a member no V8.2 anchor could commit (RB5 design D2).
func TestRestoreRefusesAMemberAdmittedBeforeV8_2(t *testing.T) {
	path := filepath.Join(t.TempDir(), "batch_mempool.json")
	pre := `[{"intent_id":"pre-v82","adi_url":"acc://orga.acme","chain_id":11155111,
	  "account":"0x32b4687bE3c02d52e2d94Dc1cFAF03a0E5af0C8B",
	  "operation_id":"0x0100000000000000000000000000000000000000000000000000000000000000",
	  "legs":[{"leg_id":"leg-0","target":"0x1111111111111111111111111111111111111111","value":"0","data":"0xdead"}],
	  "commit_height":105,
	  "governance_commitment":"0x0200000000000000000000000000000000000000000000000000000000000000"}]`
	if err := os.WriteFile(path, []byte(pre), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewBatchMempoolStore(path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	m := newTestMempool(BatchMempoolConfig{})
	_, err = store.Load(m)
	if err == nil || !strings.Contains(err.Error(), "retired V8.1 anchor") {
		t.Fatalf("a pre-V8.2 member was restored (err %v)", err)
	}
	if m.PendingCount() != 0 {
		t.Fatalf("%d member(s) restored from a refused queue", m.PendingCount())
	}
}
