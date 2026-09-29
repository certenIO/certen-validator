package execution

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/ethereum/go-ethereum/common"
)

// RB4-F66. A batch anchor committed nothing of its members' governance: the batch operation id - the one value the
// quorum signs and the anchor stores that is free to carry it - aggregated the operation ids alone, so two batches
// whose members were decided by different authorities signed and anchored the same id. It now commits to each
// member's governance decision.

func f66Inputs(gov byte) []BatchLeafInput {
	a := BatchLeafInput{ADIURL: "acc://a.acme", ExecutionCommitment: [32]byte{1}, OperationID: [32]byte{2}}
	b := BatchLeafInput{ADIURL: "acc://b.acme", ExecutionCommitment: [32]byte{3}, OperationID: [32]byte{4}}
	a.GovernanceCommitment = [32]byte{0xA0, gov}
	b.GovernanceCommitment = [32]byte{0xB0}
	return []BatchLeafInput{a, b}
}

func TestF66_TheBatchOperationIDCommitsEachMembersGovernance(t *testing.T) {
	one, err := BuildBatchTree(84532, f66Inputs(1), 100)
	if err != nil {
		t.Fatal(err)
	}
	two, err := BuildBatchTree(84532, f66Inputs(2), 100)
	if err != nil {
		t.Fatal(err)
	}
	if one.BatchOperationID == two.BatchOperationID || one.BundleID == two.BundleID {
		t.Fatal("members decided differently produce the same batch operation id and bundle id")
	}
	// The leaves - what each account reconstructs - do not move.
	if one.Root != two.Root {
		t.Fatal("governance moved the batch root; the account's leaf must not depend on it")
	}
}

func TestF66_AMemberWithoutAGovernanceDecisionIsNotBatched(t *testing.T) {
	in := f66Inputs(1)
	in[1].GovernanceCommitment = [32]byte{}
	if _, err := BuildBatchTree(84532, in, 100); err == nil {
		t.Fatal("a member with no governance commitment was batched")
	}
}

func TestF66_TheBatchOperationIDDoesNotDependOnMemberOrder(t *testing.T) {
	in := f66Inputs(1)
	rev := []BatchLeafInput{in[1], in[0]}
	a, err := DeriveBatchOperationIDV2(in)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveBatchOperationIDV2(rev)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("the batch operation id depends on the order members arrived in")
	}
}

// The v2 id, reproduced by an independent encoder (Node, ethers keccak256, from the specification in
// DeriveBatchOperationIDV2's documentation).
func TestF66_TheV2IDMatchesAnIndependentEncoder(t *testing.T) {
	got, err := DeriveBatchOperationIDV2(f66Inputs(1))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got[:]) != "18e4f580608716d836722846a68e016f56bd1b5e8ed18ac436e85160f224007c" {
		t.Fatalf("v2 batch operation id %x", got)
	}
}

// Members admitted before governance commitments keep the v1 id their anchors may carry; they are never mixed
// with members that commit.
func TestF66_LegacyMembersKeepTheV1ID(t *testing.T) {
	legacy := f66Inputs(1)
	for i := range legacy {
		legacy[i].GovernanceCommitment = [32]byte{}
		legacy[i].LegacyNoGovernance = true
	}
	tree, err := BuildBatchTree(84532, legacy, 100)
	if err != nil {
		t.Fatal(err)
	}
	if want := DeriveBatchOperationID([][32]byte{legacy[0].OperationID, legacy[1].OperationID}); tree.BatchOperationID != want {
		t.Fatalf("a legacy batch has id %x, want the v1 id %x", tree.BatchOperationID, want)
	}
	mixed := f66Inputs(1)
	mixed[0].GovernanceCommitment, mixed[0].LegacyNoGovernance = [32]byte{}, true
	if _, err := BuildBatchTree(84532, mixed, 100); err == nil {
		t.Fatal("a batch mixed legacy members with members that commit")
	}
	bad := f66Inputs(1)
	bad[0].LegacyNoGovernance = true // and still carries a commitment
	if _, err := BuildBatchTree(84532, bad, 100); err == nil {
		t.Fatal("a member marked legacy with a commitment was batched")
	}
}

// Admission requires the commitment, and requires the round's snapshot to state the same one.
func TestF66_AdmissionRequiresTheSnapshotsCommitment(t *testing.T) {
	legs := admissionLeg(11155111)
	s := stackForChain(t, 11155111)
	if err := s.EnqueueForBatch("i0", "acc://a.acme", 11155111, acct(1), opid(1), legs, testAtt, [32]byte{}, 100, "",
		time.Time{}, ""); !errors.Is(err, ErrNoGovernanceCommitment) || !errors.Is(err, ErrBatchUnavailable) {
		t.Fatalf("a member with no commitment: %v", err)
	}
	if err := s.EnqueueForBatch("i1", "acc://a.acme", 11155111, acct(1), opid(2), legs, "no decision", testGov, 100, "",
		time.Time{}, ""); !errors.Is(err, ErrNoGovernanceCommitment) {
		t.Fatalf("a snapshot stating no decision: %v", err)
	}
	other := [32]byte{0xee}
	if err := s.EnqueueForBatch("i2", "acc://a.acme", 11155111, acct(1), opid(3), legs, testAtt, other, 100, "",
		time.Time{}, ""); err == nil || !strings.Contains(err.Error(), "not the one its round's snapshot states") {
		t.Fatalf("a commitment its snapshot does not state: %v", err)
	}
	if err := s.EnqueueForBatch("i3", "acc://a.acme", 11155111, acct(1), opid(4), legs, testAtt, testGov, 100, "",
		time.Time{}, ""); err != nil {
		t.Fatalf("a member committing to its snapshot's decision: %v", err)
	}
}

// A period with legacy members cuts them into their own chunks, the same on every validator.
func TestF66_APeriodChunksLegacyMembersApart(t *testing.T) {
	o := &BatchOrchestrator{screen: func(context.Context, *PendingBatchIntent) error { return nil }}
	legacy := &PendingBatchIntent{IntentID: "old", ChainID: 1, OperationID: opid(1), LegacyNoGovernance: true}
	fresh := &PendingBatchIntent{IntentID: "new", ChainID: 1, OperationID: opid(2), GovernanceCommitment: testGov}
	none := &PendingBatchIntent{IntentID: "none", ChainID: 1, OperationID: opid(3)}
	chunks, excluded, err := o.periodChunks(context.Background(), []*PendingBatchIntent{fresh, legacy, none}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 2 || chunks[0][0] != legacy || chunks[1][0] != fresh {
		t.Fatalf("chunks %v", chunks)
	}
	if len(excluded) != 1 || excluded[0].member != none || !errors.Is(excluded[0].cause, ErrNoGovernanceCommitment) {
		t.Fatalf("excluded %+v", excluded)
	}
}

// The mempool persists each member's commitment. A member written before commitments existed restores as legacy;
// a commitment or operation id that does not decode stops the restore rather than being padded or truncated.
func TestF66_TheQueueKeepsEachMembersCommitment(t *testing.T) {
	path, doc := savedQueue(t)
	st, err := NewBatchMempoolStore(path, jsonCodec{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	m := NewBatchMempool(BatchMempoolConfig{MaxBatchSize: 64})
	if err := m.SetStore(st, nil); err != nil {
		t.Fatal(err)
	}
	got := m.PeriodMembers(11155111, 6259200, 100)
	if len(got) != 1 || got[0].GovernanceCommitment != testGov || got[0].LegacyNoGovernance {
		t.Fatalf("restored %+v", got)
	}

	write := func(mutate func(map[string]interface{})) {
		cp, _ := json.Marshal(doc)
		var d []map[string]interface{}
		_ = json.Unmarshal(cp, &d)
		mutate(d[0])
		raw, _ := json.Marshal(d)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write(func(m map[string]interface{}) { delete(m, "governance_commitment") })
	st, _ = NewBatchMempoolStore(path, jsonCodec{}, nil)
	m = NewBatchMempool(BatchMempoolConfig{MaxBatchSize: 64})
	if err := m.SetStore(st, nil); err != nil {
		t.Fatal(err)
	}
	if got := m.PeriodMembers(11155111, 6259200, 100); len(got) != 1 || !got[0].LegacyNoGovernance ||
		got[0].GovernanceCommitment != ([32]byte{}) {
		t.Fatalf("a member written before commitments restored as %+v", got)
	}

	for name, mutate := range map[string]func(map[string]interface{}){
		"short commitment": func(m map[string]interface{}) { m["governance_commitment"] = "0xabcd" },
		"zero commitment":  func(m map[string]interface{}) { m["governance_commitment"] = "0x" + strings.Repeat("0", 64) },
		"short operation":  func(m map[string]interface{}) { m["operation_id"] = "0x01" },
	} {
		write(mutate)
		if err := restore(t, path); err == nil {
			t.Errorf("%s: restored", name)
		}
	}
}

// A peer whose own proof decided a member's governance differently refuses by name: which member, both decisions.
func TestF66_APeerRefusesAGovernanceItDidNotDecide(t *testing.T) {
	add := func(s *BatchStack, gov [32]byte) {
		t.Helper()
		if err := s.Mempool.Add(&PendingBatchIntent{GovernanceCommitment: gov,
			IntentID: "alpha", ADIURL: "acc://alpha.acme", ChainID: 11155111,
			Account:      common.HexToAddress("0x32b4687bE3c02d52e2d94Dc1cFAF03a0E5af0C8B"),
			OperationID:  opid(5),
			Legs:         []LegExecution{{LegID: "l0", ChainID: 11155111, Target: tgt(0xAA), Value: big.NewInt(1000)}},
			CommitHeight: 100,
		}); err != nil {
			t.Fatal(err)
		}
	}
	proposer := stackForChain(t, 11155111)
	add(proposer, [32]byte{0x01})
	members := proposer.Mempool.PeriodMembers(11155111, 100, DefaultBatchPeriodBlocks)
	in, err := members[0].LeafInput()
	if err != nil {
		t.Fatal(err)
	}
	tree, err := BuildBatchTree(11155111, []BatchLeafInput{in}, 100)
	if err != nil {
		t.Fatal(err)
	}
	req, err := NewBatchAttestationRequest(tree, 100, DefaultBatchPeriodBlocks, "validator-2")
	if err != nil {
		t.Fatal(err)
	}

	us := stackForChain(t, 11155111)
	add(us, [32]byte{0x02}) // this validator's own G1 decided it otherwise
	resp := us.HandleBatchAttestationRequest(req, attesterID())
	op := opid(5)
	if resp.SignatureHex != "" || resp.Code != CodeGovernanceMismatch || !strings.Contains(resp.Error, hex.EncodeToString(op[:8])) ||
		!strings.Contains(resp.Error, "0100000000000000") || !strings.Contains(resp.Error, "0200000000000000") {
		t.Fatalf("code %q: %s", resp.Code, resp.Error)
	}

	// Agreeing on governance, the same request is signed.
	agree := stackForChain(t, 11155111)
	add(agree, [32]byte{0x01})
	if resp := agree.HandleBatchAttestationRequest(req, attesterID()); resp.Code == CodeGovernanceMismatch ||
		resp.Code == CodeBundleMismatch {
		t.Fatalf("an agreeing peer refused: %s %s", resp.Code, resp.Error)
	}
}

// Layer 5 carries what the anchored batch operation id commits to about each member's governance, and recomputes
// it offline.
func f66Governance(t *testing.T) (*BatchTree, *BatchGovernance) {
	t.Helper()
	tree, err := BuildBatchTree(84532, f66Inputs(1), 100)
	if err != nil {
		t.Fatal(err)
	}
	g := &BatchGovernance{Version: tree.BatchOperationIDVersion,
		BatchOperationID: "0x" + hex.EncodeToString(tree.BatchOperationID[:])}
	for _, in := range tree.Inputs {
		g.Members = append(g.Members, database.BatchMemberGovernance{
			OperationID:          "0x" + hex.EncodeToString(in.OperationID[:]),
			GovernanceCommitment: "0x" + hex.EncodeToString(in.GovernanceCommitment[:]),
		})
	}
	g.OperationID, g.GovernanceCommitment = g.Members[1].OperationID, g.Members[1].GovernanceCommitment
	return tree, g
}

func TestF66_Layer5RecomputesTheBatchOperationID(t *testing.T) {
	tree, g := f66Governance(t)
	if tree.BatchOperationIDVersion != BatchOperationIDV2 {
		t.Fatalf("a batch of committing members was formed as %s", tree.BatchOperationIDVersion)
	}
	if err := g.Verify(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*BatchGovernance){
		"another member's decision": func(g *BatchGovernance) { g.Members[0].GovernanceCommitment = "0x" + strings.Repeat("11", 32) },
		"this member's decision":    func(g *BatchGovernance) { g.GovernanceCommitment = "0x" + strings.Repeat("22", 32) },
		"a member removed":          func(g *BatchGovernance) { g.Members = g.Members[1:] },
		"not a member":              func(g *BatchGovernance) { g.OperationID = "0x" + strings.Repeat("33", 32) },
		"another batch id":          func(g *BatchGovernance) { g.BatchOperationID = "0x" + strings.Repeat("44", 32) },
		"claimed v1":                func(g *BatchGovernance) { g.Version = BatchOperationIDV1 },
		"no members":                func(g *BatchGovernance) { g.Members = nil },
	} {
		_, g := f66Governance(t)
		mutate(g)
		if err := g.Verify(); err == nil {
			t.Errorf("%s: verified", name)
		}
	}

	// A v1 batch verifies as v1: its anchor commits to no governance, and nothing claims it does.
	legacy := f66Inputs(1)
	for i := range legacy {
		legacy[i].GovernanceCommitment, legacy[i].LegacyNoGovernance = [32]byte{}, true
	}
	lt, err := BuildBatchTree(84532, legacy, 100)
	if err != nil {
		t.Fatal(err)
	}
	lg := &BatchGovernance{Version: lt.BatchOperationIDVersion, BatchOperationID: "0x" + hex.EncodeToString(lt.BatchOperationID[:])}
	for _, in := range lt.Inputs {
		lg.Members = append(lg.Members, database.BatchMemberGovernance{OperationID: "0x" + hex.EncodeToString(in.OperationID[:])})
	}
	lg.OperationID = lg.Members[0].OperationID
	if lt.BatchOperationIDVersion != BatchOperationIDV1 || lg.Verify() != nil {
		t.Fatalf("a v1 batch: %s %v", lt.BatchOperationIDVersion, lg.Verify())
	}
}
