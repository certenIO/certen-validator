// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/config"
	"github.com/certen/independant-validator/pkg/consensus"
)

// RB3-F52 step B: a sequential cross-chain intent's later member settles only once the member before
// it has its outcome on chain - read by the leader before it settles, and by every peer before it
// co-signs, each from its own copy of the member.

const seqPredChain = int64(84532)

var seqPredDeadline = time.Unix(1_800_003_600, 0).UTC()

// successor is a member on odChain that follows a predecessor on seqPredChain.
func successor(continueOnFailure bool) *PendingBatchIntent {
	p := odMember(2, odChain, 100)
	p.CommitTime = time.Unix(1_800_000_000, 0).UTC()
	p.SequencePosition = 1
	p.After = &MemberPredecessor{ChainID: seqPredChain, OperationID: [32]byte{2}, Account: p.Account,
		Leaf: [32]byte{0xaa}, Deadline: seqPredDeadline, ContinueOnFailure: continueOnFailure}
	return p
}

// predChain is the predecessor's chain with its finalized block at time t, the leaf consumed or not.
func predChain(t time.Time, consumed bool) *fakeNSChain {
	return &fakeNSChain{finalized: 50, times: map[uint64]int64{50: t.Unix()}, consumed: map[uint64]bool{50: consumed}}
}

func TestSequenceReadiness(t *testing.T) {
	past := seqPredDeadline.Add(nonSettlementFinality + time.Second)
	for name, tc := range map[string]struct {
		member *PendingBatchIntent
		chain  *fakeNSChain
		want   sequenceState
	}{
		"predecessor settled":                         {successor(false), predChain(seqPredDeadline.Add(-time.Hour), true), sequenceReady},
		"predecessor not yet settled, before its end": {successor(false), predChain(seqPredDeadline, false), sequenceWaiting},
		"predecessor did not settle: stop":            {successor(false), predChain(past, false), sequenceStopped},
		"predecessor did not settle: continue":        {successor(true), predChain(past, false), sequenceReady},
		"no predecessor":                              {odMember(1, odChain, 100), predChain(past, false), sequenceReady},
	} {
		t.Run(name, func(t *testing.T) {
			got, cause, err := sequenceReadiness(context.Background(), tc.chain, tc.member)
			if err != nil || got != tc.want {
				t.Fatalf("state %d (%q, %v), want %d", got, cause, err, tc.want)
			}
			if got == sequenceStopped && !strings.Contains(cause, "84532") {
				t.Fatalf("the cause %q does not name the predecessor's chain", cause)
			}
		})
	}

	// The member's own deadline passing while its predecessor is still in flight stops it.
	late := successor(true)
	late.Legs[0].Deadline = seqPredDeadline.Add(-30 * time.Minute).Unix()
	if got, cause, err := sequenceReadiness(context.Background(), predChain(seqPredDeadline.Add(-time.Minute), false), late); err != nil ||
		got != sequenceStopped || !strings.Contains(cause, "deadline") {
		t.Fatalf("own deadline passed while waiting: state %d (%q, %v)", got, cause, err)
	}

	// A read that fails decides nothing.
	if _, _, err := sequenceReadiness(context.Background(), &fakeNSChain{readErr: errors.New("rpc down")}, successor(false)); !IsChainReadError(err) {
		t.Fatalf("a failed read must be a chain read error, got %v", err)
	}
}

// The leader: a successor whose predecessor has no outcome yet is not touched; once the predecessor
// settled it goes on to form its anchor; a predecessor that did not settle stops it, recorded with why.
func TestSequencedSuccessorOnTheLeader(t *testing.T) {
	run := func(pred *fakeNSChain) (f *fakeODChain, queued bool, dropped []string) {
		// Anchor creation fails, so a successor that proceeds stops there - counted - before any quorum.
		f = &fakeODChain{createErr: errors.New("test: anchor creation stops here")}
		s, _ := settlementSubmitter(t, f)
		s.cfg.Stack.SequenceChain = pred
		s.cfg.OnDropped = func(_ context.Context, _ *PendingBatchIntent, cause string) { dropped = append(dropped, cause) }
		m := successor(false)
		if err := s.cfg.Stack.Mempool.AddOnDemand(m); err != nil {
			t.Fatal(err)
		}
		s.consider(context.Background(), m)
		return f, s.cfg.Stack.Mempool.GetOnDemand(odChain, m.OperationID) != nil, dropped
	}

	if f, queued, dropped := run(predChain(seqPredDeadline, false)); !queued || len(dropped) != 0 || f.createCalls != 0 {
		t.Fatalf("predecessor in flight: queued=%v dropped=%v anchors=%d; the successor must wait untouched", queued, dropped, f.createCalls)
	}
	if f, _, _ := run(predChain(seqPredDeadline.Add(-time.Hour), true)); f.createCalls == 0 {
		t.Fatal("predecessor settled: the successor must go on to form its anchor")
	}
	f, queued, dropped := run(predChain(seqPredDeadline.Add(nonSettlementFinality+time.Minute), false))
	if queued || f.createCalls != 0 || len(dropped) != 1 || !strings.Contains(dropped[0], "did not settle") {
		t.Fatalf("predecessor failed: queued=%v anchors=%d dropped=%v; the successor must be stopped unexecuted and recorded with why",
			queued, f.createCalls, dropped)
	}
}

// A peer co-signs a successor only once it reads the predecessor's outcome itself; until then it says
// so with a code the proposer retries on.
func TestSequencedSuccessorOnAPeer(t *testing.T) {
	ask := func(pred *fakeNSChain, continueOnFailure bool) *BatchAttestationResponse {
		m := successor(continueOnFailure)
		s := odStack(t, odChain, m)
		s.SequenceChain = pred
		return s.HandleOnDemandAttestationRequest(&OnDemandAttestationRequest{
			ChainID: odChain, OperationID: hex32(m.OperationID), BundleID: hex32([32]byte{9}), ProposerID: "validator-2",
		}, odIdentity())
	}
	if r := ask(predChain(seqPredDeadline, false), false); r.Code != CodePredecessorPending || r.SignatureHex != "" {
		t.Fatalf("predecessor in flight: code %q; want %q and no signature", r.Code, CodePredecessorPending)
	}
	if r := ask(&fakeNSChain{readErr: errors.New("rpc down")}, false); r.Code != CodePredecessorPending {
		t.Fatalf("predecessor unreadable: code %q; want the retryable %q", r.Code, CodePredecessorPending)
	}
	if r := ask(predChain(seqPredDeadline.Add(nonSettlementFinality+time.Minute), false), false); r.Code != CodeRefused {
		t.Fatalf("predecessor failed, intent stops: code %q; want %q", r.Code, CodeRefused)
	}
	// Past readiness the usual checks run: the proposer's wrong bundleId is a mismatch.
	if r := ask(predChain(seqPredDeadline.Add(-time.Hour), true), false); r.Code != CodeBundleMismatch {
		t.Fatalf("predecessor settled: code %q; want the request to reach the bundle check (%q)", r.Code, CodeBundleMismatch)
	}
	if r := ask(predChain(seqPredDeadline.Add(nonSettlementFinality+time.Minute), false), true); r.Code != CodeBundleMismatch {
		t.Fatalf("predecessor failed, intent continues: code %q; want the request to reach the bundle check", r.Code)
	}
	// And the proposer counts it as a peer that is behind, not one that disagrees.
	if !(OnDemandCollectResult{PredecessorPending: 1}).CouldStillConverge() {
		t.Fatal("a peer that does not yet see the predecessor settled must be waited for")
	}
}

// EnqueueAfter takes the predecessor's facts from this validator's own copy of it.
func TestEnqueueAfterBindsThePredecessor(t *testing.T) {
	r, err := NewEVMChainResolver(&config.AnchorConfig{}, map[int64]common.Address{
		odChain:      common.HexToAddress("0x3c0bf2dCC9D2945a933E36F8Ee1E10D8feEA9a32"),
		seqPredChain: common.HexToAddress("0x3c0bf2dCC9D2945a933E36F8Ee1E10D8feEA9a32"),
	})
	if err != nil {
		t.Fatal(err)
	}
	s := &BatchStack{Resolver: r, Mempool: NewBatchMempool(BatchMempoolConfig{MaxBatchSize: 64}),
		Orchestrators:  map[int64]*BatchOrchestrator{odChain: {screen: acceptEveryAccount}, seqPredChain: {screen: acceptEveryAccount}},
		MemberOutcomes: recordedOutcomes{}}
	commit := time.Unix(1_800_000_000, 0).UTC()
	legsOn := func(c int64) []mirrorLeg {
		return []mirrorLeg{{LegID: "leg", ChainID: c, Target: tgt(1), Value: big.NewInt(1)}}
	}
	after := consensus.SequencePredecessor{ChainID: seqPredChain, OperationID: opid(7), Position: 1, ContinueOnFailure: true}

	if err := s.EnqueueAfter("i1", "acc://a.acme", odChain, acct(1), opid(7), legsOn(odChain), "att", 100, "", commit, "", after); !errors.Is(err, ErrBatchUnavailable) {
		t.Fatalf("a successor whose predecessor is not queued must not be queued: %v", err)
	}
	if err := s.EnqueueForBatch("i1", "acc://a.acme", seqPredChain, acct(1), opid(7), legsOn(seqPredChain), "att", 100, "", commit, ""); err != nil {
		t.Fatal(err)
	}
	bad := after
	bad.Position = 0
	if err := s.EnqueueAfter("i1", "acc://a.acme", odChain, acct(1), opid(7), legsOn(odChain), "att", 100, "", commit, "", bad); err == nil {
		t.Fatal("position 0 is the first member, which follows nothing")
	}
	if err := s.EnqueueAfter("i1", "acc://a.acme", odChain, acct(1), opid(7), legsOn(odChain), "att", 100, "", commit, "", after); err != nil {
		t.Fatalf("EnqueueAfter: %v", err)
	}
	got := s.Mempool.GetOnDemand(odChain, opid(7))
	pred, _ := s.Mempool.FindMember(seqPredChain, opid(7))
	facts, err := memberFacts(pred)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.After == nil || got.SequencePosition != 1 || !got.After.ContinueOnFailure ||
		got.After.ChainID != seqPredChain || got.After.Leaf != facts.Leaf || got.After.Account != facts.Account ||
		!got.After.Deadline.Equal(facts.Deadline) || got.After.OperationID != opid(7) {
		t.Fatalf("successor %+v after %+v; want the predecessor's own facts %+v", got, got.After, facts)
	}
}

// A successor's horizon is one horizon per position, and its copy is held until its non-settlement
// can no longer be attested - past the TTL a first member is pruned at.
func TestSuccessorHorizonAndRetention(t *testing.T) {
	commit := time.Now().UTC()
	first := odMember(1, odChain, 100)
	first.CommitTime = commit
	second := odMember(2, odChain, 100)
	second.CommitTime, second.SequencePosition = commit, 1
	if d, _ := first.Deadline(); !d.Equal(commit.Add(maxGasDeferral)) {
		t.Fatalf("first member's deadline %s, want commit + %s", d, maxGasDeferral)
	}
	if d, _ := second.Deadline(); !d.Equal(commit.Add(2 * maxGasDeferral)) {
		t.Fatalf("second member's deadline %s, want commit + %s", d, 2*maxGasDeferral)
	}

	m := NewBatchMempool(BatchMempoolConfig{})
	for _, p := range []*PendingBatchIntent{first, second} {
		if err := m.AddOnDemand(p); err != nil {
			t.Fatal(err)
		}
	}
	m.PruneOnDemandOlderThan(DefaultOnDemandTTL, commit.Add(150*time.Minute))
	if m.GetOnDemand(odChain, first.OperationID) != nil {
		t.Fatal("the first member is past its TTL and its non-settlement window: pruned")
	}
	if m.GetOnDemand(odChain, second.OperationID) == nil {
		t.Fatal("the second member's failure can still be attested from this copy: held")
	}
	m.PruneOnDemandOlderThan(DefaultOnDemandTTL, commit.Add(3*time.Hour))
	if m.GetOnDemand(odChain, second.OperationID) != nil {
		t.Fatal("past its non-settlement window the second member is pruned")
	}
}

// The predecessor survives a restart with the member; a successor whose predecessor record is damaged
// is not restored, since it would settle out of order.
func TestSuccessorPredecessorIsPersisted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mempool.json")
	store, err := NewBatchMempoolStore(path, nil, func(string, ...interface{}) {})
	if err != nil {
		t.Fatal(err)
	}
	m := NewBatchMempool(BatchMempoolConfig{})
	m.SetStore(store, func(string, ...interface{}) {})
	p := successor(true)
	if err := m.AddOnDemand(p); err != nil {
		t.Fatal(err)
	}
	restored := NewBatchMempool(BatchMempoolConfig{})
	if n, err := store.Load(restored); err != nil || n != 1 {
		t.Fatalf("load: %d, %v", n, err)
	}
	got := restored.GetOnDemand(odChain, p.OperationID)
	if got == nil || got.After == nil || *got.After != *p.After || got.SequencePosition != 1 {
		t.Fatalf("restored %+v; want predecessor %+v at position 1", got, p.After)
	}

	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	damaged := strings.Replace(string(blob), common.Bytes2Hex(p.After.Leaf[:]), "00", 1)
	if damaged == string(blob) {
		t.Fatal("test premise: the leaf is in the file")
	}
	if err := os.WriteFile(path, []byte(damaged), 0o600); err != nil {
		t.Fatal(err)
	}
	again := NewBatchMempool(BatchMempoolConfig{})
	if n, _ := store.Load(again); n != 0 || again.GetOnDemand(odChain, p.OperationID) != nil {
		t.Fatalf("restored %d member(s) with a damaged predecessor", n)
	}
}
