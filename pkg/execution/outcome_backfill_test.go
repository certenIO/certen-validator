package execution

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// RB5 D4: the kept trees of anchors attested before validators kept them are rebuilt from the database's rows used
// only as hints plus the signed intents, and kept only when they rebuild the anchor on the chain exactly.

type fakeBackfillHints struct {
	bundles  []string
	recorded []string
	hints    *database.AnchorMemberHints
	pages    map[string][2]string
}

func (f *fakeBackfillHints) AttestedAnchorsWithoutOutcome(context.Context, int64, int) ([]string, error) {
	return f.bundles, nil
}
func (f *fakeBackfillHints) RecordedAnchorsWithoutProofEvidence(context.Context, int64, int) ([]string, error) {
	return f.recorded, nil
}
func (f *fakeBackfillHints) AnchorMemberHints(context.Context, int64, string) (*database.AnchorMemberHints, error) {
	if f.hints == nil {
		return nil, nil
	}
	cp := *f.hints
	cp.Members = append([]database.AnchorMemberHint(nil), f.hints.Members...)
	return &cp, nil
}
func (f *fakeBackfillHints) CertifiedAuthority(_ context.Context, op string) (string, string, error) {
	p := f.pages[strings.ToLower(op)]
	return p[0], p[1], nil
}

// fakeIntents serves signed intents by Accumulate transaction, on the principal <adi>/data.
type fakeIntents map[string][][]byte

func (f fakeIntents) SignedIntent(_ context.Context, tx, principal string) ([][]byte, time.Time, error) {
	if !strings.HasSuffix(principal, "/data") {
		return nil, time.Time{}, fmt.Errorf("no transaction %s on %s", tx, principal)
	}
	b := f[tx]
	if b == nil {
		return nil, time.Time{}, fmt.Errorf("no transaction %s", tx)
	}
	return b, outcomeTestCommit, nil
}

type treeBackfillFixture struct {
	b      *OutcomeBackfill
	hints  *fakeBackfillHints
	reader *fakeOutcomeReader
	tree   *BatchTree
	byOp   map[[32]byte]*PendingBatchIntent
	store  *OutcomeTreeStore
}

// newTreeBackfillFixture is a two-member anchor on Base Sepolia attested on chain, the database's rows for it, and the two
// members' signed intents on Accumulate.
func newTreeBackfillFixture(t *testing.T) *treeBackfillFixture {
	t.Helper()
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	legs := map[string][]map[string]interface{}{
		"alpha": {f77NativeLeg(84532, "1000"), f77CallLeg(84532, true)},
		"beta":  {f77NativeLeg(84532, "7")},
	}
	var members []*PendingBatchIntent
	intents := fakeIntents{}
	hints := &fakeBackfillHints{hints: &database.AnchorMemberHints{BatchOperationIDVersion: BatchOperationIDV3}, pages: map[string][2]string{}}
	for _, id := range []string{"alpha", "beta"} {
		p := outcomeTestMember(t, 84532, id, legs[id]...)
		members = append(members, p)
		tx := fmt.Sprintf("%064x", len(id))
		intents[tx] = signedBlobs(t, id, legs[id]...)
		hints.pages[strings.ToLower(hex32(p.OperationID))] = [2]string{p.CertifiedKeyPage, p.CertifiedKeyBook}
	}
	tree, byOp := outcomeTestTree(t, 84532, members...)
	for i, p := range members {
		hints.hints.Members = append(hints.hints.Members, database.AnchorMemberHint{TreeIndex: i, Leaf: tree.Leaves[i][:],
			OperationID: hex32(p.OperationID), GovernanceCommitment: hex32(p.GovernanceCommitment),
			CertifiedIntentMessage: hex32(p.CertifiedMessage), IntentID: p.IntentID, ADIURL: p.ADIURL,
			AccumTxHash: fmt.Sprintf("%064x", len(p.IntentID)), Account: p.Account.Hex(), CommitHeight: int64(p.CommitHeight)})
	}
	hints.bundles = []string{hex32(tree.BundleID)}
	_, f := derivationFixture(t)
	reader := &fakeOutcomeReader{fakeOutcomeChain: f, registryOK: true, view: OutcomeAnchorView{At: f.header(2005),
		Anchor: &contracts.AnchorState{Version: contracts.BatchAnchorV8_2, Valid: true, ProofExecuted: true, MerkleRoot: tree.Root,
			OperationID: tree.BatchOperationID, AccumulateBlockHeight: big.NewInt(int64(tree.BlockHeight)),
			AccumulateSetRoot: tree.AccumulateSetRoot, Incarnation: tree.Incarnation},
		LeafCount: uint64(tree.Size()), CurrentSetRoot: peerSetRoot}}
	store, err := NewOutcomeTreeStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b := &OutcomeBackfill{Chains: map[int64]OutcomeChainReader{84532: reader}, Hints: hints, Intents: intents, Trees: store}
	return &treeBackfillFixture{b: b, hints: hints, reader: reader, tree: tree, byOp: byOp, store: store}
}

func TestATreeRebuiltFromHintsAndSignedIntentsIsKeptOnlyWhenItIsTheAnchor(t *testing.T) {
	f := newTreeBackfillFixture(t)
	ctx := context.Background()
	res, err := f.b.Run(ctx)
	if err != nil || len(res) != 1 || res[0].Outcome != "would-keep" {
		t.Fatalf("dry run: %+v %v", res, err)
	}
	if _, err := f.store.Load(84532, f.tree.BundleID); !errors.Is(err, ErrOutcomeTreeNotHeld) {
		t.Fatalf("a dry run wrote a tree: %v", err)
	}
	f.b.Apply = true
	if res, _ := f.b.Run(ctx); res[0].Outcome != "kept" {
		t.Fatalf("apply: %+v", res)
	}
	kept, err := f.store.Load(84532, f.tree.BundleID)
	if err != nil {
		t.Fatal(err)
	}
	// The rebuilt tree states exactly what the validators that signed it kept: the same members, legs, effects and
	// deadlines.
	native, err := NewOutcomeTree(f.tree, f.byOp, OutcomeTreeSigned)
	if err != nil {
		t.Fatal(err)
	}
	if !kept.sameMembers(native) || kept.Roles[0] != OutcomeTreeBackfilled {
		t.Fatalf("the rebuilt tree is not the signed one: %+v", kept)
	}
	// Idempotent: a second run keeps nothing new.
	if res, _ := f.b.Run(ctx); res[0].Outcome != "held" {
		t.Fatalf("second run: %+v", res)
	}
}

func TestABackfillMergesWithTheTreeAValidatorKeptItself(t *testing.T) {
	f := newTreeBackfillFixture(t)
	native, err := NewOutcomeTree(f.tree, f.byOp, OutcomeTreeSigned)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.Retain(native); err != nil {
		t.Fatal(err)
	}
	f.b.Apply = true
	if res, _ := f.b.Run(context.Background()); res[0].Outcome != "kept" {
		t.Fatalf("%+v", res)
	}
	kept, _ := f.store.Load(84532, f.tree.BundleID)
	if len(kept.Roles) != 2 || kept.Members[0].SearchFrom != native.Members[0].SearchFrom {
		t.Fatalf("not merged into the kept tree: roles %v", kept.Roles)
	}
}

func TestATamperedRowIsRefusedAndNothingIsKept(t *testing.T) {
	for name, tamper := range map[string]func(*treeBackfillFixture){
		"a leaf": func(f *treeBackfillFixture) { f.hints.hints.Members[1].Leaf = make([]byte, 32) },
		"the order": func(f *treeBackfillFixture) {
			m := f.hints.hints.Members
			m[0].TreeIndex, m[1].TreeIndex = 1, 0
		},
		"an operation id": func(f *treeBackfillFixture) { f.hints.hints.Members[0].OperationID = hex32([32]byte{0x0e}) },
		"a governance commitment": func(f *treeBackfillFixture) {
			f.hints.hints.Members[1].GovernanceCommitment = hex32([32]byte{0x0f})
		},
		"a certified message": func(f *treeBackfillFixture) {
			f.hints.hints.Members[0].CertifiedIntentMessage = hex32([32]byte{0x10})
		},
		"the ADI":          func(f *treeBackfillFixture) { f.hints.hints.Members[0].ADIURL = "acc://mallory.acme" },
		"a missing member": func(f *treeBackfillFixture) { f.hints.hints.Members = f.hints.hints.Members[:1] },
		"the key page": func(f *treeBackfillFixture) {
			for op, p := range f.hints.pages {
				f.hints.pages[op] = [2]string{strings.TrimSuffix(p[0], "/1") + "/2", p[1]}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newTreeBackfillFixture(t)
			f.b.Apply = true
			tamper(f)
			res, err := f.b.Run(context.Background())
			t.Logf("refused: %s", res[0].Reason)
			if err != nil || len(res) != 1 || res[0].Outcome != "refused" || res[0].Reason == "" || strings.Contains(res[0].Reason, "is at leaf") {
				t.Fatalf("%+v %v", res, err)
			}
			if _, err := f.store.Load(84532, f.tree.BundleID); !errors.Is(err, ErrOutcomeTreeNotHeld) {
				t.Fatalf("a refused tree was kept: %v", err)
			}
		})
	}
}

func TestAnAnchorWhoseBundleIdDoesNotRebuildIsRefused(t *testing.T) {
	f := newTreeBackfillFixture(t)
	f.b.Apply = true
	// The same root and members, committed at another Accumulate height: another bundle id.
	f.reader.view.Anchor.AccumulateBlockHeight = big.NewInt(int64(f.tree.BlockHeight) + 1)
	res, _ := f.b.Run(context.Background())
	if res[0].Outcome != "refused" || !strings.Contains(res[0].Reason, "bundle id") {
		t.Fatalf("%+v", res)
	}
	f = newTreeBackfillFixture(t)
	f.b.Apply = true
	f.reader.view.LeafCount = 3
	if res, _ := f.b.Run(context.Background()); res[0].Outcome != "refused" {
		t.Fatalf("a leaf count the rows do not match: %+v", res)
	}
}

func TestOnlyAttestedUnrecordedAnchorsAreBackfilled(t *testing.T) {
	f := newTreeBackfillFixture(t)
	f.b.Apply = true
	f.reader.view.Anchor.ProofExecuted = false
	if res, _ := f.b.Run(context.Background()); res[0].Outcome != "not-attested" {
		t.Fatalf("%+v", res)
	}
	f.reader.view.Anchor.ProofExecuted = true
	f.reader.view.RecordedRoot = [32]byte{1}
	if res, _ := f.b.Run(context.Background()); res[0].Outcome != "recorded" {
		t.Fatalf("%+v", res)
	}
	if _, err := f.store.Load(84532, f.tree.BundleID); !errors.Is(err, ErrOutcomeTreeNotHeld) {
		t.Fatalf("kept: %v", err)
	}
}

// RB5-F15: an anchor whose outcome is recorded while some of its members' proofs lack its evidence (recorded before
// evidence was attached, its tree since released) is rebuilt with Recorded, so the recorder attaches the evidence; an
// anchor not recorded yet is left to the default mode.
func TestARecordedAnchorWithoutProofEvidenceIsRebuilt(t *testing.T) {
	f := newTreeBackfillFixture(t)
	f.b.Apply, f.b.Recorded = true, true
	f.hints.recorded = f.hints.bundles
	f.reader.view.RecordedRoot = [32]byte{1}
	if res, _ := f.b.Run(context.Background()); len(res) != 1 || res[0].Outcome != "kept" {
		t.Fatalf("%+v", res)
	}
	if _, err := f.store.Load(84532, f.tree.BundleID); err != nil {
		t.Fatalf("not kept: %v", err)
	}
	g := newTreeBackfillFixture(t)
	g.b.Apply, g.b.Recorded = true, true
	g.hints.recorded = g.hints.bundles
	if res, _ := g.b.Run(context.Background()); len(res) != 1 || res[0].Outcome != "not-recorded" {
		t.Fatalf("%+v", res)
	}
}
