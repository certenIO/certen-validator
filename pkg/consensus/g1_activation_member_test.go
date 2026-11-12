package consensus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/certen/independant-validator/pkg/ledger"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// DAX-1G (G-83), rules v16: the initiating-signature member of evidence 2.1 is a governed fact. The cross-partition activation transaction has a second
// version; a version-2 activation is accepted only after version 1 and only once; from the height after it the member is read, and until then a v16
// binary clears the member from the document it judges, so it decides every block as v15 did.

func memberActivation(f *rotationFixture, admins ...string) *G1ActivationTx {
	tx := &G1ActivationTx{Kind: G1ActivationKind, ChainID: rotChain, Version: 2}
	return tx.signedBy(f.admins, admins...)
}

func TestVersionTwoActivationNeedsVersionOneAndIsAcceptedOnce(t *testing.T) {
	f := newRotationFixture()
	v1 := ledger.G1ActivationRecord{Version: 1, Height: 2, ID: liveG1Activation(f).ActivationID()}
	rec, err := VerifyG1Activation(memberActivation(f, "ops-1", "ops-2"), rotChain, f.policy, &ledger.G1ActivationLog{Activations: []ledger.G1ActivationRecord{v1}}, 5)
	if err != nil {
		t.Fatalf("a version-2 activation after version 1, signed by two admins: %v", err)
	}
	if rec.Version != 2 || rec.Height != 5 || rec.ID != memberActivation(f).ActivationID() || rec.ID == v1.ID {
		t.Fatalf("record %+v: it carries its own version and id", rec)
	}
	both := &ledger.G1ActivationLog{Activations: []ledger.G1ActivationRecord{v1, {Version: 2, Height: 5, ID: "m"}}}
	for name, tc := range map[string]struct {
		tx   *G1ActivationTx
		log  *ledger.G1ActivationLog
		want string
	}{
		"before version 1":            {memberActivation(f, "ops-1", "ops-2"), nil, "only after the cross-partition activation"},
		"before version 1, empty log": {memberActivation(f, "ops-1", "ops-2"), &ledger.G1ActivationLog{}, "only after the cross-partition activation"},
		"twice":                       {memberActivation(f, "ops-1", "ops-2"), both, "activated the initiating-signature member at height 5"},
		"version 1 after both":        {liveG1Activation(f, "ops-1", "ops-2"), both, "an activation cannot be replayed, moved or undone"},
		"one admin":                   {memberActivation(f, "ops-1"), &ledger.G1ActivationLog{Activations: []ledger.G1ActivationRecord{v1}}, "cross-partition activation"},
		"signed as version 1 for it": {func() *G1ActivationTx {
			tx := memberActivation(f)
			tx.Signatures = liveG1Activation(f, "ops-1", "ops-2").Signatures // another version's approval cannot be moved
			return tx
		}(), &ledger.G1ActivationLog{Activations: []ledger.G1ActivationRecord{v1}}, "cross-partition activation"},
		"version three": {func() *G1ActivationTx {
			tx := memberActivation(f)
			tx.Version = 3
			return tx.signedBy(f.admins, "ops-1", "ops-2")
		}(), &ledger.G1ActivationLog{Activations: []ledger.G1ActivationRecord{v1}}, "version 1"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyG1Activation(tc.tx, rotChain, f.policy, tc.log, 5); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

// The member is read for the heights above the block that accepted its activation, never at or below it, and never without it; the 2.1 requirement
// of version 1 is unaffected.
func TestInitiatorMemberIsInForceOnlyAboveItsBlock(t *testing.T) {
	log := &ledger.G1ActivationLog{Activations: []ledger.G1ActivationRecord{{Version: 1, Height: 2, ID: "a"}, {Version: 2, Height: 10, ID: "b"}}}
	for h, want := range map[int64]bool{1: false, 3: false, 10: false, 11: true, 1000: true} {
		if got := G1InitiatorMemberInForce(log, h); got != want {
			t.Errorf("height %d: member in force %v, want %v", h, got, want)
		}
		g := G1ActivationAt(log, h)
		if h > 2 {
			if g == nil || !G1CrossPartitionRequired(g) || g.MemberInForce != want || g.Version != 1 || g.Height != 2 {
				t.Errorf("height %d: the activation in force is %+v, want version 1 at height 2 with the member in force %v", h, g, want)
			}
		} else if g != nil {
			t.Errorf("height %d: 2.1 required before its activation: %+v", h, g)
		}
	}
	if G1InitiatorMemberInForce(nil, 50) || G1InitiatorMemberInForce(&ledger.G1ActivationLog{}, 50) ||
		G1InitiatorMemberInForce(&ledger.G1ActivationLog{Activations: []ledger.G1ActivationRecord{{Version: 1, Height: 2}}}, 50) {
		t.Error("the member is in force without a version-2 activation")
	}
	// The flag is a reading of the log, not a stored fact: it never reaches the persisted record.
	raw, err := json.Marshal(G1ActivationAt(log, 50))
	if err != nil || strings.Contains(string(raw), "MemberInForce") || strings.Contains(string(raw), "memberInForce") {
		t.Fatalf("the record serializes the flag: %s (%v)", raw, err)
	}
}

// A version-2 activation is a verdict only v16 decides: refused before version 1, accepted after it. It is recorded at its height, in the app hash, served
// by the query, stamps the state v16, and cannot be repeated.
func TestTheMemberActivationIsRecordedAndStampsRulesV16(t *testing.T) {
	f := newRotationFixture()
	app, store := rotationApp(t, f)
	v1 := rotJSON(t, liveG1Activation(f, "ops-1", "ops-2"))
	v2 := rotJSON(t, memberActivation(f, "ops-1", "ops-2"))

	v14Step(t, app, 1, []uint32{0}, anchoredBlockJSON(t, "op-1", "validator-1", []ChainTarget{target(84532, liveAnchorBaseAndSepolia)}, nil))
	// Version 2 before version 1: refused (code 18, the code v15 gave every version but 1) - and stamped, because v16 may accept what v15 refused.
	v14Step(t, app, 2, []uint32{codeG1ActivationRefused}, v2)
	if app.committedRulesVersion() != executionRulesV16 {
		t.Fatalf("a decided version-2 activation left the state stamped v%d", app.committedRulesVersion())
	}
	if l, err := store.LoadG1Activation(); err != nil || len(l.Activations) != 0 {
		t.Fatalf("a refused activation was recorded: %+v (%v)", l, err)
	}

	v14Step(t, app, 3, []uint32{0}, v1)
	// The accepted activation is folded into the block's app hash through its id, and a refusal is not.
	finalize(t, app, 4, abcitypes.CommitInfo{}, v2)
	folded := false
	for _, b := range app.blockBundles {
		folded = folded || b == memberActivation(f).ActivationID()
	}
	if !folded {
		t.Fatalf("the accepted member activation's id is not among the block's folded ids: %v", app.blockBundles)
	}
	accepted := finalize(t, app, 4, abcitypes.CommitInfo{}, v2).AppHash
	refused := finalize(t, app, 4, abcitypes.CommitInfo{}, rotJSON(t, memberActivation(f, "ops-1"))).AppHash
	if bytes.Equal(accepted, refused) {
		t.Fatal("the member activation is not in the app hash")
	}
	resp2 := v14Step(t, app, 4, []uint32{codeG1ActivationRefused, 0, 0, 0},
		rotJSON(t, memberActivation(f, "ops-1")), v2, v2, rotJSON(t, memberActivation(f, "ops-2", "ops-3")))
	if !strings.Contains(resp2.TxResults[0].Log, "cross-partition activation refused") {
		t.Fatalf("refusal log %q", resp2.TxResults[0].Log)
	}
	l, err := store.LoadG1Activation()
	if err != nil || len(l.Activations) != 2 || l.Activations[0].Version != 1 || l.Activations[0].Height != 3 ||
		l.Activations[1].Version != 2 || l.Activations[1].Height != 4 || l.Activations[1].ID != memberActivation(f).ActivationID() {
		t.Fatalf("activation log (%+v, %v)", l, err)
	}
	if got, err := store.RulesFirstVerdict(executionRulesV16); err != nil || got != 2 {
		t.Fatalf("the first v16 verdict (%d, %v), want height 2 (the first version-2 activation decided)", got, err)
	}
	// Later, the same activation is refused: the chain activates the member once.
	v14Step(t, app, 5, []uint32{codeG1ActivationRefused}, v2)

	q, err := app.Query(context.Background(), &abcitypes.RequestQuery{Path: "/certen/g1_activation"})
	if err != nil || q.Code != 0 {
		t.Fatalf("query (%+v, %v)", q, err)
	}
	var got ledger.G1ActivationLog
	if err := json.Unmarshal(q.Value, &got); err != nil || len(got.Activations) != 2 {
		t.Fatalf("query answered %s (%v)", q.Value, err)
	}
	if in, err := app.G1InitiatorMemberInForce(); err != nil || !in {
		t.Fatalf("the proposer's gate (%v, %v): the member is in force for the next block", in, err)
	}
	if act := app.g1ActivationInForce(4); act == nil || act.MemberInForce {
		t.Fatalf("the member is in force in the block that accepted its activation: %+v", act)
	}
	if act := app.g1ActivationInForce(5); act == nil || !act.MemberInForce {
		t.Fatalf("the member is not in force the block after: %+v", act)
	}
}

// Before the activation the certificate's evidence is judged WITHOUT the member, as v15 judged it; from it, with it. The document the certificate keeps
// is never edited.
func TestEvidenceIsJudgedWithoutTheMemberUntilItsActivation(t *testing.T) {
	hop := &proofv2.VoteHop{Page: "acc://erp.acme/book/1", Message: "ab", Signature: "cd", Block: 3}
	ev := &proofv2.Evidence{Version: proofv2.Version21, Account: "acc://a.acme/data", InitiatingSignature: hop}
	if got := withoutInitiatingSignature(ev); got == ev || got.InitiatingSignature != nil || got.Account != ev.Account || ev.InitiatingSignature != hop {
		t.Fatalf("the member is not cleared from a copy: %+v (original %+v)", got, ev)
	}
	none := &proofv2.Evidence{Version: proofv2.Version21}
	if withoutInitiatingSignature(none) != none || withoutInitiatingSignature(nil) != nil {
		t.Fatal("a document without the member is not returned as it is")
	}
	// judgeProofV2 hands the verifier the document of the activation in force.
	for name, tc := range map[string]struct {
		g1   *ledger.G1ActivationRecord
		want bool // the member reaches the verifier
	}{
		"2.1 in force, member not":    {&ledger.G1ActivationRecord{Version: 1, Height: 2}, false},
		"2.1 and the member in force": {&ledger.G1ActivationRecord{Version: 1, Height: 2, MemberInForce: true}, true},
	} {
		t.Run(name, func(t *testing.T) {
			var seen *proofv2.Evidence
			stop := errors.New("the verifier saw the document")
			verify := func(doc *proofv2.Evidence, _ *ledger.AccumulateSpineLog, _ [32]byte) (*proofv2.Report, error) {
				seen = doc
				return nil, stop
			}
			cert := &IntentCertificateEvidence{ProofV2: ev}
			_, _, err := judgeProofV2(cert, nil, nil, nil, [32]byte{}, [32]byte{}, [32]byte{}, nil, tc.g1, verify)
			if !errors.Is(err, ErrIntentProofV2Invalid) || !strings.Contains(err.Error(), stop.Error()) {
				t.Fatalf("judgeProofV2: %v", err)
			}
			if (seen.InitiatingSignature != nil) != tc.want {
				t.Fatalf("the verifier saw the member: %v, want %v", seen.InitiatingSignature != nil, tc.want)
			}
			if ev.InitiatingSignature != hop {
				t.Fatal("the certificate's own document was edited")
			}
		})
	}
}

// A committed version-2 activation that v15 refused is a verdict v16 might reverse: the node refuses to continue the state (the version-1 case is unchanged).
func TestCommittedVersionTwoActivationHistoryIsChecked(t *testing.T) {
	f := newRotationFixture()
	raw := rotJSON(t, memberActivation(f, "ops-1", "ops-2"))
	hist := func(code uint32) *fakeHistory {
		return &fakeHistory{base: 1, blocks: map[int64][][]byte{1: {raw}}, times: map[int64]time.Time{1: beforeV9},
			codes: map[int64][]uint32{1: {code}}}
	}
	err := historyApp(t, 1).IndexCommittedHistory(hist(codeG1ActivationRefused))
	if !errors.Is(err, ErrCommittedHistoryUnderCurrentRules) || !strings.Contains(err.Error(), "version-2 cross-partition activation that v15 refused") {
		t.Fatalf("a version-2 activation refused by v15: %v", err)
	}
	// Accepted: it is a v16 verdict and needs its record.
	if err := historyApp(t, 1).IndexCommittedHistory(hist(0)); !errors.Is(err, ErrCommittedHistoryUnderCurrentRules) {
		t.Fatalf("a version-2 activation accepted with no record: %v", err)
	}
	accepted := historyApp(t, 1)
	tx, _ := DecodeG1Activation(raw)
	if err := accepted.ledgerStore.SaveG1Activation(&ledger.G1ActivationLog{Activations: []ledger.G1ActivationRecord{
		{Version: 1, Height: 1, ID: "v1"}, {Version: 2, Height: 1, ID: tx.ActivationID()}}}); err != nil {
		t.Fatal(err)
	}
	if err := accepted.IndexCommittedHistory(hist(0)); err != nil {
		t.Fatalf("a version-2 activation accepted and recorded: %v", err)
	}
	if accepted.committedRulesVersion() != executionRulesV16 {
		t.Fatalf("a committed version-2 activation left the state stamped v%d", accepted.committedRulesVersion())
	}
	// The tool's check agrees.
	v, _, cerr := CommittedBlockViolations(1, [][]byte{raw}, []uint32{codeG1ActivationRefused}, &CommittedRecords{})
	if cerr != nil || len(v) != 1 {
		t.Fatalf("the check of a refused version-2 activation: %v %v", v, cerr)
	}
}

func TestCheckTxFiltersTheVersionTwoActivationShape(t *testing.T) {
	f := newRotationFixture()
	app, _ := rotationApp(t, f)
	check := func(tx *G1ActivationTx) uint32 {
		t.Helper()
		r, err := app.CheckTx(context.Background(), &abcitypes.RequestCheckTx{Tx: rotJSON(t, tx)})
		if err != nil {
			t.Fatal(err)
		}
		return r.Code
	}
	if c := check(memberActivation(f, "ops-1", "ops-2")); c != 0 {
		t.Fatalf("a version-2 activation is a mempool shape: code %d", c)
	}
	bad := memberActivation(f, "ops-1", "ops-2")
	bad.Version = 3
	if c := check(bad); c != codeG1ActivationRefused {
		t.Fatalf("version 3: code %d, want %d", c, codeG1ActivationRefused)
	}
}

// Both versions in one block: version 2 follows version 1 in the same block (the record of version 1 written there counts), both are recorded at that
// height, and executing the block again decides every transaction as the first execution did (v14Step runs each block twice).
func TestVersionOneAndTwoInOneBlockAreBothRecorded(t *testing.T) {
	f := newRotationFixture()
	app, store := rotationApp(t, f)
	v1 := rotJSON(t, liveG1Activation(f, "ops-1", "ops-2"))
	v2 := rotJSON(t, memberActivation(f, "ops-1", "ops-2"))
	v14Step(t, app, 1, []uint32{0}, anchoredBlockJSON(t, "op-1", "validator-1", []ChainTarget{target(84532, liveAnchorBaseAndSepolia)}, nil))
	// Version 2 before version 1 in the block is refused (nothing recorded yet); after it, accepted.
	v14Step(t, app, 2, []uint32{codeG1ActivationRefused, 0, 0, 0}, v2, v1, v2, v1)
	l, err := store.LoadG1Activation()
	if err != nil || len(l.Activations) != 2 || l.Activations[0].Version != 1 || l.Activations[0].Height != 2 ||
		l.Activations[1].Version != 2 || l.Activations[1].Height != 2 {
		t.Fatalf("activation log (%+v, %v)", l, err)
	}
	if G1InitiatorMemberInForce(l, 2) || !G1InitiatorMemberInForce(l, 3) {
		t.Fatal("the member must be in force above the block that accepted version 2, and not in it")
	}
	if act := app.g1ActivationInForce(3); act == nil || !act.MemberInForce || !G1CrossPartitionRequired(act) {
		t.Fatalf("both gates are in force the block after: %+v", act)
	}
}
