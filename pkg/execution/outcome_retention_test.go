package execution

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// RB5 D4: every batch tree a validator signs or proves is kept on its own disk, before it signs, with what stating
// each member's outcome needs - so it can later certify the outcome from its own copy, never from the shared database.

var outcomeTestCommit = time.Unix(1_790_000_000, 0).UTC()

// outcomeTestMember is a certified member whose round snapshot carries its user-signed intent.
func outcomeTestMember(t *testing.T, chainID int64, id string, legs ...map[string]interface{}) *PendingBatchIntent {
	t.Helper()
	blobs := signedBlobs(t, id, legs...)
	committed, account, opID, err := memberLegsFromSignedIntent(blobs, chainID)
	if err != nil {
		t.Fatal(err)
	}
	var le []LegExecution
	for i, l := range committed {
		le = append(le, LegExecution{LegID: fmt.Sprintf("leg-%d", i), ChainID: chainID, Target: l.Call.Target,
			Value: callValue(l.Call.Value), Data: l.Call.Data})
	}
	att := &consensus.PendingAttestation{IntentID: id, CertenIntent: &consensus.CertenIntent{IntentID: id,
		IntentData: blobs[0], CrossChainData: blobs[1], GovernanceData: blobs[2], ReplayData: blobs[3]}}
	return certifiedForTest(&PendingBatchIntent{AccumulateSetRoot: testAccSet, GovernanceCommitment: testGov,
		IntentID: id, ADIURL: "acc://" + id + ".acme", ChainID: chainID, Account: account, OperationID: opID,
		CommitHeight: 105, CommitTime: outcomeTestCommit, FirstSeen: outcomeTestCommit.Add(time.Minute), Legs: le,
		Attestation: att})
}

func outcomeTestTree(t *testing.T, chainID int64, members ...*PendingBatchIntent) (*BatchTree, map[[32]byte]*PendingBatchIntent) {
	t.Helper()
	var inputs []BatchLeafInput
	byOp := map[[32]byte]*PendingBatchIntent{}
	for _, p := range members {
		in, err := p.LeafInput()
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, in)
		byOp[p.OperationID] = p
	}
	tree, err := BuildBatchTree(chainID, inputs, 105, testIncarnation)
	if err != nil {
		t.Fatal(err)
	}
	return tree, byOp
}

func TestAKeptTreeHoldsWhatEachMemberCommittedAndRebuildsItsAnchor(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	a := outcomeTestMember(t, 84532, "alpha", f77NativeLeg(84532, "1000"), f77CallLeg(84532, true))
	b := outcomeTestMember(t, 84532, "beta", f77NativeLeg(84532, "7"))
	tree, byOp := outcomeTestTree(t, 84532, a, b)

	kept, err := NewOutcomeTree(tree, byOp, OutcomeTreeSigned)
	if err != nil {
		t.Fatal(err)
	}
	if kept.BundleID != tree.BundleID || len(kept.Members) != 2 || kept.Members[0].OperationID != a.OperationID {
		t.Fatalf("kept %+v", kept)
	}
	legs := kept.Members[0].CommittedLegs()
	if len(legs) != 2 || len(legs[1].Events) != 1 || legs[0].Call.Value.Int64() != 1000 {
		t.Fatalf("the kept legs are not the signed intent's: %+v", legs)
	}
	wantDeadline, _ := a.Deadline()
	if kept.Members[0].Deadline != wantDeadline.Unix() || kept.Members[0].SearchFrom != outcomeTestCommit.Add(-leafSpendMargin).Unix() {
		t.Fatalf("deadline %d search from %d", kept.Members[0].Deadline, kept.Members[0].SearchFrom)
	}

	store, err := NewOutcomeTreeStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Retain(kept); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(84532, tree.BundleID)
	if err != nil || !got.sameMembers(kept) {
		t.Fatalf("load: %v", err)
	}
	// A second write of the same tree in another role is the same tree: it is merged, never a second copy.
	again, err := NewOutcomeTree(tree, byOp, OutcomeTreeProved)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Retain(again); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.Load(84532, tree.BundleID); len(got.Roles) != 2 {
		t.Fatalf("roles %v", got.Roles)
	}
	if all, err := store.List(); err != nil || len(all) != 1 {
		t.Fatalf("list %d, %v", len(all), err)
	}
	if err := store.Release(84532, tree.BundleID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(84532, tree.BundleID); !errors.Is(err, ErrOutcomeTreeNotHeld) {
		t.Fatalf("a released tree is still held: %v", err)
	}
}

func TestAMemberWithoutItsSignedIntentIsNotKept(t *testing.T) {
	a := outcomeTestMember(t, 84532, "alpha", f77NativeLeg(84532, "1000"))
	a.Attestation = nil
	tree, byOp := outcomeTestTree(t, 84532, a)
	if _, err := NewOutcomeTree(tree, byOp, OutcomeTreeSigned); !errors.Is(err, ErrOutcome) || !strings.Contains(err.Error(), "user-signed intent") {
		t.Fatalf("a member without its signed intent was kept: %v", err)
	}
}

func TestAMemberWhoseLeafCommitsOtherCallsThanItsSignedIntentIsNotKept(t *testing.T) {
	a := outcomeTestMember(t, 84532, "alpha", f77NativeLeg(84532, "1000"))
	a.Legs[0].Value.SetInt64(999)
	tree, byOp := outcomeTestTree(t, 84532, a)
	if _, err := NewOutcomeTree(tree, byOp, OutcomeTreeSigned); err == nil || !strings.Contains(err.Error(), "not the calls its signed intent commits") {
		t.Fatalf("a leaf committing other calls than the signed intent was kept: %v", err)
	}
}

func TestAMemberWithoutADeadlineIsNotKeptYet(t *testing.T) {
	a := outcomeTestMember(t, 84532, "alpha", f77NativeLeg(84532, "1000"))
	a.CommitTime = time.Time{}
	tree, byOp := outcomeTestTree(t, 84532, a)
	if _, err := NewOutcomeTree(tree, byOp, OutcomeTreeSigned); !errors.Is(err, ErrOutcomeNotYet) {
		t.Fatalf("a member with no deadline: %v", err)
	}
}

func TestAKeptTreeIsNeverOverwrittenByAContradictingOne(t *testing.T) {
	a := outcomeTestMember(t, 84532, "alpha", f77NativeLeg(84532, "1000"))
	tree, byOp := outcomeTestTree(t, 84532, a)
	store, err := NewOutcomeTreeStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first, err := NewOutcomeTree(tree, byOp, OutcomeTreeSigned)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Retain(first); err != nil {
		t.Fatal(err)
	}
	a.CommitTime = a.CommitTime.Add(-time.Hour) // the same anchor, now stating another deadline
	second, err := NewOutcomeTree(tree, byOp, OutcomeTreeSigned)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Retain(second); !errors.Is(err, ErrOutcomeTreeContradiction) {
		t.Fatalf("a contradicting tree: %v", err)
	}
	if got, _ := store.Load(84532, tree.BundleID); !got.sameMembers(first) {
		t.Fatal("the kept tree was overwritten")
	}
}

func TestATamperedKeptTreeIsRefusedAndStopsTheStore(t *testing.T) {
	a := outcomeTestMember(t, 84532, "alpha", f77NativeLeg(84532, "1000"))
	tree, byOp := outcomeTestTree(t, 84532, a)
	dir := t.TempDir()
	store, err := NewOutcomeTreeStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	kept, err := NewOutcomeTree(tree, byOp, OutcomeTreeSigned)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Retain(kept); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, fmt.Sprintf("84532_%x.json", tree.BundleID))
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Another payee: the leaf no longer rebuilds.
	tampered := bytes.Replace(blob, []byte(strings.ToLower(f77Payee[2:])), []byte(strings.Repeat("ab", 20)), 1)
	if bytes.Equal(tampered, blob) {
		t.Fatal("the fixture did not tamper")
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(84532, tree.BundleID); err == nil || !strings.Contains(err.Error(), "rebuild") {
		t.Fatalf("a tampered tree was loaded: %v", err)
	}
	if _, err := NewOutcomeTreeStore(dir); err == nil {
		t.Fatal("a store holding a tampered tree opened")
	}
}

// The peers' side, end to end through the on-demand handler: the tree is on disk before the signature leaves, and
// without a store nothing is signed.
func TestAPeerKeepsTheTreeBeforeItSigns(t *testing.T) {
	withOutcomeSigningKey(t)
	p := outcomeTestMember(t, odChain, "alpha", f77NativeLeg(odChain, "1000"))
	s := odStack(t, odChain, p)
	in, err := p.LeafInput()
	if err != nil {
		t.Fatal(err)
	}
	tree, err := BuildBatchTree(odChain, []BatchLeafInput{in}, p.CommitHeight, testIncarnation)
	if err != nil {
		t.Fatal(err)
	}
	req := &OnDemandAttestationRequest{ChainID: odChain, OperationID: hex32(p.OperationID), BundleID: hex32(tree.BundleID)}

	if resp := s.HandleOnDemandAttestationRequest(req, odIdentity()); resp.SignatureHex != "" || !strings.Contains(resp.Error, "no outcome tree store") {
		t.Fatalf("signed with nowhere to keep the tree: %+v", resp)
	}

	store, err := NewOutcomeTreeStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.OutcomeTrees = store
	resp := s.HandleOnDemandAttestationRequest(req, odIdentity())
	if resp.SignatureHex == "" {
		t.Fatalf("an agreed batch was not signed: %+v", resp)
	}
	kept, err := store.Load(odChain, tree.BundleID)
	if err != nil {
		t.Fatalf("the signed tree was not kept: %v", err)
	}
	if kept.Roles[0] != OutcomeTreeSigned || kept.Members[0].OperationID != p.OperationID {
		t.Fatalf("kept %+v", kept)
	}
}

// withOutcomeSigningKey loads a BLS key and configures the validator set, so a handler reaches signing.
func withOutcomeSigningKey(t *testing.T) *bls.KeyManager {
	t.Helper()
	km, err := bls.InitializeValidatorBLSKey("validator-1", filepath.Join(t.TempDir(), "bls.hex"), bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CERTEN_VALIDATOR_SET_ADDRESSES", "0x1111111111111111111111111111111111111111,0x2222222222222222222222222222222222222222,0x3333333333333333333333333333333333333333")
	t.Setenv("CERTEN_VALIDATOR_SET_POWERS", "100,100,100")
	t.Setenv("CERTEN_VALIDATOR_SET_THRESHOLD_NUM", "2")
	t.Setenv("CERTEN_VALIDATOR_SET_THRESHOLD_DEN", "3")
	contracts.ResetV6_1ValidatorSetRootCache()
	t.Cleanup(contracts.ResetV6_1ValidatorSetRootCache)
	return km
}

// The same on the period path: the tree the peer cut and matched is kept before it signs.
func TestAPeriodPeerKeepsTheTreeBeforeItSigns(t *testing.T) {
	withOutcomeSigningKey(t)
	s := stackForChain(t, 11155111)
	for _, id := range []string{"alpha", "beta"} {
		if err := s.Mempool.Add(outcomeTestMember(t, 11155111, id, f77NativeLeg(11155111, "1000"))); err != nil {
			t.Fatal(err)
		}
	}
	cutoff := uint64(105) - uint64(105)%DefaultBatchPeriodBlocks
	bundle := derivedBundle(t, s, cutoff)
	req := &BatchAttestationRequest{ChainID: 11155111, CutoffHeight: cutoff, BundleID: bundle}
	if resp := s.HandleBatchAttestationRequest(req, attesterID()); resp.SignatureHex != "" || !strings.Contains(resp.Error, "no outcome tree store") {
		t.Fatalf("signed with nowhere to keep the tree: %+v", resp)
	}
	store, err := NewOutcomeTreeStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.OutcomeTrees = store
	resp := s.HandleBatchAttestationRequest(req, attesterID())
	if resp.SignatureHex == "" {
		t.Fatalf("an agreed batch was not signed: %+v", resp)
	}
	b, _ := parseHex32(bundle)
	kept, err := store.Load(11155111, b)
	if err != nil || len(kept.Members) != 2 {
		t.Fatalf("the signed tree was not kept: %v", err)
	}
}

// The leader's side: the prover keeps the tree it proves through the stack, from the members its mempool holds.
func TestTheLeaderKeepsTheTreeItProvesFromItsMempool(t *testing.T) {
	p := outcomeTestMember(t, odChain, "alpha", f77NativeLeg(odChain, "1000"))
	s := odStack(t, odChain, p)
	store, err := NewOutcomeTreeStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.OutcomeTrees = store
	tree, _ := outcomeTestTree(t, odChain, p)
	if err := s.RetainTree(tree, OutcomeTreeProved); err != nil {
		t.Fatal(err)
	}
	if kept, err := store.Load(odChain, tree.BundleID); err != nil || kept.Roles[0] != OutcomeTreeProved {
		t.Fatalf("the proved tree was not kept: %v", err)
	}
	stranger := outcomeTestMember(t, odChain, "beta", f77NativeLeg(odChain, "5"))
	other, _ := outcomeTestTree(t, odChain, stranger)
	if err := s.RetainTree(other, OutcomeTreeProved); !errors.Is(err, ErrOutcomeTreeNotHeld) {
		t.Fatalf("a tree whose member is not held: %v", err)
	}
}
