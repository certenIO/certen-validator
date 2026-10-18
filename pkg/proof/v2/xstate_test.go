// Copyright 2026 Certen Protocol

package proofv2_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/ledger"
	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"github.com/certen/independant-validator/pkg/proof/v2/xworld"
)

// RB9-F5 package F5-3 (GoA-state): the accounting of every write to the network AND the globals accounts (V-E A2(b)), the set check that
// reports verified when every write is accounted (A3), the chain identity of an anchored document (A1b, F-VE-2) and the freshness of the
// checkpoint a document builds on (F-VE-1). The shared vectors (testdata/certify1) pin the same verdicts for the TypeScript verifier.

func glob(a bool, kind string) xworld.ChainItem { return xworld.ChainItem{Anchored: a, Update: kind} }

// acctChain is the set-changing chain of the accounted vectors: the globals are rewritten (B, then the genesis content: A -> B -> A) and the
// network to its version 2 (a fourth validator).
func acctChain() *xworld.Chain {
	return &xworld.Chain{Items: []xworld.ChainItem{glob(true, xworld.UpdateGlobalsB), glob(true, xworld.UpdateGenesisGlobals), glob(true, xworld.UpdateNetworkV2)},
		Final: xworld.ChainItem{Anchored: true}}
}

func verify21(t *testing.T, b *xworld.Built) (*proofv2.Report, error) {
	t.Helper()
	return proofv2.Verify21FromGenesis(b.Evidence, b.Archive, b.Inputs, b.Pin)
}

// V-E A3: a set that changed in the minor run, with every write accounted, is verified (and the proven accounts hold 2 and 3 entries).
func TestAccountedSetChangeIsVerified(t *testing.T) {
	b := buildChain(t, acctChain())
	if h, _ := b.Evidence.Check.Set.MainChainHeight(); h != 2 {
		t.Fatalf("network main chain height %d, want 2", h)
	}
	if h, _ := b.Evidence.Check.Set.GlobalsMainChainHeight(); h != 3 {
		t.Fatalf("globals main chain height %d, want 3", h)
	}
	rep, err := verify21(t, b)
	if err != nil {
		t.Fatal(err)
	}
	if rep.SetVerdict != proof.VerdictVerified || rep.Validators != 4 || rep.Threshold != 3 {
		t.Fatalf("set %s with %d validators (threshold %d), want verified with 4 (3)", rep.SetVerdict, rep.Validators, rep.Threshold)
	}
}

// V-E A3: the set proof alone still reports a changed set as asserted, for every caller that does not account the writes (evidence 2.0).
func TestSetProofWithoutAccountedHistoryStaysAsserted(t *testing.T) {
	b := buildChain(t, acctChain())
	set := b.Evidence.Check.Set
	derived, thr, err := set.DerivedSet()
	if err != nil {
		t.Fatal(err)
	}
	pin := hex.EncodeToString(b.Pin[:])
	root, err := set.ProvenRoot()
	if err != nil {
		t.Fatal(err)
	}
	in := proof.VerifyInput{AssertedSet: derived, AssertedThreshold: thr, BoundStateTreeAnchor: root, PinnedIncarnation: &pin}
	if v, err := set.Verify(in); err != nil || v != proof.VerdictValidatorSetAsserted {
		t.Fatalf("verdict %s (%v), want validator_set_asserted", v, err)
	}
	in.AccountedHistory = true
	if v, err := set.Verify(in); err != nil || v != proof.VerdictVerified {
		t.Fatalf("with the history accounted: verdict %s (%v), want verified", v, err)
	}
}

// V-E A2(b): the first globals write of an A -> B -> A sequence is left out of the document. The globals the walk derives equal the proven
// ones (the genesis content again), so only the count shows it: refused by name with the account, the block and the two counts.
func TestOmittedGlobalsUpdateRefused(t *testing.T) {
	c := &xworld.Chain{Items: []xworld.ChainItem{glob(true, xworld.UpdateGlobalsB), glob(true, xworld.UpdateGenesisGlobals)}, Final: xworld.ChainItem{Anchored: true}, Omit: []int{0}}
	b := buildChain(t, c)
	if got := len(b.Evidence.Certify); got != 2 {
		t.Fatalf("the document keeps %d certify items, want 2 (one omitted, one closing)", got)
	}
	_, err := verify21(t, b)
	wantCertifyState(t, err, proofv2.StateCertifyWindowUnaccounted, "globals", "300", "2", "3")

	// The same chain without the omission is accounted.
	c.Omit = nil
	if _, err := verify21(t, buildChain(t, c)); err != nil {
		t.Fatalf("the complete chain is refused: %v", err)
	}
}

// V-E A2(b): the network account is counted the same way, with the same named state.
func TestUnaccountedNetworkWriteRefused(t *testing.T) {
	b := buildChain(t, &xworld.Chain{Items: []xworld.ChainItem{glob(true, xworld.UpdateNetworkV2)}, Final: xworld.ChainItem{Anchored: true}})
	// The document's proven network account says it was rewritten twice: the walk applied one write.
	b.Evidence.Check.Set.Network.Chains[0].Count = 3
	_, err := verify21(t, b)
	if err == nil {
		t.Fatal("verified")
	}
	if !strings.Contains(err.Error(), "set check") && !strings.Contains(err.Error(), proofv2.StateCertifyWindowUnaccounted) {
		t.Fatalf("refused with %v", err)
	}
}

// V-E A1b / F-VE-2: the chain identity. A document with links must carry the receipt from the pinned genesis root chain anchor to the
// certified root, and each way of not carrying it is a named state at the index "genesis".
func TestGenesisLinkIsRequiredAndChecked(t *testing.T) {
	good := buildChain(t, &xworld.Chain{Final: xworld.ChainItem{Anchored: true}})
	if good.Evidence.GenesisLink == "" {
		t.Fatal("the world carries no genesis link")
	}
	if _, err := verify21(t, good); err != nil {
		t.Fatal(err)
	}
	absent := buildChain(t, &xworld.Chain{Final: xworld.ChainItem{Anchored: true}})
	absent.Evidence.GenesisLink = ""
	_, err := verify21(t, absent)
	wantCertifyState(t, err, proofv2.StateCertifyLinkMissing, "genesis")

	garbage := buildChain(t, &xworld.Chain{Final: xworld.ChainItem{Anchored: true}})
	garbage.Evidence.GenesisLink = "zz"
	_, err = verify21(t, garbage)
	wantCertifyState(t, err, proofv2.StateCertifyLinkInvalid, "genesis")

	// A chain of another incarnation that shares the pinned genesis records and the genesis set, complete and validly signed, with its own
	// genesis link: it does not start at the pinned genesis root chain anchor.
	foreign := buildChain(t, &xworld.Chain{Final: xworld.ChainItem{Anchored: true}, Start: xworld.ForeignGenesis()})
	_, err = verify21(t, foreign)
	wantCertifyState(t, err, proofv2.StateCertifyLinkStart, "genesis")
}

// A document that claims 2.0 does not read the member: whatever it holds, the 2.0 entry point's verdict is not a genesis link state (the shared
// vector genesis-link-member-in-an-evidence-2.0-document pins the same for a document that verifies).
func TestGenesisLinkIsNotReadIn20(t *testing.T) {
	b := buildChain(t, &xworld.Chain{Final: xworld.ChainItem{Anchored: true}})
	b.Evidence.Version = proofv2.Version
	b.Evidence.GenesisLink = "not even hex"
	_, err := proofv2.VerifyFromGenesis(b.Evidence, b.Archive, b.Inputs, b.Pin)
	if err == nil {
		t.Fatal("verified")
	}
	var cs *proofv2.CertifyState
	if errors.As(err, &cs) {
		t.Fatalf("a 2.0 document is refused with the certify state %v", cs)
	}
}

// V-E F-VE-1: a 2.1 document that builds on a checkpoint more than CheckpointLag behind the newest the chain holds is refused by name; one at
// the edge of the lag is judged on its merits.
func TestCheckpointStaleIsRefusedForEvidence21(t *testing.T) {
	b := buildChain(t, &xworld.Chain{Final: xworld.ChainItem{Anchored: true}})
	g, set, err := proofv2.AcceptSpineGenesis(b.Inputs, b.Pin, 1)
	if err != nil {
		t.Fatal(err)
	}
	l := &ledger.AccumulateSpineLog{Genesis: g, Sets: []ledger.AccumulateSpineSet{set}}
	cps, sets, err := proofv2.ExtendSpine(l, b.Archive.Majors, 2)
	if err != nil {
		t.Fatal(err)
	}
	l.Checkpoints, l.Sets = cps, append(l.Sets, sets...)
	if _, err := proofv2.VerifyEvidence21FromSpine(b.Evidence, l, b.Pin); err != nil {
		t.Fatalf("a document on the newest checkpoint: %v", err)
	}
	// The chain goes on: copies of the checkpoint stand for later majors (the stale check is about the count, before the checkpoints are read).
	for n := uint64(2); n <= 1+proofv2.CheckpointLag; n++ {
		c := cps[0]
		c.Major = n
		l.Checkpoints = append(l.Checkpoints, c)
	}
	if _, err := proofv2.VerifyEvidence21FromSpine(b.Evidence, l, b.Pin); err != nil {
		t.Fatalf("a document exactly CheckpointLag majors behind the newest is refused: %v", err)
	}
	c := cps[0]
	c.Major = uint64(len(l.Checkpoints)) + 1
	l.Checkpoints = append(l.Checkpoints, c)
	_, err = proofv2.VerifyEvidence21FromSpine(b.Evidence, l, b.Pin)
	wantCertifyState(t, err, proofv2.StateCheckpointStale, "1", "4", "2")
}

// V-E A2(b), gate: a checkpoint carries the globals count only when consensus asks for it (from the rules v15 activation), and the field is
// omitted when empty, so every checkpoint a v13 or v14 chain holds keeps its bytes, and so does one recorded after the activation on a chain
// whose globals were never rewritten.
func TestCheckpointGlobalsFieldIsOmittedWhenEmptyAndGated(t *testing.T) {
	b := buildChain(t, &xworld.Chain{Final: xworld.ChainItem{Anchored: true}})
	g, set, err := proofv2.AcceptSpineGenesis(b.Inputs, b.Pin, 1)
	if err != nil {
		t.Fatal(err)
	}
	l := &ledger.AccumulateSpineLog{Genesis: g, Sets: []ledger.AccumulateSpineSet{set}}
	plain, _, err := proofv2.ExtendSpine(l, b.Archive.Majors, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, gate := range []bool{false, true} {
		got, _, err := proofv2.ExtendSpineCounting(l, b.Archive.Majors, 2, gate)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := json.Marshal(plain)
		z, _ := json.Marshal(got)
		if string(a) != string(z) {
			t.Fatalf("gate %v: the checkpoints differ from ExtendSpine's:\n%s\n%s", gate, a, z)
		}
		if strings.Contains(string(z), "globals_updates") {
			t.Fatalf("gate %v: an empty count is encoded: %s", gate, z)
		}
	}
	// A checkpoint that holds a count restores a spine that continues it.
	c := plain[0]
	c.GlobalsUpdates = 5
	l.Checkpoints = []ledger.AccumulateSpineCheckpoint{c}
	sp, err := proofv2.SpineAt(l, 1)
	if err != nil {
		t.Fatal(err)
	}
	if sp.GlobalsUpdates() != 5 {
		t.Fatalf("the restored spine counts %d globals writes, want 5", sp.GlobalsUpdates())
	}
	if raw, _ := json.Marshal(c); !strings.Contains(string(raw), `"globals_updates":5`) {
		t.Fatalf("the count is not encoded: %s", raw)
	}
}

// V-E A2(b): the spine counts the writes to the globals account it applies, beside the network's.
func TestSpineCountsGlobalsWrites(t *testing.T) {
	b := buildChain(t, &xworld.Chain{Items: []xworld.ChainItem{glob(true, xworld.UpdateGlobalsB), glob(true, xworld.UpdateGenesisGlobals)}, Final: xworld.ChainItem{Anchored: true}})
	sp, recs, links := spineAt1(t, b)
	if sp.GlobalsUpdates() != 0 || sp.NetworkUpdates() != 0 {
		t.Fatalf("a spine at the first major block counts %d globals and %d network writes", sp.GlobalsUpdates(), sp.NetworkUpdates())
	}
	for i := 0; i < 2; i++ {
		if err := sp.AdvanceAnchored(recs[i], links[i]); err != nil {
			t.Fatal(err)
		}
	}
	if sp.GlobalsUpdates() != 2 || sp.NetworkUpdates() != 0 {
		t.Fatalf("after two globals writes: %d globals and %d network writes counted", sp.GlobalsUpdates(), sp.NetworkUpdates())
	}
}
