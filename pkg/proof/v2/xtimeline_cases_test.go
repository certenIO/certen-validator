// Copyright 2026 Certen Protocol

package proofv2_test

import (
	"strings"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"github.com/certen/independant-validator/pkg/proof/v2/xworld"
)

func refusedWith(t *testing.T, err error, code, partition string, block uint64) {
	t.Helper()
	if err == nil {
		t.Fatalf("accepted; want %s{%s,%d}", code, partition, block)
	}
	named(t, err, code, partition, block)
}

// Step 2: the history's entry hashes must fold to the proven main chain root. An entry changed, an entry removed, an entry inserted
// and the entries reordered each fail the fold - by name, at the page's partition and block.
func TestTimelineHistoryEntryTamperedFailsTheFold(t *testing.T) {
	script := xworld.Timeline{Events: []xworld.PageEvent{{Block: 40, Add: []string{"K1"}}, {Block: 50, Credits: true}},
		Sigs: []xworld.SigEvent{{Key: "K0", Version: 2, Block: xworld.HopBlock}}}
	if _, err := tl(t, script, nil); err != nil {
		t.Fatalf("the untampered world must verify: %v", err)
	}
	for name, mut := range map[string]func(h *proofv2.PageHistory){
		// the credit burn's slot holds the key addition's transaction again: a valid transaction, not the one the chain holds
		"tampered":      func(h *proofv2.PageHistory) { h.Entries[2] = h.Entries[1] },
		"removed":       func(h *proofv2.PageHistory) { h.Entries = append(h.Entries[:1], h.Entries[2:]...) },
		"reordered":     func(h *proofv2.PageHistory) { h.Entries[1], h.Entries[2] = h.Entries[2], h.Entries[1] },
		"inserted":      func(h *proofv2.PageHistory) { h.Entries = append(h.Entries, h.Entries[2]) },
		"index removed": func(h *proofv2.PageHistory) { h.Index = h.Index[:len(h.Index)-1] },
	} {
		t.Run(name, func(t *testing.T) {
			_, err := tl(t, script, func(ev *proofv2.Evidence) { mut(ev.Pages[at(t, ev, xworld.BankPage1)].History) })
			refusedWith(t, err, proofv2.StateHistoryFoldMismatch, "BVN2", xworld.BlockBVN2)
		})
	}
}

// Step 3: the replay of the folded history must end in the proven page.
func TestTimelineReplayMustEndInTheProvenPage(t *testing.T) {
	script := xworld.Timeline{Genesis: []string{"K0", "K1"}, Events: []xworld.PageEvent{{Block: 68, Remove: []string{"K1"}}}, ProvenHeadKeys: []string{"K0", "K1"}}
	_, err := tl(t, script, nil)
	refusedWith(t, err, proofv2.StateHistoryHeadMismatch, "BVN2", xworld.BlockBVN2)
}

// S3 "as those pages were at the time": a key removed after its signature arrived and before B_Y still counts - judged at arrival,
// the page held it; at B_Y it does not.
func TestTimelineKeyRemovedAfterArrivalStillCounts(t *testing.T) {
	rep, err := tl(t, xworld.Timeline{Events: []xworld.PageEvent{{Block: 68, Add: []string{"K1"}, Remove: []string{"K0"}}}}, nil)
	if err != nil {
		t.Fatalf("a signature by a key the page held when it arrived must count: %v", err)
	}
	if rep.Arrivals[0].Block != xworld.HopBlock {
		t.Fatalf("arrival %+v", rep.Arrivals)
	}
}

// ... and a key added after the signature arrived must NOT count, although the page proven at B_Y holds it.
func TestTimelineKeyAddedAfterArrivalDoesNotCount(t *testing.T) {
	_, err := tl(t, xworld.Timeline{
		Events: []xworld.PageEvent{{Block: 68, Add: []string{"K1"}}},
		Sigs:   []xworld.SigEvent{{Key: "K1", Version: 1, Block: xworld.HopBlock}},
	}, nil)
	refusedWith(t, err, proofv2.StateVoteNotReproduced, "BVN1", xworld.BlockBVN1)
	if !strings.Contains(err.Error(), "holds its key") {
		t.Fatalf("refused for another reason than the key not held at arrival: %v", err)
	}
}

// A threshold lowered between arrival and B_Y does not make a vote that arrival could not have produced; one raised after it does
// not undo a vote that arrival produced.
func TestTimelineThresholdChangedBetweenArrivalAndBYIsJudgedAtArrival(t *testing.T) {
	lowered := xworld.Timeline{Genesis: []string{"K0", "K1"}, Events: []xworld.PageEvent{{Block: 20, Threshold: 2}, {Block: 68, Threshold: 1}},
		Sigs: []xworld.SigEvent{{Key: "K0", Version: 2, Block: xworld.HopBlock}}}
	_, err := tl(t, lowered, nil)
	refusedWith(t, err, proofv2.StateVoteNotReproduced, "BVN1", xworld.BlockBVN1)
	if !strings.Contains(err.Error(), "reaches no vote") {
		t.Fatalf("refused for another reason than the threshold at arrival: %v", err)
	}

	raised := xworld.Timeline{Genesis: []string{"K0", "K1"}, Events: []xworld.PageEvent{{Block: 68, Threshold: 2}}}
	if _, err := tl(t, raised, nil); err != nil {
		t.Fatalf("a threshold raised after the vote was produced must not undo it: %v", err)
	}
}

// The key signature names the signer version it was made at; the page it arrives at must hold that version (sig_user.go:249-252).
func TestTimelineVersionReplacedBeforeArrivalRefusesTheSignature(t *testing.T) {
	_, err := tl(t, xworld.Timeline{
		Events: []xworld.PageEvent{{Block: 60, Add: []string{"K1"}}},
		Sigs:   []xworld.SigEvent{{Key: "K0", Version: 1, Block: xworld.HopBlock}},
	}, nil)
	refusedWith(t, err, proofv2.StateVoteNotReproduced, "BVN1", xworld.BlockBVN1)
	if !strings.Contains(err.Error(), "did not hold during that block") {
		t.Fatalf("refused for another reason than the version: %v", err)
	}
	if _, err := tl(t, xworld.Timeline{
		Events: []xworld.PageEvent{{Block: 60, Add: []string{"K1"}}},
		Sigs:   []xworld.SigEvent{{Key: "K0", Version: 2, Block: xworld.HopBlock}},
	}, nil); err != nil {
		t.Fatalf("a signature at the version the page held must count: %v", err)
	}
}

// The recorded Origin and Vote must equal the re-evaluation; readiness is required.
func TestTimelineRecordedVoteMustEqualTheReevaluation(t *testing.T) {
	for name, mut := range map[string]func(ev *proofv2.Evidence){
		"vote": func(ev *proofv2.Evidence) { ev.Votes[0].Vote = "reject" },
		"origin": func(ev *proofv2.Evidence) {
			ev.Votes[0].Origin = xworld.BankPage2
			p := &ev.Pages[at(t, ev, xworld.BankPage2)]
			p.Roles = append(p.Roles, proofv2.RoleVoter) // so the roles are consistent and the refusal is the vote's
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := tl(t, xworld.Timeline{}, mut)
			refusedWith(t, err, proofv2.StateVoteNotReproduced, "BVN1", xworld.BlockBVN1)
		})
	}
}

// Two keys on a page whose threshold is 2: the cause chain carries the last signature, the other counted signature is carried and
// its arrival derived too. With one of them dropped the vote is not reproduced.
func TestTimelineCountedSignaturesReachTheThreshold(t *testing.T) {
	two := xworld.Timeline{Genesis: []string{"K0", "K1"}, Events: []xworld.PageEvent{{Block: 20, Threshold: 2}},
		Sigs: []xworld.SigEvent{{Key: "K0", Version: 2, Block: 62}, {Key: "K1", Version: 2, Block: 66}}}
	rep, err := tl(t, two, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Arrivals) != 2 || rep.Arrivals[0].Block != 66 || rep.Arrivals[1].Block != 62 {
		t.Fatalf("arrivals %+v", rep.Arrivals)
	}
	_, err = tl(t, two, func(ev *proofv2.Evidence) { ev.Votes[0].Counted = nil })
	refusedWith(t, err, proofv2.StateVoteNotReproduced, "BVN1", xworld.BlockBVN1)
}

// The arrival block is derived, never claimed: a claimed block that differs, a missing previous index entry, one that does not
// precede the entry, and a position lied about are each refused by name.
func TestTimelineArrivalIsDerivedNeverClaimed(t *testing.T) {
	cases := map[string]func(ev *proofv2.Evidence){
		"claimed block":           func(ev *proofv2.Evidence) { ev.Votes[0].Hops[0].Block = xworld.HopBlock - 1 },
		"no previous index entry": func(ev *proofv2.Evidence) { ev.Votes[0].Hops[0].Arrival.Before = nil },
		"previous entry is the at entry": func(ev *proofv2.Evidence) {
			a := ev.Votes[0].Hops[0].Arrival
			b := a.At
			a.Before = &b
		},
		"position lied about": func(ev *proofv2.Evidence) { ev.Votes[0].Hops[0].Arrival.At.Position++ },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := tl(t, xworld.Timeline{}, mut)
			refusedWith(t, err, proofv2.StateArrivalUnproven, "BVN2", xworld.BlockBVN2)
		})
	}
}

// HoldUntil: the block that produced the vote is the block that released it, read from the SequencedMessage's entry in the source
// partition's synthetic ledger. Without that proof the vote is the named state g1_vote_held; a vote produced before its cause arrived
// is refused.
func TestTimelineHeldVoteIsJudgedAtItsReleaseBlock(t *testing.T) {
	rep, err := tl(t, xworld.Timeline{ProduceBlock: 66}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Unproven) != 0 {
		t.Fatalf("a vote whose production block is established leaves %v unproven", codes(rep))
	}
	var produced uint64
	for _, a := range rep.Arrivals {
		if a.Kind == "produced" {
			produced = a.Block
		}
	}
	if produced != 66 {
		t.Fatalf("the vote was produced in block %d, want 66 (arrivals %+v)", produced, rep.Arrivals)
	}
	_, err = tl(t, xworld.Timeline{ProduceBlock: xworld.HopBlock - 1}, nil)
	refusedWith(t, err, proofv2.StateBlockBeforeArrival, "BVN2", xworld.BlockBVN2)
}

// Without the transaction the votes are not re-evaluated, and the report says so by name: never a verified S3 shaped like one.
func TestTimelineWithoutTheTransactionNamesWhatIsUnproven(t *testing.T) {
	rep, err := tl(t, xworld.Timeline{OmitTransaction: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := codes(rep); strings.Join(got, ",") != proofv2.StateCompletenessUnproven {
		t.Fatalf("unproven %v", got)
	}
	_, err = tl(t, xworld.Timeline{}, func(ev *proofv2.Evidence) { ev.TxHash = strings.Repeat("00", 32) })
	if err == nil {
		t.Fatal("a transaction that is not the one the receipt names was accepted")
	}
}

// Delegated hops (design D3): the delegating page is judged at the authority signature's arrival - it must hold the delegate entry
// THEN (a later removal does not undo the vote; an earlier one means the vote could not have been counted) and, unlike a key
// signature, the hop takes the page's then-current version, so a version bump before arrival does not refuse it.
func TestTimelineDelegatedHops(t *testing.T) {
	rep, err := tl(t, xworld.Timeline{Delegated: true}, nil)
	if err != nil {
		t.Fatalf("a delegated vote through a page holding the delegate entry must verify: %v", err)
	}
	if len(rep.Arrivals) != 2 || rep.Arrivals[0].Account != xworld.BankPage2 || rep.Arrivals[0].Block != 66 ||
		rep.Arrivals[1].Account != xworld.DelePage1 || rep.Arrivals[1].Block != 64 {
		t.Fatalf("arrivals %+v", rep.Arrivals)
	}
	if _, err := tl(t, xworld.Timeline{Delegated: true, DelegatorEvents: []xworld.PageEvent{{Block: 68, Add: []string{"K1"}, RemoveDelegate: true}}}, nil); err != nil {
		t.Fatalf("a delegate entry removed after the delegated vote arrived must not undo it: %v", err)
	}
	if _, err := tl(t, xworld.Timeline{Delegated: true, DelegatorEvents: []xworld.PageEvent{{Block: 60, Add: []string{"K1"}}}}, nil); err != nil {
		t.Fatalf("a delegated hop takes the page's current version; a bump before arrival must not refuse it: %v", err)
	}
	_, err = tl(t, xworld.Timeline{Delegated: true, DelegatorEvents: []xworld.PageEvent{{Block: 60, Add: []string{"K1"}, RemoveDelegate: true}}}, nil)
	refusedWith(t, err, proofv2.StateVoteNotReproduced, "BVN1", xworld.BlockBVN1)
	if !strings.Contains(err.Error(), "delegating") {
		t.Fatalf("refused for another reason than the missing delegate entry: %v", err)
	}
}
