// Copyright 2026 Certen Protocol

package xworld

import (
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// Cases2 is the certified-timeline suite (RB9 Phase C1b-1; testdata/xpartition2b): documents of the timeline world, each with the
// verdict every verifier must reach. The first suite (Cases, testdata/xpartition2) is untouched; these are new files under their own
// manifest. A verified document lists the codes its report must carry; a refusal names the state with the partition and block it
// was judged at.
func Cases2() []Case {
	hist := func(f func(h *proofv2.PageHistory)) func(ev *proofv2.Evidence) {
		return func(ev *proofv2.Evidence) { f(ev.Pages[idx(ev, BankPage1)].History) }
	}
	withEvents := Timeline{Events: []PageEvent{{Block: 40, Add: []string{"K1"}}, {Block: 50, Credits: true}},
		Sigs: []SigEvent{{Key: "K0", Version: 2, Block: HopBlock}}}
	held := proofv2.StateVoteHeld
	c := proofv2.StateCompletenessUnproven
	return []Case{
		{Name: "timeline-valid", Description: "the history folds to the proven main chain, the key signature's arrival block is derived from the signature-index chain, the vote is reproduced; the vote's production block is not established", Expect: verified,
			Unproven: []string{held}, Opts: Options{Timeline: &Timeline{}}},
		{Name: "timeline-history-with-update-and-credit", Description: "a page that gained a key and burned credits before the signature arrived: three history entries, two index entries", Expect: verified,
			Unproven: []string{held}, Opts: Options{Timeline: &withEvents}},
		{Name: "timeline-key-removed-after-arrival", Description: "the signing key was removed in block 68, after the signature arrived in block 65 and before B_Y: it still counts", Expect: verified,
			Unproven: []string{held}, Opts: Options{Timeline: &Timeline{Events: []PageEvent{{Block: 68, Add: []string{"K1"}, Remove: []string{"K0"}}}}}},
		{Name: "timeline-threshold-raised-after-arrival", Description: "the threshold was raised to 2 in block 68, after a one-key vote was produced: the vote stands", Expect: verified,
			Unproven: []string{held}, Opts: Options{Timeline: &Timeline{Genesis: []string{"K0", "K1"}, Events: []PageEvent{{Block: 68, Threshold: 2}}}}},
		{Name: "timeline-two-counted-signatures", Description: "a threshold-2 page: the cause signature and one other counted signature, both with derived arrival blocks", Expect: verified,
			Unproven: []string{held}, Opts: Options{Timeline: &Timeline{Genesis: []string{"K0", "K1"}, Events: []PageEvent{{Block: 20, Threshold: 2}},
				Sigs: []SigEvent{{Key: "K0", Version: 2, Block: 62}, {Key: "K1", Version: 2, Block: 66}}}}},
		{Name: "timeline-vote-released-later", Description: "the vote was produced in block 66 (a HoldUntil release after the signature arrived in block 65), established by its SequencedMessage's entry in the synthetic ledger", Expect: verified,
			Opts: Options{Timeline: &Timeline{ProduceBlock: 66}}},
		{Name: "timeline-delegated-vote", Description: "the vote is cast through a delegation: the key signature on the delegate book's page (BVN3, block 64), the delegate's authority signature on BankPage2 (BVN2, block 66), which holds the delegate entry; the book's vote is decided by BankPage2", Expect: verified,
			Unproven: []string{held}, Opts: Options{Timeline: &Timeline{Delegated: true}}},
		{Name: "timeline-delegated-entry-removed-after-arrival", Description: "the delegating page dropped its delegate entry in block 68, after the delegated vote arrived in block 66: the vote stands, and the delegate book is still in the governing set", Expect: verified,
			Unproven: []string{held}, Opts: Options{Timeline: &Timeline{Delegated: true, DelegatorEvents: []PageEvent{{Block: 68, Add: []string{"K1"}, RemoveDelegate: true}}}}},
		{Name: "timeline-delegated-page-version-bumped", Description: "the delegating page became version 2 in block 60: a delegated hop takes the page's then-current version, so it still counts", Expect: verified,
			Unproven: []string{held}, Opts: Options{Timeline: &Timeline{Delegated: true, DelegatorEvents: []PageEvent{{Block: 60, Add: []string{"K1"}}}}}},
		{Name: "timeline-without-transaction", Description: "no transaction is carried, so the votes are not re-evaluated: a named state, not a verified S3", Expect: verified,
			Unproven: []string{c}, Opts: Options{Timeline: &Timeline{OmitTransaction: true}}},

		{Name: "timeline-history-entry-tampered", Description: "a history entry replaced by another valid transaction: the entries do not fold to the proven main chain", Expect: refused,
			State: proofv2.StateHistoryFoldMismatch, Partition: "BVN2", Block: BlockBVN2, Opts: Options{Timeline: &withEvents},
			Mutate: hist(func(h *proofv2.PageHistory) { h.Entries[2] = h.Entries[1] })},
		{Name: "timeline-history-entry-removed", Description: "a history entry removed", Expect: refused,
			State: proofv2.StateHistoryFoldMismatch, Partition: "BVN2", Block: BlockBVN2, Opts: Options{Timeline: &withEvents},
			Mutate: hist(func(h *proofv2.PageHistory) { h.Entries = append(h.Entries[:1], h.Entries[2:]...) })},
		{Name: "timeline-history-index-entry-removed", Description: "the last main-index entry removed: the index does not fold to the proven main-index chain", Expect: refused,
			State: proofv2.StateHistoryFoldMismatch, Partition: "BVN2", Block: BlockBVN2, Opts: Options{Timeline: &withEvents},
			Mutate: hist(func(h *proofv2.PageHistory) { h.Index = h.Index[:len(h.Index)-1] })},
		{Name: "timeline-replay-ends-elsewhere", Description: "the folded history removes K1 but the page proven at B_Y still holds it", Expect: refused,
			State: proofv2.StateHistoryHeadMismatch, Partition: "BVN2", Block: BlockBVN2,
			Opts: Options{Timeline: &Timeline{Genesis: []string{"K0", "K1"}, Events: []PageEvent{{Block: 68, Remove: []string{"K1"}}}, ProvenHeadKeys: []string{"K0", "K1"}}}},
		{Name: "timeline-key-added-after-arrival", Description: "the signing key was added in block 68, after the signature claimed to arrive in block 65: it must not count although the page at B_Y holds it", Expect: refused,
			State: proofv2.StateVoteNotReproduced, Partition: "BVN1", Block: BlockBVN1,
			Opts: Options{Timeline: &Timeline{Events: []PageEvent{{Block: 68, Add: []string{"K1"}}}, Sigs: []SigEvent{{Key: "K1", Version: 1, Block: HopBlock}}}}},
		{Name: "timeline-threshold-lowered-after-arrival", Description: "the threshold of a 2-key page was lowered to 1 in block 68: one signature at block 65 did not make a vote", Expect: refused,
			State: proofv2.StateVoteNotReproduced, Partition: "BVN1", Block: BlockBVN1,
			Opts: Options{Timeline: &Timeline{Genesis: []string{"K0", "K1"}, Events: []PageEvent{{Block: 20, Threshold: 2}, {Block: 68, Threshold: 1}},
				Sigs: []SigEvent{{Key: "K0", Version: 2, Block: HopBlock}}}}},
		{Name: "timeline-version-replaced-before-arrival", Description: "the page became version 2 in block 60: a version-1 signature arriving in block 65 is not accepted", Expect: refused,
			State: proofv2.StateVoteNotReproduced, Partition: "BVN1", Block: BlockBVN1,
			Opts: Options{Timeline: &Timeline{Events: []PageEvent{{Block: 60, Add: []string{"K1"}}}}}},
		{Name: "timeline-vote-value-disagrees", Description: "the recorded vote is reject, the re-evaluation reaches accept", Expect: refused,
			State: proofv2.StateVoteNotReproduced, Partition: "BVN1", Block: BlockBVN1, Opts: Options{Timeline: &Timeline{}},
			Mutate: func(ev *proofv2.Evidence) { ev.Votes[0].Vote = "reject" }},
		{Name: "timeline-vote-origin-disagrees", Description: "the recorded origin is the book's second page, the re-evaluation decides it with the first", Expect: refused,
			State: proofv2.StateVoteNotReproduced, Partition: "BVN1", Block: BlockBVN1, Opts: Options{Timeline: &Timeline{}},
			Mutate: func(ev *proofv2.Evidence) {
				ev.Votes[0].Origin = BankPage2
				p := &ev.Pages[idx(ev, BankPage2)]
				p.Roles = append(p.Roles, proofv2.RoleVoter)
			}},
		{Name: "timeline-counted-signature-dropped", Description: "a threshold-2 page's vote with its second counted signature left out", Expect: refused,
			State: proofv2.StateVoteNotReproduced, Partition: "BVN1", Block: BlockBVN1,
			Opts: Options{Timeline: &Timeline{Genesis: []string{"K0", "K1"}, Events: []PageEvent{{Block: 20, Threshold: 2}},
				Sigs: []SigEvent{{Key: "K0", Version: 2, Block: 62}, {Key: "K1", Version: 2, Block: 66}}}},
			Mutate: func(ev *proofv2.Evidence) { ev.Votes[0].Counted = nil }},
		{Name: "timeline-arrival-block-claimed", Description: "the hop claims block 64; the signature-index chain derives 65", Expect: refused,
			State: proofv2.StateArrivalUnproven, Partition: "BVN2", Block: BlockBVN2, Opts: Options{Timeline: &Timeline{}},
			Mutate: func(ev *proofv2.Evidence) { ev.Votes[0].Hops[0].Block = HopBlock - 1 }},
		{Name: "timeline-arrival-previous-index-entry-missing", Description: "the previous signature-index entry is left out, so nothing shows the signature was not in an earlier block", Expect: refused,
			State: proofv2.StateArrivalUnproven, Partition: "BVN2", Block: BlockBVN2, Opts: Options{Timeline: &Timeline{}},
			Mutate: func(ev *proofv2.Evidence) { ev.Votes[0].Hops[0].Arrival.Before = nil }},
		{Name: "timeline-delegated-entry-removed-before-arrival", Description: "the delegating page dropped its delegate entry in block 60: the delegate's vote arriving in block 66 could not have been counted", Expect: refused,
			State: proofv2.StateVoteNotReproduced, Partition: "BVN1", Block: BlockBVN1,
			Opts: Options{Timeline: &Timeline{Delegated: true, DelegatorEvents: []PageEvent{{Block: 60, Add: []string{"K1"}, RemoveDelegate: true}}}}},
		{Name: "timeline-vote-produced-before-its-cause", Description: "the SequencedMessage is in the synthetic ledger in block 64, before the signature that caused the vote arrived in block 65", Expect: refused,
			State: proofv2.StateBlockBeforeArrival, Partition: "BVN2", Block: BlockBVN2, Opts: Options{Timeline: &Timeline{ProduceBlock: HopBlock - 1}}},
	}
}
