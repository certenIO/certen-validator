// Copyright 2026 Certen Protocol

package proofv2_test

import (
	"encoding/hex"
	"strings"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"github.com/certen/independant-validator/pkg/proof/v2/xworld"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// RB9 verifier round VA, fix package J1: the verifier-level defects DEF-1 (executor override gate), DEF-2 (partition from the
// committed anchor body) and DEF-4 (a sequenced vote's production bound to the vote).

// DEF-1: every body type of the shared override table is refused by name, at the transaction's partition and block, before the vote is
// re-evaluated - whatever the votes say.
func TestJ1EveryExecutorOverrideTypeIsRefusedBeforeTheVote(t *testing.T) {
	types := proofv2.ExecutorOverrideTypes()
	for _, want := range []protocol.TransactionType{protocol.TransactionTypeCreateIdentity, protocol.TransactionTypeCreateKeyBook,
		protocol.TransactionTypeCreateTokenAccount, protocol.TransactionTypeCreateDataAccount, protocol.TransactionTypeCreateToken,
		protocol.TransactionTypeReleaseLockedOperation, protocol.TransactionTypeNetworkMaintenance, protocol.TransactionTypeUpdateKey,
		protocol.TransactionTypeUpdateKeyPage, protocol.TransactionTypeCreateLiteTokenAccount} {
		found := false
		for _, g := range types {
			found = found || g == want
		}
		if !found {
			t.Fatalf("%v is not in the override table", want)
		}
	}
	for _, typ := range types {
		body, err := protocol.NewTransactionBody(typ)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tl(t, xworld.Timeline{Body: body}, nil)
		refusedWith(t, err, proofv2.StateExecutorOverrideUnsupported, "BVN1", xworld.BlockBVN1)
	}
}

// DEF-1: the types the verifier models (a default rule extended by the authorities the body adds) are not refused by the gate.
func TestJ1ModelledTypesAreNotRefusedByTheGate(t *testing.T) {
	for _, typ := range []protocol.TransactionType{protocol.TransactionTypeWriteData, protocol.TransactionTypeUpdateAccountAuth} {
		if proofv2.HasExecutorOverride(typ) {
			t.Fatalf("%v is in the override table", typ)
		}
	}
	body, _ := protocol.NewTransactionBody(protocol.TransactionTypeUpdateAccountAuth)
	rep, err := tl(t, xworld.Timeline{Body: body}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.AuthorizationMode != proofv2.ModeAuthoritiesRequired {
		t.Fatalf("mode %q", rep.AuthorizationMode)
	}
}

// relabelAnchor changes only the wrapper (SequencedMessage.Source) of the partition anchor held under key, and every claim that names
// the partition (the anchors key, the pages' partition) with it: the anchor transaction (header and body) is untouched, so its receipt
// still proves it into the certified root.
func relabelAnchor(t *testing.T, ev *proofv2.Evidence, key, to string) {
	t.Helper()
	a := ev.Anchors[key]
	raw, err := hex.DecodeString(a.Message)
	if err != nil {
		t.Fatal(err)
	}
	seq := new(messaging.SequencedMessage)
	if err := seq.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	seq.Source = url.MustParse(to)
	b, err := seq.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	a.Message = hex.EncodeToString(b)
	delete(ev.Anchors, key)
	ev.Anchors[to] = a
	for i := range ev.Pages {
		if ev.Pages[i].Partition == key {
			ev.Pages[i].Partition = to
		}
	}
}

// DEF-2: the receipt covers the anchor transaction (header and body), not the SequencedMessage wrapper that carries it. A document
// that relabels the wrapper's Source - and every claim that follows it - still verifies every receipt; the partition is the committed
// body's Source, so the relabelled document is refused by name, at the partition the body names.
func TestJ1AnchorWrapperSourceAlteredIsRefusedAtTheBodysPartition(t *testing.T) {
	_, err := runX(t, xworld.Options{NoRouting: true}, func(ev *proofv2.Evidence) { relabelAnchor(t, ev, xworld.PartBVN3, "acc://bvn-BVN4.acme") })
	refusedWith(t, err, proofv2.StateForeignPartitionMismatch, "BVN3", xworld.BlockBVN3)
	// the same relabelling of the transaction's own anchor
	_, err = runX(t, xworld.Options{NoRouting: true}, func(ev *proofv2.Evidence) {
		raw, _ := hex.DecodeString(ev.Anchor.Message)
		seq := new(messaging.SequencedMessage)
		if e := seq.UnmarshalBinary(raw); e != nil {
			t.Fatal(e)
		}
		seq.Source = url.MustParse("acc://bvn-BVN4.acme")
		b, _ := seq.MarshalBinary()
		ev.Anchor.Message = hex.EncodeToString(b)
		for i := range ev.Pages {
			if ev.Pages[i].Partition == xworld.PartBVN1 {
				ev.Pages[i].Partition = "acc://bvn-BVN4.acme"
			}
		}
	})
	refusedWith(t, err, proofv2.StateForeignPartitionMismatch, "BVN1", xworld.BlockBVN1)
}

// DEF-2: a spelling that differs only in case is the same partition (both are the committed value's spelling folded).
func TestJ1AnchorWrapperSourceCaseOnlyIsTheSamePartition(t *testing.T) {
	rep, err := runX(t, xworld.Options{}, func(ev *proofv2.Evidence) {
		a := ev.Anchors[xworld.PartBVN3]
		raw, _ := hex.DecodeString(a.Message)
		seq := new(messaging.SequencedMessage)
		if e := seq.UnmarshalBinary(raw); e != nil {
			t.Fatal(e)
		}
		seq.Source = url.MustParse(strings.ToLower(xworld.PartBVN3))
		b, _ := seq.MarshalBinary()
		a.Message = hex.EncodeToString(b)
		ev.Anchors[xworld.PartBVN3] = a
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep == nil {
		t.Fatal("no report")
	}
}

func bound(t *testing.T, mut func(*proofv2.Evidence)) (*proofv2.Report, error) {
	t.Helper()
	return tl(t, xworld.Timeline{ProduceBlock: 66, BindSequenced: true}, mut)
}

func resign(t *testing.T, pr *proofv2.Production, edit func(*messaging.SequencedMessage)) {
	t.Helper()
	raw, err := hex.DecodeString(pr.Sequenced)
	if err != nil {
		t.Fatal(err)
	}
	seq := new(messaging.SequencedMessage)
	if err := seq.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	edit(seq)
	b, err := seq.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	pr.Sequenced = hex.EncodeToString(b)
}

// DEF-4: a sequenced vote's production carries the SequencedMessage; the verifier recomputes its hash, requires it to wrap the vote's
// SignatureMessage and to name the vote's transport. The valid document verifies with no disclosure of an unbound production.
func TestJ1SequencedProductionIsBoundToTheVote(t *testing.T) {
	rep, err := bound(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range rep.Disclosures {
		if d.Code == proofv2.StateVoteProductionUnbound {
			t.Fatalf("a bound production is disclosed as unbound: %+v", d)
		}
	}
	if len(rep.Arrivals) != 2 || rep.Arrivals[1].Kind != "produced" || rep.Arrivals[1].Block != 66 {
		t.Fatalf("arrivals %+v", rep.Arrivals)
	}
}

func TestJ1SequencedProductionNotTheVotesMessageIsRefused(t *testing.T) {
	bad := func(name string, mut func(*proofv2.Evidence)) {
		t.Run(name, func(t *testing.T) {
			_, err := bound(t, mut)
			refusedWith(t, err, proofv2.StateArrivalUnproven, "BVN2", xworld.BlockBVN2)
		})
	}
	bad("hash is not the chain entry", func(ev *proofv2.Evidence) {
		resign(t, ev.Votes[0].Produced, func(s *messaging.SequencedMessage) { s.Number++ })
	})
	bad("wraps another signature message", func(ev *proofv2.Evidence) {
		pr := ev.Votes[0].Produced
		resign(t, pr, func(s *messaging.SequencedMessage) {
			sm := s.Message.(*messaging.SignatureMessage)
			as := *sm.Signature.(*protocol.AuthoritySignature)
			as.Vote = protocol.VoteTypeReject
			s.Message = &messaging.SignatureMessage{Signature: &as, TxID: sm.TxID}
		})
		// the chain entry is the altered message's hash, so only the binding to the vote can refuse it
		raw, _ := hex.DecodeString(pr.Sequenced)
		seq := new(messaging.SequencedMessage)
		if err := seq.UnmarshalBinary(raw); err != nil {
			t.Fatal(err)
		}
		h := seq.Hash()
		pr.Message = hex.EncodeToString(h[:])
	})
	bad("sequenced bytes are not a sequenced message", func(ev *proofv2.Evidence) { ev.Votes[0].Produced.Sequenced = "00" })
}

// DEF-4: Source, Destination and Number of the carried message are the vote's Transport. The chain entry is re-pointed at the altered
// message, so the hash check passes and only the transport binding refuses.
func TestJ1SequencedProductionTransportMustEqualTheVotes(t *testing.T) {
	for name, edit := range map[string]func(*messaging.SequencedMessage){
		"source":      func(s *messaging.SequencedMessage) { s.Source = url.MustParse(xworld.PartBVN3) },
		"destination": func(s *messaging.SequencedMessage) { s.Destination = url.MustParse(xworld.PartBVN3) },
		"number":      func(s *messaging.SequencedMessage) { s.Number = 99 },
	} {
		edit := edit
		t.Run(name, func(t *testing.T) {
			_, err := bound(t, func(ev *proofv2.Evidence) {
				pr := ev.Votes[0].Produced
				resign(t, pr, edit)
				raw, _ := hex.DecodeString(pr.Sequenced)
				seq := new(messaging.SequencedMessage)
				if e := seq.UnmarshalBinary(raw); e != nil {
					t.Fatal(e)
				}
				h := seq.Hash()
				pr.Message = hex.EncodeToString(h[:])
			})
			refusedWith(t, err, proofv2.StateArrivalUnproven, "BVN2", xworld.BlockBVN2)
		})
	}
}

// DEF-4: a document made before the production carried its message (the shipped xpartition2b vectors) keeps its verdict, and the report
// discloses by name that the production is not bound to the vote.
func TestJ1ProductionWithoutTheMessageIsDisclosedAsUnbound(t *testing.T) {
	rep, err := tl(t, xworld.Timeline{ProduceBlock: 66}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range rep.Disclosures {
		if d.Code == proofv2.StateVoteProductionUnbound && d.Partition == "BVN2" {
			return
		}
	}
	t.Fatalf("no %s disclosure: %+v", proofv2.StateVoteProductionUnbound, rep.Disclosures)
}

// (d): g1_vote_held is for a vote whose production a HoldUntil release could have moved. A held transaction whose vote carries no
// production proof reports it; the same vote, inline, on a transaction that is not held reports nothing.
func TestJ1HeldIsReportedOnlyForAHeldTransaction(t *testing.T) {
	rep, err := tl(t, xworld.Timeline{HoldUntil: 60}, func(ev *proofv2.Evidence) { ev.Votes[0].Produced = nil })
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(codes(rep), ","); got != proofv2.StateVoteHeld {
		t.Fatalf("held, no production: unproven %q", got)
	}
	rep, err = tl(t, xworld.Timeline{}, func(ev *proofv2.Evidence) {
		ev.Votes[0].Transport = proofv2.VoteTransport{Kind: proofv2.TransportInline}
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := codes(rep); len(got) != 0 {
		t.Fatalf("not held, inline vote without a production: unproven %v", got)
	}
}
