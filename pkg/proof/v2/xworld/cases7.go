// Copyright 2026 Certen Protocol

package xworld

import (
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// The suite of DAX-1G (G-83): a transaction initiated by a page that is NOT a voting authority - the tcl `*-erp` initiator, decision 0042 - whose
// signature the document CARRIES (Evidence.InitiatingSignature) and the verifier PROVES. The world is Timeline.ExternalInitiator at blocks the
// pinned executor-activation table proves (LayoutBVNProven), so intentcert.BindProofV21 can judge the same document (bind_v21_nonvoting_initiator_test.go).
// Every case is a genesis-linked document (F-VE-2 (b)); a refusal names the signer page's partition and block: BVN3, ProvenBlockBVN3 (BVN2 and
// ProvenBlockBVN2 where the member names BankPage1). New files under their own directory and manifest (testdata/xpartition7); the earlier
// suites are never touched.

// initiatorWorld is the valid non-voting-initiator world with the vote's production bound (nothing about the votes is left unproven).
func initiatorWorld(tl Timeline) Options {
	tl.ExternalInitiator = true
	tl.ProduceBlock, tl.BindSequenced = 66, true
	return Options{Layout: LayoutBVNProven, GenesisLinked: true, Timeline: &tl}
}

// alterReceiptHex flips one byte of the first step of a binary merkle.Receipt (hex): still a decodable receipt, no longer the chain's.
func alterReceiptHex(h string) string {
	r := new(merkle.Receipt)
	must(0, r.UnmarshalBinary(must(hexDecode(h))))
	if len(r.Entries) == 0 {
		panic("xworld: a receipt with no steps")
	}
	r.Entries[0].Hash = append([]byte(nil), r.Entries[0].Hash...)
	r.Entries[0].Hash[0] ^= 0xff
	return rcptHex(r)
}

// Cases7 is the suite in a fixed order.
func Cases7() []Case {
	notCarried := proofv2.StateInitiatorSignatureNotCarried
	erpPartition, erpBlock := "BVN3", uint64(ProvenBlockBVN3)
	return []Case{
		{Name: "initiator-nonvoting-carried", Description: "ErpPage1, a page of an identity that is no authority of the principal, signs first and pays (Header.Initiator is its signature's metadata hash) and BankBook votes afterwards: the document carries the initiating signature with its receipt in ErpPage1's signature chain, its arrival proof and the page's certified history; initiator-signer is a PROVEN role of ErpPage1 (nothing unproven, no declared initiator-signer)", Expect: verified,
			Opts: initiatorWorld(Timeline{})},
		{Name: "initiator-nonvoting-key-removed-after-arrival", Description: "the initiating key was removed from ErpPage1 (and another added) after the signature arrived: judged on the certified history at the arrival block the page held the key, so the role is proven", Expect: verified,
			Opts: initiatorWorld(Timeline{InitiatorGenesis: []string{"K4"}, InitiatorEvents: []PageEvent{{Block: 66, Add: []string{"K9"}, Remove: []string{"K4"}}}})},
		{Name: "initiator-nonvoting-delegated-carried", Description: "the initiating signature is a delegated signature: ErpPage1's key signed it on behalf of DelePage1 (its delegator, a proven page): the roles are proven for the payer (ErpPage1) and the delegator (DelePage1). The delegation entry itself is not re-evaluated by this member (it authorizes nothing; docs/proof/G1_CROSS_PARTITION.md, initiator-signer)", Expect: verified,
			Opts: initiatorWorld(Timeline{InitiatorDelegator: DelePage1})},
		{Name: "initiator-signature-tampered", Description: "one nibble of the carried initiating signature changed: no longer the message its signature-chain entry holds", Expect: refused,
			State: proofv2.StateSignatureInvalid, Partition: erpPartition, Block: erpBlock, Opts: initiatorWorld(Timeline{}),
			Mutate: func(ev *proofv2.Evidence) {
				b := []byte(ev.InitiatingSignature.Signature)
				if b[len(b)-1] == '0' {
					b[len(b)-1] = '1'
				} else {
					b[len(b)-1] = '0'
				}
				ev.InitiatingSignature.Signature = string(b)
			}},
		{Name: "initiator-signature-other-transaction", Description: "the member is the initiating signature of ANOTHER transaction (another body): ErpPage1's chain does not hold its message for this transaction", Expect: refused,
			State: proofv2.StateBlockBeforeArrival, Partition: erpPartition, Block: erpBlock, Opts: initiatorWorld(Timeline{}),
			Mutate: func(ev *proofv2.Evidence) {
				other, err := Build(initiatorWorld(Timeline{Body: &protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{[]byte("another transaction")}}}}))
				if err != nil {
					panic(err)
				}
				h := *other.Initiating
				ev.InitiatingSignature = &h
			}},
		{Name: "initiator-signature-signs-another-transaction", Description: "ErpPage1's signature chain holds the message of a signature that has the initiating signature's metadata but signs ANOTHER transaction (a forgery no real chain holds): it is a member of the chain and it initiates by metadata, but it does not sign this transaction", Expect: refused,
			State: proofv2.StateSignatureInvalid, Partition: erpPartition, Block: erpBlock, Opts: initiatorWorld(Timeline{InitiatorSignsAnotherTransaction: true})},
		{Name: "initiator-signature-other-page", Description: "the member names BankPage1 as the page that records the signature, but the message is ErpPage1's: BankPage1's signature chain does not hold it", Expect: refused,
			State: proofv2.StateBlockBeforeArrival, Partition: "BVN2", Block: ProvenBlockBVN2, Opts: initiatorWorld(Timeline{}),
			Mutate: func(ev *proofv2.Evidence) { ev.InitiatingSignature.Page = BankPage1 }},
		{Name: "initiator-signature-recorded-on-another-page", Description: "BankPage1's signature chain holds the message of a signature MADE as ErpPage1 (a forgery no real chain holds), and the member names BankPage1: the chain does hold the message, but the signer is not the page it is recorded on", Expect: refused,
			State: proofv2.StateSignatureInvalid, Partition: "BVN2", Block: ProvenBlockBVN2,
			Opts:        initiatorWorld(Timeline{Sigs: []SigEvent{{Key: "K4", Version: 1, Block: 62, SignAs: ErpPage1, Hidden: true}, {Key: "K0", Version: 1, Block: HopBlock}}}),
			MutateBuilt: func(b *Built) { h := *b.HiddenOnBank; b.Evidence.InitiatingSignature = &h }},
		{Name: "initiator-member-absent", Description: "ErpPage1 records initiator-signer but the document carries no initiating signature (every document made before the member): the role is a declared fact, the report says g1_initiator_signature_not_carried, and the binding refuses it", Expect: verified,
			Unproven: []string{notCarried}, Opts: initiatorWorld(Timeline{OmitInitiatingSignature: true})},
		{Name: "initiator-member-page-records-no-role", Description: "the member is carried and proves ErpPage1 an initiator-signer, but the page does not record the role: justified by the proven states, not recorded", Expect: refused,
			State: proofv2.StateRoleMismatch, Partition: erpPartition, Block: erpBlock, Opts: initiatorWorld(Timeline{}),
			Mutate: func(ev *proofv2.Evidence) {
				p := &ev.Pages[idx(ev, ErpPage1)]
				var roles []proofv2.PageRole
				for _, r := range p.Roles {
					if r != proofv2.RoleInitiatorSigner {
						roles = append(roles, r)
					}
				}
				p.Roles = roles
			}},
		{Name: "initiator-member-not-the-initiator", Description: "the member is a VALID signature of ErpPage1 (a second key signed after the initiating one) that did not initiate the transaction: its metadata hash is not Header.Initiator, so the role it would justify is not the transaction's", Expect: refused,
			State: proofv2.StateRoleMismatch, Partition: erpPartition, Block: erpBlock, Opts: initiatorWorld(Timeline{InitiatorCosign: "K5"}),
			MutateBuilt: func(b *Built) { h := *b.InitiatorCosign; b.Evidence.InitiatingSignature = &h }},
		{Name: "initiator-key-not-held", Description: "ErpPage1's certified history never held the signing key (K4): the signature is recorded in its chain but no state of the page at the signature's version during its arrival block holds the key", Expect: refused,
			State: proofv2.StateInitiatorKeyNotHeld, Partition: erpPartition, Block: erpBlock, Opts: initiatorWorld(Timeline{InitiatorGenesis: []string{"K9"}})},
		{Name: "initiator-member-no-history", Description: "the member is carried without ErpPage1's certified history, which the proof of its key needs", Expect: refused,
			State: proofv2.StateHistoryUnavailable, Partition: erpPartition, Block: erpBlock, Opts: initiatorWorld(Timeline{OmitInitiatorHistory: true})},
		{Name: "initiator-member-arrival-altered", Description: "the claimed arrival block differs from the block ErpPage1's signature-index chain gives", Expect: refused,
			State: proofv2.StateArrivalUnproven, Partition: erpPartition, Block: erpBlock, Opts: initiatorWorld(Timeline{}),
			Mutate: func(ev *proofv2.Evidence) { ev.InitiatingSignature.Block++ }},
		{Name: "initiator-member-receipt-altered", Description: "a step of the member's receipt altered: it no longer ends at ErpPage1's signature chain root as bound at the page's block", Expect: refused,
			State: proofv2.StateBlockBeforeArrival, Partition: erpPartition, Block: erpBlock, Opts: initiatorWorld(Timeline{}),
			Mutate: func(ev *proofv2.Evidence) {
				ev.InitiatingSignature.Receipt = alterReceiptHex(ev.InitiatingSignature.Receipt)
			}},
		{Name: "initiator-member-in-20-document", Description: "a document that says 2.0 but carries the member (with the other 2.1 members): refused as every 2.0 document that carries 2.1 members is", Expect: refused,
			Opts:   initiatorWorld(Timeline{}),
			Mutate: func(ev *proofv2.Evidence) { ev.Version = proofv2.Version }},
	}
}
