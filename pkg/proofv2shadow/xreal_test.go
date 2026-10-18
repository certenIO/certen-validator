// Copyright 2026 Certen Protocol

package proofv2shadow

import (
	"compress/gzip"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// The capture the collector made live from Kermit (certen-protocol.acme/billing-receipts, BVN1 block 14713382, RB9 Phase C1b-2) holds
// what evidence 2.1 is assembled from: the transaction, the vote's signatures, and the history of the page the vote was cast on. The
// evidence built from it (pkg/proof/v2/testdata/xpartition3/real-bvn1-billing-receipts) is verified by pkg/proof/v2's real tests.
func TestStoredLiveCaptureCarriesTheTimelineMembers(t *testing.T) {
	f, err := os.Open("testdata/capture21_billing_receipts_bvn1_14713382.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := DecodeCapture(raw)
	if err != nil {
		t.Fatal(err)
	}
	if cp.HasForeignPages() {
		t.Fatal("the BVN1 capture reports a foreign page")
	}
	if cp.Transaction == "" || len(cp.Votes) == 0 {
		t.Fatalf("transaction %v, %d votes", cp.Transaction != "", len(cp.Votes))
	}
	txn := new(protocol.Transaction)
	b, _ := hex.DecodeString(cp.Transaction)
	if err := txn.UnmarshalBinary(b); err != nil || txn.Header.Principal.String() != cp.Principal {
		t.Fatalf("the captured transaction: %v", err)
	}
	for _, v := range cp.Votes {
		if len(v.Hops) == 0 {
			t.Fatalf("the vote of %s records no hop", v.Authority)
		}
		for _, h := range v.Hops {
			if h.Signature == "" {
				t.Fatalf("the hop on %s carries no signature", h.Page)
			}
		}
	}
	withHistory := 0
	for _, p := range cp.Pages {
		if p.History != nil {
			withHistory++
		}
	}
	if withHistory == 0 {
		t.Fatal("no page of the capture carries a history")
	}
}

// A hop's signature and the other signatures its page counted travel with the vote.
func TestVoteOfCarriesTheSignaturesItsPagesCounted(t *testing.T) {
	page := url.MustParse("acc://bank.acme/book/1")
	sig := &protocol.ED25519Signature{PublicKey: make([]byte, 32), Signature: make([]byte, 64), Signer: page, SignerVersion: 1, Timestamp: 1}
	id := page.WithTxID([32]byte{1})
	other := page.WithTxID([32]byte{2})
	v := voteOf(VoteFact{Authority: url.MustParse("acc://bank.acme/book"), Origin: page, Vote: protocol.VoteTypeAccept,
		Hops:    []Hop{{Page: page, ID: id, Block: 9, Sig: sig}},
		Counted: []Hop{{Page: page, ID: other, Block: 8, Sig: sig}}})
	if len(v.Hops) != 1 || v.Hops[0].Signature == "" || len(v.Counted) != 1 || v.Counted[0].Signature == "" {
		t.Fatalf("hops %+v counted %+v", v.Hops, v.Counted)
	}
	oh := other.Hash()
	if v.Counted[0].Message != hex.EncodeToString(oh[:]) {
		t.Fatalf("counted message %q", v.Counted[0].Message)
	}
}

// A cross-partition capture becomes the assembly evidence 2.1 is built from: every page with its partition and roles, the state root
// of each partition, and the Directory's anchor for each partition other than the transaction's, at the block the capture read it at.
// A capture whose recorded state root is not the one the Directory's anchor carries is the named state g1_chain_moved.
func TestAssemblyOfACrossPartitionCaptureLoadsEachForeignAnchor(t *testing.T) {
	f := newFakeNet(t, tclWorld())
	f.facts = facts("acc://cust.acme/pay")
	c, err := f.collect()
	if err != nil {
		t.Fatal(err)
	}
	asm, err := c.Assembly(context.Background(), fakeLog{f}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(asm.Pages) != len(c.Pages) || len(asm.Roots) != len(c.Partitions) || len(asm.Foreign) != len(c.Partitions)-1 {
		t.Fatalf("%d pages of %d, %d roots of %d, %d foreign anchors for %d partitions", len(asm.Pages), len(c.Pages), len(asm.Roots), len(c.Partitions), len(asm.Foreign), len(c.Partitions))
	}
	for _, pb := range asm.Foreign {
		pc := c.Partitions[pb.Partition]
		if pb.Block != pc.Block || pb.Index != pc.Index {
			t.Fatalf("%s: anchor %d block %d, the capture read it at anchor %d block %d", pb.Partition, pb.Index, pb.Block, pc.Index, pc.Block)
		}
		if root := asm.Roots[protocol.PartitionUrl(pb.Partition).String()]; root != pb.Anchor.StateTreeAnchor {
			t.Fatalf("%s: root %x, the anchor carries %x", pb.Partition, root, pb.Anchor.StateTreeAnchor)
		}
	}
	bad := *c
	bad.Partitions = map[string]PartitionCapture{}
	for k, v := range c.Partitions {
		if k != c.Partition {
			v.StateRoot = hex.EncodeToString(make([]byte, 32))
		}
		bad.Partitions[k] = v
	}
	_, err = bad.Assembly(context.Background(), fakeLog{f}, nil)
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StateChainMoved {
		t.Fatalf("a state root the anchor does not carry gave %v", err)
	}
}
