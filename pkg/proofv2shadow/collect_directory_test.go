// Copyright 2026 Certen Protocol

package proofv2shadow

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
)

// dnFake is the tcl model with the Directory as a partition: the customer's payment account on BVN1 is governed by the bank's book on
// BVN2 and by a book on the Directory (acc://dn.acme/book); the Directory's own anchors, as it executed them, are at DN blocks 470,
// 498 and 505 for its blocks 4000, 4020 and 4030.
func dnFake(t *testing.T) *fakeNet {
	w := tclWorld()
	f := newFakeNet(t, w)
	f.part["dn.acme"] = "Directory"
	w.adi("dn.acme", 1)
	w.add(data("cust.acme", "dirpay", "acc://dn.acme/book", "acc://cust.acme/book"))
	f.anchors["Directory"] = []fakeAnchor{{470, 4000}, {498, 4020}, {505, 4030}}
	f.facts = facts("acc://cust.acme/dirpay")
	return f
}

func stateRootOfPage(t *testing.T, pg CapturedPage) []byte {
	t.Helper()
	var r merkle.Receipt
	raw, _ := hex.DecodeString(pg.Receipt)
	if err := r.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	if !r.Validate(nil) {
		t.Fatalf("%s: the stored receipt does not validate", pg.URL)
	}
	return r.Anchor
}

// D2b: a governing book on the Directory is read at a Directory block chosen from the Directory's own anchors - the latest whose
// anchor the Directory executed at or before the Directory block that executed the transaction's partition's anchor - and its receipt
// ends at that block's state root.
func TestCollectDirectoryAuthorityBookIsCapturedAtADirectoryBlock(t *testing.T) {
	f := dnFake(t)
	c, err := f.collect()
	if err != nil {
		t.Fatal(err)
	}
	// The transaction's anchor was executed at DN 500: the Directory's anchors executed by then are for blocks 4000 and 4020.
	pg := pageByURL(t, *c, "acc://dn.acme/book/1")
	if pg.Block != 4020 || pg.Partition != "acc://dn.acme" {
		t.Fatalf("the Directory page was captured at block %d on %s", pg.Block, pg.Partition)
	}
	want := f.rootAt("Directory", 4020)
	if !bytes.Equal(stateRootOfPage(t, pg), want[:]) {
		t.Fatal("the Directory page's receipt does not end at the Directory's state root for its block")
	}
	pc := c.Partitions["Directory"]
	if pc.Block != 4020 || pc.Index != 1 || pc.DNBlock != 498 {
		t.Fatalf("the Directory's capture record: %+v", pc)
	}
	if !hasRoleOf(c, "acc://dn.acme/book/1", proofv2.RoleAuthorityPage) || !hasRoleOf(c, "acc://dn.acme/book", proofv2.RoleAuthorityBook) {
		t.Fatalf("roles not recorded: %+v", c.Pages)
	}
	// Every read of a Directory page was made at the Directory's block, never the transaction's.
	for _, r := range f.reads {
		if strings.Contains(r, "@Directory:") && !strings.HasSuffix(r, ":4020") {
			t.Fatalf("a Directory page was read at the wrong block: %s", r)
		}
	}
}

// The Directory's block is bounded below by the arrival of a counted signature on it, exactly as a block validator partition's is.
func TestCollectDirectoryBlockFollowsTheArrivalBound(t *testing.T) {
	f := dnFake(t)
	v := vote("acc://dn.acme/book", "acc://dn.acme/book/1")
	f.facts.Votes = []VoteFact{v}
	f.arrivals[v.Cause.String()] = fakeArrival{"Directory", 4000}
	c, err := f.collect()
	if err != nil {
		t.Fatal(err)
	}
	if pg := pageByURL(t, *c, "acc://dn.acme/book/1"); pg.Block != 4000 {
		t.Fatalf("a signature arriving at block 4000 gave B_Y %d, the smallest admissible block is 4000", pg.Block)
	}
	f.arrivals[v.Cause.String()] = fakeArrival{"Directory", 4001}
	if c, err = f.collect(); err != nil {
		t.Fatal(err)
	} else if pg := pageByURL(t, *c, "acc://dn.acme/book/1"); pg.Block != 4020 {
		t.Fatalf("a signature arriving at block 4001 gave B_Y %d, want 4020", pg.Block)
	}
	f.arrivals[v.Cause.String()] = fakeArrival{"Directory", 4021} // after the latest block the Directory had anchored by DN 500
	_, err = f.collect()
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StateBlockBeforeArrival || ns.Partition != "Directory" || ns.Block != 4020 {
		t.Fatalf("B_Y before a counted arrival on the Directory gave %v", err)
	}
}

// A Directory anchor the Directory has not executed is a named state with the partition and block; the page is not read.
func TestCollectNamesADirectoryAnchorTheDirectoryHasNotExecuted(t *testing.T) {
	f := dnFake(t)
	f.noAnchor["Directory"] = true
	_, err := f.collect()
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StatePartitionAnchorUnavailable || ns.Partition != "Directory" || ns.Block != 4020 {
		t.Fatalf("an unexecuted Directory anchor gave %v", err)
	}
	for _, r := range f.reads {
		if strings.Contains(r, "@Directory:") {
			t.Fatalf("the Directory was read although its anchor is unavailable: %v", f.reads)
		}
	}
}

// A Directory page served for another block than B_Y does not pass through the Directory's anchor and is refused by name.
func TestCollectRefusesADirectoryPageServedForAnotherBlock(t *testing.T) {
	f := dnFake(t)
	f.liar["Directory"] = 4030
	_, err := f.collect()
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StatePageBlockMismatch || ns.Partition != "Directory" || ns.Block != 4020 {
		t.Fatalf("a Directory page served for another block gave %v", err)
	}
}

// D2c: a principal on the Directory keeps the Directory block B and the DirectoryAnchor for it; the pages of a book on a block
// validator partition are read at the latest block whose anchor the Directory executed at or before B (DN 500 here).
func TestCollectPrincipalOnTheDirectoryReadsBVNPagesAtTheLatestAnchoredBlock(t *testing.T) {
	w := tclWorld()
	f := newFakeNet(t, w)
	f.part["dn.acme"] = "Directory"
	f.x = "Directory"
	w.adi("dn.acme", 1)
	w.add(data("dn.acme", "pay", "acc://bank.acme/book", "acc://dn.acme/book"))
	f.facts = facts("acc://dn.acme/pay")
	f.dnBlock = f.block // the limit is B itself for a principal on the Directory
	c, err := f.collect()
	if err != nil {
		t.Fatal(err)
	}
	if c.Partition != "Directory" || c.Block != 1000 {
		t.Fatalf("capture is of %s block %d", c.Partition, c.Block)
	}
	own := pageByURL(t, *c, "acc://dn.acme/pay")
	if own.Block != 1000 || own.Partition != "acc://dn.acme" {
		t.Fatalf("the principal was captured at block %d on %s", own.Block, own.Partition)
	}
	root := f.rootAt("Directory", 1000)
	if !bytes.Equal(stateRootOfPage(t, own), root[:]) {
		t.Fatal("the principal's receipt does not end at the Directory's state root for its block")
	}
	// BVN2's anchors were executed at DN 480, 490, 499, 510; the limit is the principal's block 1000, so the latest is 510 -> block 2030.
	bank := pageByURL(t, *c, "acc://bank.acme/book/2")
	if bank.Block != 2030 || bank.Partition != "acc://bvn-BVN2.acme" {
		t.Fatalf("the bank page was captured at block %d on %s", bank.Block, bank.Partition)
	}
	if pc := c.Partitions["Directory"]; pc.Block != 1000 || pc.DNBlock != 1000 {
		t.Fatalf("the transaction partition's record: %+v", pc)
	}
	// The Directory's own pages (its book) are bound to the same anchor as the principal.
	bk := pageByURL(t, *c, "acc://dn.acme/book/1")
	if bk.Block != 1000 || !bytes.Equal(stateRootOfPage(t, bk), root[:]) {
		t.Fatalf("a page of the principal's own partition was captured at block %d", bk.Block)
	}
}
