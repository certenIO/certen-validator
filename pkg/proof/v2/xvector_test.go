// Copyright 2026 Certen Protocol

package proofv2

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/proof"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// xvector mirrors cmd/proofv2xvector's Vector: a real page of a partition other than a transaction's, captured live from
// Kermit on 2026-10-17 by that command, with the anchor the Directory executed for its block.
type xvector struct {
	Format           string          `json:"format"`
	Page             string          `json:"page"`
	Partition        string          `json:"partition"`
	Block            uint64          `json:"block"`
	Index            uint64          `json:"index"`
	DNBlock          uint64          `json:"dnBlock"`
	RetainedEarliest uint64          `json:"retainedEarliest"`
	RetainedLatest   uint64          `json:"retainedLatest"`
	PageState        PageState       `json:"pageState"`
	ServedReceipt    string          `json:"servedReceipt"`
	Anchor           PartitionAnchor `json:"anchor"`
	AnchorTx         string          `json:"anchorTx"`
	StateRoot        string          `json:"stateRoot"`
	RootChain        string          `json:"rootChain"`
	AnchorHeight     uint64          `json:"anchorHeight"`
	AnchorAtH        PartitionAnchor `json:"anchorAtHeight"`
	Routing          json.RawMessage `json:"routing"`
}

func loadVector(t *testing.T, name string) *xvector {
	t.Helper()
	f, err := os.Open("testdata/xpartition/" + name)
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
	v := new(xvector)
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatal(err)
	}
	if v.Format != "certen-xpartition-vector/1" {
		t.Fatalf("vector format %q", v.Format)
	}
	return v
}

// The real foreign page: read at its own partition's block, it passes through the state tree root of the BlockValidatorAnchor
// the Directory executed for that block, the chain roots bind to it, and the anchor is proven into a Directory root - the
// facts the capture establishes while the block is servable, checked here against what a live node served.
func TestRealForeignPageVectorIsProvenThroughItsPartitionsAnchor(t *testing.T) {
	v := loadVector(t, "bvn1-fdb-compliance-book2.json.gz")

	// The anchor: a BlockValidatorAnchor of the page's partition, delivered to the Directory's anchor pool, for exactly the
	// block the page was read at.
	body, seq, anchorTx, err := anchorBody(v.Anchor.Message)
	if err != nil {
		t.Fatal(err)
	}
	if seq.Source.String() != "acc://bvn-"+v.Partition+".acme" || body.MinorBlockIndex != v.Block {
		t.Fatalf("anchor from %v for block %d, the page was read on %s at %d", seq.Source, body.MinorBlockIndex, v.Partition, v.Block)
	}
	if hex.EncodeToString(anchorTx) != v.AnchorTx || hex.EncodeToString(body.StateTreeAnchor[:]) != v.StateRoot || hex.EncodeToString(body.RootChainAnchor[:]) != v.RootChain {
		t.Fatal("the anchor message is not the one the vector names")
	}
	if v.Block < v.RetainedEarliest || v.Block > v.RetainedLatest {
		t.Fatalf("block %d was not inside the advertised retained range [%d, %d] when captured", v.Block, v.RetainedEarliest, v.RetainedLatest)
	}

	// The anchor transaction is proven into a Directory root, at the root the node chose and at a later root asked for.
	for name, a := range map[string]PartitionAnchor{"any root": v.Anchor, "a later root": v.AnchorAtH} {
		r, err := decodeReceipt(a.Receipt)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(r.Start, anchorTx) || !r.Validate(nil) {
			t.Fatalf("the anchor's receipt to %s does not validate from the anchor transaction", name)
		}
	}
	r1, _ := decodeReceipt(v.Anchor.Receipt)
	r2, _ := decodeReceipt(v.AnchorAtH.Receipt)
	if len(r2.Entries) < len(r1.Entries) {
		t.Fatalf("the receipt to the later root (%d steps) is shorter than the one to the node's root (%d)", len(r2.Entries), len(r1.Entries))
	}

	// The page: its receipt, as the node served it, passes through the anchor's state root, and trimmed to it equals what was
	// stored; the chain roots bind to it, so the page's main chain at the block is proven.
	root := body.StateTreeAnchor
	served := v.PageState
	served.Receipt = v.ServedReceipt
	trimmed, err := trimPage(&served, root[:])
	if err != nil {
		t.Fatalf("the served receipt never passes through the anchor's root: %v", err)
	}
	if trimmed.Receipt != v.PageState.Receipt {
		t.Fatal("the stored receipt is not the served one cut at the anchor's root")
	}
	acct, pc, err := verifyPage(&v.PageState, root[:])
	if err != nil {
		t.Fatal(err)
	}
	if kp, ok := acct.(*protocol.KeyPage); !ok || !strings.EqualFold(kp.Url.String(), v.Page) {
		t.Fatalf("the proven account is %T %v", acct, acct.GetUrl())
	}
	if !pc.Bound || pc.MainHeight == 0 {
		t.Fatalf("the page's chains are not bound: %+v", pc)
	}
	if v.PageState.Partition != "acc://bvn-"+v.Partition+".acme" {
		t.Fatalf("the captured partition is %q", v.PageState.Partition)
	}

	// Attacks on the real data: another block's root, a flipped state, and a page claimed for a block the anchor is not for.
	other := root
	other[0] ^= 1
	if _, err := BindToAnchor(&served, v.Partition, v.Block, other); err == nil {
		t.Fatal("a page was bound to a root it does not pass through")
	} else if ns, ok := err.(*NamedState); !ok || ns.Code != StatePageBlockMismatch || ns.Partition != v.Partition || ns.Block != v.Block {
		t.Fatalf("the refusal is not the named page-block mismatch: %v", err)
	}
	forged := v.PageState
	forged.State = flipHexByte(forged.State, len(forged.State)/2-2)
	if _, _, err := verifyPage(&forged, root[:]); err == nil {
		t.Fatal("a page with a changed key was verified")
	}
}

// The routing table the network published when the page was captured routes the page to the partition it was read on.
func TestRealForeignPageVectorRoutesToItsPartition(t *testing.T) {
	v := loadVector(t, "bvn1-fdb-compliance-book2.json.gz")
	tbl := new(protocol.RoutingTable)
	if err := json.Unmarshal(v.Routing, tbl); err != nil {
		t.Fatal(err)
	}
	router, err := proof.NewNetworkRouter(tbl)
	if err != nil {
		t.Fatal(err)
	}
	id, err := router.PartitionID(v.Page)
	if err != nil {
		t.Fatal(err)
	}
	if id != v.Partition {
		t.Fatalf("the routing table routes %s to %s, the page was read on %s", v.Page, id, v.Partition)
	}
	// The lower-case form chain names use is unchanged.
	if lc, _ := router.Partition(v.Page); lc != strings.ToLower(v.Partition) {
		t.Fatalf("lower-case partition %q", lc)
	}
}

// Observed live on Kermit 2026-10-17 (this capture, 20:55-21:10 UTC): BVN2 and BVN3 had committed no anchor-bearing block for
// longer than their retention, so the last block the Directory had an anchor for left the retained range and can never be
// read. The refusal text is the node's own; it is a named state, with the advertised range.
func TestLiveLullIsHistoricalUnavailableNotACurrentRead(t *testing.T) {
	text := "request failed: no BPT history retained for block 14701204; this node's retained range is [14702572, 14702572]"
	calls := 0
	r := &PageReader{Poll: 1, Budget: 1e9, Read: func(context.Context, string, uint64) (*PageState, error) {
		calls++
		return nil, &liveErr{text}
	}}
	_, err := r.PageAt(context.Background(), "acc://fdb-risk-tcl1.acme/book/2", "BVN2", 14701204)
	ns, ok := err.(*NamedState)
	if !ok || ns.Code != StateHistoricalUnavailable || ns.Partition != "BVN2" || ns.Block != 14701204 || calls != 1 {
		t.Fatalf("got %v after %d reads", err, calls)
	}
	if !strings.Contains(ns.Detail, "[14702572, 14702572]") {
		t.Fatalf("the advertised range is missing from %q", ns.Detail)
	}
}

type liveErr struct{ s string }

func (e *liveErr) Error() string { return e.s }
