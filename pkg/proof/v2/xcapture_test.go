// Copyright 2026 Certen Protocol

package proofv2

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	acerrors "gitlab.com/accumulatenetwork/accumulate/pkg/errors"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// ---- block selection -------------------------------------------------------------------------------------------------

type sliceLog struct {
	dn     []uint64 // the Directory block that executed anchor i
	blocks []uint64 // the partition block anchor i is for
}

func (l sliceLog) Len(context.Context, string) (uint64, error) { return uint64(len(l.dn)), nil }
func (l sliceLog) DNBlock(_ context.Context, _ string, i uint64) (uint64, error) {
	return l.dn[i], nil
}
func (l sliceLog) Block(_ context.Context, _ string, i uint64) (uint64, error) {
	return l.blocks[i], nil
}
func (l sliceLog) Produced(_ context.Context, p string, i uint64) (*protocol.Transaction, error) {
	return &protocol.Transaction{Body: &protocol.BlockValidatorAnchor{PartitionAnchor: protocol.PartitionAnchor{
		Source: protocol.PartitionUrl(p), MinorBlockIndex: l.blocks[i], RootChainIndex: i}}}, nil
}

func TestSelectPartitionBlockBoundaries(t *testing.T) {
	l := sliceLog{dn: []uint64{100, 110, 120, 130}, blocks: []uint64{5000, 5010, 5020, 5030}}
	cases := []struct {
		name         string
		limit, bound uint64
		wantIdx      uint64
		wantBlock    uint64
		wantCode     string
	}{
		{"limit before the first anchor", 99, 0, 0, 0, StatePartitionAnchorUnavailable},
		{"limit at the first anchor", 100, 0, 0, 5000, ""},
		{"limit between anchors takes the earlier", 119, 0, 1, 5010, ""},
		{"limit at an anchor takes it", 120, 0, 2, 5020, ""},
		{"limit after the last takes the last", 9999, 0, 3, 5030, ""},
		{"a bound selects the smallest block at or after it", 9999, 5011, 2, 5020, ""},
		{"a bound equal to a block selects that block", 9999, 5010, 1, 5010, ""},
		{"a bound under the first selects the first", 9999, 1, 0, 5000, ""},
		{"a bound is clipped by the limit and refused when beyond it", 119, 5011, 0, 0, StateBlockBeforeArrival},
		{"a bound at the limit's block is fine", 119, 5010, 1, 5010, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pb, err := SelectPartitionBlock(context.Background(), l, "BVN2", c.limit, c.bound)
			if c.wantCode != "" {
				var ns *NamedState
				if !errors.As(err, &ns) || ns.Code != c.wantCode || ns.Partition != "BVN2" {
					t.Fatalf("got %v, want %s", err, c.wantCode)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if pb.Index != c.wantIdx || pb.Block != c.wantBlock {
				t.Fatalf("selected index %d block %d, want %d / %d", pb.Index, pb.Block, c.wantIdx, c.wantBlock)
			}
		})
	}
	// No anchors at all.
	if _, err := SelectPartitionBlock(context.Background(), sliceLog{}, "BVN2", 100, 0); err == nil || !strings.Contains(err.Error(), StatePartitionAnchorUnavailable) {
		t.Fatalf("a partition with no anchor gave %v", err)
	}
	// NextPartitionBlock walks to the next admissible anchor and stops at the last.
	pb, _ := SelectPartitionBlock(context.Background(), l, "BVN2", 129, 5001)
	if pb.Block != 5010 || pb.Latest != 2 {
		t.Fatalf("selected %+v", pb)
	}
	n1, err := NextPartitionBlock(context.Background(), l, pb)
	if err != nil || n1.Block != 5020 {
		t.Fatalf("next: %+v %v", n1, err)
	}
	if _, err := NextPartitionBlock(context.Background(), l, n1); err == nil || !strings.Contains(err.Error(), StateHistoricalUnavailable) {
		t.Fatalf("past the last admissible anchor gave %v", err)
	}
}

// ---- retention-aware page reads --------------------------------------------------------------------------------------

func TestPageReaderNamesWhatItCannotRead(t *testing.T) {
	const bvn, blk = "BVN2", uint64(14004595)
	ok := &PageState{URL: "acc://fdb-risk-tcl1.acme/book/2"}
	run := func(read func(n int) (*PageState, error), ret Retention, budget time.Duration) (*PageState, error, int) {
		calls := 0
		r := &PageReader{Retention: ret, Poll: time.Millisecond, Budget: budget,
			Read: func(context.Context, string, uint64) (*PageState, error) { calls++; return read(calls) }}
		p, err := r.PageAt(context.Background(), "acc://fdb-risk-tcl1.acme/book/2", bvn, blk)
		return p, err, calls
	}
	notReady := acerrors.NotReady.WithFormat("block %d is beyond this node's latest indexed block %d", blk, blk-1)
	below := acerrors.IncompleteChain.WithFormat("no BPT history retained for block %d; this node's retained range is [%d, %d]", blk, blk+10, blk+900)
	newest := acerrors.IncompleteChain.WithFormat("no BPT history retained for block %d; this node's retained range is [%d, %d]", blk, blk-800, blk+5)

	t.Run("not ready, then servable", func(t *testing.T) {
		p, err, calls := run(func(n int) (*PageState, error) {
			if n < 4 {
				return nil, notReady
			}
			return ok, nil
		}, nil, time.Second)
		if err != nil || p != ok || calls != 4 {
			t.Fatalf("got %v %v after %d calls", p, err, calls)
		}
	})
	t.Run("the newest block is incomplete until the partition commits again", func(t *testing.T) {
		p, err, calls := run(func(n int) (*PageState, error) {
			if n < 3 {
				return nil, newest
			}
			return ok, nil
		}, nil, time.Second)
		if err != nil || p != ok || calls != 3 {
			t.Fatalf("got %v %v after %d calls", p, err, calls)
		}
	})
	t.Run("below the retained range is permanent", func(t *testing.T) {
		_, err, calls := run(func(int) (*PageState, error) { return nil, below }, nil, time.Second)
		var ns *NamedState
		if !errors.As(err, &ns) || ns.Code != StateHistoricalUnavailable || ns.Partition != bvn || ns.Block != blk || calls != 1 {
			t.Fatalf("got %v after %d calls", err, calls)
		}
		if !strings.Contains(ns.Detail, fmt.Sprintf("[%d, %d]", blk+10, blk+900)) {
			t.Fatalf("the advertised range is not reported: %s", ns.Detail)
		}
	})
	t.Run("below the advertised range, from the advertisement", func(t *testing.T) {
		_, err, _ := run(func(int) (*PageState, error) { return nil, acerrors.IncompleteChain.With("no BPT history") },
			fixedRetention{blk + 1, blk + 900}, time.Second)
		var ns *NamedState
		if !errors.As(err, &ns) || ns.Code != StateHistoricalUnavailable {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("still not ready at the horizon", func(t *testing.T) {
		_, err, calls := run(func(int) (*PageState, error) { return nil, notReady }, nil, 30*time.Millisecond)
		var ns *NamedState
		if !errors.As(err, &ns) || ns.Code != StateNotReady || ns.Partition != bvn || ns.Block != blk || calls < 2 {
			t.Fatalf("got %v after %d calls", err, calls)
		}
	})
	t.Run("incomplete forever with no range known is historical at the horizon", func(t *testing.T) {
		_, err, _ := run(func(int) (*PageState, error) { return nil, acerrors.IncompleteChain.With("no BPT history") }, nil, 30*time.Millisecond)
		var ns *NamedState
		if !errors.As(err, &ns) || ns.Code != StateHistoricalUnavailable {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("the refusal survives a hop that reduced the status to its text", func(t *testing.T) {
		_, err, _ := run(func(int) (*PageState, error) {
			return nil, errors.New("jsonrpc: no BPT history retained for block 14004595; this node's retained range is [14004600, 14005000]")
		}, nil, time.Second)
		var ns *NamedState
		if !errors.As(err, &ns) || ns.Code != StateHistoricalUnavailable {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("any other error is returned as it is, with where it was", func(t *testing.T) {
		boom := errors.New("connection reset")
		_, err, calls := run(func(int) (*PageState, error) { return nil, boom }, nil, time.Second)
		if !errors.Is(err, boom) || calls != 1 || !strings.Contains(err.Error(), "BVN2 block 14004595") {
			t.Fatalf("got %v after %d calls", err, calls)
		}
	})
}

type fixedRetention struct{ e, l uint64 }

func (f fixedRetention) Retained(context.Context, string) (uint64, uint64, error) {
	return f.e, f.l, nil
}

// ---- the anchor the Directory executed -------------------------------------------------------------------------------

type chainFake struct {
	t        *testing.T
	pool     *url.URL
	txn      *protocol.Transaction // as produced
	hash     [32]byte              // as delivered
	source   *url.URL              // the delivered message's source
	missing  bool
	badStart bool
	short    *merkle.Receipt // ForAny receipt
	long     *merkle.Receipt // ForHeight receipt
}

func step(h []byte, e *merkle.ReceiptEntry) []byte {
	var s [32]byte
	if e.Right {
		s = sha256.Sum256(append(append([]byte(nil), h...), e.Hash...))
	} else {
		s = sha256.Sum256(append(append([]byte(nil), e.Hash...), h...))
	}
	return s[:]
}

func mkReceipt(start []byte, sib ...string) *merkle.Receipt {
	r := &merkle.Receipt{Start: start}
	h := start
	for i, s := range sib {
		e := &merkle.ReceiptEntry{Hash: sha256Of(s), Right: i%2 == 0}
		r.Entries = append(r.Entries, e)
		h = step(h, e)
	}
	r.Anchor = h
	return r
}

func sha256Of(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }

func newChainFake(t *testing.T, partition string, block uint64) (*chainFake, *PartitionBlock) {
	pool := protocol.DnUrl().JoinPath(protocol.AnchorPool)
	body := &protocol.BlockValidatorAnchor{PartitionAnchor: protocol.PartitionAnchor{
		Source: protocol.PartitionUrl(partition), MinorBlockIndex: block, RootChainIndex: 9,
		RootChainAnchor: sha256.Sum256([]byte("root")), StateTreeAnchor: sha256.Sum256([]byte("state"))}}
	txn := &protocol.Transaction{Body: body}
	f := &chainFake{t: t, pool: pool, txn: txn, source: protocol.PartitionUrl(partition)}
	delivered := txn.Copy()
	delivered.Header.Principal = pool
	f.hash = delivered.Hash()
	f.short = mkReceipt(f.hash[:], "a", "b", "c")
	f.long = mkReceipt(f.hash[:], "a", "b", "c", "d", "e")
	return f, &PartitionBlock{Partition: partition, Block: block, Index: 9, Txn: txn, Anchor: body}
}

func (f *chainFake) Query(_ context.Context, scope *url.URL, q api.Query) (api.Record, error) {
	switch q := q.(type) {
	case *api.DefaultQuery:
		return &api.AccountRecord{Account: &protocol.DataAccount{Url: f.pool}}, nil
	case *api.ChainQuery:
		if f.missing {
			return nil, acerrors.NotFound.With("anchor not found")
		}
		delivered := f.txn.Copy()
		delivered.Header.Principal = f.pool
		ce := &api.ChainEntryRecord[api.Record]{Name: "main", Index: 77, Entry: f.hash,
			Value: &api.MessageRecord[messaging.Message]{
				Message:  &messaging.TransactionMessage{Transaction: delivered},
				Status:   acerrors.Delivered,
				Sequence: &messaging.SequencedMessage{Source: f.source, Destination: protocol.DnUrl(), Number: 12},
			}}
		r := f.short
		if q.IncludeReceipt != nil && q.IncludeReceipt.ForHeight > 0 {
			r = f.long
		}
		rc := *r
		if f.badStart {
			rc.Start = sha256Of("not the anchor")
		}
		ce.Receipt = &api.Receipt{Receipt: rc, LocalBlock: 4242}
		return ce, nil
	}
	return nil, fmt.Errorf("unexpected query %T", q)
}

// The foreign partition's anchor is returned as the Directory executed it, with the receipt to the certified root asked for.
func TestAnchorAtProvesTheForeignAnchorIntoTheCertifiedRoot(t *testing.T) {
	f, pb := newChainFake(t, "BVN2", 14004595)
	a, h, err := AnchorAt(context.Background(), f, pb, 0)
	if err != nil {
		t.Fatal(err)
	}
	if h != f.hash {
		t.Fatalf("anchor hash %x, want %x", h, f.hash)
	}
	body, seq, txh, err := anchorBody(a.Message)
	if err != nil {
		t.Fatal(err)
	}
	if body.MinorBlockIndex != 14004595 || seq.Source.String() != "acc://bvn-BVN2.acme" || !bytes.Equal(txh, f.hash[:]) {
		t.Fatalf("anchor message: block %d from %v", body.MinorBlockIndex, seq.Source)
	}
	r, err := decodeReceipt(a.Receipt)
	if err != nil || !bytes.Equal(r.Start, f.hash[:]) || !bytes.Equal(r.Anchor, f.short.Anchor) || !r.Validate(nil) {
		t.Fatalf("receipt: %v", err)
	}
	// Asked for the root at a height, the receipt ends there, not at the root the node chose.
	a, _, err = AnchorAt(context.Background(), f, pb, 1000)
	if err != nil {
		t.Fatal(err)
	}
	r, _ = decodeReceipt(a.Receipt)
	if !bytes.Equal(r.Anchor, f.long.Anchor) || bytes.Equal(r.Anchor, f.short.Anchor) || !r.Validate(nil) {
		t.Fatal("the receipt does not end at the certified root asked for")
	}
}

// An anchor the Directory delivered from another partition is not the claimed partition's: refused by name.
func TestAnchorAtRefusesAPartitionThatIsNotTheAnchorsSource(t *testing.T) {
	f, pb := newChainFake(t, "BVN2", 14004595)
	f.source = protocol.PartitionUrl("BVN3")
	_, _, err := AnchorAt(context.Background(), f, pb, 0)
	var ns *NamedState
	if !errors.As(err, &ns) || ns.Code != StateForeignPartitionMismatch || ns.Partition != "BVN2" || ns.Block != 14004595 {
		t.Fatalf("an anchor from another partition gave %v", err)
	}
}

func TestAnchorAtNamesAnAnchorTheDirectoryHasNotExecuted(t *testing.T) {
	f, pb := newChainFake(t, "BVN2", 14004595)
	f.missing = true
	_, _, err := AnchorAt(context.Background(), f, pb, 0)
	var ns *NamedState
	if !errors.As(err, &ns) || ns.Code != StatePartitionAnchorUnavailable || ns.Partition != "BVN2" || ns.Block != 14004595 {
		t.Fatalf("an unexecuted anchor gave %v", err)
	}
}

func TestAnchorAtRefusesAReceiptThatDoesNotProveTheAnchor(t *testing.T) {
	f, pb := newChainFake(t, "BVN2", 14004595)
	f.badStart = true
	if _, _, err := AnchorAt(context.Background(), f, pb, 0); err == nil || !strings.Contains(err.Error(), "does not prove the anchor") {
		t.Fatalf("a receipt for another leaf gave %v", err)
	}
	// And an anchor the Directory executed for another block than the one selected.
	f, pb = newChainFake(t, "BVN2", 14004595)
	pb.Block = 14004596
	if _, _, err := AnchorAt(context.Background(), f, pb, 0); err == nil || !strings.Contains(err.Error(), "different anchor") {
		t.Fatalf("an anchor for another block gave %v", err)
	}
}

// ---- reading a page at a block ---------------------------------------------------------------------------------------

type pageFake struct {
	acct    protocol.Account // served
	receipt *merkle.Receipt
}

func (p pageFake) Query(_ context.Context, _ *url.URL, q api.Query) (api.Record, error) {
	return &api.AccountRecord{Account: p.acct, Receipt: &api.Receipt{Receipt: *p.receipt, StartsAtMainState: true}}, nil
}

type noChains struct{}

func (noChains) Query(context.Context, any) (json.RawMessage, error) {
	return nil, errors.New("no chains")
}

// A node that serves a book with its PageCount understated (so the page it hides is never captured) cannot prove it: the
// receipt starts at the hash of the true state.
func TestCapturePageRefusesAForeignBookWithItsPageCountUnderstated(t *testing.T) {
	book := &protocol.KeyBook{Url: url.MustParse("acc://fdb-risk-tcl1.acme/book"), PageCount: 2}
	trueState, _ := book.MarshalBinary()
	start := sha256.Sum256(trueState)
	r := mkReceipt(start[:], "x", "y", "z")

	honest, err := capturePageWith(context.Background(), pageFake{acct: book, receipt: r}, noChains{}, "acc://fdb-risk-tcl1.acme/book", 100)
	if err != nil || honest.State != hex.EncodeToString(trueState) {
		t.Fatalf("the honest book: %v", err)
	}

	forged := book.Copy()
	forged.PageCount = 1
	if _, err := capturePageWith(context.Background(), pageFake{acct: forged, receipt: r}, noChains{}, "acc://fdb-risk-tcl1.acme/book", 100); err == nil ||
		!strings.Contains(err.Error(), "does not prove the served state") {
		t.Fatalf("a book with PageCount understated gave %v", err)
	}
}

// A page served for a block other than the one asked for passes through that other block's root, not the anchor's.
func TestBindToAnchorRefusesAPageOfAnotherBlock(t *testing.T) {
	acct := &protocol.KeyPage{Url: url.MustParse("acc://fdb-risk-tcl1.acme/book/2"), AcceptThreshold: 1}
	st, _ := acct.MarshalBinary()
	start := sha256.Sum256(st)
	// A receipt through the root of block 100 and on; the anchor for block 101 carries another root.
	r := mkReceipt(start[:], "p", "q", "r", "s")
	rb, _ := r.MarshalBinary()
	p := &PageState{URL: acct.Url.String(), State: hex.EncodeToString(st), Receipt: hex.EncodeToString(rb)}

	// Its root at the third step is the anchor of the block it was read at.
	third := start[:]
	for _, e := range r.Entries[:3] {
		third = step(third, e)
	}
	var root [32]byte
	copy(root[:], third)
	trimmed, err := BindToAnchor(p, "BVN2", 100, root)
	if err != nil {
		t.Fatal(err)
	}
	tr, _ := decodeReceipt(trimmed.Receipt)
	if len(tr.Entries) != 3 || !bytes.Equal(tr.Anchor, root[:]) || !tr.Validate(nil) {
		t.Fatal("the page is not trimmed to the anchor's root")
	}
	_, err = BindToAnchor(p, "BVN2", 101, sha256.Sum256([]byte("the root of block 101")))
	var ns *NamedState
	if !errors.As(err, &ns) || ns.Code != StatePageBlockMismatch || ns.Partition != "BVN2" || ns.Block != 101 {
		t.Fatalf("a page of another block gave %v", err)
	}
}
