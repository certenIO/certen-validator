// Copyright 2026 Certen Protocol

package capture_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/capture"
	"github.com/certen/independant-validator/pkg/contractidentity/world"
	"github.com/certen/independant-validator/pkg/ethproof"
)

// wholeLeg runs E1 and E2 against the fake, ties B_v to N the way the builder does, and assembles the container.
func wholeLeg(t *testing.T, fc *fakeChain, src *fakeSource) (container []byte, att *capture.AttestResult, set *capture.SettleResult, part *capture.AttestPart) {
	t.Helper()
	cfg := fc.config(src)
	att, err := capture.CaptureAttest(context.Background(), cfg, capture.AttestRequest{TxHash: fc.attTx})
	if err != nil || att.Stated != nil {
		t.Fatalf("CaptureAttest: %v %+v", err, att)
	}
	set, err = capture.CaptureSettle(context.Background(), cfg, fc.request())
	if err != nil || set.Stated != nil {
		t.Fatalf("CaptureSettle: %v %+v", err, set)
	}
	plan, err := capture.ChooseLink(fc.w.Manifest, fc.w.Spec.Chain, att.Block.Number, set.Block.Number, 0)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Link != fc.request().Link {
		t.Fatalf("the builder's link %d is not the world's link %d", plan.Link, fc.request().Link)
	}
	part, err = capture.BuildAttestPart(context.Background(), src, att, fc.headers[set.Block.Number], plan, nil)
	if err != nil {
		t.Fatalf("BuildAttestPart: %v", err)
	}
	_, container, err = capture.Assemble(capture.Parts{Chain: fc.w.Spec.Chain, Leg: set.Block, Facts: fc.facts(t), Settle: set, Attest: part})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	return container, att, set, part
}

func TestE1AssemblesTheWorldContainerByteForByte(t *testing.T) {
	for _, chain := range chains {
		for _, rich := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/rich=%v", chain, rich), func(t *testing.T) {
				var edit func(*world.Spec)
				if rich {
					edit = enrich
				}
				fc := newFakeChainWith(t, chain, "h0", edit)
				src, _ := fc.source(honest)
				got, att, _, _ := wholeLeg(t, fc, src)
				if !bytes.Equal(got, fc.w.ContainerBytes) {
					t.Fatalf("container built from E1 and E2 (%d B) differs from the world's (%d B)", len(got), len(fc.w.ContainerBytes))
				}
				if att.AnchorID != fc.facts(t).AnchorID || int(att.TxIndex) != int(fc.w.Container.Attest.Attest.TxIndex) || len(att.BlockTxs) != len(fc.w.Container.Attest.Attest.BlockTxs) {
					t.Fatalf("E1 result: anchor %x tx index %d block txs %d", att.AnchorID[:4], att.TxIndex, len(att.BlockTxs))
				}
			})
		}
	}
}

func TestE1IsDeterministicAndStoredCanonically(t *testing.T) {
	fc := newFakeChain(t, 11155111, "h0")
	var first []byte
	st := capture.NewMemStore()
	var wg sync.WaitGroup
	errs := make([]error, 7)
	rows := make([][]byte, 7)
	for i := 0; i < 7; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			modes := []hostile{honest, pruned, honest, lieSlot, honest}
			src, _ := fc.source(modes[i%3:]...)
			cfg := fc.config(src)
			cfg.Parallel = 1 + i%4
			res, err := capture.CaptureAttest(context.Background(), cfg, capture.AttestRequest{TxHash: fc.attTx})
			if err == nil {
				rows[i], err = capture.EncodeAttest(res)
			}
			if err == nil {
				err = capture.SaveAttest(context.Background(), st, res)
			}
			errs[i] = err
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("validator %d: %v", i, err)
		}
		if first == nil {
			first = rows[i]
		} else if !bytes.Equal(first, rows[i]) {
			t.Fatalf("validator %d wrote a different row", i)
		}
	}
	res, err := capture.LoadAttest(context.Background(), st, 11155111, fc.facts(t).AnchorID, fc.w.BlockHashes["attest"])
	if err != nil || res == nil || res.Stated != nil {
		t.Fatalf("LoadAttest = %+v, %v", res, err)
	}
	if again, _ := capture.EncodeAttest(res); !bytes.Equal(again, first) {
		t.Fatal("encode(decode(row)) != row")
	}
	for i := 4; i < len(first); i += 211 {
		mut := append([]byte(nil), first...)
		mut[i] ^= 0xff
		if d, err := capture.DecodeAttest(mut); err == nil {
			if again, e2 := capture.EncodeAttest(d); e2 != nil || !bytes.Equal(again, mut) {
				t.Fatalf("a mutated attest row decoded to something that does not re-encode to it (byte %d)", i)
			}
		}
	}
	for _, bad := range [][]byte{first[:len(first)-1], append(append([]byte(nil), first...), 0), nil} {
		if _, err := capture.DecodeAttest(bad); err == nil {
			t.Fatal("accepted a malformed attest row")
		}
	}
}

func TestE1ProviderLiesAreNotKept(t *testing.T) {
	for name, mode := range map[string]hostile{"proof of another slot": lieSlot, "wrong value": lieValue, "another block's state": lieBlock, "wrong code": lieCode, "padding": padNodes, "oversize": hugeReply} {
		t.Run(name, func(t *testing.T) {
			fc := newFakeChain(t, 421614, "h0")
			src, _ := fc.source(mode, honest)
			got, _, _, _ := wholeLeg(t, fc, src)
			if !bytes.Equal(got, fc.w.ContainerBytes) {
				t.Fatal("a lie changed the evidence")
			}
			src, _ = fc.source(mode)
			if mode == padNodes {
				return // padding verifies; it is pruned, not refused
			}
			res, err := capture.CaptureAttest(context.Background(), fc.config(src), capture.AttestRequest{TxHash: fc.attTx})
			if err != nil || res.Stated == nil || res.Stated.Reason != ci.StatedAttestBlockStateUnavailable || len(res.Nodes) != 0 || len(res.Codes) != 0 || len(res.BlockTxs) != 0 {
				t.Fatalf("liar alone: %v %+v", err, res)
			}
			if res.Stated.JudgedBlock != fc.w.Spec.Blocks.Attest.Number || len(res.Stated.Failures) != 1 {
				t.Fatalf("Stated %+v", res.Stated)
			}
		})
	}
}

func TestE1StatedOutcomes(t *testing.T) {
	fc := newFakeChain(t, 2017, "h0")
	bv := fc.w.Spec.Blocks.Attest.Number
	ctx := context.Background()
	t.Run("the parent state is not served (Adiri depth 1)", func(t *testing.T) {
		src, _ := fc.source(prunedPre, prunedPre)
		res, err := capture.CaptureAttest(ctx, fc.config(src), capture.AttestRequest{TxHash: fc.attTx})
		if err != nil || res.Stated == nil || res.Stated.Reason != ci.StatedAttestBlockStateUnavailable || res.Stated.JudgedBlock != bv ||
			res.Stated.JudgedHash != [32]byte(fc.w.BlockHashes["attest"]) || len(res.Stated.Failures) != 2 || len(res.Nodes) != 0 {
			t.Fatalf("%v %+v", err, res)
		}
		// the part is assembled as a Stated part; the settle part is captured on its own
		sset, _ := fc.source(honest)
		set, err := capture.CaptureSettle(ctx, fc.config(sset), fc.request())
		if err != nil || set.Stated != nil {
			t.Fatal(err, set)
		}
		part, err := capture.BuildAttestPart(ctx, sset, res, fc.headers[set.Block.Number], capture.LinkPlan{Link: ci.LinkSpine}, nil)
		if err != nil || part.Stated == nil {
			t.Fatalf("%v %+v", err, part)
		}
		if _, _, err := capture.Assemble(capture.Parts{Chain: 2017, Leg: set.Block, Facts: fc.facts(t), Settle: set, Attest: part}); err != nil {
			t.Fatalf("settle captured, attest Stated: %v", err)
		}
	})
	t.Run("no ProofExecuted log", func(t *testing.T) {
		src, _ := fc.source(honest)
		none := []*types.Log{}
		src.attestLogs = &none
		res, err := capture.CaptureAttest(ctx, fc.config(src), capture.AttestRequest{TxHash: fc.attTx, AnchorID: common.Hash{1}})
		if err != nil || res.Stated == nil || res.Stated.Reason != ci.StatedAttestEventNotFound || res.AnchorID != (common.Hash{1}) {
			t.Fatalf("%v %+v", err, res)
		}
		if err := capture.SaveAttest(ctx, capture.NewMemStore(), res); err != nil {
			t.Fatalf("a Stated attest result is storable under the trigger's anchor id: %v", err)
		}
	})
	t.Run("a failed transaction is no attestation", func(t *testing.T) {
		src, _ := fc.source(honest)
		zero := uint64(0)
		src.attestStatus = &zero
		if _, err := capture.CaptureAttest(ctx, fc.config(src), capture.AttestRequest{TxHash: fc.attTx}); !errors.Is(err, capture.ErrNotAttestation) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("blocks over the caps are Stated, never truncated", func(t *testing.T) {
		lim := ci.DefaultLimits()
		txs, rcs, _ := fc.w.BlockLists("attest")
		hdr := fc.headers[bv]
		for _, c := range []struct {
			name   string
			txs    [][]byte
			detail string
		}{
			{"count", func() [][]byte {
				out := append([][]byte(nil), txs...)
				for len(out) <= lim.MaxBlockTxs {
					out = append(out, []byte{1})
				}
				return out
			}(), fmt.Sprintf("txs=%d;limit=%d", lim.MaxBlockTxs+1, lim.MaxBlockTxs)},
			{"bytes", [][]byte{bytes.Repeat([]byte{1}, lim.MaxBlockTxsBytes+1)}, fmt.Sprintf("bytes=%d;limit=%d", lim.MaxBlockTxsBytes+1, lim.MaxBlockTxsBytes)},
		} {
			src, _ := fc.source(honest)
			src.oversize = &ethproof.Block{Header: hdr, Txs: c.txs, Receipts: rcs}
			res, err := capture.CaptureAttest(ctx, fc.config(src), capture.AttestRequest{TxHash: fc.attTx})
			if err != nil || res.Stated == nil || res.Stated.Reason != ci.StatedBlockTooLarge || res.Stated.Detail != c.detail || len(res.BlockTxs) != 0 {
				t.Fatalf("%s: %v %+v", c.name, err, res)
			}
		}
		// the exact boundary: 4096 transactions and 1 MiB are accepted by the caps (the block is then judged on its roots)
		src, _ := fc.source(honest)
		edge := make([][]byte, lim.MaxBlockTxs)
		for i := range edge {
			edge[i] = []byte{1}
		}
		src.oversize = &ethproof.Block{Header: hdr, Txs: edge, Receipts: rcs}
		if res, err := capture.CaptureAttest(ctx, fc.config(src), capture.AttestRequest{TxHash: fc.attTx}); res != nil && res.Stated != nil && res.Stated.Reason == ci.StatedBlockTooLarge {
			t.Fatalf("4096 transactions refused as too large: %v", err)
		}
	})
}

func TestE1ParallelServeEqualsSequentialAndLeaksNothing(t *testing.T) {
	fc := newFakeChain(t, 84532, "h0")
	base := runtime.NumGoroutine()
	var want []byte
	for _, par := range []int{1, 2, 4, 8} {
		src, _ := fc.source(honest, honest, pruned)
		cfg := fc.config(src)
		cfg.Parallel = par
		for i := 0; i < 5; i++ {
			res, err := capture.CaptureAttest(context.Background(), cfg, capture.AttestRequest{TxHash: fc.attTx})
			if err != nil || res.Stated != nil {
				t.Fatalf("parallel %d: %v %+v", par, err, res)
			}
			row, _ := capture.EncodeAttest(res)
			if want == nil {
				want = row
			} else if !bytes.Equal(want, row) {
				t.Fatalf("parallel %d wrote another row", par)
			}
		}
	}
	// a failing provider ends a parallel pass with the first error and still joins every goroutine
	src, _ := fc.source(down, down)
	cfg := fc.config(src)
	cfg.Parallel, cfg.Clock, cfg.Backoff = 4, ethproof.NewVirtualClock(time.Unix(1_700_000_000, 0)), time.Millisecond
	if res, err := capture.CaptureAttest(context.Background(), cfg, capture.AttestRequest{TxHash: fc.attTx}); err != nil || res.Stated == nil {
		t.Fatalf("%v %+v", err, res)
	}
	time.Sleep(50 * time.Millisecond)
	if n := runtime.NumGoroutine(); n > base+1 {
		t.Fatalf("goroutines: %d before, %d after", base, n)
	}
}

func TestE1ProviderThatFailedIsAskedLast(t *testing.T) {
	fc := newFakeChain(t, 11155111, "h0")
	src, ps := fc.source(down, honest)
	if _, err := capture.CaptureAttest(context.Background(), fc.config(src), capture.AttestRequest{TxHash: fc.attTx}); err != nil {
		t.Fatal(err)
	}
	if ps[0].count() != 1 || ps[1].count() < 6 {
		t.Fatalf("the failing provider was asked %d times, the honest one %d: after its first failure it must be asked last", ps[0].count(), ps[1].count())
	}
}

func TestChooseLinkBoundariesAreExact(t *testing.T) {
	m, _ := ci.Embedded()
	type c struct {
		chain  uint64
		gap    uint64
		link   uint8
		window uint64 // out of reach when non-zero
	}
	for _, tc := range []c{
		{11155111, 0, ci.LinkSameBlock, 0}, {11155111, 1, ci.LinkSpine, 0}, {11155111, 16, ci.LinkSpine, 0}, {11155111, 17, ci.LinkHops, 0},
		{11155111, 8191, ci.LinkHops, 0}, {11155111, 8192, 0, 8191},
		{84532, 8191, ci.LinkHops, 0}, {84532, 8192, 0, 8191},
		{421614, 393168, ci.LinkHops, 0}, {421614, 393169, 0, 393168},
		{2017, 17, ci.LinkHops, 0}, {2017, 8192, 0, 8191},
	} {
		bv := uint64(1000)
		p, err := capture.ChooseLink(m, tc.chain, bv, bv+tc.gap, 0)
		var oor *capture.OutOfReachError
		switch {
		case tc.window != 0:
			if !errors.As(err, &oor) || oor.Gap != tc.gap || oor.Window != tc.window || oor.HopsCarried != 0 || oor.LastHop != bv {
				t.Fatalf("chain %d gap %d: %v", tc.chain, tc.gap, err)
			}
			st := capture.OutOfReachStated(oor, ci.BlockRef{Number: bv, Hash: [32]byte{1}})
			if st.Reason != ci.StatedAttestBlockOutOfReach || st.Detail != fmt.Sprintf("gap=%d;window=%d;hops_carried=0;last_hop=%d", tc.gap, tc.window, bv) {
				t.Fatalf("Stated %+v", st)
			}
		case err != nil || p.Link != tc.link:
			t.Fatalf("chain %d gap %d: %+v %v", tc.chain, tc.gap, p, err)
		case tc.link == ci.LinkHops && (len(p.HopNumbers) != 1 || p.HopNumbers[0] != bv):
			t.Fatalf("hop numbers %v", p.HopNumbers)
		}
	}
	if _, err := capture.ChooseLink(m, 11155111, 10, 9, 0); err == nil {
		t.Fatal("a settlement before the attestation was linked")
	}
}

func TestBuildAttestPartRefusesABlockThatIsNotAnAncestor(t *testing.T) {
	fc := newFakeChain(t, 11155111, "h0")
	src, _ := fc.source(honest)
	att, err := capture.CaptureAttest(context.Background(), fc.config(src), capture.AttestRequest{TxHash: fc.attTx})
	if err != nil {
		t.Fatal(err)
	}
	set := fc.headers[fc.w.Spec.Blocks.Settle.Number]
	// link 0 only when B_v is the settlement block itself
	if _, err := capture.BuildAttestPart(context.Background(), src, att, set, capture.LinkPlan{Link: ci.LinkSameBlock}, nil); !errors.Is(err, capture.ErrNotAncestor) {
		t.Fatalf("link 0 over another block: %v", err)
	}
	// a settlement header on another fork: its parent chain does not reach B_v
	forked := types.CopyHeader(set)
	forked.ParentHash = common.Hash{9}
	if _, err := capture.BuildAttestPart(context.Background(), src, att, forked, capture.LinkPlan{Link: ci.LinkSpine}, nil); err == nil {
		t.Fatal("a spine over an unknown parent was built")
	}
	// a hop plan needs its hop headers
	if _, err := capture.BuildAttestPart(context.Background(), src, att, set, capture.LinkPlan{Link: ci.LinkHops, HopNumbers: []uint64{att.Block.Number, att.Block.Number + 1}}, nil); err == nil {
		t.Fatal("a hop plan without its hop headers was built")
	}
	if _, err := capture.BuildAttestPart(context.Background(), src, att, set, capture.LinkPlan{Link: 9}, nil); err == nil {
		t.Fatal("an unknown link was built")
	}
}
