// Copyright 2026 Certen Protocol

package capture_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/capture"
	"github.com/certen/independant-validator/pkg/ethproof"
)

// TestRuntimeHopTicksFromE1ToE2VerifyWithTheRealVerifier: the whole path on a hops world with a gap of about 5 x W/2 - E1 stores the
// attestation and hands the anchor to the tick goroutine, the head moves over the ticks, E2 finds the stored hop chain through PlanLink,
// the rows assemble to the world's container byte for byte, and NewDefaultVerifier verifies it.
func TestRuntimeHopTicksFromE1ToE2VerifyWithTheRealVerifier(t *testing.T) {
	chain := uint64(11155111)
	h, _ := halfWindow(t, chain)
	fc := newFakeChainWith(t, chain, "hops", longEdit([]uint64{h, h, h, h, h + 2}))
	src := newHeadSource(fc, honest, honest)
	st := newSpy()
	deps := capture.Deps{Store: st, Manifest: fc.w.Manifest, Clock: ethproof.NewVirtualClock(time.Unix(1_700_000_000, 0)), TickPoll: 5 * time.Millisecond,
		SourceFor: func(uint64) (capture.AttestSource, error) { return src, nil }}
	rt, dis := capture.Start(context.Background(), enabled(), deps)
	if rt == nil || dis != nil {
		t.Fatalf("Start: %v", dis)
	}
	defer rt.Stop()
	facts := fc.facts(t)
	ctx := context.Background()
	rt.AttestationObserved(int64(chain), facts.AnchorID, fc.attTx, 0)
	waitFor(t, "the attestation row", func() bool {
		_, ok, _ := st.Store.Get(ctx, capture.Key{Chain: chain, AnchorID: facts.AnchorID, BlockHash: fc.w.BlockHashes["attest"], Item: capture.ItemAttest})
		return ok
	})
	count := func() int { st.mu.Lock(); defer st.mu.Unlock(); return len(st.puts) }
	base := count() // the attestation row
	for i, head := range fc.tickHeads() {
		src.setHead(head)
		want := base + (i + 1) + 1 // one tick row per head so far, and the first link made with the first tick
		waitFor(t, "the tick row of the head", func() bool { return count() >= want })
	}
	rt.SettlementObserved(int64(chain), fc.tx.Hash())
	waitFor(t, "the settlement row", func() bool {
		_, ok, _ := st.Store.Get(ctx, capture.Key{Chain: chain, AnchorID: facts.AnchorID, BlockHash: fc.w.BlockHashes["settle"], Item: capture.ItemSettle})
		return ok
	})
	att, err := capture.LoadAttest(ctx, st.Store, chain, facts.AnchorID, fc.w.BlockHashes["attest"])
	if err != nil || att == nil || att.Stated != nil {
		t.Fatalf("LoadAttest: %v %+v", err, att)
	}
	set, err := capture.LoadSettle(ctx, st.Store, chain, facts.AnchorID, fc.w.BlockHashes["settle"])
	if err != nil || set == nil || set.Stated != nil {
		t.Fatalf("LoadSettle: %v %+v", err, set)
	}
	plan, hc, err := capture.PlanLink(ctx, st.Store, fc.w.Manifest, chain, facts.AnchorID, att.Block, set.Block.Number)
	if err != nil || hc == nil || len(plan.HopNumbers) != 5 {
		t.Fatalf("PlanLink: %v %+v", err, plan)
	}
	part, err := capture.BuildAttestPartHops(ctx, src, att, fc.headers[set.Block.Number], plan, hc)
	if err != nil {
		t.Fatal(err)
	}
	_, container, err := capture.Assemble(capture.Parts{Chain: chain, Leg: set.Block, Facts: facts, Settle: set, Attest: part})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(container, fc.w.ContainerBytes) {
		t.Fatalf("the container assembled from the runtime's stored rows (%d B) differs from the world's (%d B)", len(container), len(fc.w.ContainerBytes))
	}
	v, err := ci.NewDefaultVerifier()
	if err != nil {
		t.Fatal(err)
	}
	rep, err := v.Verify(fc.w.Ctx, container, fc.w.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	requireAttestVerified(t, rep)
}
