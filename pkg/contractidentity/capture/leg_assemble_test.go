// Copyright 2026 Certen Protocol

package capture_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/capture"
)

// WP-S8-7: the runtime hands every finished leg to Deps.OnLeg; AssembleParts builds the Parts from the runtime's own results and the stored
// rows; the container is the world's byte for byte, and the REAL verifier behind the Appender accepts it (the DB step is the repository sink,
// proved on PostgreSQL in pkg/database and in the validator's finisher test).
func TestRuntimeHandsTheFinishedLegToTheAssemblyAndTheRealVerifyAcceptsTheContainer(t *testing.T) {
	ctx := context.Background()
	fc := newFakeChain(t, 11155111, "h0")
	st := capture.NewMemStore()
	legs := make(chan capture.CapturedLeg, 4)
	d := baseDeps(fc, st)
	d.OnLeg = func(l capture.CapturedLeg) { legs <- l }
	rt, dis := capture.Start(ctx, enabled(), d)
	if rt == nil || dis != nil {
		t.Fatalf("Start: %v", dis)
	}
	defer rt.Stop()
	facts := fc.facts(t)
	chain := int64(fc.w.Spec.Chain)
	rt.AttestationObserved(chain, facts.AnchorID, fc.attTx, 0)
	waitFor(t, "the attestation row", func() bool {
		_, ok, _ := st.Get(ctx, capture.Key{Chain: fc.w.Spec.Chain, AnchorID: facts.AnchorID, BlockHash: fc.w.BlockHashes["attest"], Item: capture.ItemAttest})
		return ok
	})
	rt.SettlementObserved(chain, fc.tx.Hash())
	var leg capture.CapturedLeg
	select {
	case leg = <-legs:
	case <-time.After(30 * time.Second):
		t.Fatal("the runtime never handed the finished leg to OnLeg")
	}
	if leg.Chain != fc.w.Spec.Chain || leg.Tx != fc.tx.Hash() || leg.AnchorID != facts.AnchorID || leg.Settle == nil || leg.Attest == nil || leg.Source == nil {
		t.Fatalf("the leg: %+v", leg)
	}
	parts, err := capture.AssembleParts(ctx, st, fc.w.Manifest, leg)
	if err != nil {
		t.Fatal(err)
	}
	_, raw, err := capture.Assemble(parts)
	if err != nil || !bytes.Equal(raw, fc.w.ContainerBytes) {
		t.Fatalf("the production assembly must build the world container byte for byte: %v", err)
	}
	v, err := ci.NewDefaultVerifier()
	if err != nil {
		t.Fatal(err)
	}
	sink := &recordingSink{}
	ap, err := capture.NewAppender(sink, v, fc.w.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ap.Append(ctx, fc.w.Ctx, parts); err != nil || len(sink.rows) != 1 || !bytes.Equal(sink.rows[0], raw) {
		t.Fatalf("the real Verify must accept the assembled leg and the sink receive it once: %v rows %d", err, len(sink.rows))
	}

	// a leg whose attestation station holds nothing, and a leg whose settle part is Stated, assemble into Stated parts the verifier accepts as unproven
	noAtt := leg
	noAtt.Attest = nil
	pa, err := capture.AssembleParts(ctx, st, fc.w.Manifest, noAtt)
	if err != nil || pa.Attest == nil || pa.Attest.Stated == nil || pa.Attest.Stated.Reason != "attest_block_state_unavailable" {
		t.Fatalf("no attestation capture: %+v %v", pa.Attest, err)
	}
	if _, _, err := capture.Assemble(pa); err != nil {
		t.Fatal(err)
	}
	stated := leg
	stated.Settle = capture.NotAttempted(leg.Chain, leg.AnchorID, leg.Settle.Block, "stated for the test")
	ps, err := capture.AssembleParts(ctx, st, fc.w.Manifest, stated)
	if err != nil || ps.Settle.Stated == nil || ps.Attest.Stated == nil {
		t.Fatalf("stated settle: %+v %v", ps, err)
	}
	if _, err := capture.AssembleParts(ctx, st, fc.w.Manifest, capture.CapturedLeg{Chain: leg.Chain}); err == nil {
		t.Fatal("a leg without a settle result is refused")
	}
}
