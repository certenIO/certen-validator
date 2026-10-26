// Copyright 2026 Certen Protocol

package capture_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/capture"
)

type recordingSink struct {
	mu   sync.Mutex
	rows [][]byte
}

func (s *recordingSink) AppendContainer(_ context.Context, _ uint64, _ ci.BlockRef, container []byte, _ [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows = append(s.rows, append([]byte(nil), container...))
	return nil
}

// WP-S8-5 end to end: the Appender is wired to the REAL composed verifier (NewDefaultVerifier, steps 1c-24), not to a fake. A container the
// real Verify accepts at level included is appended; one it refuses (any part in an R state, or a framework refusal) is not, and the
// sink is never called. The same assembled leg is judged twice, once with the honest context and once with a context the real Verify refuses.
func TestAppenderWithTheRealVerifierStoresTheHonestLegAndRefusesWhatTheRealVerifyRefuses(t *testing.T) {
	v, err := ci.NewDefaultVerifier()
	if err != nil {
		t.Fatal(err)
	}
	for _, chain := range chains {
		fc := newFakeChainWith(t, chain, "h0", nil)
		src, _ := fc.source(honest)
		_, _, set, part := wholeLeg(t, fc, src)
		parts := capture.Parts{Chain: fc.w.Spec.Chain, Leg: set.Block, Facts: fc.facts(t), Settle: set, Attest: part}

		sink := &recordingSink{}
		ap, err := capture.NewAppender(sink, v, fc.w.Manifest)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ap.Append(context.Background(), fc.w.Ctx, parts); err != nil {
			t.Fatalf("chain %d: the real Verify must accept the honest leg: %v", chain, err)
		}
		if len(sink.rows) != 1 {
			t.Fatalf("chain %d: the accepted container is appended once, got %d", chain, len(sink.rows))
		}

		// a context the real Verify refuses: a chain the manifest does not publish (framework refusal manifest_unknown)
		bad := fc.w.Ctx
		bad.Chain = 999999937
		sink2 := &recordingSink{}
		ap2, _ := capture.NewAppender(sink2, v, fc.w.Manifest)
		_, err = ap2.Append(context.Background(), bad, parts)
		var refused *capture.RefusedError
		if !errors.As(err, &refused) {
			t.Fatalf("chain %d: the real Verify must refuse an unpublished chain and Append must return RefusedError, got %v", chain, err)
		}
		if refused.Report.Headline.Kind != ci.HeadlineRefused || len(sink2.rows) != 0 {
			t.Fatalf("chain %d: a refused container is never appended: kind %v rows %d", chain, refused.Report.Headline.Kind, len(sink2.rows))
		}
	}
}
