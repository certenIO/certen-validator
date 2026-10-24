// Copyright 2026 Certen Protocol

package finality

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The mutation gate's kills for the record writers and readers of gaps.go (RB12-CAPTURE-GAP).

type vanishStore struct{ CaptureStore }

func (vanishStore) Get(context.Context, CaptureKey) ([]byte, bool, error) { return nil, false, nil }

type getFailStore struct{ CaptureStore }

func (getFailStore) Get(context.Context, CaptureKey) ([]byte, bool, error) {
	return nil, false, errors.New("store down: get")
}

func TestRB12ARecordWritersRefuseWhatIsOutsideTheirVocabularyAndAcceptTheBoundaries(t *testing.T) {
	ctx := context.Background()
	st := newGapStore()
	for _, c := range []GapClass{GapBlockUnavailable, GapStateProofUnavailable, GapBlobUnavailable, GapCaptureFailed, GapOutageUnscanned, GapSpacingUnproven, GapOperatorDeclared} {
		if !c.Valid() {
			t.Errorf("class %s is in the closed set", c)
		}
		if err := RecordGap(ctx, st, gapChain, 1, 1, c); err != nil {
			t.Errorf("%s: %v", c, err)
		}
	}
	if GapClass("").Valid() || GapClass("open").Valid() {
		t.Error("an empty class or a state name is not a class")
	}
	if err := RecordGap(ctx, st, gapChain, 1, MaxCaptureBlock, GapOutageUnscanned); err != nil {
		t.Errorf("the largest block is a block: %v", err)
	}
	if err := RecordGap(ctx, st, gapChain, 1, MaxCaptureBlock+1, GapOutageUnscanned); err == nil {
		t.Error("a block above the largest capture block was accepted")
	}
	if err := RecordGapNote(ctx, st, gapChain, 5, GapClass("nope"), "x"); err == nil {
		t.Error("a note of an unknown class was accepted")
	}
	// the bound of a note's text: exactly the bound is kept whole, more is cut to it
	for _, n := range []int{MaxGapNoteBytes, MaxGapNoteBytes + 40} {
		s := newGapStore()
		if err := RecordGapNote(ctx, s, gapChain, 5, GapBlobUnavailable, strings.Repeat("a", n)); err != nil {
			t.Fatal(err)
		}
		ks, _ := s.ListByRange(ctx, gapChain, 5, 5, GapNotePrefix)
		b, _, _ := s.Get(ctx, ks[0])
		r := NewReader(b, DefaultLimits())
		_, _ = r.Fixed("m", len(noteMagic))
		_, _ = r.U64("b")
		_, _ = r.STR("c")
		text, err := r.LP("t", 4096)
		if err != nil || len(text) != MaxGapNoteBytes {
			t.Errorf("a %d-byte text is stored as %d bytes (want %d): %v", n, len(text), MaxGapNoteBytes, err)
		}
	}
	// the fill says whether the block held inbox transactions
	for _, inbox := range []bool{true, false} {
		s := newGapStore()
		_ = RecordGapFill(ctx, s, gapChain, 9, [32]byte{3}, inbox)
		ks, _ := s.ListByRange(ctx, gapChain, 9, 9, GapFillPrefix)
		b, _, _ := s.Get(ctx, ks[0])
		want := byte(0)
		if inbox {
			want = 1
		}
		if b[len(b)-1] != want {
			t.Errorf("hasInbox=%v is stored as %d", inbox, b[len(b)-1])
		}
	}
	// the reason of an end is a token of at most 64 characters
	for _, tc := range []struct {
		reason string
		ok     bool
	}{{"", false}, {"a", true}, {strings.Repeat("a", 64), true}, {strings.Repeat("a", 65), false}, {"Bad Reason", false}, {"has space", false}} {
		err := RecordGapEnd(ctx, newGapStore(), gapChain, 1, GapEnd{Kind: GapRetentionExpired, Reason: tc.reason})
		if (err == nil) != tc.ok {
			t.Errorf("reason %q: err=%v, want ok=%v", tc.reason, err, tc.ok)
		}
	}
	// a window that is empty (to before from) holds nothing, even over recorded gaps
	_ = RecordGap(ctx, st, gapChain, 50, 60, GapOutageUnscanned)
	if got, err := GapsIn(ctx, st, gapChain, 60, 50); err != nil || len(got) != 0 {
		t.Errorf("an inverted window: %v %v", got, err)
	}
	// single-digit ends and blocks are read like any other (the item is gap/<to>/<class>, the store refuses an empty field)
	one := newGapStore()
	_ = RecordGap(ctx, one, gapChain, 1, 3, GapBlobUnavailable)
	_ = RecordGapFill(ctx, one, gapChain, 2, [32]byte{1}, false)
	if got, err := GapsIn(ctx, one, gapChain, 0, 100); err != nil || fmt.Sprint(got) != "[1-1:open[blob_unavailable] 3-3:open[blob_unavailable]]" {
		t.Errorf("%v %v", got, err)
	}
}

func TestRB12AGapEndsOfReportsStoreFailuresAndRefusesMalformedRows(t *testing.T) {
	ctx := context.Background()
	st := newGapStore()
	e := GapEnd{Kind: GapUnavailableProven, Reason: "beacon_404_every_provider", Providers: []string{"a", "b"}}
	if err := RecordGapEnd(ctx, st, gapChain, 77, e); err != nil {
		t.Fatal(err)
	}
	got, err := GapEndsOf(ctx, st, gapChain, 77)
	if err != nil || len(got) != 1 || got[0].Kind != GapUnavailableProven || got[0].Reason != e.Reason || fmt.Sprint(got[0].Providers) != "[a b]" {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if _, err := GapEndsOf(ctx, faultStore{CaptureStore: st, failList: map[string]bool{GapEndPrefix: true}}, gapChain, 77); err == nil {
		t.Error("a failing listing was swallowed")
	}
	if _, err := GapEndsOf(ctx, getFailStore{st}, gapChain, 77); err == nil {
		t.Error("a failing read was swallowed")
	}
	if _, err := GapEndsOf(ctx, vanishStore{st}, gapChain, 77); err == nil {
		t.Error("a row that vanished between the listing and the read was swallowed")
	}
	// every truncation of a valid end row, a wrong magic and trailing bytes are malformed
	ks, _ := st.ListByRange(ctx, gapChain, 77, 77, GapEndPrefix)
	good, _, _ := st.Get(ctx, ks[0])
	variants := [][]byte{append([]byte("XGEND1"), good[len(endMagic):]...), append(append([]byte(nil), good...), 0)}
	for cut := 0; cut < len(good); cut++ {
		variants = append(variants, append([]byte(nil), good[:cut]...))
	}
	for i, v := range variants {
		s := newGapStore()
		_ = s.Put(ctx, CaptureKey{Chain: gapChain, L1Block: 77, L1Hash: [32]byte{byte(i), byte(i >> 8)}, Item: "gapend/77/unavailable_proven"}, v)
		if _, err := GapEndsOf(ctx, s, gapChain, 77); err == nil {
			t.Errorf("variant %d (%d bytes of %d) was accepted: %q", i, len(v), len(good), bytes.TrimSpace(v))
		}
	}
}
