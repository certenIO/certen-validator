// Copyright 2026 Certen Protocol

package finality

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

// RB12-EPS-MUTKILL-3: tests that pin the carried-leg header bounds, the carried-header judgement of Registry.VerifyCarried and the
// nil-state guard of the builder status. Every expectation is a literal.

func TestCarriedLegRefRefusesABadBlockHashBeforeAnythingElse(t *testing.T) {
	for _, bad := range []string{"zz", strings.Repeat("3", 63), strings.Repeat("33", 31), strings.Repeat("33", 33), strings.Repeat("A3", 32), ""} {
		_, err := CarriedLeg{Chain: ChainBaseSepolia, BlockNumber: 1, BlockHash: bad}.Ref()
		if err == nil {
			t.Fatalf("block hash %q was accepted", bad)
		}
		wantNamed(t, err, CodeAddendumMalformed, "field", "leg.blockHash")
	}
	ref, err := CarriedLeg{Chain: ChainBaseSepolia, BlockNumber: 7, BlockHash: strings.Repeat("33", 32)}.Ref()
	if err != nil || ref.Number != 7 || ref.Hash[0] != 0x33 || ref.Hash[31] != 0x33 || len(ref.HeaderRLP) != 0 {
		t.Fatalf("a leg without a header: %+v %v", ref, err)
	}
}

func TestCarriedLegRefBoundsTheHeaderAtExactlySixteenKiB(t *testing.T) {
	leg := func(n int) CarriedLeg {
		return CarriedLeg{Chain: ChainBaseSepolia, BlockNumber: 1, BlockHash: strings.Repeat("33", 32), HeaderRLP: strings.Repeat("00", n)}
	}
	if MaxLegHeaderBytes != 16384 {
		t.Fatalf("the carried header bound is %d", MaxLegHeaderBytes)
	}
	_, err := leg(16385).Ref()
	wantNamed(t, err, CodeAddendumMalformed, "field", "leg.headerRlp", "reason", AddendumBadValue)
	// exactly the bound is not refused by the size rule; the bytes are not a header, so ReadHeader refuses them for its own reason
	_, err = leg(16384).Ref()
	if err == nil {
		t.Fatal("sixteen KiB of zero bytes was read as a header")
	}
	if st, ok := AsNamed(err); !ok || (st.Code == CodeAddendumMalformed && fmt.Sprint(st.Fields["reason"]) == string(AddendumBadValue)) {
		t.Fatalf("a header of exactly the bound was refused by the size rule: %v", err)
	}
	_, err = leg(1).Ref()
	if err == nil {
		t.Fatal("one zero byte was read as a header")
	}
	if st, ok := AsNamed(err); ok && st.Code == CodeAddendumMalformed && fmt.Sprint(st.Fields["reason"]) == string(AddendumBadValue) {
		t.Fatalf("a one-byte header was refused by the size rule: %v", err)
	}
}

func TestParseSectionBoundsAndTypesTheCarriedHeader(t *testing.T) {
	section := func(header string) []byte {
		return []byte(`{"format":"` + SectionFormat + `","leg":{"chain":84532,"blockNumber":1,"blockHash":"` + strings.Repeat("33", 32) + `","headerRlp":` + header + `},"addenda":[]}`)
	}
	for _, c := range []struct{ name, header string }{
		{"a number", `5`},
		{"null", `null`},
		{"an object", `{}`},
		{"empty", `""`},
		{"one byte over the bound", `"` + strings.Repeat("00", 16385) + `"`},
		{"upper case hex", `"AB"`},
		{"odd length", `"abc"`},
	} {
		_, err := ParseSection(section(c.header))
		if err == nil {
			t.Fatalf("%s: a header member that is not a bounded lower-case hex string was accepted", c.name)
		}
		wantNamed(t, err, CodeAddendumMalformed, "field", "leg.headerRlp")
	}
	s, err := ParseSection(section(`"` + strings.Repeat("00", 16384) + `"`))
	if err != nil || len(s.Leg.HeaderRLP) != 2*16384 {
		t.Fatalf("a header of exactly the bound: %v", err)
	}
	s, err = ParseSection(section(`"ab"`))
	if err != nil || s.Leg.HeaderRLP != "ab" {
		t.Fatalf("a one-byte header: %q %v", s.Leg.HeaderRLP, err)
	}
}

func TestCarriedLegWithHeaderOfCarriesTheHeaderExactlyWhenTheBlockHoldsOne(t *testing.T) {
	b := testBase()
	if got := CarriedLegWithHeaderOf(b); got.HeaderRLP != "" || got.BlockNumber != 47368146 || got.Chain != ChainBaseSepolia {
		t.Fatalf("a block without a header: %+v", got)
	}
	b.HeaderRLP = []byte{0xab}
	if got := CarriedLegWithHeaderOf(b); got.HeaderRLP != "ab" {
		t.Fatalf("a one-byte header: %+v", got)
	}
	b.HeaderRLP = []byte{0xc0, 0x01, 0xff}
	if got := CarriedLegWithHeaderOf(b); got.HeaderRLP != hex.EncodeToString(b.HeaderRLP) || got.HeaderRLP != "c001ff" {
		t.Fatalf("a header: %+v", got)
	}
}

func TestVerifyCarriedJudgesOnlyWhatTheCarriedHeaderBinds(t *testing.T) {
	r, _, _ := baseRegistry(t, nil, nil)
	// a carried leg without a header judges nothing: pending, and no other level is claimed or judged
	bare := testBase()
	rep := r.VerifyCarried(bare, nil, nil)
	st := rep.Levels[LevelIncluded]
	if st.Status != StatusPending || st.State == nil || st.State.Code != CodeIncludedUnavailable || fmt.Sprint(st.State.Fields["reason"]) != "no_settlement_to_recompute_d0" {
		t.Fatalf("a leg without a header: %+v", st)
	}
	if len(rep.Levels) != 1 || rep.Headline != LevelNone || rep.Unsupported != nil {
		t.Fatalf("a leg without a header judged more: %+v headline %v", rep.Levels, rep.Headline)
	}
	// even a verifiable addendum chain is not judged without the header
	withChain := r.VerifyCarried(bare, buildChain(t, bare, LevelL1Posted), nil)
	if len(withChain.Levels) != 1 || withChain.Headline != LevelNone {
		t.Fatalf("addenda judged against a leg without a header: %+v", withChain)
	}

	// a one-byte header is a header for this decision: level 1 is not claimed, the headline is the highest verified addendum
	b := testBase()
	b.HeaderRLP = []byte{1}
	none := r.VerifyCarried(b, nil, nil)
	inc := none.Levels[LevelIncluded]
	if inc.Status != StatusPending || inc.State == nil || inc.State.Code != CodeIncludedUnavailable || fmt.Sprint(inc.State.Fields["reason"]) != "no_settlement" || fmt.Sprint(inc.State.Fields["chain"]) != fmt.Sprint(ChainBaseSepolia) {
		t.Fatalf("a carried header: %+v", inc)
	}
	if none.Headline != LevelNone {
		t.Fatalf("level 1 was claimed from a carried header: headline %v", none.Headline)
	}
	withL1 := r.VerifyCarried(b, buildChain(t, b, LevelL1Posted), nil)
	if withL1.Levels[LevelL1Posted].Status != StatusVerified || withL1.Headline != LevelL1Posted {
		t.Fatalf("a verified l1_posted addendum is the headline: %+v headline %v", withL1.Levels[LevelL1Posted], withL1.Headline)
	}
	if withL1.Levels[LevelIncluded].Status != StatusPending {
		t.Fatalf("level 1 with an addendum: %+v", withL1.Levels[LevelIncluded])
	}

	// a chain that is not a table row is returned as unsupported before level 1 is written
	other := BlockRef{Chain: 999999, Number: 1, HeaderRLP: []byte{1}}
	un := r.VerifyCarried(other, nil, nil)
	if un.Unsupported == nil || un.Unsupported.Code != CodeChainUnsupported {
		t.Fatalf("an unsupported chain: %+v", un)
	}
	if _, has := un.Levels[LevelIncluded]; has {
		t.Fatalf("level 1 was written for an unsupported chain: %+v", un.Levels)
	}
}

func TestANilStateOfABuilderStatusIsNotAnAttemptNote(t *testing.T) {
	var s BuilderStatus
	s.noteNextAttempt(time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC))
	if s.State != nil {
		t.Fatalf("a status without a state gained one: %+v", s.State)
	}
}
