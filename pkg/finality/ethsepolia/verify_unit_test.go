// Copyright 2026 Certen Protocol

package ethsepolia

import (
	"bytes"
	"errors"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

func stateOfT(t testing.TB, err error) *finality.StateError {
	t.Helper()
	s, ok := finality.AsNamed(err)
	if !ok {
		t.Fatalf("not a named state: %v", err)
	}
	return s
}

func bodyOf(t testing.TB, l recordedLeg) []byte {
	t.Helper()
	c, err := finality.DecodeContainer(l.ev, finality.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return c.Body
}

// A body cut anywhere in the light-client part names the part it ended in, and nothing after the cut is read.
func TestATruncatedLCPartNamesThePartItEndedIn(t *testing.T) {
	l := loadRecorded(t, "gloas_latest")
	body := bodyOf(t, l)
	anchorBody := len(l.body.LC.AnchorBody.SSZ)
	p1 := 58 + anchorBody // the link count
	linkAt := p1 + 4
	last := len(l.body.LC.Links) - 1 // cuts in the last link: the link count was already satisfied by the bytes before it
	lastAt := linkAt
	for _, lk := range l.body.LC.Links[:last] {
		lastAt += 5 + len(lk.SSZ)
	}
	lastLen := len(l.body.LC.Links[last].SSZ)
	finalAt := linkAt
	for _, lk := range l.body.LC.Links {
		finalAt += 5 + len(lk.SSZ)
	}
	spineAt := finalAt + 5 + len(l.body.LC.FinalUpdate.SSZ)
	for cut, want := range map[int]string{
		2: "lc.profile.len", 7: "lc.profile", 12: "lc.anchorKind", 15: "lc.anchorPeriod", 25: "lc.anchorRoot", 53: "lc.anchorBody.layout",
		56: "lc.anchorBody.len", 100: "lc.anchorBody", p1 + 2: "lc.links.count", lastAt: "lc.link.layout", lastAt + 3: "lc.link.len",
		lastAt + 5 + lastLen/2: "lc.link", finalAt: "lc.finalUpdate.layout", finalAt + 3: "lc.finalUpdate.len", finalAt + 10: "lc.finalUpdate",
		spineAt + 2: "spine.count",
	} {
		_, err := DecodeBody(body[:cut], finality.DefaultLimits(), 64, 16384)
		s := stateOfT(t, err)
		if s.Code != finality.CodeEvidenceMalformed || s.Fields["part"] != want {
			t.Errorf("cut at %d: want a malformed %s, got %s", cut, want, s.Canonical())
		}
	}
}

// The spine bound is the smaller of the pins max_spine_headers and the generic limit; zero means the generic limit alone.
func TestTheSpineBoundIsTheSmallerOfThePinsAndTheGenericLimit(t *testing.T) {
	l := loadRecorded(t, "legacy") // 4,057 headers
	body := bodyOf(t, l)
	n := len(l.body.Spine)
	lim := finality.DefaultLimits()
	small := lim
	small.MaxSpineHeaders = 100
	lowGeneric := lim
	lowGeneric.MaxSpineHeaders = n - 1
	for name, tc := range map[string]struct {
		lim      finality.Limits
		maxSpine int
		limit    int // 0: accepted
	}{
		"the pins bound is lower":      {lim, 100, 100},
		"the pins bound is zero":       {lim, 0, 0},
		"the pins bound is one":        {lim, 1, 1},
		"the pins bound is larger":     {small, 5000, 100},
		"the generic bound is lower":   {small, 0, 100},
		"the pins bound equals count":  {lim, n, 0},
		"the pins bound is one short":  {lim, n - 1, n - 1},
		"both are larger than count":   {lim, 20000, 0},
		"the generic bound is one low": {lowGeneric, 0, n - 1},
	} {
		_, err := DecodeBody(body, tc.lim, 64, tc.maxSpine)
		if tc.limit == 0 {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		s := stateOfT(t, err)
		if s.Code != finality.CodeEvidenceTooLarge || s.Fields["limit"] != uint64(tc.limit) || s.Fields["count"] != uint64(n) {
			t.Errorf("%s: %s", name, s.Canonical())
		}
	}
}

func pinsReplace(t testing.TB, old, replacement string) *finality.Pins {
	t.Helper()
	b := bytes.Replace(finality.EmbeddedPinsBytes(), []byte(old), []byte(replacement), 1)
	p, err := finality.ParsePinsOverride(b)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Through the verifier: a pins file with a lower max_spine_headers refuses the same evidence by count.
func TestAPinsFileWithALowerSpineBoundRefusesTheEvidenceByCount(t *testing.T) {
	l := loadRecorded(t, "legacy")
	_, err := New().Verify(pinsReplace(t, `"max_spine_headers": 16384`, `"max_spine_headers": 4056`), l.ref, l.ev)
	s := stateOfT(t, err)
	if s.Code != finality.CodeEvidenceTooLarge || s.Fields["limit"] != uint64(4056) || s.Fields["part"] != "spine" {
		t.Fatalf("%s", s.Canonical())
	}
}

func TestVerifyWithoutPinsOrWithAnotherLegChainIsANamedState(t *testing.T) {
	l := loadRecorded(t, "legacy")
	_, err := New().Verify(nil, l.ref, l.ev)
	if s := stateOfT(t, err); s.Code != finality.CodePinUnknown {
		t.Fatalf("nil pins: %s", s.Canonical())
	}
	other := l.ref
	other.Chain = 1
	_, err = New().Verify(embeddedPinsT(t), other, l.ev)
	s := stateOfT(t, err)
	if s.Code != finality.CodeBlockMismatch || s.Fields["field"] != "chain" || s.Fields["want"] != uint64(finality.ChainSepolia) || s.Fields["got"] != uint64(1) {
		t.Fatalf("another leg chain: %s", s.Canonical())
	}
}

func TestTheVerifierLimitsOverrideTheGenericBounds(t *testing.T) {
	l := loadRecorded(t, "legacy")
	lim := finality.DefaultLimits()
	lim.MaxEvidenceBytes = 1 << 20
	_, err := (&Verifier{Lim: &lim}).Verify(embeddedPinsT(t), l.ref, l.ev)
	if s := stateOfT(t, err); s.Code != finality.CodeEvidenceTooLarge || s.Fields["part"] != "evidence" {
		t.Fatalf("%s", s.Canonical())
	}
	if _, err := New().Verify(embeddedPinsT(t), l.ref, l.ev); err != nil {
		t.Fatal(err)
	}
}

// A spine element that is not an RLP list is a malformed spine part with its index, before any chain rule is applied.
func TestAnUnreadableSpineHeaderIsMalformedWithItsIndex(t *testing.T) {
	l := loadRecorded(t, "legacy")
	b := l.body
	b.Spine = append([][]byte(nil), l.body.Spine...)
	bad := append([]byte(nil), b.Spine[3]...)
	bad[0] = 0x00
	b.Spine[3] = bad
	ev, err := BuildContainer(l.ref, b)
	if err != nil {
		t.Fatal(err)
	}
	_, err = New().Verify(embeddedPinsT(t), l.ref, ev)
	s := stateOfT(t, err)
	if s.Code != finality.CodeEvidenceMalformed || s.Fields["part"] != "spine" || s.Fields["index"] != uint64(3) || s.Fields["reason"] != finality.ReasonHeaderNotRLPList {
		t.Fatalf("%s", s.Canonical())
	}
}

// Only a light-client fault is translated; any other error passes through untouched; an unreadable-header fault is never a
// header-chain reason outside the registry's set.
func TestStateOfTranslatesOnlyLightClientFaults(t *testing.T) {
	plain := errors.New("not a fault")
	if got := stateOf(plain); got != plain {
		t.Fatalf("%v", got)
	}
	if got := stateOf(nil); got != nil {
		t.Fatalf("%v", got)
	}
	f := ethl1.HeaderChainBroken("l1", 7, [32]byte{1}, [32]byte{2}, "rlp")
	s := stateOfT(t, stateOf(f))
	if s.Code != finality.CodeEvidenceMalformed || s.Fields["part"] != "spine" || s.Fields["reason"] != finality.ReasonHeaderBadItem {
		t.Fatalf("%s", s.Canonical())
	}
	for in, want := range map[string]string{"hash": "parent_hash_mismatch", "number": "number_gap"} {
		g := stateOfT(t, stateOf(ethl1.HeaderChainBroken("l1", 7, [32]byte{1}, [32]byte{2}, in)))
		if g.Code != ethl1.CodeHeaderChainBroken || g.Fields["reason"] != want || g.Fields["at_number"] != uint64(7) || g.Fields["spine"] != "l1" {
			t.Errorf("%s: %s", in, g.Canonical())
		}
	}
	other := stateOfT(t, stateOf(ethl1.PinUnknown(1, 5, [32]byte{3})))
	if other.Code != finality.CodePinUnknown || other.Fields["period"] != uint64(5) {
		t.Fatalf("%s", other.Canonical())
	}
}
