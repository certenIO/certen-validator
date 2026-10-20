// Copyright 2026 Certen Protocol

package adiri_test

import (
	"bytes"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/adiri"
)

// RB11-GATE-A, the kind: the body decoder refuses a body cut at each of its fields by that field's name, the spine bound is the pin
// when the pin is small, a custom limit set is the one used, and Verify names a missing pins section, an undecodable container and
// a history-slot link whose final header cannot be read.

func TestDecodeBodyRefusesEachTruncationAtItsFieldByName(t *testing.T) {
	lim := finality.DefaultLimits()
	empty := func() *finality.Writer { w := &finality.Writer{}; w.LP(nil); return w }
	build := func(f func(w *finality.Writer)) []byte { w := empty(); f(w); return w.Bytes() }
	for _, c := range []struct {
		name string
		body []byte
		part string
	}{
		{"cut in the cfa1 length", []byte{0, 0}, "cfa1.len"},
		{"no linkKind", empty().Bytes(), "linkKind"},
		{"spine without its count", build(func(w *finality.Writer) { w.U8(adiri.LinkSpine) }), "spine.count"},
		{"slot without its final header", build(func(w *finality.Writer) { w.U8(adiri.LinkSlot) }), "finalHeader.len"},
		{"slot without its nodes", build(func(w *finality.Writer) { w.U8(adiri.LinkSlot); w.LP([]byte{1}) }), "nodes.count"},
	} {
		_, err := adiri.DecodeBody(c.body, lim, 0)
		gateNamed(t, err, finality.CodeEvidenceMalformed, "part", c.part, "reason", finality.ReasonTruncated)
	}
	_, err := adiri.DecodeBody(build(func(w *finality.Writer) { w.U8(adiri.LinkSpine); w.LPList(nil) }), lim, 0)
	gateNamed(t, err, finality.CodeEvidenceMalformed, "part", "spine", "reason", finality.ReasonSpineEmpty)
	_, err = adiri.DecodeBody(build(func(w *finality.Writer) { w.U8(3) }), lim, 0)
	gateNamed(t, err, finality.CodeEvidenceMalformed, "part", "linkKind", "reason", finality.ReasonLinkKindUnknown)
	_, err = adiri.DecodeBody(append(build(func(w *finality.Writer) { w.U8(adiri.LinkSpine); w.LPList([][]byte{{1}}) }), 0), lim, 0)
	gateNamed(t, err, finality.CodeEvidenceMalformed, "part", "body", "reason", finality.ReasonTrailingBytes)
}

func TestTheSpineBoundIsTheSmallerOfThePinAndTheLimitAndAPinOfOneCounts(t *testing.T) {
	lim := finality.DefaultLimits()
	two := &finality.Writer{}
	two.LP(nil)
	two.U8(adiri.LinkSpine)
	two.LPList([][]byte{{1}, {2}})
	body := two.Bytes()
	if b, err := adiri.DecodeBody(body, lim, 2); err != nil || len(b.Spine) != 2 {
		t.Fatalf("a spine of exactly max_headers: %v", err)
	}
	_, err := adiri.DecodeBody(body, lim, 1)
	gateNamed(t, err, finality.CodeEvidenceTooLarge, "part", "spine", "count", 2, "limit", 1)
	// a pin of 0 (or a missing one) leaves only the framework limit
	if _, err := adiri.DecodeBody(body, lim, 0); err != nil {
		t.Fatalf("no pin: %v", err)
	}
	// a pin larger than the framework limit does not raise it
	small := lim
	small.MaxSpineHeaders = 1
	_, err = adiri.DecodeBody(body, small, 100)
	gateNamed(t, err, finality.CodeEvidenceTooLarge, "part", "spine", "limit", 1)
}

func TestAVerifierUsesItsOwnLimitsAndNamesAnUndecodableContainerAndMissingPins(t *testing.T) {
	_, _, _, leg, pins := liveParts(t, "syn-rotation")
	ev := mustEvidence(t, "syn-rotation")
	if _, err := (&adiri.Verifier{Mode: adiri.ModeOneByOne}).Verify(pins, leg, ev); err != nil {
		t.Fatalf("default limits: %v", err)
	}
	tight := finality.DefaultLimits()
	tight.MaxEvidenceBytes = len(ev) - 1
	_, err := (&adiri.Verifier{Mode: adiri.ModeOneByOne, Lim: &tight}).Verify(pins, leg, ev)
	gateNamed(t, err, finality.CodeEvidenceTooLarge, "part", "evidence", "limit", len(ev)-1)
	tight.MaxEvidenceBytes = len(ev)
	if _, err := (&adiri.Verifier{Mode: adiri.ModeOneByOne, Lim: &tight}).Verify(pins, leg, ev); err != nil {
		t.Fatalf("a limit equal to the size: %v", err)
	}
	v := &adiri.Verifier{Mode: adiri.ModeOneByOne}
	_, err = v.Verify(pins, leg, []byte("CFE1"))
	gateNamed(t, err, finality.CodeEvidenceMalformed, "reason", finality.ReasonTruncated)
	_, err = v.Verify(pins, leg, nil)
	gateNamed(t, err, finality.CodeEvidenceMalformed, "part", "header.magic")
	_, err = v.Verify(&finality.Pins{Format: finality.PinsFormat}, leg, ev)
	gateNamed(t, err, finality.CodePinUnknown, "chain", 2017)
	_, err = v.Verify(nil, leg, ev)
	gateNamed(t, err, finality.CodePinUnknown)
}

func TestAHistorySlotLinkWhoseFinalHeaderCannotBeReadIsBrokenByName(t *testing.T) {
	c, body, _, leg, pins := liveParts(t, "syn-kind2")
	if body.LinkKind != adiri.LinkSlot {
		t.Fatalf("link kind %d", body.LinkKind)
	}
	v := &adiri.Verifier{Mode: adiri.ModeOneByOne}
	if _, err := v.Verify(pins, leg, mustEvidence(t, "syn-kind2")); err != nil {
		t.Fatalf("the untouched slot vector: %v", err)
	}
	bad := *body
	bad.FinalHeader = bytes.Repeat([]byte{0x01}, 8) // not an RLP list
	ev, err := adiri.BuildContainer(leg, bad)
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Verify(pins, leg, ev)
	gateNamed(t, err, adiri.CodeLinkBroken, "check", adiri.LinkHeaderDecode)
	_ = c
}
