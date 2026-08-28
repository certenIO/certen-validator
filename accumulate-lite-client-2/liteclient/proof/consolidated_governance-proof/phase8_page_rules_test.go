// Copyright 2026 Certen Protocol
//
// Phase 8 item 5 — a page's rules beyond the accept threshold.
//
// G1 re-derives the ACCEPT threshold and nothing else. A page may also carry a
// reject, response or block threshold, and until this evidence existed those
// were dropped at parse: a proof that said "threshold satisfied: true" was
// making a NARROWER claim than the page's own rules, without saying so.
//
// The three are not equivalent, and the tests below keep them apart, because
// reporting them identically would hide the only one that could have changed
// the answer:
//
//	responseThreshold  could change it - it gates on votes of every kind, which
//	                   this proof does not enumerate
//	rejectThreshold    could not - the executor tests accept first, and the
//	                   transaction executed
//	blockThreshold     is not enforced against the page by accumulate-core at all
package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func p8pageDef(url string, extra map[string]interface{}) map[string]interface{} {
	def := map[string]interface{}{
		"url":       url,
		"type":      "keyPage",
		"version":   float64(1),
		"threshold": float64(1),
		"keys": []interface{}{
			map[string]interface{}{
				"publicKeyHash": "4d07443e23bf3d244facb56f7fd4614d29b21f5530361ca1f77c40ac17f16192",
			},
		},
	}
	for k, v := range extra {
		def[k] = v
	}
	return def
}

// TestP8_UnsetThresholdsAreNotARule is the compatibility direction, and it is
// the one that keeps cases A, D and F behaving exactly as before.
//
// Accumulate omits a zero threshold rather than writing it, so a page that sets
// none of the three reports none of them. That must produce no evidence at all
// - not an empty note, not a note saying "zero".
func TestP8_UnsetThresholdsAreNotARule(t *testing.T) {
	got := parsePageThresholds(p8pageDef("acc://a.acme/book/1", nil))

	if got.any() {
		t.Fatalf("a page with no extra thresholds was read as carrying rules: %+v", got)
	}
	if n := pageRuleNotes("acc://a.acme/book/1", got); len(n) != 0 {
		t.Fatalf("a page with no extra thresholds earned %d note(s); every corpus and "+
			"production page is this shape and must be unchanged", len(n))
	}
}

// TestP8_ZeroIsNotSet guards the same thing against an endpoint that writes the
// zero explicitly instead of omitting it.
func TestP8_ZeroIsNotSet(t *testing.T) {
	got := parsePageThresholds(p8pageDef("acc://a.acme/book/1", map[string]interface{}{
		"rejectThreshold":   float64(0),
		"responseThreshold": float64(0),
		"blockThreshold":    float64(0),
	}))

	if got.any() {
		t.Fatalf("explicit zeros were read as rules: %+v", got)
	}
}

// TestP8_ResponseThresholdIsTheLoadBearingOne pins the rule that could have
// changed the verdict, and pins that its note says so.
func TestP8_ResponseThresholdIsTheLoadBearingOne(t *testing.T) {
	th := parsePageThresholds(p8pageDef("acc://a.acme/book/1", map[string]interface{}{
		"responseThreshold": float64(3),
	}))
	notes := pageRuleNotes("acc://a.acme/book/1", th)

	if len(notes) != 1 {
		t.Fatalf("want exactly one note, got %d", len(notes))
	}
	n := notes[0]
	if n.Reason != PageRuleUnverifiedResponse {
		t.Errorf("reason = %q, want %q", n.Reason, PageRuleUnverifiedResponse)
	}
	if n.Value != 3 {
		t.Errorf("value = %d, want the page's own number 3", n.Value)
	}
	// The explanation must say the two things a reader needs: that it was NOT
	// recounted, and what it would have counted.
	for _, want := range []string{"NOT recounted", "rejects and abstains"} {
		if !strings.Contains(n.Explanation, want) {
			t.Errorf("explanation must contain %q, got: %s", want, n.Explanation)
		}
	}
}

// TestP8_RejectThresholdIsRecordedAsMoot pins the opposite: a rule that is
// recorded for completeness and is NOT a gap in the proof.
//
// Calling this "not verified" in the same words as the response threshold would
// invent a doubt that does not exist - the executor tests accept before reject
// and the transaction executed.
func TestP8_RejectThresholdIsRecordedAsMoot(t *testing.T) {
	th := parsePageThresholds(p8pageDef("acc://a.acme/book/1", map[string]interface{}{
		"rejectThreshold": float64(2),
	}))
	notes := pageRuleNotes("acc://a.acme/book/1", th)

	if len(notes) != 1 || notes[0].Reason != PageRuleMootReject {
		t.Fatalf("want one moot-reject note, got %+v", notes)
	}
	if !strings.Contains(notes[0].Explanation, "could not have changed the outcome") {
		t.Errorf("a moot rule must say it is moot, got: %s", notes[0].Explanation)
	}
}

// TestP8_BlockThresholdIsRecordedAsUnenforced pins the third case: the protocol
// itself does not enforce it against the page, so verifying it would claim more
// than accumulate-core does.
func TestP8_BlockThresholdIsRecordedAsUnenforced(t *testing.T) {
	th := parsePageThresholds(p8pageDef("acc://a.acme/book/1", map[string]interface{}{
		"blockThreshold": float64(9),
	}))
	notes := pageRuleNotes("acc://a.acme/book/1", th)

	if len(notes) != 1 || notes[0].Reason != PageRuleUnenforcedBlock {
		t.Fatalf("want one unenforced-block note, got %+v", notes)
	}
	if !strings.Contains(notes[0].Explanation, "HoldUntil") {
		t.Errorf("the note must name what the protocol actually reads, got: %s",
			notes[0].Explanation)
	}
}

// TestP8_PageRuleNotesAreCanonicallyOrdered is rule 12.
//
// Pages are reached by concurrent queries, so discovery order is not stable.
// Two validators reading identical chain data must emit identical bytes.
func TestP8_PageRuleNotesAreCanonicallyOrdered(t *testing.T) {
	notes := []PageRuleNote{
		{Page: "acc://z.acme/book/1", Rule: "responseThreshold"},
		{Page: "acc://a.acme/book/1", Rule: "responseThreshold"},
		{Page: "acc://a.acme/book/1", Rule: "blockThreshold"},
	}
	sortPageRuleNotes(notes)

	want := []string{
		"acc://a.acme/book/1|blockThreshold",
		"acc://a.acme/book/1|responseThreshold",
		"acc://z.acme/book/1|responseThreshold",
	}
	for i, w := range want {
		if got := notes[i].Page + "|" + notes[i].Rule; got != w {
			t.Errorf("position %d = %q, want %q", i, got, w)
		}
	}
}

// TestP8_PageRulesCollectedAtTheOneParsePoint proves the collector actually
// sees pages, rather than being a well-formed thing nothing feeds.
//
// Every key page definition in this package is parsed by
// parseKeyPageStateFromDef, which is what makes one collector enough to cover
// the principal's replayed page AND every page reached by delegation.
func TestP8_PageRulesCollectedAtTheOneParsePoint(t *testing.T) {
	ab := NewAuthorityBuilder(nil, nil)

	if _, err := ab.parseKeyPageStateFromDef(p8pageDef("acc://plain.acme/book/1", nil)); err != nil {
		t.Fatalf("parse plain page: %v", err)
	}
	if _, err := ab.parseKeyPageStateFromDef(p8pageDef("acc://strict.acme/book/1",
		map[string]interface{}{"responseThreshold": float64(2)})); err != nil {
		t.Fatalf("parse strict page: %v", err)
	}

	notes := ab.UnverifiedPageRules()
	if len(notes) != 1 {
		t.Fatalf("want exactly the strict page recorded, got %d note(s): %+v", len(notes), notes)
	}
	if notes[0].Page != "acc://strict.acme/book/1" {
		t.Errorf("recorded the wrong page: %s", notes[0].Page)
	}
}

// TestP8_PageRulesAreOmittedWhenEmpty is the govRoot-safety property on this
// side of the wire.
//
// The field must be absent - not null, not [] - from a document for a page that
// sets nothing, so that every G1 document produced for the corpus and for
// production is byte-identical to the ones produced before this field existed.
func TestP8_PageRulesAreOmittedWhenEmpty(t *testing.T) {
	out, err := json.Marshal(&G1Result{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "unverifiedPageRules") {
		t.Fatalf("the key appears on a result that has no page rules; omitempty is missing "+
			"and every existing document's bytes have changed:\n%s", out)
	}
}
