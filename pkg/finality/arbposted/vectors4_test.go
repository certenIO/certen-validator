// Copyright 2026 Certen Protocol

package arbposted

import (
	"encoding/json"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// finality_arb_posted4 (RB11-E2-FIX, the findings of the completeness review V-E2-A1): a delayed message that derives nothing proves nothing, a top-level sequencer message is capped like Nitro's, Kind.Verify binds the BlockRef, the numeric pins are judged by presence. Every case is judged by Kind.Verify and must produce exactly the canonical verdict the generator
// wrote as a literal. The L1 side of every case is synthetic; the L2 leg is the real header of finality_arb_posted1.
func TestPublishedVectorsFinalityArbPosted4(t *testing.T) {
	saved := vectorDir
	vectorDir = "testdata/finality_arb_posted4"
	defer func() { vectorDir = saved }()
	cases, files := loadManifest(t)
	if len(cases) != 27 {
		t.Fatalf("only %d cases", len(cases))
	}
	for _, id := range cases {
		if _, ok := files["cases/"+id+".json"]; !ok {
			t.Errorf("case %s is not in the manifest's files", id)
		}
		var c vecCase
		if err := json.Unmarshal(readVec(t, "cases/"+id+".json"), &c); err != nil {
			t.Fatal(err)
		}
		pins, err := finality.ParsePinsOverride(readVec(t, c.Pins))
		if err != nil {
			t.Fatalf("%s: pins: %v", id, err)
		}
		v, verr := New().Verify(pins, refOf(t, c.Leg), evidenceOf(t, c))
		if got := verdictCanon(v, verr); got != c.Expect {
			t.Errorf("%s:\n got  %s\n want %s", id, got, c.Expect)
		}
	}
}
