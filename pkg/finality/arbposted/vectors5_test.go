// Copyright 2026 Certen Protocol

package arbposted

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// finality_arb_posted5 (RB12-ARBFINAL-FIX, BETA audit G2): the binding of the BlockRef to the CONTAINER (verify.go: container.blockNumber ==
// leg.number, then container.blockHash == leg.hash) is pinned by cases whose leg agrees with its OWN header and disagrees with the container
// only. Set 4's cases of the binding (adv_leg_number_differs_from_container, adv_leg_hash_differs_from_container) alter the leg and leave
// its header, so the later header checks answer the same state and the container binding is pinned by no vector.
func TestPublishedVectorsFinalityArbPosted5(t *testing.T) {
	saved := vectorDir
	vectorDir = "testdata/finality_arb_posted5"
	defer func() { vectorDir = saved }()
	cases, files := loadManifest(t)
	if len(cases) != 3 {
		t.Fatalf("%d cases, want 3", len(cases))
	}
	// the documented verdict of each case, written here independently of the literals of the case files
	documented := map[string]func(c vecCase) (prefix, contains string){
		"valid_control_leg_and_container_agree": func(c vecCase) (string, string) { return `{"code":"verified",`, "" },
		// want = the leg's number, got = the number the container is about (the number of the real header the evidence was built for)
		"adv_leg_number_differs_from_container_leg_header_agrees": func(c vecCase) (string, string) {
			return `{"code":"finality_block_mismatch","fields":{"field":"blockNumber","got":"` + legNumberOf(t, readVec(t, "raw/leg.json")) + `","want":"` + c.Leg.Number + `"}}`, ""
		},
		// want = the leg's hash, got = the hash the container is about
		"adv_leg_hash_differs_from_container_leg_header_agrees": func(c vecCase) (string, string) {
			return `{"code":"finality_block_mismatch","fields":{"field":"blockHash","got":"0x`, `"want":"` + c.Leg.Hash + `"`
		},
	}
	for _, id := range cases {
		if _, ok := files["cases/"+id+".json"]; !ok {
			t.Errorf("case %s is not in the manifest's files", id)
		}
		want, ok := documented[id]
		if !ok {
			t.Errorf("case %s is not documented", id)
			continue
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
		got := verdictCanon(v, verr)
		if got != c.Expect {
			t.Errorf("%s:\n got  %s\n want %s", id, got, c.Expect)
		}
		prefix, contains := want(c)
		if !strings.HasPrefix(got, prefix) || !strings.Contains(got, contains) {
			t.Errorf("%s: documented as starting %s and containing %s, got %s", id, prefix, contains, got)
		}
		// the leg of every case agrees with its own header: that is what the set is for
		ref := refOf(t, c.Leg)
		hdr, herr := finality.ReadHeader(ref.HeaderRLP)
		if herr != nil || hdr.Hash != ref.Hash || hdr.Number != ref.Number {
			t.Errorf("%s: the leg does not agree with its own header (%v)", id, herr)
		}
	}
}

// legNumberOf is the block number of the raw leg file of the set (the block the containers are about).
func legNumberOf(t *testing.T, raw []byte) string {
	t.Helper()
	var l struct {
		Number string `json:"number"`
	}
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatal(err)
	}
	return l.Number
}
