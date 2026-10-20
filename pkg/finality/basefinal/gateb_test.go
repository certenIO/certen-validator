// Copyright 2026 Certen Protocol

package basefinal

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

func wantNamed(t *testing.T, what string, err error, code string, fields map[string]string) {
	t.Helper()
	se, ok := finality.AsNamed(err)
	if !ok {
		t.Fatalf("%s: want %s, got %v", what, code, err)
	}
	if se.Code != code {
		t.Fatalf("%s: want %s, got %s", what, code, se.Canonical())
	}
	for k, v := range fields {
		x := finality.NewState("x", "k", se.Fields[k]).Canonical()
		// {"code":"x","fields":{"k":"v"}}
		var m struct {
			Fields map[string]any `json:"fields"`
		}
		if err := json.Unmarshal(x, &m); err != nil {
			t.Fatal(err)
		}
		if got, _ := m.Fields["k"].(string); got != v {
			t.Fatalf("%s: field %s = %q, want %q (%s)", what, k, got, v, se.Canonical())
		}
	}
}

// The container is judged against the leg and the pins before any proof is read: every mismatch is its own named state.
func TestKindVerifyRefusesAMislabelledContainerAGarbageBodyAndMissingPins(t *testing.T) {
	pinsRaw, err := ReadFile(setDir, "pins/main.json")
	if err != nil {
		t.Fatal(err)
	}
	pins, err := finality.ParsePinsOverride(pinsRaw)
	if err != nil {
		t.Fatal(err)
	}
	legRaw, _ := ReadFile(setDir, "legs/leg_47604755.json")
	var leg Leg
	if err := json.Unmarshal(legRaw, &leg); err != nil {
		t.Fatal(err)
	}
	ref := leg.BlockRef(t)
	ev, err := ReadFile(setDir, "evidence/valid_leg_47604755.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (Kind{}).Verify(pins, ref, ev); err != nil {
		t.Fatalf("the base case must verify: %v", err)
	}
	c, err := finality.DecodeContainer(ev, finality.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	reenc := func(mod func(*finality.Container)) []byte {
		cc := c
		mod(&cc)
		out, err := cc.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	// not a container at all
	_, err = Kind{}.Verify(pins, ref, []byte{1, 2, 3})
	if _, ok := finality.AsNamed(err); !ok {
		t.Fatalf("garbage evidence must be a named state, got %v", err)
	}
	_, err = Kind{}.Verify(pins, ref, reenc(func(x *finality.Container) { x.Header.Kind = "arb-sepolia/l1_posted/v1" }))
	wantNamed(t, "kind", err, finality.CodeEvidenceUnrecognised, nil)
	_, err = Kind{}.Verify(pins, ref, reenc(func(x *finality.Container) { x.Header.Chain = 421614 }))
	wantNamed(t, "chain only", err, finality.CodeEvidenceMalformed, map[string]string{"part": "header"})
	_, err = Kind{}.Verify(pins, ref, reenc(func(x *finality.Container) { x.Header.Level = finality.LevelL1Posted }))
	wantNamed(t, "level only", err, finality.CodeEvidenceMalformed, map[string]string{"part": "header"})
	// the block the container names: each of number, hash and the leg's chain alone is a mismatch
	_, err = Kind{}.Verify(pins, ref, reenc(func(x *finality.Container) { x.Header.BlockNumber++ }))
	wantNamed(t, "number only", err, finality.CodeBlockMismatch, map[string]string{"field": "blockHash"})
	_, err = Kind{}.Verify(pins, ref, reenc(func(x *finality.Container) { x.Header.BlockHash[0] ^= 1 }))
	wantNamed(t, "hash only", err, finality.CodeBlockMismatch, map[string]string{"field": "blockHash"})
	otherChain := ref
	otherChain.Chain = 421614
	_, err = Kind{}.Verify(pins, otherChain, ev)
	wantNamed(t, "leg chain only", err, finality.CodeBlockMismatch, map[string]string{"field": "blockHash"})
	// a body that does not decode
	_, err = Kind{}.Verify(pins, ref, reenc(func(x *finality.Container) { x.Body = x.Body[:len(x.Body)/2] }))
	if _, ok := finality.AsNamed(err); !ok {
		t.Fatalf("a truncated body must be a named state, got %v", err)
	}
	// the pins carry no base_sepolia section
	empty, _ := finality.ParsePinsOverride([]byte(`{"format":"certen-finality-pins/1","onchain_commitment":null,"published_utc":"2026-10-20T00:00:00Z"}` + "\n"))
	_, err = Kind{}.Verify(empty, ref, ev)
	wantNamed(t, "no base pins", err, finality.CodePinUnknown, nil)
	// base_sepolia pins present, no Sepolia network section
	var m map[string]any
	_ = json.Unmarshal(pinsRaw, &m)
	delete(m, "eth_sepolia")
	nb, _ := json.MarshalIndent(m, "", "  ")
	noEth, err := finality.ParsePinsOverride(append(nb, '\n'))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Kind{}.Verify(noEth, ref, ev)
	wantNamed(t, "no sepolia pins", err, finality.CodePinUnknown, map[string]string{"kind": "eth_sepolia"})
}

type wireFixture struct {
	lim  finality.Limits
	ep   ethl1.Pins
	l2   int
	body Body
	enc  []byte
}

func loadWireFixture(t *testing.T) wireFixture {
	t.Helper()
	pinsRaw, _ := ReadFile(setDir, "pins/main.json")
	pins, err := finality.ParsePinsOverride(pinsRaw)
	if err != nil {
		t.Fatal(err)
	}
	bp, err := ParsePins(pins)
	if err != nil {
		t.Fatal(err)
	}
	es, err := pins.Sepolia()
	if err != nil {
		t.Fatal(err)
	}
	ep := ethl1Pins(es)
	ev, _ := ReadFile(setDir, "evidence/valid_leg_47604755.bin")
	c, err := finality.DecodeContainer(ev, finality.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	body, err := DecodeBody(c.Body, finality.DefaultLimits(), ep, bp.MaxL2Headers)
	if err != nil {
		t.Fatal(err)
	}
	return wireFixture{lim: finality.DefaultLimits(), ep: ep, l2: bp.MaxL2Headers, body: body, enc: c.Body}
}

// The spine counts are bounded by the smaller of the pin and the framework limit; a pin that is zero or negative means the limit.
func TestTheSpineCountBoundsAreThePinCappedByTheFrameworkLimitAndAnUnsetPinIsTheLimit(t *testing.T) {
	f := loadWireFixture(t)
	items := func(n int) [][]byte {
		out := make([][]byte, n)
		for i := range out {
			out[i] = []byte{1}
		}
		return out
	}
	tooLarge := func(what string, err error, part string, count, limit string) {
		t.Helper()
		wantNamed(t, what, err, finality.CodeEvidenceTooLarge, map[string]string{"part": part, "count": count, "limit": limit})
	}
	// L2 spine: pin 1 refuses 2 items; a pin above the limit, zero and a negative pin are the limit (1024)
	b2 := f.body
	b2.L2Spine = items(2)
	_, err := DecodeBody(EncodeBody(b2), f.lim, f.ep, 1)
	tooLarge("l2 pin 1", err, "l2Spine", "2", "1")
	_, err = DecodeBody(EncodeBody(b2), f.lim, f.ep, 2)
	if err != nil {
		t.Fatalf("l2 pin 2 admits 2: %v", err)
	}
	over := f.body
	over.L2Spine = items(f.lim.MaxL2Headers + 1)
	for _, pin := range []int{f.lim.MaxL2Headers + 1, 1 << 30, 0, -1} {
		_, err = DecodeBody(EncodeBody(over), f.lim, f.ep, pin)
		tooLarge(fmt.Sprintf("l2 pin %d", pin), err, "l2Spine", fmt.Sprint(f.lim.MaxL2Headers+1), fmt.Sprint(f.lim.MaxL2Headers))
	}
	atLimit := f.body
	atLimit.L2Spine = items(f.lim.MaxL2Headers)
	for _, pin := range []int{f.lim.MaxL2Headers, 0, -1} {
		if _, err = DecodeBody(EncodeBody(atLimit), f.lim, f.ep, pin); err != nil {
			t.Fatalf("l2 pin %d admits exactly the limit: %v", pin, err)
		}
	}
	// L1 spine, bounded by the Sepolia pin max_spine_headers
	s2 := f.body
	s2.L1Spine = items(2)
	ep := f.ep
	ep.MaxSpineHeaders = 1
	_, err = DecodeBody(EncodeBody(s2), f.lim, ep, f.l2)
	tooLarge("l1 pin 1", err, "l1Spine", "2", "1")
	ep.MaxSpineHeaders = 2
	if _, err = DecodeBody(EncodeBody(s2), f.lim, ep, f.l2); err != nil {
		t.Fatalf("l1 pin 2 admits 2: %v", err)
	}
	sover := f.body
	sover.L1Spine = items(f.lim.MaxSpineHeaders + 1)
	for _, pin := range []int{f.lim.MaxSpineHeaders + 1, 1 << 30, 0, -1} {
		ep.MaxSpineHeaders = pin
		_, err = DecodeBody(EncodeBody(sover), f.lim, ep, f.l2)
		tooLarge(fmt.Sprintf("l1 pin %d", pin), err, "l1Spine", fmt.Sprint(f.lim.MaxSpineHeaders+1), fmt.Sprint(f.lim.MaxSpineHeaders))
	}
	sat := f.body
	sat.L1Spine = items(f.lim.MaxSpineHeaders)
	for _, pin := range []int{f.lim.MaxSpineHeaders, 0, -1} {
		ep.MaxSpineHeaders = pin
		if _, err = DecodeBody(EncodeBody(sat), f.lim, ep, f.l2); err != nil {
			t.Fatalf("l1 pin %d admits exactly the limit: %v", pin, err)
		}
	}
}

// Cutting the body at every length names, in wire order, the part that ran short: the LC part (profile, anchor kind, period, root,
// anchor body, links, final update), then the L1 spine, the state block, the game proxy and code, the output-root index, the L2
// spine and the nodes.
func TestEveryCutOfTheBodyNamesThePartThatRanShortInWireOrder(t *testing.T) {
	f := loadWireFixture(t)
	var seen []string
	for cut := 0; cut < len(f.enc); cut++ {
		_, err := DecodeBody(f.enc[:cut], f.lim, f.ep, f.l2)
		se, ok := finality.AsNamed(err)
		if !ok {
			t.Fatalf("cut %d: not a named state: %v", cut, err)
		}
		part := strings.TrimSuffix(fmt.Sprint(se.Fields["part"]), ".len") // an element's length prefix runs short as its element does
		if len(seen) == 0 || seen[len(seen)-1] != part {
			seen = append(seen, part)
		}
	}
	want := []string{"lc.profile", "lc.anchorKind", "lc.anchorPeriod", "lc.anchorRoot", "lc.anchorBody.layout", "lc.anchorBody",
		"lc.links.count", "lc.finalUpdate.layout", "lc.finalUpdate", "l1Spine.count", "l1Spine", "stateBlock", "gameProxy", "gameCode",
		"outputRootIndex", "l2Spine.count", "l2Spine", "nodes.count", "nodes"}
	if fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Fatalf("parts in order\n got  %v\n want %v", seen, want)
	}
}
