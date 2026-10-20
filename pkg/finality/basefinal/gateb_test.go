// Copyright 2026 Certen Protocol

package basefinal

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
	"github.com/certen/independant-validator/pkg/finality/l1adapt"
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
	wantNamed(t, "garbage", err, finality.CodeEvidenceMalformed, nil)
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
	// a spine with a hole does not reach the finalized head
	{
		fx := loadWireFixture(t)
		hole := fx.body
		hole.L1Spine = append(append([][]byte(nil), fx.body.L1Spine[:3]...), fx.body.L1Spine[4:]...)
		_, err = Kind{}.Verify(pins, ref, reenc(func(x *finality.Container) { x.Body = EncodeBody(hole) }))
		wantNamed(t, "spine hole", err, "finality_header_chain_broken", map[string]string{"spine": "l1"})
	}
	// a body that does not decode
	_, err = Kind{}.Verify(pins, ref, reenc(func(x *finality.Container) { x.Body = x.Body[:len(x.Body)/2] }))
	if _, ok := finality.AsNamed(err); !ok {
		t.Fatalf("a truncated body must be a named state, got %v", err)
	}
	// the pins carry no base_sepolia section
	empty, _ := finality.ParsePinsOverride([]byte(`{"format":"certen-finality-pins/1","onchain_commitment":null,"published_utc":"2026-10-20T00:00:00Z"}` + "\n"))
	_, err = Kind{}.Verify(empty, ref, ev)
	wantNamed(t, "no base pins", err, finality.CodePinUnknown, map[string]string{"kind": "base_sepolia"})
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
	ep := l1adapt.Pins(es)
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

// Every proof the judge reads is either in the node set or it is not: removing any one node of a world is a state-proof refusal
// (account or slot), never an accepted verdict and never another state, whichever read the node served.
func TestEveryNodeOfTheProofSetIsNeededAndItsAbsenceIsOnlyAStateProofRefusal(t *testing.T) {
	p := loadPins(t)
	proof := map[string]bool{
		`{"code":"l1_state_proof_invalid","fields":{"which":"account"}}`: true,
		`{"code":"l1_state_proof_invalid","fields":{"which":"slot"}}`:    true,
	}
	for _, spec := range []SynthSpec{{}, {K: 3, Depth: 4}} {
		o, err := BuildSynth(p, spec)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Judge(p, o.A, o.Body, o.Leg, ethl1.FinalizedHead{}); err != nil {
			t.Fatalf("the world must verify: %v", err)
		}
		for i := range o.Body.Nodes {
			b := o.Body
			b.Nodes = append(append([][]byte(nil), o.Body.Nodes[:i]...), o.Body.Nodes[i+1:]...)
			_, jerr := Judge(p, o.A, b, o.Leg, ethl1.FinalizedHead{})
			if jerr == nil {
				t.Errorf("%+v: node %d of %d is not needed by any proof of this world", spec, i, len(o.Body.Nodes))
				continue
			}
			if got := canonOf(t, jerr); !proof[got] {
				t.Errorf("%+v: removing node %d of %d gave %s", spec, i, len(o.Body.Nodes), got)
			}
		}
	}
}

// finalizationPath names the delay a game's expectedResolution implies: exactly the slow delay, more than it (extended), or less
// than it with two provers and no counter (fast); anything else, and an expectedResolution before the creation, is none.
func TestTheFinalizationPathIsDerivedFromTheDelayBetweenCreationAndExpectedResolution(t *testing.T) {
	const slow = 100
	two := func(created, exp uint64, proofs uint64, countered byte) GameState {
		g := GameState{CreatedAt: created, ExpectedResolution: exp, ProofCount: proofs}
		g.Countered[31] = countered
		return g
	}
	for _, c := range []struct {
		name string
		g    GameState
		path string
		ok   bool
	}{
		{"before the creation", two(10, 9, 2, 0), "", false},
		{"equal to the creation, two provers", two(10, 10, 2, 0), "fast", true},
		{"equal to the creation, one prover", two(10, 10, 1, 0), "", false},
		{"exactly the slow delay", two(10, 10+slow, 1, 0), "slow", true},
		{"one second under the slow delay, two provers", two(10, 10+slow-1, 2, 0), "fast", true},
		{"one second under the slow delay, one prover", two(10, 10+slow-1, 1, 0), "", false},
		{"one second under the slow delay, two provers, countered", two(10, 10+slow-1, 2, 1), "", false},
		{"one second over the slow delay", two(10, 10+slow+1, 1, 0), "extended", true},
		{"far over the slow delay, countered", two(10, 10+10*slow, 0, 1), "extended", true},
	} {
		path, ok := c.g.finalizationPath(slow)
		if path != c.path || ok != c.ok {
			t.Errorf("%s: (%q, %v), want (%q, %v)", c.name, path, ok, c.path, c.ok)
		}
	}
}

// gameUUID is DGF's keccak256(abi.encode(gameType, rootClaim, extraData)): extraData is padded to a whole word, whatever its length.
func TestTheGameUUIDIsTheABIEncodingOfTypeRootAndPaddedExtraData(t *testing.T) {
	u32, _ := abi.NewType("uint32", "", nil)
	b32, _ := abi.NewType("bytes32", "", nil)
	byt, _ := abi.NewType("bytes", "", nil)
	args := abi.Arguments{{Type: u32}, {Type: b32}, {Type: byt}}
	root := [32]byte(crypto.Keccak256Hash([]byte("root")))
	for _, n := range []int{0, 1, 31, 32, 33, 36, 64, 65} {
		extra := make([]byte, n)
		for i := range extra {
			extra[i] = byte(i + 1)
		}
		packed, err := args.Pack(uint32(621), root, extra)
		if err != nil {
			t.Fatal(err)
		}
		if want := [32]byte(crypto.Keccak256Hash(packed)); gameUUID(621, root, extra) != want {
			t.Errorf("extraData of %d bytes: %x, want %x", n, gameUUID(621, root, extra), want)
		}
	}
}

// A game is resolved when its resolution time is set and its status is a final one; it was resolved after the time it was due.
func TestAGameResolvedAtTheSecondTheProofsMadeItDueIsAcceptedAndOneResolvedBeforeIsNot(t *testing.T) {
	p := loadPins(t)
	const resolved = 1791412824
	// resolved exactly when due: accepted (the base world is due 288 s earlier)
	if _, err := run(t, p, SynthSpec{ExpectedRes: u64(resolved)}, nil); err != nil {
		t.Fatalf("resolved exactly when due: %v", err)
	}
	// resolved one second before it was due: the slots disagree
	_, err := run(t, p, SynthSpec{ExpectedRes: u64(resolved + 1)}, nil)
	if got := canonOf(t, err); got != `{"code":"l1_state_proof_invalid","fields":{"which":"slot"}}` {
		t.Errorf("%s", got)
	}
	// a resolution time of 1 second is a time, not an unset one: the game is judged on it (it is not within the delay and was
	// resolved before it was due)
	_, err = run(t, p, SynthSpec{ResolvedAt: 1}, nil)
	if got := canonOf(t, err); got != `{"code":"l1_state_proof_invalid","fields":{"which":"slot"}}` {
		t.Errorf("%s", got)
	}
}

// lcExtent only delimits the LC part: it walks the profile, anchor, the anchor body, every link and the final update by their
// length prefixes, so a link that runs short is named as such and a well-formed LC with links reports its exact extent.
func TestTheLCExtentWalksEveryLinkAndNamesTheOneThatRunsShort(t *testing.T) {
	lim := finality.DefaultLimits()
	lc := ethl1.LC{Profile: "p", AnchorKind: 1, AnchorPeriod: 7, AnchorBody: ethl1.LB{Layout: 1, SSZ: []byte{1, 2, 3}},
		Links:       []ethl1.LB{{Layout: 1, SSZ: []byte{4, 5}}, {Layout: 2, SSZ: []byte{6}}},
		FinalUpdate: ethl1.LB{Layout: 2, SSZ: []byte{7, 8, 9, 10}}}
	enc := ethl1.EncodeLC(lc)
	n, err := lcExtent(append(append([]byte(nil), enc...), 0xee, 0xee), lim, 64)
	if err != nil || n != len(enc) {
		t.Fatalf("extent %d, %v; want %d", n, err, len(enc))
	}
	// the links are counted against the pin
	_, err = lcExtent(enc, lim, 1)
	wantNamed(t, "links over the pin", err, finality.CodeEvidenceTooLarge, map[string]string{"part": "lc.links", "count": "2", "limit": "1"})
	// a cut inside the second link (its layout byte, its length prefix, its bytes) names the links
	second := len(enc) - (1 + 4 + 4) - (1 + 4 + 1) - 0 // the final update is 1+4+4 bytes, the second link 1+4+1
	_ = second
	for cut := len(enc) - (1 + 4 + 4) - (1 + 4 + 1); cut < len(enc)-(1+4+4); cut++ {
		_, err = lcExtent(enc[:cut], lim, 64)
		se, ok := finality.AsNamed(err)
		if !ok || (fmt.Sprint(se.Fields["part"]) != "lc.links.layout" && fmt.Sprint(se.Fields["part"]) != "lc.links.len" && fmt.Sprint(se.Fields["part"]) != "lc.links") {
			t.Fatalf("cut %d inside the second link: %v", cut, err)
		}
	}
}
