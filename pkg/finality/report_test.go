// Copyright 2026 Certen Protocol

package finality

import (
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

type fakeKind struct {
	chain uint64
	name  string
	level Level
	got   Level // the level the kind claims to have proven (default: its row's)
	err   error
	calls int
}

func (k *fakeKind) Name() string  { return k.name }
func (k *fakeKind) Chain() uint64 { return k.chain }
func (k *fakeKind) Level() Level  { return k.level }
func (k *fakeKind) Verify(_ *Pins, _ BlockRef, _ []byte) (Verdict, error) {
	k.calls++
	if k.err != nil {
		return Verdict{}, k.err
	}
	l := k.got
	if l == LevelNone {
		l = k.level
	}
	return Verdict{Level: l, Kind: k.name, Fields: map[string]any{"ok": true}}, nil
}

func baseRegistry(t testing.TB, l1Err, finErr error) (*Registry, *fakeKind, *fakeKind) {
	t.Helper()
	r := NewRegistry()
	l1 := &fakeKind{chain: ChainBaseSepolia, name: kBaseL1, level: LevelL1Posted, err: l1Err}
	fin := &fakeKind{chain: ChainBaseSepolia, name: kBaseFin, level: LevelFinalized, err: finErr}
	for _, k := range []*fakeKind{l1, fin} {
		if err := r.RegisterKind(k); err != nil {
			t.Fatal(err)
		}
	}
	return r, l1, fin
}

func TestRegisterKindRefusesWhatIsNotARowOfTheTable(t *testing.T) {
	r := NewRegistry()
	if err := r.RegisterKind(&fakeKind{chain: ChainSepolia, name: kBaseL1, level: LevelL1Posted}); err == nil {
		t.Fatal("a kind on a chain that does not have the level was registered")
	}
	if err := r.RegisterKind(&fakeKind{chain: ChainBaseSepolia, name: "base-sepolia/finalized/v2", level: LevelFinalized}); err == nil {
		t.Fatal("an unlisted kind version was registered")
	}
	k := &fakeKind{chain: ChainBaseSepolia, name: kBaseFin, level: LevelFinalized}
	if err := r.RegisterKind(k); err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterKind(k); err == nil {
		t.Fatal("a second kind for one name was registered")
	}
}

func TestR1R2LevelsAreIndependentAndTheHeadlineIsTheHighestVerified(t *testing.T) {
	b := testBase()
	r, _, _ := baseRegistry(t, errors.New("blobs expired"), nil)
	rep := r.VerifyLeg(b, b, buildChain(t, b, LevelFinalized, LevelL1Posted), nil)
	if rep.Headline != LevelFinalized || rep.Broken != nil {
		t.Fatalf("headline %v broken %v", rep.Headline, rep.Broken)
	}
	if rep.Levels[LevelIncluded].Status != StatusVerified || rep.Levels[LevelFinalized].Status != StatusVerified {
		t.Fatalf("%+v", rep.Levels)
	}
	// finalized does not imply l1_posted: a refused l1_posted addendum leaves finalized verified (R2, R3)
	l1 := rep.Levels[LevelL1Posted]
	if l1.Status != StatusRefused || l1.State.Code != CodeVerifierFailed {
		t.Fatalf("l1_posted: %+v", l1)
	}
}

func TestR3ABrokenChainVoidsAllAddendaAndTheHeadlineIsIncluded(t *testing.T) {
	b := testBase()
	r, _, fin := baseRegistry(t, nil, nil)
	adds := buildChain(t, b, LevelL1Posted, LevelFinalized)
	adds[0].OwnHash[0] ^= 1
	rep := r.VerifyLeg(b, b, adds, nil)
	if rep.Headline != LevelIncluded || rep.Broken == nil || rep.Broken.Fields["check"] != CheckOwnHash {
		t.Fatalf("headline %v broken %v", rep.Headline, rep.Broken)
	}
	for _, l := range []Level{LevelL1Posted, LevelFinalized} {
		if st := rep.Levels[l]; st.Status != StatusRefused || st.State.Code != CodeChainBroken {
			t.Errorf("%s: %+v", l, st)
		}
	}
	if fin.calls != 0 {
		t.Fatal("a kind ran over the addenda of a broken chain")
	}
}

func TestR4AbsentLevelsArePendingNoEvidenceInFileAndR5NotApplicableComesFromTheTable(t *testing.T) {
	r := NewRegistry()
	b := BlockRef{Chain: ChainSepolia, Number: 10, Hash: fill(1)}
	rep := r.VerifyLeg(b, b, nil, nil)
	if rep.Headline != LevelIncluded {
		t.Fatalf("headline %v", rep.Headline)
	}
	if st := rep.Levels[LevelL1Posted]; st.Status != StatusNotApplicable || st.State.Fields["reason"] != ReasonChainIsL1 {
		t.Fatalf("l1_posted on Sepolia: %+v", st)
	}
	st := rep.Levels[LevelFinalized]
	if st.Status != StatusPending || st.State.Code != CodePending || st.State.Fields["reason"] != "no_evidence_in_file" || st.State.Fields["next_level"] != LevelFinalized {
		t.Fatalf("finalized: %+v", st)
	}
	// and on Base both are pending
	bb := testBase()
	rb := r.VerifyLeg(bb, bb, nil, nil)
	for _, l := range []Level{LevelL1Posted, LevelFinalized} {
		if rb.Levels[l].Status != StatusPending {
			t.Errorf("%s: %+v", l, rb.Levels[l])
		}
	}
}

func TestR5AChainThatIsNotATableRowHasNoS7Statement(t *testing.T) {
	r := NewRegistry()
	b := BlockRef{Chain: 1, Number: 10, Hash: fill(1)}
	rep := r.VerifyLeg(b, b, nil, nil)
	if rep.Unsupported == nil || rep.Unsupported.Code != CodeChainUnsupported || len(rep.Levels) != 0 || rep.Headline != LevelNone {
		t.Fatalf("%+v", rep)
	}
}

func TestTheCarriedLegIsComparedFirstAndAMismatchJudgesNothingElse(t *testing.T) {
	b := testBase()
	r, l1, fin := baseRegistry(t, nil, nil)
	carried := b
	carried.Hash[0] ^= 1
	rep := r.VerifyLeg(b, carried, buildChain(t, b, LevelL1Posted, LevelFinalized), nil)
	if rep.Broken == nil || rep.Broken.Fields["check"] != CheckLegBinding || rep.Broken.Fields["seq"] != uint64(0) || rep.Headline != LevelIncluded {
		t.Fatalf("%+v", rep)
	}
	if l1.calls+fin.calls != 0 {
		t.Fatal("a kind ran although the carried leg differs from the verified Settlement")
	}
}

func TestAKindNobodyRegisteredIsRefusedAsUnrecognisedNotAsAWeakerLevel(t *testing.T) {
	b := testBase()
	r := NewRegistry() // no kinds: the chain packages register them
	rep := r.VerifyLeg(b, b, buildChain(t, b, LevelFinalized), nil)
	st := rep.Levels[LevelFinalized]
	if st.Status != StatusRefused || st.State.Code != CodeEvidenceUnrecognised || st.State.Fields["kind"] != kBaseFin || st.State.Fields["version"] != "v1" {
		t.Fatalf("%+v", st)
	}
	if rep.Headline != LevelIncluded {
		t.Fatalf("headline %v", rep.Headline)
	}
}

func TestAKindCannotProveAnotherLevelThanItsRow(t *testing.T) {
	b := testBase()
	r := NewRegistry()
	k := &fakeKind{chain: ChainBaseSepolia, name: kBaseL1, level: LevelL1Posted, got: LevelFinalized}
	if err := r.RegisterKind(k); err != nil {
		t.Fatal(err)
	}
	rep := r.VerifyLeg(b, b, buildChain(t, b, LevelL1Posted), nil)
	if st := rep.Levels[LevelL1Posted]; st.Status != StatusRefused || st.State.Code != CodeVerifierFailed || rep.Headline != LevelIncluded {
		t.Fatalf("%+v headline %v", st, rep.Headline)
	}
}

func TestEvidenceAboutAnotherBlockIsRefusedAsBlockMismatchForThatLevelOnly(t *testing.T) {
	b := testBase()
	r, _, _ := baseRegistry(t, nil, nil)
	other := b
	other.Number++
	good := buildChain(t, b, LevelL1Posted)
	// the finalized addendum is correctly chained but its container is about the next block
	a, err := NewAddendum(LegBindingOf(b), testProofID, good, b.Chain, LevelFinalized, kBaseFin, containerFor(t, kBaseFin, other, LevelFinalized, "x"))
	if err != nil {
		t.Fatal(err)
	}
	rep := r.VerifyLeg(b, b, append(good, a), nil)
	if st := rep.Levels[LevelFinalized]; st.Status != StatusRefused || st.State.Code != CodeBlockMismatch || st.State.Fields["field"] != "blockNumber" {
		t.Fatalf("%+v", st)
	}
	if rep.Levels[LevelL1Posted].Status != StatusVerified || rep.Headline != LevelL1Posted {
		t.Fatalf("a refused finalized addendum affected l1_posted: %+v headline %v", rep.Levels[LevelL1Posted], rep.Headline)
	}
	// a container whose header kind differs from the addendum's is malformed
	bad := good[0]
	bad.Evidence = containerFor(t, kBaseFin, b, LevelL1Posted, "x")
	bad.OwnHash = OwnHash(LegBindingOf(b), bad)
	if st := r.VerifyLeg(b, b, []Addendum{bad}, nil).Levels[LevelL1Posted]; st.Status != StatusRefused || st.State.Code != CodeEvidenceMalformed {
		t.Fatalf("%+v", st)
	}
}

func TestR6FinalizedExposesTheLegsOwnBlockForS8(t *testing.T) {
	// a synthetic 17-item header whose hash and number are the leg's
	items := [][]byte{}
	for i := 0; i < 17; i++ {
		switch i {
		case 0, 3, 4, 5, 16:
			h := fill(byte(0x40 + i))
			items = append(items, h[:])
		case 8:
			items = append(items, []byte{0x2a})
		case 11:
			items = append(items, []byte{0x01, 0x02})
		default:
			items = append(items, []byte{byte(i)})
		}
	}
	raw := rlpList(items)
	b := BlockRef{Chain: ChainBaseSepolia, Number: 0x2a, Hash: [32]byte(crypto.Keccak256Hash(raw)), HeaderRLP: raw}
	r, _, _ := baseRegistry(t, nil, nil)
	rep := r.VerifyLeg(b, b, buildChain(t, b, LevelFinalized), nil)
	if rep.FinalizedBlock == nil || rep.FinalizedBlock.Number != 0x2a || rep.FinalizedBlock.Hash != b.Hash || rep.FinalizedBlock.StateRoot != fill(0x43) {
		t.Fatalf("%+v", rep.FinalizedBlock)
	}
	if rep2 := r.VerifyLeg(b, b, buildChain(t, b, LevelL1Posted), nil); rep2.FinalizedBlock != nil {
		t.Fatal("finalized_block exposed without a finalized verdict")
	}
}

func TestAPinsNilReportsNoneAndRealPinsReportTheirHash(t *testing.T) {
	b := testBase()
	r := NewRegistry()
	if rep := r.VerifyLeg(b, b, nil, nil); rep.PinsSHA256 != "" || rep.PinsSource != "none" {
		t.Fatalf("%q %q", rep.PinsSHA256, rep.PinsSource)
	}
	p, err := EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	if rep := r.VerifyLeg(b, b, nil, p); rep.PinsSHA256 != PinsSHA256 || rep.PinsSource != "embedded" {
		t.Fatalf("%q %q", rep.PinsSHA256, rep.PinsSource)
	}
}
