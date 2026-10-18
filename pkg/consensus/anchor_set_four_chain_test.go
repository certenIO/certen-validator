package consensus

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/ledger"
)

// RB7: Telcoin Adiri (2017) is live, so the first anchor set - the v14 activation - must name all four settlement
// chains. A set that names only the original three would leave every Adiri block refused with ANCHOR_NOT_COMMITTED
// (code 17) from the height after the activation, until a second set (v2) named it.
const liveAnchorAdiri = "0xEE381d01Dab7ffeA0F0006943F8337bA88B4070C"

// fourChainAnchorSet is anchor set v1 as the activation runbook proposes it, signed by the named admins of f.
func fourChainAnchorSet(f *rotationFixture, admins ...string) *AnchorSetTx {
	tx := &AnchorSetTx{Kind: AnchorSetKind, ChainID: rotChain, Version: 1, Anchors: []ledger.AnchorSetEntry{
		{ChainID: 11155111, Anchor: liveAnchorBaseAndSepolia},
		{ChainID: 84532, Anchor: liveAnchorBaseAndSepolia},
		{ChainID: 421614, Anchor: liveAnchorArbitrum},
		{ChainID: 2017, Anchor: liveAnchorAdiri},
	}}
	return tx.signedBy(f.admins, admins...)
}

// The bytes the admins sign for the four-chain set v1 on certen-testnet, pinned against an independent computation
// (Python hashlib over the same length-prefixed fields, 2026-10-06; the same script reproduces the three-chain pin
// 51985f55... in TestTheAnchorSetEncodingIsPinned).
func TestTheFourChainAnchorSetEncodingIsPinned(t *testing.T) {
	const pinned = "52ef59eafedbb8e2b4bf575530733bff0a04f3035ff9a342c4185daebaed65d7"
	tx := fourChainAnchorSet(newRotationFixture())
	if got := hex.EncodeToString(tx.SigningBytes()); got != pinned {
		t.Fatalf("signing bytes %s, pinned %s", got, pinned)
	}
	if err := tx.CheckShape(); err != nil {
		t.Fatalf("the four-chain set v1: %v", err)
	}
}

// The four-chain set is accepted when two admins sign it, records every chain's anchor, and judges a block targeting
// each of the four chains accepted.
func TestTheFourChainAnchorSetIsVerifiedAndCommitsEveryChain(t *testing.T) {
	f := newRotationFixture()
	rec, err := VerifyAnchorSet(fourChainAnchorSet(f, "ops-1", "ops-2"), rotChain, f.policy, nil, 5)
	if err != nil {
		t.Fatalf("verified: %v", err)
	}
	if len(rec.Anchors) != 4 {
		t.Fatalf("recorded %d anchors, want 4: %+v", len(rec.Anchors), rec.Anchors)
	}
	for chain, anchor := range map[int64]string{11155111: liveAnchorBaseAndSepolia, 84532: liveAnchorBaseAndSepolia,
		421614: liveAnchorArbitrum, 2017: liveAnchorAdiri} {
		got, ok := CommittedAnchorOf(rec, chain)
		if !ok || got != common.HexToAddress(anchor) {
			t.Fatalf("chain %d: committed (%s, %v), want %s", chain, got.Hex(), ok, anchor)
		}
		vb := &ValidatorBlock{CrossChainProof: CrossChainProof{ChainTargets: []ChainTarget{target(chain, anchor)}}}
		if err := CheckChainTargetAnchors(vb, rec); err != nil {
			t.Fatalf("a target on chain %d: %v", chain, err)
		}
	}
	anchorOf := func(c int64) (common.Address, error) {
		got, _ := CommittedAnchorOf(rec, c)
		return got, nil
	}
	if err := CheckAnchorSetAdmission([]int64{11155111, 84532, 421614, 2017}, fixedAnchorSets{set: rec}, anchorOf); err != nil {
		t.Fatalf("the proposer's admission across all four chains: %v", err)
	}
}

// Why 2017 must be in v1: through the real app, a three-chain v1 leaves a block targeting Adiri refused with code 17
// from the next height, and the four-chain v1 accepts the same block.
func TestAThreeChainSetRefusesAdiriWithCode17AndTheFourChainSetAcceptsIt(t *testing.T) {
	adiri := func(op string) []byte {
		return anchoredBlockJSON(t, op, "validator-1", []ChainTarget{target(2017, liveAnchorAdiri)}, nil)
	}

	f := newRotationFixture()
	app, _ := rotationApp(t, f)
	v14Step(t, app, 1, []uint32{0}, rotJSON(t, liveAnchorSet(f, 1, "ops-1", "ops-2")))
	resp := v14Step(t, app, 2, []uint32{codeAnchorNotCommitted}, adiri("op-3chain"))
	if want := "chain 2017, for which anchor set v1 commits no anchor"; !strings.Contains(resp.TxResults[0].Log, want) ||
		!strings.Contains(resp.TxResults[0].Log, ReasonAnchorNotCommitted) {
		t.Fatalf("refusal log %q, want it to name %q", resp.TxResults[0].Log, want)
	}

	f4 := newRotationFixture()
	app4, _ := rotationApp(t, f4)
	v14Step(t, app4, 1, []uint32{0}, rotJSON(t, fourChainAnchorSet(f4, "ops-1", "ops-2")))
	v14Step(t, app4, 2, []uint32{0}, adiri("op-4chain"))

	// The proposer says the same by name before signing anything, and the intent is retried, never held against it.
	three := &ledger.AnchorSetRecord{Version: 1, Anchors: []ledger.AnchorSetEntry{
		{ChainID: 84532, Anchor: liveAnchorBaseAndSepolia}}}
	err := CheckAnchorSetAdmission([]int64{2017}, fixedAnchorSets{set: three},
		func(int64) (common.Address, error) { return common.HexToAddress(liveAnchorAdiri), nil })
	if !errors.Is(err, ErrBatchUnavailable) || !errors.Is(err, ErrAnchorNotCommitted) {
		t.Fatalf("admission on a set that leaves Adiri out: %v", err)
	}
}
