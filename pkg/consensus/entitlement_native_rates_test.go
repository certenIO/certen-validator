// Copyright 2026 Certen Protocol

package consensus

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/certen/independant-validator/pkg/entitlement"
)

// Header v3 (RB7 Task 4 follow-up) adds per-chain native rates to the signed header. The consensus gate does not read
// them: it bounds an intent with the per-chain micro-USD cost basis, exactly as for v2. So on the three live chains the
// same epoch published as v2 (one ETH rate) or as v3 (a rate per chain) must reach the identical verdict, reason and
// detail for every block - otherwise the header version would be a consensus change. Pinned here over a grid of leg
// counts that straddles the leaf's ceiling.
func TestTheLiveChainsGetTheSameGateVerdictFromV2AndV3(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := activeLeaf(gatePayer) // intent ceiling $5
	set := &entitlement.Set{Leaves: []entitlement.Leaf{leaf}}
	sh, err := set.SetHash()
	if err != nil {
		t.Fatal(err)
	}
	proof, l, ok := set.BuildProof(gatePayer)
	if !ok {
		t.Fatal("no proof")
	}
	cfg := EntitlementConfig{Mode: EntitlementEnforce, Keys: entitlement.KeySet{"k": pub}}
	const eth = 2_713_640_000
	basis := []entitlement.ChainCostBasis{
		{ChainID: 84532, BaseMicroUSD: 1_362_200, PerLegMicroUSD: 598_100},
		{ChainID: 11155111, BaseMicroUSD: 2_100_000, PerLegMicroUSD: 900_000},
		{ChainID: 421614, BaseMicroUSD: 2_998_300, PerLegMicroUSD: 900_000},
	}
	sign := func(h entitlement.Header) entitlement.Header {
		h.Epoch, h.Root, h.SetHash, h.KeyID = 9, set.Root(), sh, "k"
		h.IssuedAtUnix, h.NotAfterUnix = gateNow-60, gateNow+3600
		h.CostBasis = basis
		h.Signature = hex.EncodeToString(ed25519.Sign(priv, h.SigningBytes()))
		return h
	}
	v2 := sign(entitlement.Header{NativeUSDMicro: eth})
	var rates []entitlement.ChainNativeRate
	for _, id := range []int64{84532, 11155111, 421614} {
		rates = append(rates, entitlement.ChainNativeRate{ChainID: id, USDPerNativeMicro: eth, Source: "corroborated:x", ObservedAtUnix: gateNow - 90})
	}
	v3 := sign(entitlement.Header{NativeRates: rates})
	if string(v2.SigningBytes()) == string(v3.SigningBytes()) {
		t.Fatal("v3 must be a different preimage from v2")
	}

	admitted, refused := 0, 0
	for _, legs := range []map[int64]int{
		{84532: 1}, {84532: 2}, {84532: 7}, {84532: 8},
		{11155111: 1}, {11155111: 4}, {421614: 1}, {421614: 3},
		{84532: 1, 11155111: 1}, {84532: 1, 11155111: 1, 421614: 1}, {84532: 2, 421614: 2},
	} {
		verdict := func(h entitlement.Header) string {
			vb := blockWithLegs(legs)
			vb.AccumulateAnchorReference = AccumulateAnchorReference{AccountURL: gatePayer}
			vb.EntitlementEvidence = &entitlement.Evidence{Header: h, Leaf: l, Proof: proof}
			reason, err := VerifyEntitlement(vb, gatePayer, gateNow, cfg)
			worst, priced, werr := WorstCaseCostMicroUSD(vb, h)
			return fmt.Sprintf("reason=%q err=%v worst=%d priced=%v werr=%v", reason, err, worst, priced, werr)
		}
		a, b := verdict(v2), verdict(v3)
		if a != b {
			t.Fatalf("legs %v: v2 %s, v3 %s", legs, a, b)
		}
		if r, _ := VerifyEntitlement(func() *ValidatorBlock {
			vb := blockWithLegs(legs)
			vb.AccumulateAnchorReference = AccumulateAnchorReference{AccountURL: gatePayer}
			vb.EntitlementEvidence = &entitlement.Evidence{Header: v3, Leaf: l, Proof: proof}
			return vb
		}(), gatePayer, gateNow, cfg); r == "" {
			admitted++
		} else {
			refused++
		}
	}
	if admitted == 0 || refused == 0 {
		t.Fatalf("the grid must straddle the ceiling (admitted %d, refused %d)", admitted, refused)
	}
}
