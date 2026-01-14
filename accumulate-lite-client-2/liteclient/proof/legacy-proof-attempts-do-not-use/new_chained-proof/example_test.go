// Copyright 2025 CERTEN
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof_test

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/new_chained-proof"
)

// -----------------------------------------------------------------------------
// TestSpecificationCompliance
// -----------------------------------------------------------------------------

func TestSpecificationCompliance(t *testing.T) {
	t.Log("CERTEN Chained Proof Specification Test")
	t.Log("Specification: services\\validator\\docs\\new_CERTEN_CHAINED_PROOF_SPEC.md")
	t.Log("Version: v3-receipt-stitch-2")

	spec := chained_proof.GetSpecificationInfo()
	for k, v := range spec {
		t.Logf("%s: %s", k, v)
	}

	t.Log("Specification compliance validated")
}

// -----------------------------------------------------------------------------
// TestProofDataStructures — REAL PROOF
// -----------------------------------------------------------------------------

func TestProofDataStructures(t *testing.T) {
	// ---------------------------
	// Layer 1 — Entry Inclusion
	// ---------------------------

	layer1 := chained_proof.Layer1EntryInclusion{
		Scope:           "acc://testtesttest10.acme/data1",
		ChainName:       "main",
		ChainIndex:      1,
		Leaf:            mustDecodeHex("057c2fc6ae1b8793a3f259705ee1b26f44e4ffed26ac0b897dc0fb733a19f116"),
		SourcePartition: "acc://bvn-BVN1.acme",
		Receipt: chained_proof.MerkleReceipt{
			Start:      mustDecodeHex("057c2fc6ae1b8793a3f259705ee1b26f44e4ffed26ac0b897dc0fb733a19f116"),
			Anchor:     mustDecodeHex("f0222b509079f55e3eea189e0d1d24a937687e8c7835e1e461fa9bf6f25d7e1e"),
			LocalBlock: 1027728,
			Entries: []chained_proof.ReceiptEntry{
				{Hash: mustDecodeHex("3017cfb4a94e754369791becdc7793f9462c64ab1b5d5f04302cbb6fef7fecb3")},
				{Hash: mustDecodeHex("4a8ebb748b35b2f35c8a50e87178a4abeeaf588f0c09f5ae9a3980e400b10838"), Right: boolPtr(true)},
				{Hash: mustDecodeHex("fc0b09dc01fc914a7d2c4792c713c55c7df13227b14d80089784fcd5c55997e6")},
				{Hash: mustDecodeHex("6177ffa2f43e51e59725cb0c7c1dd960d8646a8981cec5521625772816be2dda")},
				{Hash: mustDecodeHex("f64474d49b204d473f05422b394f0e8124d891f5d4bd858d30a0155253ed35f6")},
				{Hash: mustDecodeHex("03c200e60ec4f0a8dbce00d867350d082e3dd23d9345bf80bd9db5a05808a29e")},
				{Hash: mustDecodeHex("8665e34d889febb70548e46906c54a95b4c61b0f5ffde69697dbe704fea9bc8f")},
				{Hash: mustDecodeHex("11d8b3ab5d1d169ab1cc4a5ba61a78a7872c615aa311040510f4759bd84408fc")},
				{Hash: mustDecodeHex("de18d33117f49e57fc433b643dc406b2ccb3dda16583fdae28250a6ce943f1b7")},
			},
		},
		Anchor:     mustDecodeHex("f0222b509079f55e3eea189e0d1d24a937687e8c7835e1e461fa9bf6f25d7e1e"),
		LocalBlock: 1027728,
	}

	// ---------------------------
	// Layer 2 — BVN → DN Anchor
	// ---------------------------

	layer2 := chained_proof.Layer2AnchorToDN{
		Scope:      "acc://dn.acme/anchors",
		RecordName: "anchor(bvn1)-root",
		Start:      mustDecodeHex("f0222b509079f55e3eea189e0d1d24a937687e8c7835e1e461fa9bf6f25d7e1e"),
		Receipt: chained_proof.MerkleReceipt{
			Start:      mustDecodeHex("f0222b509079f55e3eea189e0d1d24a937687e8c7835e1e461fa9bf6f25d7e1e"),
			Anchor:     mustDecodeHex("537b1b726b35cd51ec562aa899daaa95932da47a23f4d731ab7f1db832144e28"),
			LocalBlock: 1027822,
			Entries: []chained_proof.ReceiptEntry{
				{Hash: mustDecodeHex("e68358a44fa701fb6c7f53b42be571730f72d4474b562cc0cc167154cee78597")},
				{Hash: mustDecodeHex("e308205e8ccfa5d28b71f9f61c32dd74d4b7837ef30d318015492ddf84879ef3")},
				{Hash: mustDecodeHex("371a39bfb2ba22e5b62c8d8296348b906b31e19fc90c23b20cfbc0df5f65734d")},
				{Hash: mustDecodeHex("55f3a069c03247a0f4d6dff9725b4aacae0bac696abdd7f2c95a2f5c4db7b702")},
				{Hash: mustDecodeHex("f9416e0deafaf89b909d6cebddc948481a8fcd12d839dd283a9b93b66e46bca3"), Right: boolPtr(true)},
				{Hash: mustDecodeHex("7529fa17714a4641ca38da1a630e37c9a08c1156d20566b34eff720090455830"), Right: boolPtr(true)},
				{Hash: mustDecodeHex("35b46cf83c71f50b86c4b774fbd3396c79f6b148593c94a6cd40a8b5c12ec8b5")},
				{Hash: mustDecodeHex("84b5c9975857ec8c7614f9de64a8e8756d1969a91f96b2023fb8524c3461dac0")},
				{Hash: mustDecodeHex("6b3fd4b5bd85e9d5a2f36c15f2211de356318b54bec80eeb0f149c27e4d83752")},
				{Hash: mustDecodeHex("f23af5b0e340a8115a873a999e4664d371ac8485b57ceb702d12f162baf00890")},
			},
		},
		Anchor:     mustDecodeHex("537b1b726b35cd51ec562aa899daaa95932da47a23f4d731ab7f1db832144e28"),
		LocalBlock: 1027822,
	}

	// ---------------------------
	// Consensus Finality
	// ---------------------------

	// Layer 1 Consensus Finality (Height = LocalBlock + 1)
	layer1Finality := &chained_proof.ConsensusFinality{
		Partition: "acc://bvn-BVN1.acme",
		Network:   "DevNet.BVN1",
		Height:    layer1.LocalBlock + 1, // 1027729
		Root:      layer1.Anchor,
		Commit: map[string]interface{}{
			"chain_id": "DevNet.BVN1",
			"height":   fmt.Sprintf("%d", layer1.LocalBlock+1),
		},
		Validators: map[string]interface{}{
			"count": "1",
			"total": "1",
		},
		PowerOK:       true,
		RootBindingOK: true,
	}

	// Layer 2 Consensus Finality (Height = LocalBlock + 1)
	layer2Finality := &chained_proof.ConsensusFinality{
		Partition: "acc://dn.acme",
		Network:   "DevNet.Directory",
		Height:    layer2.LocalBlock + 1, // 1027823
		Root:      layer2.Anchor,
		Commit: map[string]interface{}{
			"chain_id": "DevNet.Directory",
			"height":   fmt.Sprintf("%d", layer2.LocalBlock+1),
		},
		Validators: map[string]interface{}{
			"count": "1",
			"total": "1",
		},
		PowerOK:       true,
		RootBindingOK: true,
	}

	// ---------------------------
	// Assemble Proof
	// ---------------------------

	proof := &chained_proof.AccumulateAnchoringProof{
		Version:        chained_proof.SpecificationVersion,
		Timestamp:      time.Now(),
		Layer1:         layer1,
		Layer2:         layer2,
		Layer1Finality: layer1Finality,
		Layer2Finality: layer2Finality,
	}

	// ---------------------------
	// Assertions
	// ---------------------------

	if err := chained_proof.ValidateSpecificationCompliance(proof); err != nil {
		t.Fatalf("Specification compliance validation failed: %v", err)
	}

	if !proof.IsComplete() {
		t.Fatal("Expected proof to be complete")
	}

	if !bytesEqual(proof.GetLeafHash(), layer1.Leaf) {
		t.Fatal("Leaf hash mismatch")
	}

	if !bytesEqual(
		proof.GetDNRoot(),
		mustDecodeHex("537b1b726b35cd51ec562aa899daaa95932da47a23f4d731ab7f1db832144e28"),
	) {
		t.Fatal("DN root mismatch")
	}

	if proof.GetDNHeight() != 1027822 { // Layer2.LocalBlock
		t.Fatal("DN height mismatch")
	}

	t.Log("All data structure validations passed")
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("invalid hex string: %s", s))
	}
	return b
}

func boolPtr(b bool) *bool {
	return &b
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
