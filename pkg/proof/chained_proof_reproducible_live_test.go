//go:build live

// Copyright 2026 Certen Protocol

// Behind the live build tag rather than a skip (00_STANDARD §2): without the tag it is not compiled;
// with it, the network is required.

package proof

import (
	"context"
	"strings"
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
)

// RB3-F87: the L1-L3 proof of an Accumulate transaction is a function of the chain, not of when it is
// built. Production stored intent 47b7e925's proof twice (its Sepolia cycle at 10:05Z and its Base cycle
// at 10:24Z, 2026-09-27) with these anchors; rebuilt any time later it must state the same ones - which
// is what lets a cycle require the proof it stores to be the one consensus signed over.
func TestLiveChainedProofIsReproducible(t *testing.T) {
	b := chained_proof.NewProofBuilder(jsonrpc.NewClient("https://kermit.accumulatenetwork.io/v3"), false)
	cp, err := b.BuildProof(context.Background(), chained_proof.ProofInput{
		Account: "acc://certen-seq-1790497115.acme/data",
		TxHash:  "1578ff3372e0e17e2c726b5d98c4022cf44857d8df874fc4cb59cc195991c8d2",
		BVN:     "bvn1",
	})
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	for name, got := range map[string]string{
		"L1 BVN root chain anchor": cp.Layer1.BVNRootChainAnchor,
		"L2 anchor":                cp.Layer2.DNRootChainAnchor + "|" + cp.Layer2.BVNStateTreeAnchor,
		"L3 anchor":                cp.Layer3.DNStateTreeAnchor + "|" + cp.Layer3.RootReceipt.Anchor + "|" + cp.Layer3.BptReceipt.Anchor,
	} {
		t.Logf("%s: %s", name, got)
	}
	stored := map[string]string{
		"L1": "14bc5d12daca507e5456477c01f861cdbc3dabf3775e5cd6df2bbd9ef8b40da8",
		"L2": "951b6c92f14e6f1cedf92810634407166a2ecf34b810d3f9745d7f078ab68e32",
		"L3": "47baa951291d84b2990d3e226d2f80e892787b73772cee52fe5f37334a0bf78b",
	}
	all := strings.ToLower(cp.Layer1.BVNRootChainAnchor + cp.Layer2.DNRootChainAnchor + cp.Layer2.BVNStateTreeAnchor +
		cp.Layer3.DNStateTreeAnchor + cp.Layer3.RootReceipt.Anchor + cp.Layer3.BptReceipt.Anchor)
	for layer, h := range stored {
		if !strings.Contains(all, h) {
			t.Errorf("%s anchor %s stored at cycle time is not in the rebuilt proof", layer, h)
		}
	}
}
