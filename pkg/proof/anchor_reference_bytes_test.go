package proof

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// AGT-F11 test A: a real bundle written by the fleet (AGT-0 scene 1, 2026-11-18; its anchor reference carries
// anchored_at 0001-01-01 and no block hash) still verifies its own artifact_hash after decoding: the anchor reference
// of every bundle without a State serialises exactly as before.
func TestARealBundleStillVerifiesItsArtifactHash(t *testing.T) {
	raw, err := os.ReadFile("testdata/agt0_scene1_bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	var b CertenProofBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	got, err := b.ComputeArtifactHash()
	if err != nil {
		t.Fatal(err)
	}
	if got != b.BundleIntegrity.ArtifactHash {
		t.Fatalf("recomputed artifact hash %s, stored %s", got, b.BundleIntegrity.ArtifactHash)
	}
	if ok, err := b.VerifyIntegrity(); !ok || err != nil {
		t.Fatalf("VerifyIntegrity = %v, %v", ok, err)
	}
	ref, _ := json.Marshal(b.ProofComponents.AnchorReference)
	if !strings.Contains(string(ref), `"anchored_at":"0001-01-01T00:00:00Z"`) || !strings.Contains(string(ref), `"anchor_block_number":60397757`) {
		t.Fatalf("the stored reference no longer serialises as written: %s", ref)
	}
}

// AGT-F11 test B: a reference that carries a State omits the block fields it does not have and is not complete.
func TestAStatedAnchorReferenceOmitsBlockFieldsAndIsNotComplete(t *testing.T) {
	ref := &AnchorReferenceProof{TargetChain: "84532", AnchorTxHash: "0x43766439c30deea319debe031b6f00d90ef1cede7735b8969e3ba15212a0f1ad",
		RequiredConfs: 2, State: "anchor_block_unread"}
	raw, err := json.Marshal(ref)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"anchor_block_number", "anchor_block_hash", "anchored_at"} {
		if strings.Contains(string(raw), `"`+k+`"`) {
			t.Fatalf("a stated reference carries %s: %s", k, raw)
		}
	}
	if !strings.Contains(string(raw), `"state":"anchor_block_unread"`) {
		t.Fatalf("no state: %s", raw)
	}
	b := &CertenProofBundle{}
	b.ProofComponents.MerkleInclusion = &MerkleInclusionProof{}
	b.ProofComponents.ChainedProof = &ChainedProofData{}
	b.ProofComponents.GovernanceProof = &GovernanceProof{}
	b.ProofComponents.AnchorReference = ref
	if b.IsComplete() {
		t.Fatal("a bundle whose anchor reference states anchor_block_unread is complete")
	}
}
