package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/commitment"
	"github.com/certen/independant-validator/pkg/proof"
)

func g1With(sigs ...proof.SignatureData) *proof.G1Result {
	g1 := &proof.G1Result{G1ProofComplete: true, ThresholdSatisfied: true}
	for _, s := range sigs {
		g1.ValidatedSignatures = append(g1.ValidatedSignatures, proof.ValidatedSignature{Signature: s,
			TimingVerified: true, TransactionHashVerified: true, CryptographicallyVerified: true})
	}
	return g1
}

// RB3-F139: the authorization leaves are the keys G1 counted - signing page, SHA-256 of the key, the
// signature - not the intent's declared signers with an invented key hash and the signer id as a signature.
func TestAuthorizationLeavesAreTheKeysG1Counted(t *testing.T) {
	pubA, pubB := strings.Repeat("aa", 32), strings.Repeat("bb", 32)
	sigA, sigB := strings.Repeat("11", 64), strings.Repeat("22", 64)
	g1 := g1With(
		proof.SignatureData{PublicKey: pubB, Signature: sigB, Signer: "acc://org.acme/book/1"},
		proof.SignatureData{PublicKey: pubA, Signature: sigA, Signer: "acc://org.acme/book/1"},
		proof.SignatureData{PublicKey: pubA, Signature: sigA, Signer: "acc://org.acme/book/1"}, // the same key again
	)
	leaves, err := authorizationLeavesFromG1(g1)
	if err != nil {
		t.Fatal(err)
	}
	hash := func(pub string) string {
		b, _ := hex.DecodeString(pub)
		h := sha256.Sum256(b)
		return hex.EncodeToString(h[:])
	}
	if len(leaves) != 2 {
		t.Fatalf("%d leaves, want one per key", len(leaves))
	}
	for _, l := range leaves {
		if l.KeyPage != "acc://org.acme/book/1" || l.Role != "signer" {
			t.Fatalf("leaf %+v", l)
		}
		if !(l.KeyHash == hash(pubA) && l.Signature == sigA) && !(l.KeyHash == hash(pubB) && l.Signature == sigB) {
			t.Fatalf("leaf %+v is not a counted key with its own signature", l)
		}
	}
	if leaves[0].KeyHash > leaves[1].KeyHash {
		t.Fatal("leaves are not in a fixed order - validators would compute different roots")
	}
	// The leaves satisfy the consensus invariant that recomputes their root.
	items := []interface{}{leaves[0], leaves[1]}
	root, err := commitment.ComputeGovernanceMerkleRoot(items)
	if err != nil || root == "0x"+strings.Repeat("00", 32) {
		t.Fatalf("root %s (%v)", root, err)
	}
}

// Nothing counted is refused - never a fabricated leaf.
func TestNoAuthorizationLeafWithoutACountedSignature(t *testing.T) {
	for name, g1 := range map[string]*proof.G1Result{
		"no G1":                   nil,
		"threshold not met":       {G1ProofComplete: true},
		"no counted signature":    g1With(),
		"a signature with no key": g1With(proof.SignatureData{Signature: "11", Signer: "acc://org.acme/book/1"}),
	} {
		if leaves, err := authorizationLeavesFromG1(g1); err == nil {
			t.Fatalf("%s: built %+v", name, leaves)
		}
	}
}
