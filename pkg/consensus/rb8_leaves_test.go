package consensus

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig/sigfixture"
	"github.com/certen/independant-validator/pkg/proof"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// RB8-B: the authorization leaf's key hash is the key page's entry, by the signature type's own rule. It was
// sha256(key) for every type, which is right for four of the nine.
func TestRB8_AuthorizationLeafKeyHashIsTheTypesOwn(t *testing.T) {
	for _, ty := range govsig.AcceptedKeyTypes() {
		for _, delegated := range []bool{false, true} {
			k, err := sigfixture.NewKey(ty, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			pub, _ := sigfixture.PublicKey(k)
			sd := proof.SignatureData{Type: strings.ToLower(ty.String()), PublicKey: hex.EncodeToString(pub),
				Signature: "ab", Signer: "acc://probe.acme/book/1"}
			if delegated {
				sd.Type = "delegated"
				if ty != protocol.SignatureTypeED25519 {
					sd.InnerType = strings.ToLower(ty.String())
				}
			}
			g1 := &proof.G1Result{G1ProofComplete: true, ThresholdSatisfied: true,
				ValidatedSignatures: []proof.ValidatedSignature{{Signature: sd}}}
			leaves, err := authorizationLeavesFromG1(g1)
			if err != nil || len(leaves) != 1 {
				t.Fatalf("%v delegated=%v: %v", ty, delegated, err)
			}
			want, _ := protocol.PublicKeyHash(pub, ty)
			if leaves[0].KeyHash != hex.EncodeToString(want) {
				t.Errorf("%v delegated=%v: leaf key hash %s, the page entry is %x", ty, delegated, leaves[0].KeyHash, want)
			}
		}
	}
}

func TestRB8_AuthorizationLeafRefusesANonKeyType(t *testing.T) {
	g1 := &proof.G1Result{G1ProofComplete: true, ThresholdSatisfied: true, ValidatedSignatures: []proof.ValidatedSignature{
		{Signature: proof.SignatureData{Type: "authority", PublicKey: "aa", Signature: "bb", Signer: "acc://p.acme/book/1"}}}}
	if _, err := authorizationLeavesFromG1(g1); err == nil || !strings.Contains(err.Error(), "ecdsaSha256") {
		t.Fatalf("a non-key type has no key hash, and the refusal states the rule: %v", err)
	}
}
