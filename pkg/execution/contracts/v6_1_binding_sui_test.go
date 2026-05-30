package contracts

import (
	"encoding/hex"
	"testing"
)

// Byte-parity vectors independently computed with ethers/@noble keccak256. The
// Sui message-hash / bundle-id / validator-set-root primitives are byte-identical
// to the (already-verified) Aptos/Solana ones for shared inputs because the
// chain_id is an INPUT, not the chain-derived value — so passing here proves the
// Sui Go signer and the on-chain Move verifier agree byte-for-byte. Only the
// deployment-chain-id vector differs (domain "sui" instead of "aptos").

func hexOfSui(b [32]byte) string { return hex.EncodeToString(b[:]) }

func TestSuiDeploymentChainIDVector(t *testing.T) {
	got := ComputeSuiDeploymentChainIDV6_1("testnet")
	// keccak256("certen:chain:v1:sui:" || "testnet")
	want := "575a70aaf99366c03a13541516803f4596590bdd8c07b13ecc725700e1376793"
	if hexOfSui(got) != want {
		t.Fatalf("sui chain id mismatch:\n got=%s\nwant=%s", hexOfSui(got), want)
	}
}

func TestSuiMessageHashVectors(t *testing.T) {
	var chain, anchor, exec, op, vset [32]byte
	for i := range chain {
		chain[i], anchor[i], exec[i], op[i], vset[i] = 1, 2, 3, 4, 5
	}
	pre := ComputeSuiMessageHashV6_1_Pre(chain, anchor, exec, op, vset)
	// Identical formula+inputs as the verified Aptos/Solana PRE_MSG vector.
	if hexOfSui(pre) != "cdf8a0a3c672e6476c93587b6a8935989376b0f783ddd0ff882eee6314cf5610" {
		t.Fatalf("sui pre msg mismatch: got=%s", hexOfSui(pre))
	}
	post := ComputeSuiMessageHashV6_1_Post(chain, anchor, exec, op, vset)
	if hexOfSui(post) != "f0eaf101247f40649dc8cce829a8d88ac8a7228faf81640152db0f84080da1d1" {
		t.Fatalf("sui post msg mismatch: got=%s", hexOfSui(post))
	}
	if hexOfSui(pre) == hexOfSui(post) {
		t.Fatal("pre and post must differ")
	}
}

func TestSuiBundleIDVector(t *testing.T) {
	mk := func(b byte) [32]byte {
		var a [32]byte
		for i := range a {
			a[i] = b
		}
		return a
	}
	got := DeriveSuiBundleIDV6_1(mk(9), mk(1), mk(2), mk(3), mk(4), mk(5), mk(6), 100)
	if hexOfSui(got) != "2bbde895c915ab6502676c98a0ff83bc249025bf1fc68ffeeb20a98473f251ed" {
		t.Fatalf("sui bundle id mismatch: got=%s", hexOfSui(got))
	}
}

func TestSuiValidatorSetRootVector(t *testing.T) {
	var addr [32]byte
	for i := range addr {
		addr[i] = 1
	}
	got := ComputeSuiValidatorSetRootV6_1([][32]byte{addr}, []uint64{100}, 2, 3)
	if hexOfSui(got) != "8c28cb46d2fefe8f659d7f00636aafd1d1f99d0c139e6c95b76a323e32c60746" {
		t.Fatalf("sui vset root mismatch: got=%s", hexOfSui(got))
	}
}
