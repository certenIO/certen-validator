package contracts

import (
	"encoding/hex"
	"testing"
)

// Byte-parity vectors independently computed with ethers.keccak256. The Aptos
// message-hash / bundle-id / validator-set-root primitives are byte-identical to
// the (already-verified) Solana ones for shared inputs because the chain_id is an
// input, not the chain-derived value — so passing here proves the Aptos Go signer
// and the on-chain Move verifier agree byte-for-byte.

func hexOfAptos(b [32]byte) string { return hex.EncodeToString(b[:]) }

func TestAptosDeploymentChainIDVector(t *testing.T) {
	got := ComputeAptosDeploymentChainIDV6_1("testnet")
	want := "f56ad75d6cc1c6726294f307048b29247a63b43cd5e4c4d193c06db14544f592"
	if hexOfAptos(got) != want {
		t.Fatalf("aptos chain id mismatch:\n got=%s\nwant=%s", hexOfAptos(got), want)
	}
}

func TestAptosMessageHashVectors(t *testing.T) {
	var chain, anchor, exec, op, vset [32]byte
	for i := range chain {
		chain[i], anchor[i], exec[i], op[i], vset[i] = 1, 2, 3, 4, 5
	}
	pre := ComputeAptosMessageHashV6_1_Pre(chain, anchor, exec, op, vset)
	// Identical formula+inputs as the verified Solana PRE_MSG vector.
	if hexOfAptos(pre) != "cdf8a0a3c672e6476c93587b6a8935989376b0f783ddd0ff882eee6314cf5610" {
		t.Fatalf("aptos pre msg mismatch: got=%s", hexOfAptos(pre))
	}
	post := ComputeAptosMessageHashV6_1_Post(chain, anchor, exec, op, vset)
	if hexOfAptos(post) != "f0eaf101247f40649dc8cce829a8d88ac8a7228faf81640152db0f84080da1d1" {
		t.Fatalf("aptos post msg mismatch: got=%s", hexOfAptos(post))
	}
	if hexOfAptos(pre) == hexOfAptos(post) {
		t.Fatal("pre and post must differ")
	}
}

func TestAptosBundleIDVector(t *testing.T) {
	mk := func(b byte) [32]byte {
		var a [32]byte
		for i := range a {
			a[i] = b
		}
		return a
	}
	got := DeriveAptosBundleIDV6_1(mk(9), mk(1), mk(2), mk(3), mk(4), mk(5), mk(6), 100)
	if hexOfAptos(got) != "2bbde895c915ab6502676c98a0ff83bc249025bf1fc68ffeeb20a98473f251ed" {
		t.Fatalf("aptos bundle id mismatch: got=%s", hexOfAptos(got))
	}
}

func TestAptosValidatorSetRootVector(t *testing.T) {
	var addr [32]byte
	for i := range addr {
		addr[i] = 1
	}
	got := ComputeAptosValidatorSetRootV6_1([][32]byte{addr}, []uint64{100}, 2, 3)
	if hexOfAptos(got) != "8c28cb46d2fefe8f659d7f00636aafd1d1f99d0c139e6c95b76a323e32c60746" {
		t.Fatalf("aptos vset root mismatch: got=%s", hexOfAptos(got))
	}
}
