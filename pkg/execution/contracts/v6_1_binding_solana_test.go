package contracts

import (
	"encoding/hex"
	"testing"
)

// Byte-parity vectors independently computed with ethers.keccak256 (the same
// keccak256 the EVM/Solana contracts use). The Solana Rust contract's own unit
// tests assert against the identical vectors, so passing here proves the Go
// signer and the on-chain verifier agree byte-for-byte.

func hexOf(b [32]byte) string { return hex.EncodeToString(b[:]) }

func TestSolanaDeploymentChainIDVector(t *testing.T) {
	got := ComputeSolanaDeploymentChainIDV6_1("devnet")
	want := "bb65a784933c3330b0dc4d76dd5cf1cec90a16be18c6cb63e40bf698e6d0d038"
	if hexOf(got) != want {
		t.Fatalf("chain id mismatch:\n got=%s\nwant=%s", hexOf(got), want)
	}
}

func TestSolanaMessageHashVectors(t *testing.T) {
	chain := [32]byte{}
	anchor := [32]byte{}
	exec := [32]byte{}
	op := [32]byte{}
	vset := [32]byte{}
	for i := range chain {
		chain[i], anchor[i], exec[i], op[i], vset[i] = 1, 2, 3, 4, 5
	}

	pre := ComputeSolanaMessageHashV6_1_Pre(chain, anchor, exec, op, vset)
	wantPre := "cdf8a0a3c672e6476c93587b6a8935989376b0f783ddd0ff882eee6314cf5610"
	if hexOf(pre) != wantPre {
		t.Fatalf("pre msg mismatch:\n got=%s\nwant=%s", hexOf(pre), wantPre)
	}

	post := ComputeSolanaMessageHashV6_1_Post(chain, anchor, exec, op, vset)
	wantPost := "f0eaf101247f40649dc8cce829a8d88ac8a7228faf81640152db0f84080da1d1"
	if hexOf(post) != wantPost {
		t.Fatalf("post msg mismatch:\n got=%s\nwant=%s", hexOf(post), wantPost)
	}
	if hexOf(pre) == hexOf(post) {
		t.Fatal("pre and post must differ")
	}
}

func TestSolanaBundleIDVector(t *testing.T) {
	mk := func(b byte) [32]byte {
		var a [32]byte
		for i := range a {
			a[i] = b
		}
		return a
	}
	got := DeriveSolanaBundleIDV6_1(
		mk(9), mk(1), mk(2), mk(3), mk(4), mk(5), mk(6), 100,
	)
	want := "2bbde895c915ab6502676c98a0ff83bc249025bf1fc68ffeeb20a98473f251ed"
	if hexOf(got) != want {
		t.Fatalf("bundle id mismatch:\n got=%s\nwant=%s", hexOf(got), want)
	}
}

func TestSolanaValidatorSetRootVector(t *testing.T) {
	var pk [32]byte
	for i := range pk {
		pk[i] = 1
	}
	got := ComputeSolanaValidatorSetRootV6_1([][32]byte{pk}, []uint64{100}, 2, 3)
	want := "8c28cb46d2fefe8f659d7f00636aafd1d1f99d0c139e6c95b76a323e32c60746"
	if hexOf(got) != want {
		t.Fatalf("vset root mismatch:\n got=%s\nwant=%s", hexOf(got), want)
	}

	// Order-independent (sorted internally).
	var pk2 [32]byte
	for i := range pk2 {
		pk2[i] = 2
	}
	a := ComputeSolanaValidatorSetRootV6_1([][32]byte{pk, pk2}, []uint64{100, 50}, 2, 3)
	b := ComputeSolanaValidatorSetRootV6_1([][32]byte{pk2, pk}, []uint64{50, 100}, 2, 3)
	if hexOf(a) != hexOf(b) {
		t.Fatal("validator set root must be order-independent")
	}
}

func TestSolanaExecutionCommitmentVector(t *testing.T) {
	var target [32]byte
	for i := range target {
		target[i] = 7
	}
	got := ComputeSolanaExecutionCommitmentV6_1("devnet", target, 1, []byte{0xde, 0xad, 0xbe, 0xef})
	want := "63541feea3c6f4c65789f98e966997fe90d92cf6b894117e40a7dbd5e207591f"
	if hexOf(got) != want {
		t.Fatalf("exec commitment mismatch:\n got=%s\nwant=%s", hexOf(got), want)
	}
}
