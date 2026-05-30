package contracts

import (
	"encoding/hex"
	"testing"
)

func hexOfTon(b [32]byte) string { return hex.EncodeToString(b[:]) }

// TON V6.1 hashes are TON cell-hashes (SHA-256 over the cell representation), NOT
// keccak256, so the vectors differ from the Aptos/Sui ones. These pin the cell
// layouts; the on-chain Tact contract's get_deployment_chain_id is checked
// against TestTonDeploymentChainIDVector at bring-up to prove Go↔Tact agree.

func TestTonDeploymentChainIDVector(t *testing.T) {
	got := ComputeTonDeploymentChainIDV6_1("testnet")
	// cellHash(snake("certen:chain:v1:ton:testnet")) — pinned; verified on-chain at bring-up.
	want := "5215992c6c3dca510dacf08ee93bc012193ba1c94cb98c7be9b512003451c533"
	if hexOfTon(got) != want {
		t.Fatalf("ton chain id mismatch:\n got=%s\nwant=%s", hexOfTon(got), want)
	}
}

func TestTonMessageHashDiffersPrePost(t *testing.T) {
	var chain, anchor, exec, op, vset [32]byte
	for i := range chain {
		chain[i], anchor[i], exec[i], op[i], vset[i] = 1, 2, 3, 4, 5
	}
	pre := ComputeTonMessageHashV6_1_Pre(chain, anchor, exec, op, vset)
	post := ComputeTonMessageHashV6_1_Post(chain, anchor, exec, op, vset)
	if hexOfTon(pre) == hexOfTon(post) {
		t.Fatal("pre and post message hashes must differ")
	}
	// determinism
	if hexOfTon(pre) != hexOfTon(ComputeTonMessageHashV6_1_Pre(chain, anchor, exec, op, vset)) {
		t.Fatal("message hash not deterministic")
	}
}

func TestTonBundleIDDeterministic(t *testing.T) {
	mk := func(b byte) [32]byte {
		var a [32]byte
		for i := range a {
			a[i] = b
		}
		return a
	}
	a := DeriveTonBundleIDV6_1(mk(9), mk(1), mk(2), mk(3), mk(4), mk(5), mk(6), 100)
	b := DeriveTonBundleIDV6_1(mk(9), mk(1), mk(2), mk(3), mk(4), mk(5), mk(6), 100)
	if hexOfTon(a) != hexOfTon(b) {
		t.Fatal("bundle id not deterministic")
	}
	// changing block height changes the id
	c := DeriveTonBundleIDV6_1(mk(9), mk(1), mk(2), mk(3), mk(4), mk(5), mk(6), 101)
	if hexOfTon(a) == hexOfTon(c) {
		t.Fatal("bundle id must depend on block height")
	}
}

func TestTonValidatorSetRootOrderIndependent(t *testing.T) {
	mk := func(b byte) [32]byte {
		var a [32]byte
		a[31] = b
		return a
	}
	r1 := ComputeTonValidatorSetRootV6_1([][32]byte{mk(1), mk(2), mk(3)}, []uint64{100, 100, 100}, 2, 3)
	r2 := ComputeTonValidatorSetRootV6_1([][32]byte{mk(3), mk(1), mk(2)}, []uint64{100, 100, 100}, 2, 3)
	if hexOfTon(r1) != hexOfTon(r2) {
		t.Fatalf("validator set root must be order-independent:\n %s\n %s", hexOfTon(r1), hexOfTon(r2))
	}
	// changing threshold changes the root
	r3 := ComputeTonValidatorSetRootV6_1([][32]byte{mk(1), mk(2), mk(3)}, []uint64{100, 100, 100}, 1, 2)
	if hexOfTon(r1) == hexOfTon(r3) {
		t.Fatal("validator set root must depend on threshold")
	}
}
