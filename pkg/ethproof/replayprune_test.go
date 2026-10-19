// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"bytes"
	"errors"
	"math/big"
	"math/rand"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethproof/replayworld"
)

// RB10-B14b: PruneStorageProof reduces an account proof and a storage proof, once they verify, to the nodes the unchanged
// verifier reads, root to leaf. These tests hold it to the verifier on randomised tries, node for node.

func pruneRandBytes(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)
	rng.Read(b)
	return b
}

func pruneSameResult(a, b *ethproof.StorageResult) bool {
	return a.Account.Exists == b.Account.Exists && a.Account.Nonce == b.Account.Nonce && a.Account.Balance.Cmp(b.Account.Balance) == 0 &&
		a.Account.StorageRoot == b.Account.StorageRoot && a.Account.CodeHash == b.Account.CodeHash && a.Value == b.Value
}

func pruneEqualLists(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// pruneIsASubset: every node of sub is a node of all.
func pruneIsASubset(sub, all [][]byte) bool {
	have := map[string]bool{}
	for _, n := range all {
		have[string(n)] = true
	}
	for _, n := range sub {
		if !have[string(n)] {
			return false
		}
	}
	return true
}

// pruneIsRootToLeaf: the first node hashes to root and each next node's hash is inside the node before it.
func pruneIsRootToLeaf(root common.Hash, list [][]byte) bool {
	for i, n := range list {
		if i == 0 && crypto.Keccak256Hash(n) != root {
			return false
		}
		if i > 0 && !bytes.Contains(list[i-1], crypto.Keccak256(n)) {
			return false
		}
	}
	return true
}

func pruneNoDuplicates(list [][]byte) bool {
	seen := map[string]bool{}
	for _, n := range list {
		if seen[string(n)] {
			return false
		}
		seen[string(n)] = true
	}
	return true
}

type pruneCase struct {
	root          common.Hash
	addr          common.Address
	slot          common.Hash
	acct, sto     [][]byte // what the verifier is given
	honestA, honS [][]byte // the honest proof (trie.Prove)
	corrupted     bool
}

func pruneRandomState(t *testing.T, rng *rand.Rand, targetAccount bool, slots int, nAcct int) (*replayworld.State, []replayworld.Account) {
	t.Helper()
	var accts []replayworld.Account
	for i := 0; i < nAcct; i++ {
		a := replayworld.Account{Addr: common.BytesToAddress(pruneRandBytes(rng, 20)), Code: pruneRandBytes(rng, 1+rng.Intn(40))}
		n := rng.Intn(4)
		if i == 0 && targetAccount {
			n = slots
		}
		if n > 0 {
			a.Storage = map[common.Hash]*big.Int{}
		}
		for k := 0; k < n; k++ {
			v := new(big.Int).SetBytes(pruneRandBytes(rng, 1+rng.Intn(32)))
			if v.Sign() == 0 {
				v.SetInt64(1)
			}
			a.Storage[common.BytesToHash(pruneRandBytes(rng, 32))] = v
		}
		accts = append(accts, a)
	}
	return replayworld.BuildState(t, accts...), accts
}

// The differential: 2000 random states (depth and branching vary with the number of accounts and slots; slots and accounts
// are present, absent, and an account may have no storage at all), each proof served honestly, padded, duplicated,
// reordered, mixed with nodes of other tries, or corrupted. For every one: pruning gives an error exactly when the verifier
// refuses (the verifier's own error), and otherwise a proof that the verifier accepts to identical results, made of nodes
// of the input only, root to leaf, each needed (dropping any one makes the verifier refuse), and equal to the honest proof
// whenever the input held it whole.
func TestPrune_TheVerifierAcceptsThePrunedProofToIdenticalResults(t *testing.T) {
	const cases = 2000
	rng := rand.New(rand.NewSource(20261019))
	var cov struct {
		present, absentSlot, absentAccount, emptyRoot, padded, reordered, corrupted, refused, accepted, paddedAccepted, deepAccount, deepStorage int
	}
	acctSizes := []int{1, 2, 3, 5, 16, 40, 300}
	slotSizes := []int{0, 1, 2, 5, 17, 70, 300}
	for i := 0; i < cases; i++ {
		nAcct := acctSizes[rng.Intn(len(acctSizes))]
		slots := slotSizes[rng.Intn(len(slotSizes))]
		st, accts := pruneRandomState(t, rng, true, slots, nAcct)
		target := accts[0]
		var addr common.Address
		var slot common.Hash
		switch kind := rng.Intn(3); {
		case kind == 0 && len(target.Storage) > 0:
			addr = target.Addr
			for s := range target.Storage {
				slot = s
				break
			}
			cov.present++
		case kind == 2:
			addr, slot = common.BytesToAddress(pruneRandBytes(rng, 20)), common.BytesToHash(pruneRandBytes(rng, 32))
			cov.absentAccount++
		default:
			addr, slot = target.Addr, common.BytesToHash(pruneRandBytes(rng, 32))
			if len(target.Storage) == 0 {
				cov.emptyRoot++
			} else {
				cov.absentSlot++
			}
		}
		honest := st.Prove(addr, slot)
		c := pruneCase{root: st.Root, addr: addr, slot: slot, honestA: b14bBytes(honest.AccountProof), honS: b14bBytes(honest.StorageProof)}
		c.acct, c.sto = append([][]byte(nil), c.honestA...), append([][]byte(nil), c.honS...)
		other, _ := pruneRandomState(t, rng, false, 0, 1+rng.Intn(5))
		op := other.Prove(common.BytesToAddress(pruneRandBytes(rng, 20)), slot)
		foreign := append(b14bBytes(op.AccountProof), b14bBytes(op.StorageProof)...)
		switch mode := rng.Intn(10); mode {
		case 0, 1, 2:
		case 3, 4: // padding: extra nodes of other tries, small and large, duplicates of honest nodes
			c.acct = append(append(c.acct, foreign...), c.honestA...)
			c.sto = append(append(c.sto, pruneRandBytes(rng, 33)), c.honS...)
			if rng.Intn(4) == 0 {
				c.acct = append(c.acct, make([]byte, 200000))
			}
			cov.padded++
		case 5: // reversed
			for a, b := 0, len(c.acct)-1; a < b; a, b = a+1, b-1 {
				c.acct[a], c.acct[b] = c.acct[b], c.acct[a]
			}
			for a, b := 0, len(c.sto)-1; a < b; a, b = a+1, b-1 {
				c.sto[a], c.sto[b] = c.sto[b], c.sto[a]
			}
			cov.reordered++
		case 6, 7: // everything, shuffled
			c.acct = append(append(c.acct, foreign...), c.honestA...)
			c.sto = append(append(c.sto, foreign...), c.honS...)
			rng.Shuffle(len(c.acct), func(a, b int) { c.acct[a], c.acct[b] = c.acct[b], c.acct[a] })
			rng.Shuffle(len(c.sto), func(a, b int) { c.sto[a], c.sto[b] = c.sto[b], c.sto[a] })
			cov.padded++
			cov.reordered++
		case 8: // corrupted: a byte flipped in, a node dropped from, or a foreign node swapped into one of the lists
			list := &c.acct
			if len(c.sto) > 0 && rng.Intn(2) == 0 {
				list = &c.sto
			}
			if len(*list) > 0 {
				k := rng.Intn(len(*list))
				cp := append([]byte(nil), (*list)[k]...)
				switch rng.Intn(3) {
				case 0:
					cp[rng.Intn(len(cp))] ^= 1 << uint(rng.Intn(8))
					(*list)[k] = cp
				case 1:
					*list = append(append([][]byte(nil), (*list)[:k]...), (*list)[k+1:]...)
				default:
					if len(foreign) > 0 {
						(*list)[k] = foreign[rng.Intn(len(foreign))]
					}
				}
			}
			c.corrupted = true
			cov.corrupted++
		default: // padded with an empty node, which the verifier refuses
			c.sto = append(c.sto, []byte{})
			cov.padded++
		}

		res, errU := ethproof.VerifyStorage(c.root, c.addr, c.acct, c.slot, c.sto)
		pr, errP := ethproof.PruneStorageProof(c.root, c.addr, c.acct, c.slot, c.sto)
		if (errU == nil) != (errP == nil) || (errU != nil && errU.Error() != errP.Error()) {
			t.Fatalf("case %d: the verifier says %v, pruning says %v", i, errU, errP)
		}
		if errU != nil {
			if !errors.Is(errP, ethproof.ErrStorageProofInvalid) {
				t.Fatalf("case %d: refusal %v is not ErrStorageProofInvalid", i, errP)
			}
			cov.refused++
			continue
		}
		cov.accepted++
		if len(c.acct) > len(c.honestA) || len(c.sto) > len(c.honS) {
			cov.paddedAccepted++
		}
		again, err := ethproof.VerifyStorage(c.root, c.addr, pr.AccountProof, c.slot, pr.StorageProof)
		if err != nil {
			t.Fatalf("case %d: the verifier refuses the pruned proof: %v", i, err)
		}
		if !pruneSameResult(res, again) || !pruneSameResult(res, pr.Result) {
			t.Fatalf("case %d: results differ\n unpruned %+v %s\n pruned   %+v %s\n returned %+v %s", i, res.Account, res.Value.Hex(), again.Account, again.Value.Hex(), pr.Result.Account, pr.Result.Value.Hex())
		}
		if !pruneIsASubset(pr.AccountProof, c.acct) || !pruneIsASubset(pr.StorageProof, c.sto) {
			t.Fatalf("case %d: the pruned proof holds a node the input did not", i)
		}
		if !pruneNoDuplicates(pr.AccountProof) || !pruneNoDuplicates(pr.StorageProof) {
			t.Fatalf("case %d: duplicate nodes survive", i)
		}
		if !pruneIsRootToLeaf(c.root, pr.AccountProof) {
			t.Fatalf("case %d: the account proof is not root to leaf", i)
		}
		if res.Account.Exists && res.Account.StorageRoot != crypto.Keccak256Hash([]byte{0x80}) && !pruneIsRootToLeaf(res.Account.StorageRoot, pr.StorageProof) {
			t.Fatalf("case %d: the storage proof is not root to leaf", i)
		}
		// each node is needed
		for k := range pr.AccountProof {
			cut := append(append([][]byte(nil), pr.AccountProof[:k]...), pr.AccountProof[k+1:]...)
			if _, err := ethproof.VerifyStorage(c.root, c.addr, cut, c.slot, pr.StorageProof); err == nil {
				t.Fatalf("case %d: account node %d of the pruned proof is not needed", i, k)
			}
		}
		if res.Account.Exists && res.Account.StorageRoot != crypto.Keccak256Hash([]byte{0x80}) {
			for k := range pr.StorageProof {
				cut := append(append([][]byte(nil), pr.StorageProof[:k]...), pr.StorageProof[k+1:]...)
				if _, err := ethproof.VerifyStorage(c.root, c.addr, pr.AccountProof, c.slot, cut); err == nil {
					t.Fatalf("case %d: storage node %d of the pruned proof is not needed", i, k)
				}
			}
		}
		// the honest proof, whole, comes back as it is whatever surrounded it
		if !c.corrupted && (!pruneEqualLists(pr.AccountProof, c.honestA) || !pruneEqualLists(pr.StorageProof, c.honS)) {
			t.Fatalf("case %d: the pruned proof (%d+%d nodes) is not the honest one (%d+%d nodes)", i, len(pr.AccountProof), len(pr.StorageProof), len(c.honestA), len(c.honS))
		}
		if len(pr.AccountProof) >= 3 {
			cov.deepAccount++
		}
		if len(pr.StorageProof) >= 3 {
			cov.deepStorage++
		}
	}
	t.Logf("cases %d: present %d, absent slot %d, absent account %d, empty storage root %d, padded %d, reordered %d, corrupted %d; accepted %d (of which padded %d), refused %d; account proofs of 3+ nodes %d, storage proofs of 3+ nodes %d",
		cases, cov.present, cov.absentSlot, cov.absentAccount, cov.emptyRoot, cov.padded, cov.reordered, cov.corrupted, cov.accepted, cov.paddedAccepted, cov.refused, cov.deepAccount, cov.deepStorage)
	if cov.present < 200 || cov.absentSlot < 200 || cov.absentAccount < 200 || cov.emptyRoot < 50 || cov.padded < 400 || cov.reordered < 200 ||
		cov.corrupted < 100 || cov.refused < 100 || cov.accepted < 1000 || cov.paddedAccepted < 300 || cov.deepAccount < 50 || cov.deepStorage < 100 {
		t.Fatalf("the random cases do not cover what they claim")
	}
}

// An account with no storage has the empty storage root, which needs no node: the verifier accepts no proof, or the empty
// node alone, and pruning keeps the accepted form as served (the walk reads no node, there is nothing to cut), while
// anything more is refused with the verifier's own error.
func TestPrune_TheEmptyStorageRootKeepsWhatTheVerifierAccepts(t *testing.T) {
	addr := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	st := replayworld.BuildState(t, replayworld.Account{Addr: addr, Code: []byte{1, 2, 3}}, replayworld.Account{Addr: replayworld.Other})
	slot := common.HexToHash("0x07")
	honest := st.Prove(addr, slot)
	if honest.StorageHash.Hex() != "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421" {
		t.Fatalf("not the empty storage root: %s", honest.StorageHash.Hex())
	}
	acct := b14bBytes(honest.AccountProof)
	for _, c := range []struct {
		name string
		sto  [][]byte
		keep bool
	}{
		{"none", nil, true},
		{"the empty node", [][]byte{{0x80}}, true},
		{"the empty node twice", [][]byte{{0x80}, {0x80}}, false},
		{"a node of another tree", [][]byte{acct[0]}, false},
		{"the 3 MiB node", [][]byte{make([]byte, 3<<20)}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, errU := ethproof.VerifyStorage(st.Root, addr, acct, slot, c.sto)
			pr, errP := ethproof.PruneStorageProof(st.Root, addr, acct, slot, c.sto)
			if (errU == nil) != c.keep || (errU == nil) != (errP == nil) || (errU != nil && errU.Error() != errP.Error()) {
				t.Fatalf("verifier %v, pruning %v, want accepted=%v", errU, errP, c.keep)
			}
			if errP == nil && (!pruneEqualLists(pr.StorageProof, c.sto) || !pruneEqualLists(pr.AccountProof, acct) || pr.Result.Value != (common.Hash{})) {
				t.Fatalf("the accepted form changed: %d nodes -> %d", len(c.sto), len(pr.StorageProof))
			}
		})
	}
}

// An absent account: a padded exclusion proof is cut to the walk; a storage proof offered beside it is refused.
func TestPrune_AnAbsentAccountKeepsOnlyTheExclusionWalk(t *testing.T) {
	st, _ := pruneRandomState(t, rand.New(rand.NewSource(7)), false, 0, 40)
	addr := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	slot := common.HexToHash("0x09")
	honest := st.Prove(addr, slot)
	if !honest.AccountAbsent {
		t.Fatal("the account exists")
	}
	acct := b14bBytes(honest.AccountProof)
	padded := append(append([][]byte{make([]byte, 3<<20)}, acct...), acct...)
	pr, err := ethproof.PruneStorageProof(st.Root, addr, padded, slot, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pr.Result.Account.Exists || !pruneEqualLists(pr.AccountProof, acct) || len(pr.StorageProof) != 0 {
		t.Fatalf("pruned to %d account nodes, %d storage nodes: %+v", len(pr.AccountProof), len(pr.StorageProof), pr.Result.Account)
	}
	if _, err := ethproof.PruneStorageProof(st.Root, addr, acct, slot, [][]byte{acct[0]}); err == nil || !errors.Is(err, ethproof.ErrStorageProofInvalid) {
		t.Fatalf("a storage proof beside an absent account: %v", err)
	}
}

// A node of fewer than 32 bytes is embedded in its parent, never a proof entry: the trie below is one entry that holds two
// embedded levels, and the walk reads that one entry, as the honest proof lists it.
func TestPrune_EmbeddedNodesAreNotSeparateEntries(t *testing.T) {
	tr := trie.NewEmpty(nil)
	for k, v := range map[string]string{"\x10": "a", "\x11": "b", "\x12": "c"} {
		if err := tr.Update([]byte(k), []byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	root := tr.Hash()
	for _, key := range []string{"\x10", "\x11", "\x12", "\x13", "\x20", "\x1000"} {
		var honest pruneCollector
		if err := tr.Prove([]byte(key), &honest); err != nil {
			t.Fatal(err)
		}
		if len(honest.nodes) != 1 {
			t.Fatalf("key %x: the honest proof has %d entries, the whole trie is embedded in its root", key, len(honest.nodes))
		}
		padded := append([][]byte{make([]byte, 1000)}, honest.nodes...)
		padded = append(padded, honest.nodes[0], []byte{0xc0})
		v, walked, err := ethproof.ProofWalk(root, []byte(key), padded)
		if err != nil {
			t.Fatalf("key %x: %v", key, err)
		}
		if !pruneEqualLists(walked, honest.nodes) {
			t.Fatalf("key %x: walked %d nodes", key, len(walked))
		}
		want, err := trie.VerifyProof(root, []byte(key), pruneDB(t, honest.nodes))
		if err != nil || !bytes.Equal(v, want) {
			t.Fatalf("key %x: walk value %x, verifier %x (%v)", key, v, want, err)
		}
	}
}

type pruneCollector struct{ nodes [][]byte }

func (c *pruneCollector) Put(_ []byte, v []byte) error {
	c.nodes = append(c.nodes, append([]byte(nil), v...))
	return nil
}
func (c *pruneCollector) Delete([]byte) error { return nil }

func pruneDB(t *testing.T, nodes [][]byte) *memorydb.Database {
	t.Helper()
	db := memorydb.New()
	for _, n := range nodes {
		if err := db.Put(crypto.Keccak256(n), n); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// The walk on raw keys of every length, with values of every size, so that embedded nodes occur at every level: 2000 random
// tries, each key asked present and absent, the proof padded and shuffled. The walked nodes are the honest proof, the value
// is the verifier's, and the walk of the walked nodes is itself.
func TestPrune_TheWalkEqualsTheHonestProofOnRandomRawKeyTries(t *testing.T) {
	rng := rand.New(rand.NewSource(14014))
	embeddedTries, multi := 0, 0
	for i := 0; i < 2000; i++ {
		tr := trie.NewEmpty(nil)
		var keys [][]byte
		n := 1 + rng.Intn(24)
		if i%7 == 0 {
			n = 1 + rng.Intn(300)
		}
		for k := 0; k < n; k++ {
			key := pruneRandBytes(rng, 1+rng.Intn(3))
			if i%5 == 0 {
				key = pruneRandBytes(rng, 1+rng.Intn(32))
			}
			if err := tr.Update(key, pruneRandBytes(rng, 1+rng.Intn(30))); err != nil {
				t.Fatal(err)
			}
			keys = append(keys, key)
		}
		root := tr.Hash()
		asks := [][]byte{keys[rng.Intn(len(keys))], pruneRandBytes(rng, 1+rng.Intn(4)), pruneRandBytes(rng, 32)}
		for _, key := range asks {
			var honest pruneCollector
			if err := tr.Prove(key, &honest); err != nil {
				t.Fatal(err)
			}
			if len(honest.nodes) == 0 {
				continue
			}
			padded := append([][]byte(nil), honest.nodes...)
			for e := 0; e < 1+rng.Intn(8); e++ {
				padded = append(padded, pruneRandBytes(rng, 1+rng.Intn(100)))
			}
			var all pruneCollector
			for _, k := range keys {
				_ = tr.Prove(k, &all)
			}
			padded = append(padded, all.nodes...)
			rng.Shuffle(len(padded), func(a, b int) { padded[a], padded[b] = padded[b], padded[a] })
			want, werr := trie.VerifyProof(root, key, pruneDB(t, padded))
			v, walked, err := ethproof.ProofWalk(root, key, padded)
			if (werr == nil) != (err == nil) || !bytes.Equal(v, want) {
				t.Fatalf("trie %d key %x: verifier (%x, %v), walk (%x, %v)", i, key, want, werr, v, err)
			}
			if err != nil {
				t.Fatalf("trie %d key %x: an honest proof inside padding is refused: %v", i, key, err)
			}
			if !pruneEqualLists(walked, honest.nodes) {
				t.Fatalf("trie %d key %x: walked %d nodes, the honest proof has %d", i, key, len(walked), len(honest.nodes))
			}
			v2, again, err := ethproof.ProofWalk(root, key, walked)
			if err != nil || !bytes.Equal(v2, v) || !pruneEqualLists(again, walked) {
				t.Fatalf("trie %d key %x: the walked nodes do not walk to themselves: %v", i, key, err)
			}
			if len(walked) > 1 {
				multi++
			}
			if len(walked) > 0 && len(walked[0]) < 400 && n > 1 && len(key) <= 3 {
				embeddedTries++
			}
		}
	}
	t.Logf("walks of 2+ nodes %d, small-key walks %d", multi, embeddedTries)
	if multi < 500 {
		t.Fatalf("only %d walks of 2 or more nodes", multi)
	}
}
