// Copyright 2026 Certen Protocol

package execution

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

// V-R10B D4 (activation freeze): StateProof.Verify and verifyAccountProof are consensus-reachable (slotsHoldAt feeds
// the hashed EffectsHash), so they must answer exactly as validator main 5565d98 answered, on every input. The two
// functions below are the 5565d98 algorithm copied verbatim (only renamed) as the reference; the corpus covers empty
// storage roots, the empty node [0x80], [], absent slots, absent accounts, short code hashes, over-long and
// leading-zero leaves, other accounts' and slots' proofs, and every node of every proof mutated.

func nodeDB5565d98(nodes [][]byte) (*memorydb.Database, error) {
	db := memorydb.New()
	for _, n := range nodes {
		if len(n) == 0 {
			return nil, errEmptyNode5565d98
		}
		if err := db.Put(crypto.Keccak256(n), n); err != nil {
			return nil, err
		}
	}
	return db, nil
}

var errEmptyNode5565d98 = rlp.ErrExpectedList

func verify5565d98(p *StateProof, stateRoot common.Hash) bool {
	if len(p.AccountProof) == 0 || len(p.StorageProof) == 0 {
		return false
	}

	// (1) Account proof against the state root.
	accDB, err := nodeDB5565d98(p.AccountProof)
	if err != nil {
		return false
	}
	accKey := crypto.Keccak256(p.Account.Bytes())
	accRLP, err := trie.VerifyProof(stateRoot, accKey, accDB)
	if err != nil || accRLP == nil {
		return false
	}
	var acc ethAccount
	if err := rlp.DecodeBytes(accRLP, &acc); err != nil {
		return false
	}
	// The account's storageRoot must be the one we verify the storage proof against.
	if acc.Root != p.StorageHash {
		return false
	}

	// (2) Storage proof against the account's storageRoot.
	stoDB, err := nodeDB5565d98(p.StorageProof)
	if err != nil {
		return false
	}
	stoKey := crypto.Keccak256(p.Slot.Bytes())
	valRLP, err := trie.VerifyProof(p.StorageHash, stoKey, stoDB)
	if err != nil {
		return false
	}

	// A cleared slot (value 0) is proven by absence: VerifyProof returns (nil, nil).
	if valRLP == nil {
		return p.Value == (common.Hash{})
	}

	// Storage leaves are RLP( big-endian value with leading zeros trimmed ).
	var valBytes []byte
	if err := rlp.DecodeBytes(valRLP, &valBytes); err != nil {
		return false
	}
	got := common.BytesToHash(valBytes) // left-pads to 32 bytes
	return bytes.Equal(got.Bytes(), p.Value.Bytes())
}

func verifyAccountProof5565d98(stateRoot common.Hash, account common.Address, proof [][]byte) bool {
	if len(proof) == 0 {
		return false
	}
	db, err := nodeDB5565d98(proof)
	if err != nil {
		return false
	}
	accRLP, err := trie.VerifyProof(stateRoot, crypto.Keccak256(account.Bytes()), db)
	if err != nil || accRLP == nil {
		return false
	}
	var acc ethAccount
	return rlp.DecodeBytes(accRLP, &acc) == nil
}

type freezeNodes struct{ nodes [][]byte }

func (s *freezeNodes) Put(_ []byte, v []byte) error {
	s.nodes = append(s.nodes, common.CopyBytes(v))
	return nil
}
func (s *freezeNodes) Delete([]byte) error { return nil }

func freezeProve(t *testing.T, tr *trie.Trie, key []byte) [][]byte {
	t.Helper()
	var ns freezeNodes
	if err := tr.Prove(key, &ns); err != nil {
		t.Fatal(err)
	}
	return ns.nodes
}

// freezeAccount is one account of the corpus state: its storage leaves are raw byte strings (so over-long and
// leading-zero leaves can be stated), and its code hash any byte string.
type freezeAccount struct {
	addr     common.Address
	codeHash []byte
	leaves   map[common.Hash][]byte // slot -> the leaf's byte string (RLP-encoded into the trie)
	storage  *trie.Trie
	root     common.Hash
}

func TestStateProofVerifyAnswersAsAt5565d98(t *testing.T) {
	slots := []common.Hash{common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(4)), common.BigToHash(big.NewInt(9)), common.BigToHash(big.NewInt(77))}
	absent := common.BigToHash(big.NewInt(12345))
	code := crypto.Keccak256([]byte{0x60, 0x00})
	accts := []*freezeAccount{
		{addr: common.HexToAddress("0x1000000000000000000000000000000000000001"), codeHash: code, leaves: map[common.Hash][]byte{
			slots[0]: {0x01}, slots[1]: bytes.Repeat([]byte{0xab}, 32), slots[2]: append([]byte{0x00}, bytes.Repeat([]byte{0x11}, 5)...),
			slots[3]: append([]byte{0x7f}, bytes.Repeat([]byte{0x22}, 32)...)}},
		{addr: common.HexToAddress("0x2000000000000000000000000000000000000002"), codeHash: code}, // the empty storage root
		{addr: common.HexToAddress("0x3000000000000000000000000000000000000003"), codeHash: []byte{0x01, 0x02, 0x03}, leaves: map[common.Hash][]byte{slots[1]: {0x05}}},
		{addr: common.HexToAddress("0x4000000000000000000000000000000000000004"), codeHash: types.EmptyCodeHash.Bytes(), leaves: map[common.Hash][]byte{slots[1]: {}}},
	}
	missing := common.HexToAddress("0x5000000000000000000000000000000000000005")

	state := trie.NewEmpty(nil)
	for _, a := range accts {
		a.storage = trie.NewEmpty(nil)
		for s, leaf := range a.leaves {
			enc, err := rlp.EncodeToBytes(leaf)
			if err != nil {
				t.Fatal(err)
			}
			if err := a.storage.Update(crypto.Keccak256(s.Bytes()), enc); err != nil {
				t.Fatal(err)
			}
		}
		a.root = a.storage.Hash()
		enc, err := rlp.EncodeToBytes(&ethAccount{Nonce: 1, Balance: big.NewInt(7), Root: a.root, CodeHash: a.codeHash})
		if err != nil {
			t.Fatal(err)
		}
		if err := state.Update(crypto.Keccak256(a.addr.Bytes()), enc); err != nil {
			t.Fatal(err)
		}
	}
	stateRoot := state.Hash()
	if accts[1].root != types.EmptyRootHash {
		t.Fatalf("the corpus needs an empty storage root, got %s", accts[1].root.Hex())
	}

	mutations := func(nodes [][]byte) [][][]byte {
		var out [][][]byte
		for i := range nodes {
			for _, pos := range []int{0, 1, len(nodes[i]) / 2, len(nodes[i]) - 1} {
				if pos < 0 || pos >= len(nodes[i]) {
					continue
				}
				m := make([][]byte, len(nodes))
				copy(m, nodes)
				m[i] = common.CopyBytes(nodes[i])
				m[i][pos] ^= 0x01
				out = append(out, m)
			}
			out = append(out, append(append([][]byte{}, nodes[:i]...), nodes[i+1:]...)) // node i dropped
		}
		return out
	}

	type subject struct {
		addr        common.Address
		accountProf [][][]byte
		storageHash []common.Hash
		storage     *trie.Trie
		valueHint   map[common.Hash][]byte
	}
	var cases, differ, acctCases int
	check := func(p *StateProof, root common.Hash) {
		cases++
		want := verify5565d98(p, root)
		if got := p.Verify(root); got != want {
			differ++
			if differ <= 20 {
				t.Errorf("StateProof.Verify = %v, 5565d98 = %v: account %s slot %s value %s storageHash %s storage proof %x", got, want, p.Account.Hex(), p.Slot.Hex(), p.Value.Hex(), p.StorageHash.Hex(), p.StorageProof)
			}
		}
	}
	addrs := []common.Address{missing}
	for _, a := range accts {
		addrs = append(addrs, a.addr)
	}
	byAddr := map[common.Address]*freezeAccount{}
	for _, a := range accts {
		byAddr[a.addr] = a
	}
	for _, addr := range addrs {
		accProof := freezeProve(t, state, crypto.Keccak256(addr.Bytes()))
		accVariants := append([][][]byte{accProof, nil, {{0x80}}}, mutations(accProof)...)
		otherAcc := freezeProve(t, state, crypto.Keccak256(accts[0].addr.Bytes()))
		accVariants = append(accVariants, otherAcc)
		for _, root := range []common.Hash{stateRoot, types.EmptyRootHash, accts[0].root} {
			for _, ap := range accVariants {
				acctCases++
				if got, want := verifyAccountProof(root, addr, ap), verifyAccountProof5565d98(root, addr, ap); got != want {
					t.Errorf("verifyAccountProof = %v, 5565d98 = %v: account %s root %s proof %x", got, want, addr.Hex(), root.Hex(), ap)
				}
			}
		}
		a := byAddr[addr]
		storageRoots := []common.Hash{types.EmptyRootHash, accts[0].root}
		var st *trie.Trie
		if a != nil {
			storageRoots = append(storageRoots, a.root)
			st = a.storage
		}
		for _, slot := range append(append([]common.Hash{}, slots...), absent) {
			var stoVariants [][][]byte
			stoVariants = append(stoVariants, nil, [][]byte{}, [][]byte{{0x80}}, [][]byte{{0xc0}}, [][]byte{{}}, [][]byte{{0x80}, {0x80}})
			if st != nil {
				sp := freezeProve(t, st, crypto.Keccak256(slot.Bytes()))
				stoVariants = append(stoVariants, sp)
				stoVariants = append(stoVariants, mutations(sp)...)
				stoVariants = append(stoVariants, append(append([][]byte{}, sp...), []byte{0x80}))
			}
			stoVariants = append(stoVariants, freezeProve(t, accts[0].storage, crypto.Keccak256(slot.Bytes())))
			values := []common.Hash{{}, common.BigToHash(big.NewInt(1)), common.BigToHash(big.NewInt(5))}
			if a != nil {
				if leaf, ok := a.leaves[slot]; ok {
					values = append(values, common.BytesToHash(leaf))
				}
			}
			for _, ap := range []([][]byte){accProof, otherAcc, nil} {
				for _, sh := range storageRoots {
					for _, sp := range stoVariants {
						for _, v := range values {
							check(&StateProof{Account: addr, Slot: slot, Value: v, AccountProof: ap, StorageHash: sh, StorageProof: sp}, stateRoot)
						}
					}
				}
			}
		}
	}
	// The reviewer's input, named: an account with the empty storage root, a committed slot, StorageProof = [0x80].
	e := accts[1]
	ep := &StateProof{Account: e.addr, Slot: slots[1], Value: common.Hash{}, AccountProof: freezeProve(t, state, crypto.Keccak256(e.addr.Bytes())), StorageHash: types.EmptyRootHash, StorageProof: [][]byte{{0x80}}}
	if verify5565d98(ep, stateRoot) {
		t.Fatalf("the reference must refuse the empty-storage [0x80] proof (it did at 5565d98)")
	}
	if ep.Verify(stateRoot) {
		t.Errorf("StateProof.Verify accepts the empty-storage [0x80] proof; 5565d98 refused it")
	}
	t.Logf("%d StateProof inputs (%d differ), %d account-proof inputs", cases, differ, acctCases)
	if differ > 0 {
		t.Errorf("%d of %d StateProof inputs are answered differently from 5565d98", differ, cases)
	}
}
