// Copyright 2026 Certen Protocol

package contractidentity

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// ---- fixtures: real go-ethereum tries and hand-crafted hostile nodes ----

type rfAccount struct {
	addr    common.Address
	nonce   uint64
	balance int64
	code    []byte
	storage map[common.Hash]common.Hash
}

type rfWorld struct {
	state    *trie.Trie
	root     common.Hash
	storage  map[common.Address]*trie.Trie
	accounts []rfAccount
}

type collectDB struct{ nodes [][]byte }

func (c *collectDB) Put(_ []byte, v []byte) error {
	c.nodes = append(c.nodes, append([]byte(nil), v...))
	return nil
}
func (c *collectDB) Delete([]byte) error { return nil }

func trimmedRLP(v common.Hash) []byte {
	enc, _ := rlp.EncodeToBytes(common.TrimLeftZeroes(v[:]))
	return enc
}

func buildRF(t *testing.T, accts []rfAccount) *rfWorld {
	t.Helper()
	w := &rfWorld{state: trie.NewEmpty(nil), storage: map[common.Address]*trie.Trie{}, accounts: accts}
	for _, a := range accts {
		sto := trie.NewEmpty(nil)
		for k, v := range a.storage {
			if v == (common.Hash{}) { // a client never stores a zero: the slot is simply absent
				continue
			}
			if err := sto.Update(crypto.Keccak256(k[:]), trimmedRLP(v)); err != nil {
				t.Fatal(err)
			}
		}
		w.storage[a.addr] = sto
		enc, err := rlp.EncodeToBytes(&accountLeaf{Nonce: a.nonce, Balance: big.NewInt(a.balance), Root: sto.Hash(), CodeHash: common.BytesToHash(crypto.Keccak256(a.code))})
		if err != nil {
			t.Fatal(err)
		}
		if err := w.state.Update(crypto.Keccak256(a.addr[:]), enc); err != nil {
			t.Fatal(err)
		}
	}
	w.root = w.state.Hash()
	return w
}

func provePath(t *testing.T, tr *trie.Trie, key []byte) [][]byte {
	t.Helper()
	var c collectDB
	if err := tr.Prove(crypto.Keccak256(key), &c); err != nil {
		t.Fatal(err)
	}
	return c.nodes
}

// dedupe returns the nodes without duplicates, in first-seen order, sorted by keccak256 as a container carries them.
func asContainerOrder(nodes [][]byte) [][]byte {
	seen := map[common.Hash]bool{}
	var out [][]byte
	for _, n := range nodes {
		h := common.BytesToHash(crypto.Keccak256(n))
		if !seen[h] {
			seen[h] = true
			out = append(out, n)
		}
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && bytes.Compare(crypto.Keccak256(out[j-1]), crypto.Keccak256(out[j])) > 0; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

func mustNS(t *testing.T, nodes [][]byte) *NodeSet {
	t.Helper()
	ns, err := NewNodeSet(nodes)
	if err != nil {
		t.Fatal(err)
	}
	return ns
}

func wantRead(t *testing.T, err error, kind ReadKind) *ReadError {
	t.Helper()
	var re *ReadError
	if !errors.As(err, &re) || !errors.Is(err, ErrProofInvalid) || re.Kind != kind {
		t.Fatalf("want proof_invalid{%s}, got %v", kind, err)
	}
	return re
}

func dynSlots(base common.Hash, data []byte, out map[common.Hash]common.Hash) {
	if len(data) < 32 {
		var w common.Hash
		copy(w[:], data)
		w[31] = byte(2 * len(data))
		out[base] = w
		return
	}
	var head common.Hash
	new(big.Int).SetUint64(uint64(2*len(data) + 1)).FillBytes(head[24:])
	out[base] = head
	for i := 0; i*32 < len(data); i++ {
		var w common.Hash
		copy(w[:], data[i*32:])
		out[DynDataSlot(base, uint64(i))] = w
	}
}

func honestWorld(t *testing.T) (*rfWorld, map[string][]byte) {
	t.Helper()
	strs := map[string][]byte{
		"empty": nil, "s31": []byte(strings.Repeat("a", 31)), "l32": []byte(strings.Repeat("b", 32)),
		"l33": []byte(strings.Repeat("c", 33)), "l70": []byte(strings.Repeat("0123456789", 7)), "l64": []byte(strings.Repeat("d", 64)),
	}
	var accts []rfAccount
	for i := 1; i <= 40; i++ {
		a := rfAccount{addr: common.BigToAddress(big.NewInt(int64(i))), nonce: uint64(i * 3), balance: int64(i) * 1000, code: bytes.Repeat([]byte{byte(i)}, i%5)}
		if i%2 == 0 {
			a.storage = map[common.Hash]common.Hash{}
			for s := 0; s < 12; s++ {
				if s == 7 { // a stored zero is deleted: the slot is simply absent
					continue
				}
				a.storage[SlotIndex(uint64(s))] = common.BigToHash(big.NewInt(int64(i*100 + s + 1)))
			}
			a.storage[SlotIndex(1)] = common.HexToHash("0xff00000000000000000000000000000000000000000000000000000000000001")
		}
		if i == 2 { // the string zoo, slots 20..25
			for j, k := range []string{"empty", "s31", "l32", "l33", "l70", "l64"} {
				dynSlots(SlotIndex(uint64(20+j)), strs[k], a.storage)
			}
		}
		accts = append(accts, a)
	}
	return buildRF(t, accts), strs
}

func TestReadsHonestWorldMatchesEthproof(t *testing.T) {
	w, _ := honestWorld(t)
	// the node set is the union of the proofs of what we read, as a capture would carry it
	var all [][]byte
	probes := []common.Address{}
	for _, a := range w.accounts {
		probes = append(probes, a.addr)
		all = append(all, provePath(t, w.state, a.addr[:])...)
	}
	absent := common.BigToAddress(big.NewInt(9999))
	probes = append(probes, absent)
	all = append(all, provePath(t, w.state, absent[:])...)
	slotProbes := map[common.Address][]common.Hash{}
	for _, a := range w.accounts {
		if len(a.storage) == 0 {
			continue
		}
		for s := uint64(0); s < 14; s++ { // slot 7 is absent, 12 and 13 never stored
			slotProbes[a.addr] = append(slotProbes[a.addr], SlotIndex(s))
			all = append(all, provePath(t, w.storage[a.addr], SlotIndex(s).Bytes())...)
		}
	}
	ns := mustNS(t, asContainerOrder(all))
	for _, addr := range probes {
		acc, err := ReadAccount(w.root, ns, addr)
		if err != nil {
			t.Fatalf("%s: %v", addr.Hex(), err)
		}
		ref, err := ethproof.VerifyAccount(w.root, addr, provePath(t, w.state, addr[:]))
		if err != nil {
			t.Fatal(err)
		}
		if acc.Exists != ref.Exists || acc.Nonce != ref.Nonce || acc.Balance.Cmp(ref.Balance) != 0 || acc.StorageRoot != ref.StorageRoot || acc.CodeHash != ref.CodeHash {
			t.Fatalf("%s: %+v vs ethproof %+v", addr.Hex(), acc, ref)
		}
		for _, slot := range slotProbes[addr] {
			got, err := ReadSlot(acc.StorageRoot, ns, slot)
			if err != nil {
				t.Fatal(err)
			}
			want, err := ethproof.VerifySlot(acc.StorageRoot, slot, provePath(t, w.storage[addr], slot.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("%s slot %s: %s vs ethproof %s", addr.Hex(), slot.Hex(), got.Hex(), want.Hex())
			}
		}
	}
	if absentAcc, _ := ReadAccount(w.root, ns, absent); absentAcc.Exists || absentAcc.StorageRoot != types.EmptyRootHash || absentAcc.HasCode() {
		t.Fatalf("absent account %+v", absentAcc)
	}
	// every node of the set was needed by some read here: nothing is unvisited
	if got := ns.Unvisited(); len(got) != 0 {
		t.Fatalf("%d nodes unvisited by reads that proved them", len(got))
	}
	if ns.VisitedCount() != ns.Len() || len(ns.VisitedNodes()) != ns.Len() {
		t.Fatal("visited accounting")
	}
}

func TestReadsDecoyNodeIsCountedNotRefused(t *testing.T) {
	w, _ := honestWorld(t)
	target := w.accounts[3].addr
	decoyOwner := w.accounts[30].addr
	path := provePath(t, w.state, target[:])
	decoy := provePath(t, w.state, decoyOwner[:]) // right hashes, never reached by the target's walk
	set := asContainerOrder(append(append([][]byte{}, path...), decoy...))
	ns := mustNS(t, set)
	acc, err := ReadAccount(w.root, ns, target)
	if err != nil || !acc.Exists || acc.Nonce != w.accounts[3].nonce {
		t.Fatalf("read with a decoy: %+v %v", acc, err)
	}
	un := ns.Unvisited()
	// the root is shared; the decoy's own tail nodes are not visited
	wantVisited := asContainerOrder(path)
	if ns.VisitedCount() != len(wantVisited) || len(un) != ns.Len()-len(wantVisited) || len(un) == 0 {
		t.Fatalf("visited %d unvisited %d (path %d, set %d)", ns.VisitedCount(), len(un), len(wantVisited), ns.Len())
	}
	for _, i := range un {
		if ns.Visited(common.BytesToHash(crypto.Keccak256(set[i]))) {
			t.Fatal("an unvisited index names a visited node")
		}
	}
	for _, n := range ns.VisitedNodes() {
		found := false
		for _, p := range path {
			found = found || bytes.Equal(n, p)
		}
		if !found {
			t.Fatal("a visited node is not on the target path")
		}
	}
}

func TestReadsMissingNodeIsNeverAnAbsence(t *testing.T) {
	w, _ := honestWorld(t)
	present := w.accounts[5].addr
	absent := common.BigToAddress(big.NewInt(9999))
	for _, addr := range []common.Address{present, absent} {
		path := provePath(t, w.state, addr[:])
		for drop := range path {
			var rest [][]byte
			for i, n := range path {
				if i != drop {
					rest = append(rest, n)
				}
			}
			ns := mustNS(t, asContainerOrder(rest))
			acc, err := ReadAccount(w.root, ns, addr)
			re := wantRead(t, err, ReadMissingNode)
			if acc.Exists || re.Missing != common.BytesToHash(crypto.Keccak256(path[drop])) || re.Address == nil || *re.Address != addr || re.Root != w.root {
				t.Fatalf("drop %d of %d: %+v %+v", drop, len(path), acc, re)
			}
		}
	}
	// an empty node set misses the root itself
	_, err := ReadAccount(w.root, mustNS(t, nil), present)
	wantRead(t, err, ReadMissingNode)
	_, err = ReadAccount(w.root, nil, present)
	wantRead(t, err, ReadMissingNode)
	// storage: dropping a node of a slot walk
	acc := w.accounts[1] // address 2 has storage
	sto := w.storage[acc.addr]
	spath := provePath(t, sto, SlotIndex(3).Bytes())
	ns := mustNS(t, asContainerOrder(spath[:len(spath)-1]))
	_, err = ReadSlot(sto.Hash(), ns, SlotIndex(3))
	re := wantRead(t, err, ReadMissingNode)
	if re.Slot == nil || *re.Slot != SlotIndex(3) {
		t.Fatal("slot not named")
	}
}

func TestReadsEmptyRootsNeedNoNode(t *testing.T) {
	ns := mustNS(t, nil)
	acc, err := ReadAccount(types.EmptyRootHash, ns, common.Address{1})
	if err != nil || acc.Exists || ns.VisitedCount() != 0 {
		t.Fatalf("empty state root: %+v %v", acc, err)
	}
	v, err := ReadSlot(types.EmptyRootHash, ns, SlotIndex(0))
	if err != nil || v != (common.Hash{}) {
		t.Fatalf("empty storage root: %v %v", v, err)
	}
	if b, err := ReadBytes(types.EmptyRootHash, ns, SlotIndex(0), 10); err != nil || len(b) != 0 {
		t.Fatalf("empty string in empty storage: %q %v", b, err)
	}
}

// ---- hand-crafted hostile nodes ----

func rv(items ...[]byte) []byte { // an RLP list of already-encoded items
	raws := make([]rlp.RawValue, len(items))
	for i, it := range items {
		raws[i] = it
	}
	b, err := rlp.EncodeToBytes(raws)
	if err != nil {
		panic(err)
	}
	return b
}

func rs(b []byte) []byte { e, _ := rlp.EncodeToBytes(b); return e }

var empty = []byte{0x80}

func hashRef(b string) []byte { return rs(crypto.Keccak256([]byte(b))) }

func branch(children map[int][]byte, value []byte) []byte {
	items := make([][]byte, 17)
	for i := 0; i < 16; i++ {
		if c, ok := children[i]; ok {
			items[i] = c
		} else {
			items[i] = empty
		}
	}
	items[16] = value
	if value == nil {
		items[16] = empty
	}
	return rv(items...)
}

func rootOf(node []byte) common.Hash { return common.BytesToHash(crypto.Keccak256(node)) }

// addrWithNibble finds an address whose account-trie key starts with the given nibble.
func addrWithNibble(nib byte) common.Address {
	for i := int64(1); ; i++ {
		a := common.BigToAddress(big.NewInt(i))
		if crypto.Keccak256(a[:])[0]>>4 == nib {
			return a
		}
	}
}

func TestReadsHostileNodes(t *testing.T) {
	good := hashRef("child")
	bigVal := bytes.Repeat([]byte{1}, 100)
	cases := []struct {
		name string
		node []byte
		kind ReadKind
		sub  string
	}{
		{"truncated", branch(map[int][]byte{0: good, 1: good}, nil)[:60], ReadNodeMalformed, "RLP"},
		{"trailing byte", append(branch(map[int][]byte{0: good, 1: good}, nil), 0x00), ReadNodeMalformed, "trailing"},
		{"17th value", branch(map[int][]byte{0: good, 1: good}, rs([]byte{1})), ReadNodeMalformed, "carrying a value"},
		{"single child branch", branch(map[int][]byte{0: good}, nil), ReadNodeMalformed, "1 children"},
		{"no child branch", branch(nil, nil), ReadNodeMalformed, "0 children"},
		{"three elements", rv(rs([]byte{0x20}), rs([]byte{1}), rs([]byte{2})), ReadNodeMalformed, "3 elements"},
		{"extension empty path", rv(rs([]byte{0x00}), good), ReadNodeMalformed, "empty path"},
		{"extension without child", rv(rs([]byte{0x11}), empty), ReadNodeMalformed, "without a child"},
		{"extension child 31 bytes", rv(rs([]byte{0x11}), rs(bytes.Repeat([]byte{7}, 31))), ReadNodeMalformed, "reference of 31"},
		{"hex-prefix flag 4", rv(rs([]byte{0x40, 0xaa}), good), ReadNodeMalformed, "flag 4"},
		{"even path dirty padding nibble", rv(rs([]byte{0x05, 0xaa}), good), ReadNodeMalformed, "padding nibble"},
		{"empty hex-prefix", rv(rs(nil), good), ReadNodeMalformed, "empty hex-prefix"},
		{"leaf empty value", rv(rs([]byte{0x20, 0xab}), empty), ReadNodeMalformed, "empty value"},
		{"leaf extra element bytes", append(rv(rs([]byte{0x20, 0xab}), rs(bigVal)), 0), ReadNodeMalformed, "trailing"},
		{"branch child 33 bytes", branch(map[int][]byte{0: good, 1: rs(bytes.Repeat([]byte{7}, 33))}, nil), ReadNodeMalformed, "reference of 33"},
		{"embedded child of 32 bytes", branch(map[int][]byte{0: good, 1: rv(rs([]byte{0x20, 0xab}), rs(bytes.Repeat([]byte{9}, 27)))}, nil), ReadNodeMalformed, "embedded node of 32"},
		{"not a list", rs(bytes.Repeat([]byte{3}, 40)), ReadNodeMalformed, "not an RLP list"},
	}
	for _, c := range cases {
		root := rootOf(c.node)
		ns := mustNS(t, [][]byte{c.node})
		_, err := ReadAccount(root, ns, addrWithNibble(0))
		re := wantRead(t, err, c.kind)
		if !strings.Contains(re.Detail, c.sub) {
			t.Fatalf("%s: detail %q lacks %q", c.name, re.Detail, c.sub)
		}
		if ns.VisitedCount() != 0 {
			t.Fatalf("%s: a refused node was counted as visited", c.name)
		}
		_, err = ReadSlot(root, ns, SlotIndex(0))
		wantRead(t, err, c.kind)
	}
}

func TestReadsWrongChildHashAndExclusion(t *testing.T) {
	// a branch whose children 0 and 1 point at nodes the set does not hold
	node := branch(map[int][]byte{0: hashRef("none-0"), 1: hashRef("none-1")}, nil)
	root := rootOf(node)
	ns := mustNS(t, [][]byte{node})
	a0, a1, a5 := addrWithNibble(0), addrWithNibble(1), addrWithNibble(5)
	for _, a := range []common.Address{a0, a1} {
		_, err := ReadAccount(root, ns, a)
		re := wantRead(t, err, ReadMissingNode)
		if re.Missing == (common.Hash{}) {
			t.Fatal("missing hash not named")
		}
	}
	// the empty child at nibble 5 is a genuine exclusion proof
	acc, err := ReadAccount(root, ns, a5)
	if err != nil || acc.Exists {
		t.Fatalf("exclusion through an empty child: %+v %v", acc, err)
	}
	if ns.VisitedCount() != 1 {
		t.Fatal("the branch was visited")
	}
}

func TestReadsLeafPathMismatchIsAnExclusionNotAnError(t *testing.T) {
	addr := common.BigToAddress(big.NewInt(77))
	// a root leaf whose path is some other 64-nibble key: valid exclusion for addr
	other := crypto.Keccak256([]byte("another key"))
	leafFor := func(path []byte, val []byte) []byte { return rv(rs(append([]byte{0x20}, path...)), rs(val)) }
	leaf := leafFor(other, []byte{1, 2, 3})
	root := rootOf(leaf)
	acc, err := ReadAccount(root, mustNS(t, [][]byte{leaf}), addr)
	if err != nil || acc.Exists {
		t.Fatalf("diverging leaf: %+v %v", acc, err)
	}
	// a shorter path that is a prefix of the key: still not the key's leaf
	short := leafFor(crypto.Keccak256(addr[:])[:31], []byte{1, 2, 3})
	acc, err = ReadAccount(rootOf(short), mustNS(t, [][]byte{short}), addr)
	if err != nil || acc.Exists {
		t.Fatalf("prefix leaf: %+v %v", acc, err)
	}
}

func TestReadsNodeSizeBoundaryIsExact(t *testing.T) {
	// a root leaf that diverges from the key (an exclusion) with a value sized so the whole node is exactly N bytes
	mk := func(n int) []byte {
		for v := 1; v < 6000; v++ {
			node := rv(rs([]byte{0x20, 0xab}), rs(bytes.Repeat([]byte{5}, v)))
			if len(node) == n {
				return node
			}
		}
		t.Fatalf("no leaf of %d bytes", n)
		return nil
	}
	addr := common.BigToAddress(big.NewInt(3))
	ok := mk(MaxTrieNodeBytes)
	if acc, err := ReadAccount(rootOf(ok), mustNS(t, [][]byte{ok}), addr); err != nil || acc.Exists {
		t.Fatalf("a node of exactly %d bytes: %+v %v", MaxTrieNodeBytes, acc, err)
	}
	over := mk(MaxTrieNodeBytes + 1)
	_, err := ReadAccount(rootOf(over), mustNS(t, [][]byte{over}), addr)
	re := wantRead(t, err, ReadNodeTooLarge)
	if !strings.Contains(re.Detail, "4097") {
		t.Fatalf("detail %q", re.Detail)
	}
	if _, err := ReadSlot(rootOf(over), mustNS(t, [][]byte{over}), SlotIndex(0)); err == nil {
		t.Fatal("storage walk accepted a 4097-byte node")
	}
}

func leafNode(key []byte, val []byte) []byte { // a root leaf for the 32-byte key, val already the leaf's value bytes
	return rv(rs(append([]byte{0x20}, key...)), rs(val))
}

func TestReadsAccountLeafStrictness(t *testing.T) {
	addr := common.BigToAddress(big.NewInt(5))
	key := crypto.Keccak256(addr[:])
	ok4, _ := rlp.EncodeToBytes([]rlp.RawValue{rlpUint(1), rlpUint(2), rs(make([]byte, 32)), rs(make([]byte, 32))})
	cases := []struct {
		name string
		val  []byte
		good bool
	}{
		{"four fields", ok4, true},
		{"extra field", rv(rlpUint(1), rlpUint(2), rs(make([]byte, 32)), rs(make([]byte, 32)), rlpUint(9)), false},
		{"three fields", rv(rlpUint(1), rlpUint(2), rs(make([]byte, 32))), false},
		{"code hash 31 bytes", rv(rlpUint(1), rlpUint(2), rs(make([]byte, 32)), rs(make([]byte, 31))), false},
		{"storage root 33 bytes", rv(rlpUint(1), rlpUint(2), rs(make([]byte, 33)), rs(make([]byte, 32))), false},
		{"balance with a leading zero", rv(rlpUint(1), []byte{0x82, 0x00, 0x01}, rs(make([]byte, 32)), rs(make([]byte, 32))), false},
		{"nonce with a leading zero", rv([]byte{0x82, 0x00, 0x01}, rlpUint(2), rs(make([]byte, 32)), rs(make([]byte, 32))), false},
		{"trailing byte after the list", append(append([]byte{}, ok4...), 0x00), false},
		{"not a list", rs([]byte{1, 2, 3}), false},
	}
	for _, c := range cases {
		node := leafNode(key, c.val)
		acc, err := ReadAccount(rootOf(node), mustNS(t, [][]byte{node}), addr)
		if c.good {
			if err != nil || !acc.Exists || acc.Nonce != 1 || acc.Balance.Int64() != 2 {
				t.Fatalf("%s: %+v %v", c.name, acc, err)
			}
			continue
		}
		wantRead(t, err, ReadAccountMalformed)
	}
}

func rlpUint(v uint64) []byte { e, _ := rlp.EncodeToBytes(v); return e }

func TestReadsStorageLeafStrictness(t *testing.T) {
	slot := SlotIndex(4)
	key := crypto.Keccak256(slot[:])
	ok := func(v []byte) ([]byte, error) { // reads the slot out of a one-leaf storage trie holding raw leaf value v
		node := leafNode(key, v)
		got, err := ReadSlot(rootOf(node), mustNS(t, [][]byte{node}), slot)
		return got[:], err
	}
	if got, err := ok(rs([]byte{0x01, 0x02})); err != nil || got[30] != 1 || got[31] != 2 {
		t.Fatalf("honest value: %x %v", got, err)
	}
	full := bytes.Repeat([]byte{0xff}, 32)
	if got, err := ok(rs(full)); err != nil || !bytes.Equal(got, full) {
		t.Fatalf("32-byte value: %v", err)
	}
	for name, v := range map[string][]byte{
		"leading zero":          rs([]byte{0x00, 0x01}),
		"single zero byte":      rs([]byte{0x00}),
		"33 bytes":              rs(bytes.Repeat([]byte{1}, 33)),
		"empty string (zero)":   {0x80},
		"non-canonical 1 byte":  {0x81, 0x05},
		"a list":                rv(rs([]byte{1})),
		"trailing after string": append(rs([]byte{1, 2}), 0x00),
	} {
		_, err := ok(v)
		wantRead(t, err, ReadValueMalformed)
		_ = name
	}
}

func TestReadsStringLayouts(t *testing.T) {
	w, strs := honestWorld(t)
	acc := w.accounts[1]
	sto := w.storage[acc.addr]
	var all [][]byte
	for i := uint64(20); i < 26; i++ {
		all = append(all, provePath(t, sto, SlotIndex(i).Bytes())...)
		for j := uint64(0); j < 3; j++ {
			all = append(all, provePath(t, sto, DynDataSlot(SlotIndex(i), j).Bytes())...)
		}
	}
	ns := mustNS(t, asContainerOrder(all))
	for i, k := range []string{"empty", "s31", "l32", "l33", "l70", "l64"} {
		got, err := ReadBytes(sto.Hash(), ns, SlotIndex(uint64(20+i)), 1024)
		if err != nil || !bytes.Equal(got, strs[k]) {
			t.Fatalf("%s: %q %v", k, got, err)
		}
	}
	if s, err := ReadString(sto.Hash(), ns, SlotIndex(24), 70); err != nil || s != string(strs["l70"]) {
		t.Fatalf("string at the limit: %v", err)
	}
	// N passes, N-1 fails, and the refusal reads no data word
	before := ns.VisitedCount()
	_, err := ReadBytes(sto.Hash(), ns, SlotIndex(24), 69)
	wantRead(t, err, ReadDynamicInvalid)
	if ns.VisitedCount() != before {
		t.Fatal("a refused over-long head read data words")
	}
	// a short value at the limit 31 and one above
	if _, err := ReadBytes(sto.Hash(), ns, SlotIndex(21), 31); err != nil {
		t.Fatal(err)
	}
	_, err = ReadBytes(sto.Hash(), ns, SlotIndex(21), 30)
	wantRead(t, err, ReadDynamicInvalid)
	// a missing data word is a missing node, not a short value
	partial := mustNS(t, asContainerOrder(provePath(t, sto, SlotIndex(24).Bytes())))
	_, err = ReadBytes(sto.Hash(), partial, SlotIndex(24), 1024)
	wantRead(t, err, ReadMissingNode)
}

func TestReadsStringPaddingAndHeadRefusals(t *testing.T) {
	// storage with a long string whose last word carries a non-zero byte after the value, a bad head, and a huge head
	slotPad, slotBad, slotHuge := SlotIndex(1), SlotIndex(2), SlotIndex(3)
	st := map[common.Hash]common.Hash{}
	var head common.Hash
	head[31] = 2*33 + 1
	st[slotPad] = head
	var w0, w1 common.Hash
	copy(w0[:], bytes.Repeat([]byte{7}, 32))
	w1[0], w1[5] = 7, 9 // byte 5 is past the 33rd value byte
	st[DynDataSlot(slotPad, 0)], st[DynDataSlot(slotPad, 1)] = w0, w1
	st[slotBad] = common.BigToHash(big.NewInt(64)) // even, above 62
	var huge common.Hash
	huge[0], huge[31] = 0x40, 1
	st[slotHuge] = huge
	w := buildRF(t, []rfAccount{{addr: common.BigToAddress(big.NewInt(1)), storage: st}})
	sto := w.storage[w.accounts[0].addr]
	var all [][]byte
	for k := range st {
		all = append(all, provePath(t, sto, k.Bytes())...)
	}
	ns := mustNS(t, asContainerOrder(all))
	for _, s := range []common.Hash{slotPad, slotBad, slotHuge} {
		_, err := ReadBytes(sto.Hash(), ns, s, 1024)
		wantRead(t, err, ReadDynamicInvalid)
	}
}

func TestNodeSetConstruction(t *testing.T) {
	if _, err := NewNodeSet([][]byte{{}}); err == nil {
		t.Fatal("empty node accepted")
	} else {
		wantRead(t, err, ReadNodeSetInvalid)
	}
	n := branch(map[int][]byte{0: hashRef("a"), 1: hashRef("b")}, nil)
	if _, err := NewNodeSet([][]byte{n, n}); err == nil {
		t.Fatal("duplicate accepted")
	} else {
		wantRead(t, err, ReadNodeSetInvalid)
	}
	var nilSet *NodeSet
	if nilSet.Len() != 0 || nilSet.Has(common.Hash{}) || nilSet.Visited(common.Hash{}) || nilSet.VisitedCount() != 0 || nilSet.Unvisited() != nil || nilSet.VisitedNodes() != nil {
		t.Fatal("nil set accessors")
	}
}

func TestReadsHostileInputAllocatesAtMostTwiceTheInput(t *testing.T) {
	// a head claiming 2^62 bytes against a limit: refused without allocating anything near the claim
	var head common.Hash
	head[24], head[31] = 0x80, 1
	st := map[common.Hash]common.Hash{SlotIndex(0): head}
	w := buildRF(t, []rfAccount{{addr: common.BigToAddress(big.NewInt(1)), storage: st}})
	sto := w.storage[w.accounts[0].addr]
	nodes := asContainerOrder(provePath(t, sto, SlotIndex(0).Bytes()))
	in := 0
	for _, n := range nodes {
		in += len(n)
	}
	ns := mustNS(t, nodes)
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	_, err := ReadBytes(sto.Hash(), ns, SlotIndex(0), 1024)
	runtime.ReadMemStats(&m1)
	wantRead(t, err, ReadDynamicInvalid)
	if used := m1.TotalAlloc - m0.TotalAlloc; used > uint64(64*1024+2*in) {
		t.Fatalf("a refused head allocated %d bytes for an input of %d", used, in)
	}
	// ParseDynHead itself allocates nothing for a refusal beyond the error
	if _, err := ParseDynHead(head, 1024); err == nil {
		t.Fatal("huge head accepted")
	}
}

func TestReadErrorText(t *testing.T) {
	e := &ReadError{Kind: ReadMissingNode, Missing: common.Hash{1}, Detail: "x"}
	if !strings.Contains(e.Error(), "missing_node") || !errors.Is(e, ErrProofInvalid) || errors.Is(e, ErrSlot) {
		t.Fatal(fmt.Sprint(e))
	}
}

func TestReadIndexedLeafOverAListTrie(t *testing.T) {
	// an ordered-list trie (transactions or receipts): key rlp(index), one leaf larger than a state node may be
	tr := trie.NewEmpty(nil)
	vals := [][]byte{bytes.Repeat([]byte{1}, 40), bytes.Repeat([]byte{2}, 6000), bytes.Repeat([]byte{3}, 70)}
	for i, v := range vals {
		k, _ := rlp.EncodeToBytes(uint64(i))
		if err := tr.Update(k, v); err != nil {
			t.Fatal(err)
		}
	}
	root := tr.Hash()
	var col collectDB
	for i := range vals {
		k, _ := rlp.EncodeToBytes(uint64(i))
		if err := tr.Prove(k, &col); err != nil {
			t.Fatal(err)
		}
	}
	ns := mustNS(t, asContainerOrder(col.nodes))
	for i, v := range vals {
		got, err := ReadIndexedLeaf(root, ns, uint64(i), DefaultLimits().MaxNodeBytes)
		if err != nil || !bytes.Equal(got, v) {
			t.Fatalf("index %d: %v", i, err)
		}
	}
	// the node bound is the caller's: a state-node bound refuses the 6000-byte leaf node, exactly
	_, err := ReadIndexedLeaf(root, ns, 1, MaxTrieNodeBytes)
	wantRead(t, err, ReadNodeTooLarge)
	// an index the list does not hold is an absence of the entry, not a zero value
	_, err = ReadIndexedLeaf(root, ns, 9, DefaultLimits().MaxNodeBytes)
	wantRead(t, err, ReadLeafAbsent)
	// a node missing from the set
	_, err = ReadIndexedLeaf(root, mustNS(t, nil), 0, DefaultLimits().MaxNodeBytes)
	wantRead(t, err, ReadMissingNode)
}
