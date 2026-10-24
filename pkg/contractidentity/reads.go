// Copyright 2026 Certen Protocol

package contractidentity

// Reads API
//
// Every fact the S8 verifier (and the capture that builds the evidence it later verifies) reads from a chain comes through three
// functions over ONE node set, the NODES list of the container:
//
//	ns, err := NewNodeSet(container.Nodes)                         // keyed by keccak256(node); a duplicate is an error
//	acc, err := ReadAccount(stateRoot, ns, address)                // nonce, balance, storageRoot, codeHash, exists (proven absence = !Exists)
//	val, err := ReadSlot(acc.StorageRoot, ns, slot)                // the 32-byte word, or the proven zero
//	str, err := ReadString(acc.StorageRoot, ns, slot, maxLen)      // short/long layout of step 6; ReadBytes is the same layout
//
// Rules, all enforced here and tested on hostile inputs:
//
//   - the walk is go-ethereum's trie.VerifyProof (no hand-written Merkle-Patricia code) over a node store that looks nodes up by their own
//     keccak256 and remembers which ones the walks asked for. A node the walk needs and the set does not hold is the named refusal
//     ReadMissingNode (a missing node is NOT an absence); a verified exclusion proof is the only way an account or slot reads as absent/zero.
//   - a hash-referenced trie node above MaxTrieNodeBytes (4096), a node that is not exactly one RLP list of 2 or 17 elements, an extension
//     with an empty path, an invalid hex-prefix flag, a branch that carries a value or fewer than two children, a leaf with an empty value, a
//     child reference that is not empty, 32 bytes or an embedded node shorter than 32 bytes, and trailing bytes after a node are refused
//     (ReadNodeTooLarge / ReadNodeMalformed) even though the hash of the node is right: the root is authenticated, the node shapes are strict.
//   - an account leaf is exactly [nonce, balance, storageRoot(32), codeHash(32)] with canonical integers; a storage leaf is the RLP string
//     of the trimmed value: 1..32 bytes, first byte non-zero (a client never stores a zero). Anything else is ReadAccountMalformed /
//     ReadValueMalformed.
//   - an empty storage root (or an empty state root) needs no node: every slot of it is zero and nothing is visited.
//   - bytes/string values: the head word (ParseDynHead) bounds the length BEFORE any data word is read or allocated; short values read one
//     slot, long values exactly ceil(len/32) more, and non-zero padding is refused.
//   - nodes that no walk visited are NOT an error here: the NodeSet counts them (Unvisited) so a capture can prune and the verifier can apply
//     step 22b (nodes_unreferenced) once every read of the run is done.
//
// Every refusal is a *ReadError (errors.Is(err, ErrProofInvalid)): the verifier raises proof_invalid{root,address,slot} from it; the Kind is
// the sub-reason it prints in the detail (missing_node, node_too_large, ...). The NodeSet is not safe for concurrent use.

import (
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

// MaxTrieNodeBytes is the bound of a hash-referenced state or storage trie node (Freeze item 1a row 9): a larger node is proof_invalid at
// the walk. (The largest honest node is a 17-element branch of 32-byte hashes, about 532 bytes.)
const MaxTrieNodeBytes = 4096

// ErrProofInvalid is the class of every read that does not verify: the registry state proof_invalid.
var ErrProofInvalid = errors.New("proof_invalid")

// ReadKind names why a read did not verify (the sub-reason printed beside proof_invalid).
type ReadKind string

// Read refusal kinds.
const (
	ReadMissingNode      ReadKind = "missing_node"
	ReadNodeTooLarge     ReadKind = "node_too_large"
	ReadNodeMalformed    ReadKind = "node_malformed"
	ReadWalkFailed       ReadKind = "walk_failed"
	ReadAccountMalformed ReadKind = "account_malformed"
	ReadValueMalformed   ReadKind = "value_malformed"
	ReadDynamicInvalid   ReadKind = "dynamic_invalid"
	ReadNodeSetInvalid   ReadKind = "node_set_invalid"
	ReadLeafAbsent       ReadKind = "leaf_absent"
)

// ReadError is a read that does not verify.
type ReadError struct {
	Kind ReadKind
	// Root is the trie root the walk started from (zero for a node-set construction error).
	Root common.Hash
	// Address is set for an account read; Slot for a storage read.
	Address *common.Address
	Slot    *common.Hash
	// Missing is the hash of the node that was needed and absent (ReadMissingNode).
	Missing common.Hash
	Detail  string
}

func (e *ReadError) Error() string {
	s := fmt.Sprintf("proof_invalid{%s} root=%s", e.Kind, e.Root.Hex())
	if e.Address != nil {
		s += " address=" + e.Address.Hex()
	}
	if e.Slot != nil {
		s += " slot=" + e.Slot.Hex()
	}
	if e.Kind == ReadMissingNode {
		s += " node=" + e.Missing.Hex()
	}
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

// Is reports the class ErrProofInvalid.
func (e *ReadError) Is(target error) bool { return target == ErrProofInvalid }

// NodeSet is the node list of a container, looked up by keccak256, with the record of which nodes the walks visited.
type NodeSet struct {
	nodes   map[common.Hash][]byte
	index   map[common.Hash]int
	visited map[common.Hash]bool
}

// NewNodeSet indexes nodes by keccak256. An empty node and two nodes with one hash are refused (the container's strictly ascending, unique
// NODES list never has either).
func NewNodeSet(nodes [][]byte) (*NodeSet, error) {
	ns := &NodeSet{nodes: make(map[common.Hash][]byte, len(nodes)), index: make(map[common.Hash]int, len(nodes)), visited: map[common.Hash]bool{}}
	for i, n := range nodes {
		if len(n) == 0 {
			return nil, &ReadError{Kind: ReadNodeSetInvalid, Detail: fmt.Sprintf("node %d is empty", i)}
		}
		h := common.BytesToHash(crypto.Keccak256(n))
		if j, dup := ns.index[h]; dup {
			return nil, &ReadError{Kind: ReadNodeSetInvalid, Detail: fmt.Sprintf("nodes %d and %d have the same hash %s", j, i, h.Hex())}
		}
		ns.nodes[h] = n
		ns.index[h] = i
	}
	return ns, nil
}

// Len is the number of nodes in the set.
func (s *NodeSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.nodes)
}

// Has reports whether the set holds a node with this hash.
func (s *NodeSet) Has(h common.Hash) bool {
	if s == nil {
		return false
	}
	_, ok := s.nodes[h]
	return ok
}

// Visited reports whether a walk read the node with this hash.
func (s *NodeSet) Visited(h common.Hash) bool { return s != nil && s.visited[h] }

// VisitedCount is the number of distinct nodes the walks read so far.
func (s *NodeSet) VisitedCount() int {
	if s == nil {
		return 0
	}
	return len(s.visited)
}

// Unvisited returns the indexes (in the order the nodes were given to NewNodeSet) of the nodes no walk has read, ascending.
func (s *NodeSet) Unvisited() []int {
	if s == nil {
		return nil
	}
	out := make([]int, 0)
	for h, i := range s.index {
		if !s.visited[h] {
			out = append(out, i)
		}
	}
	sort.Ints(out) // the map order is random: a deterministic result
	return out
}

// VisitedNodes returns the visited nodes, in the order given to NewNodeSet.
func (s *NodeSet) VisitedNodes() [][]byte {
	if s == nil {
		return nil
	}
	ordered := make([][]byte, len(s.nodes))
	for h, i := range s.index {
		if s.visited[h] {
			ordered[i] = s.nodes[h]
		}
	}
	out := make([][]byte, 0, len(s.visited))
	for _, n := range ordered {
		if n != nil {
			out = append(out, n)
		}
	}
	return out
}

// walkReader is the node store trie.VerifyProof reads: it answers from the set, validates each node's shape as it is read, and remembers
// the first reason a read failed (VerifyProof reports a nil answer only as "missing").
type walkReader struct {
	set     *NodeSet
	fail    *ReadError
	maxNode int
}

func (r *walkReader) Has(key []byte) (bool, error) {
	if r.set == nil {
		return false, nil
	}
	_, ok := r.set.nodes[common.BytesToHash(key)]
	return ok, nil
}

func (r *walkReader) Get(key []byte) ([]byte, error) {
	h := common.BytesToHash(key)
	var buf []byte
	if r.set != nil {
		buf = r.set.nodes[h]
	}
	if buf == nil {
		r.fail = &ReadError{Kind: ReadMissingNode, Missing: h}
		return nil, nil
	}
	if len(buf) > r.maxNode {
		r.fail = &ReadError{Kind: ReadNodeTooLarge, Missing: h, Detail: fmt.Sprintf("%d bytes, limit %d", len(buf), r.maxNode)}
		return nil, nil
	}
	if err := checkTrieNode(buf); err != nil {
		r.fail = &ReadError{Kind: ReadNodeMalformed, Missing: h, Detail: err.Error()}
		return nil, nil
	}
	r.set.visited[h] = true
	return buf, nil
}

// walk runs trie.VerifyProof(root, key) over the set. It returns the leaf value (nil for a verified exclusion proof).
func (s *NodeSet) walk(root common.Hash, key []byte, maxNode int) ([]byte, *ReadError) {
	r := &walkReader{set: s, maxNode: maxNode}
	val, err := trie.VerifyProof(root, key, r)
	if err != nil {
		if r.fail != nil {
			r.fail.Root = root
			return nil, r.fail
		}
		return nil, &ReadError{Kind: ReadWalkFailed, Root: root, Detail: err.Error()}
	}
	return val, nil
}

// checkTrieNode is the strict shape of one trie node (the hash is checked by the lookup, the shape here).
func checkTrieNode(buf []byte) error {
	elems, rest, err := rlp.SplitList(buf)
	if err != nil {
		return fmt.Errorf("not an RLP list: %v", err)
	}
	if len(rest) != 0 {
		return fmt.Errorf("%d trailing bytes after the node", len(rest))
	}
	n, err := rlp.CountValues(elems)
	if err != nil {
		return fmt.Errorf("invalid element list: %v", err)
	}
	switch n {
	case 2:
		key, tail, err := rlp.SplitString(elems)
		if err != nil {
			return fmt.Errorf("hex-prefix path is not a string: %v", err)
		}
		if len(key) == 0 {
			return errors.New("empty hex-prefix path")
		}
		flag := key[0] >> 4
		if flag > 3 {
			return fmt.Errorf("invalid hex-prefix flag %d", flag)
		}
		if flag&1 == 0 && key[0]&0x0f != 0 {
			return errors.New("even-length path with a non-zero padding nibble")
		}
		if flag >= 2 { // leaf
			val, extra, err := rlp.SplitString(tail)
			if err != nil {
				return fmt.Errorf("leaf value is not a string: %v", err)
			}
			if len(extra) != 0 {
				return errors.New("bytes after the leaf value")
			}
			if len(val) == 0 {
				return errors.New("leaf with an empty value")
			}
			return nil
		}
		nibbles := 2*(len(key)-1) + int(flag&1)
		if nibbles == 0 {
			return errors.New("extension with an empty path")
		}
		after, empty, err := checkTrieRef(tail)
		if err != nil {
			return fmt.Errorf("extension child: %v", err)
		}
		if empty {
			return errors.New("extension without a child")
		}
		if len(after) != 0 {
			return errors.New("bytes after the extension child")
		}
		return nil
	case 17:
		children := 0
		rem := elems
		for i := 0; i < 16; i++ {
			after, empty, err := checkTrieRef(rem)
			if err != nil {
				return fmt.Errorf("branch child %d: %v", i, err)
			}
			if !empty {
				children++
			}
			rem = after
		}
		val, extra, err := rlp.SplitString(rem)
		if err != nil {
			return fmt.Errorf("branch value is not a string: %v", err)
		}
		if len(extra) != 0 {
			return errors.New("bytes after the branch value")
		}
		if len(val) != 0 {
			return errors.New("branch carrying a value")
		}
		if children < 2 {
			return fmt.Errorf("branch with %d children", children)
		}
		return nil
	default:
		return fmt.Errorf("%d elements (want 2 or 17)", n)
	}
}

// checkTrieRef checks one child reference at the head of buf: empty, a 32-byte hash, or an embedded node whose encoding is under 32 bytes.
func checkTrieRef(buf []byte) (rest []byte, empty bool, err error) {
	kind, val, rest, err := rlp.Split(buf)
	if err != nil {
		return nil, false, err
	}
	switch {
	case kind == rlp.List:
		size := len(buf) - len(rest)
		if size >= 32 {
			return nil, false, fmt.Errorf("embedded node of %d bytes (want < 32)", size)
		}
		if err := checkTrieNode(buf[:size]); err != nil {
			return nil, false, fmt.Errorf("embedded node: %v", err)
		}
		return rest, false, nil
	case kind == rlp.String && len(val) == 0:
		return rest, true, nil
	case kind == rlp.String && len(val) == 32:
		return rest, false, nil
	}
	return nil, false, fmt.Errorf("reference of %d bytes (want 0 or 32)", len(val))
}

// AccountState is an account as a verified account walk states it. Exists is false for a verified exclusion proof: the state holds no such
// account, so its storage is empty (StorageRoot is the empty root, CodeHash the zero hash) and every slot of it is zero.
type AccountState struct {
	Exists      bool
	Nonce       uint64
	Balance     *big.Int
	StorageRoot common.Hash
	CodeHash    common.Hash
}

// HasCode reports a proven account with contract code (a code hash that is neither empty-code nor zero).
func (a AccountState) HasCode() bool {
	return a.Exists && a.CodeHash != types.EmptyCodeHash && a.CodeHash != (common.Hash{})
}

type accountLeaf struct {
	Nonce    uint64
	Balance  *big.Int
	Root     common.Hash
	CodeHash common.Hash
}

// ReadAccount walks stateRoot to keccak256(address) over nodes. A verified exclusion proof is the absent account; a needed node that the
// set does not hold is ReadMissingNode, never an absence.
func ReadAccount(stateRoot common.Hash, nodes *NodeSet, address common.Address) (AccountState, error) {
	absent := AccountState{Balance: new(big.Int), StorageRoot: types.EmptyRootHash}
	if stateRoot == types.EmptyRootHash {
		return absent, nil
	}
	val, rerr := nodes.walk(stateRoot, crypto.Keccak256(address[:]), MaxTrieNodeBytes)
	if rerr != nil {
		a := address
		rerr.Address = &a
		return AccountState{}, rerr
	}
	if val == nil {
		return absent, nil
	}
	var leaf accountLeaf
	if err := rlp.DecodeBytes(val, &leaf); err != nil {
		a := address
		return AccountState{}, &ReadError{Kind: ReadAccountMalformed, Root: stateRoot, Address: &a, Detail: err.Error()}
	}
	if leaf.Balance == nil {
		leaf.Balance = new(big.Int)
	}
	return AccountState{Exists: true, Nonce: leaf.Nonce, Balance: leaf.Balance, StorageRoot: leaf.Root, CodeHash: leaf.CodeHash}, nil
}

// ReadSlot walks storageRoot to keccak256(slot) over nodes and returns the 32-byte word; a verified exclusion proof (and the empty storage
// root) is the zero word.
func ReadSlot(storageRoot common.Hash, nodes *NodeSet, slot common.Hash) (common.Hash, error) {
	if storageRoot == types.EmptyRootHash {
		return common.Hash{}, nil
	}
	val, rerr := nodes.walk(storageRoot, crypto.Keccak256(slot[:]), MaxTrieNodeBytes)
	if rerr != nil {
		s := slot
		rerr.Slot = &s
		return common.Hash{}, rerr
	}
	if val == nil {
		return common.Hash{}, nil
	}
	var trimmed []byte
	if err := rlp.DecodeBytes(val, &trimmed); err != nil {
		s := slot
		return common.Hash{}, &ReadError{Kind: ReadValueMalformed, Root: storageRoot, Slot: &s, Detail: err.Error()}
	}
	if len(trimmed) == 0 || len(trimmed) > common.HashLength || trimmed[0] == 0 {
		s := slot
		return common.Hash{}, &ReadError{Kind: ReadValueMalformed, Root: storageRoot, Slot: &s,
			Detail: fmt.Sprintf("storage leaf of %d bytes is not a trimmed non-zero value of at most 32 bytes", len(trimmed))}
	}
	return common.BytesToHash(trimmed), nil
}

// ReadBytes reads a bytes (or string) storage variable declared at slot: the head word, then for a long value exactly its data words.
// maxLen bounds the length before any data word is read.
func ReadBytes(storageRoot common.Hash, nodes *NodeSet, slot common.Hash, maxLen uint64) ([]byte, error) {
	head, err := ReadSlot(storageRoot, nodes, slot)
	if err != nil {
		return nil, err
	}
	dh, err := ParseDynHead(head, maxLen)
	if err != nil {
		s := slot
		return nil, &ReadError{Kind: ReadDynamicInvalid, Root: storageRoot, Slot: &s, Detail: err.Error()}
	}
	if !dh.Long {
		return dh.Assemble(nil)
	}
	words := make([]common.Hash, 0, dh.DynWordCount())
	for i := uint64(0); i < dh.DynWordCount(); i++ {
		w, err := ReadSlot(storageRoot, nodes, DynDataSlot(slot, i))
		if err != nil {
			return nil, err
		}
		words = append(words, w)
	}
	out, err := dh.Assemble(words)
	if err != nil {
		s := slot
		return nil, &ReadError{Kind: ReadDynamicInvalid, Root: storageRoot, Slot: &s, Detail: err.Error()}
	}
	return out, nil
}

// ReadString is ReadBytes as a Go string.
func ReadString(storageRoot common.Hash, nodes *NodeSet, slot common.Hash, maxLen uint64) (string, error) {
	b, err := ReadBytes(storageRoot, nodes, slot, maxLen)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ReadIndexedLeaf walks an ordered-list trie (the transactions or receipts root of a header: key rlp(index), NOT hashed) to the entry at
// index and returns its consensus encoding. The entry must exist (an absence is ReadLeafAbsent: a block holds the entry the proof names).
// Nodes of these tries may be larger than a state or storage node (a leaf holds a whole transaction), so the bound is maxNode, the node
// bound of the container (Limits.MaxNodeBytes); the shape rules of the reads are unchanged.
func ReadIndexedLeaf(root common.Hash, nodes *NodeSet, index uint64, maxNode int) ([]byte, error) {
	key, err := rlp.EncodeToBytes(index)
	if err != nil {
		return nil, &ReadError{Kind: ReadWalkFailed, Root: root, Detail: err.Error()}
	}
	val, rerr := nodes.walk(root, key, maxNode)
	if rerr != nil {
		return nil, rerr
	}
	if val == nil {
		return nil, &ReadError{Kind: ReadLeafAbsent, Root: root, Detail: fmt.Sprintf("no entry at index %d", index)}
	}
	return append([]byte{}, val...), nil
}
