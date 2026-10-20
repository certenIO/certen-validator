// Copyright 2026 Certen Protocol

package arbfinal

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/certen/independant-validator/pkg/finality"
)

// pathRecorder is the read side of a proof database that remembers which nodes a proof walk read.
type pathRecorder struct {
	db   ethdb.KeyValueReader
	seen map[common.Hash]struct{}
}

func (r *pathRecorder) Has(key []byte) (bool, error) { return r.db.Has(key) }

func (r *pathRecorder) Get(key []byte) ([]byte, error) {
	v, err := r.db.Get(key)
	if err == nil {
		r.seen[common.BytesToHash(key)] = struct{}{}
	}
	return v, err
}

// proofPathNodes is the set of node hashes (keccak256) that the walk of key rlp(index) from root reads out of nodes. A walk that
// fails part-way still reports what it read; the proof itself is judged by proveLeaf.
func proofPathNodes(root common.Hash, index uint32, nodes [][]byte, seen map[common.Hash]struct{}) {
	db := memorydb.New()
	for _, n := range nodes {
		if err := db.Put(crypto.Keccak256(n), n); err != nil {
			return
		}
	}
	key, err := rlp.EncodeToBytes(uint64(index))
	if err != nil {
		return
	}
	_, _ = trie.VerifyProof(root, key, &pathRecorder{db: db, seen: seen})
}

// checkNodeBounds is the spec 8.2 split of the NODES bound: the decoder bounds every element by max_tx_leaf_bytes because the
// transaction and receipt proof paths are only known once K is on the covered spine; here, with K's roots, every element that is
// not read by the walk of key rlp(confTxIndex) from K's transactionsRoot or receiptsRoot is a state, storage or unreferenced node
// and must be at most max_node_bytes (finality_evidence_too_large{part:"nodes", count: its length, limit, index: its position in
// the ascending NODES order}).
func checkNodeBounds(kHeader finality.HeaderFields, e Evidence, maxNodeBytes int) error {
	big := false
	for _, n := range e.Nodes {
		if len(n) > maxNodeBytes {
			big = true
			break
		}
	}
	if !big {
		return nil
	}
	onPath := map[common.Hash]struct{}{}
	proofPathNodes(common.Hash(kHeader.TransactionRoot), e.ConfTxIndex, e.Nodes, onPath)
	proofPathNodes(common.Hash(kHeader.ReceiptsRoot), e.ConfTxIndex, e.Nodes, onPath)
	for i, n := range e.Nodes {
		if len(n) <= maxNodeBytes {
			continue
		}
		if _, ok := onPath[crypto.Keccak256Hash(n)]; ok {
			continue
		}
		s := finality.EvidenceTooLarge("nodes", uint64(len(n)), uint64(maxNodeBytes))
		s.Fields["index"] = uint64(i)
		return s
	}
	return nil
}
