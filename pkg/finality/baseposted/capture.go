// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/baseposted/kzgsetup"
)

// ---- the capture store (V2_SPEC_S7 2.8) ----

// CaptureKey is the key of one captured item: (chain, l1_block, l1_hash, item). Rows are insert-only; a reorg yields a second
// row set for the same height under another hash. It is the framework's key (V2_SPEC_S7 2.8).
type CaptureKey = finality.CaptureKey

// ErrCaptureConflict is returned when an item already exists with different bytes: a capture row is never updated.
var ErrCaptureConflict = finality.ErrCaptureConflict

// CaptureStore is what the Capturer writes and the Builder reads: the framework's insert-only store, implemented by
// pkg/database.FinalityCaptureStore in production and by MemStore and DirStore here. The Builder asks which blocks hold the
// inbox item through finality.CaptureKeysOfItem.
type CaptureStore = finality.CaptureStore

// MemStore is the in-memory CaptureStore of tests.
type MemStore = finality.MemCaptureStore

// NewMemStore returns an empty store.
func NewMemStore() *MemStore { return finality.NewMemCaptureStore() }

// Item names of the capture rows of one L1 block that holds batch-inbox transactions.
const (
	ItemHeader  = "hdr"      // raw header RLP
	ItemInbox   = "inbox"    // LIST<u32> indexes of the batch-inbox transactions
	ItemSysCfg  = "syscfg"   // LIST<LP> trie nodes: SystemConfig account, slot 103, EIP-1967 slot, implementation account
	itemTxPre   = "tx/"      // tx/<index>: raw EIP-2718 transaction
	itemNodePre = "txnodes/" // txnodes/<index>: LIST<LP> the transaction-trie proof nodes, root first
	itemBlobPre = "blob/"    // blob/<index>/<j>: LP raw || B48 commitment || B48 proof
)

// ItemTx, ItemTxNodes and ItemBlob name the per-transaction rows.
func ItemTx(index uint32) string      { return fmt.Sprintf("%s%d", itemTxPre, index) }
func ItemTxNodes(index uint32) string { return fmt.Sprintf("%s%d", itemNodePre, index) }
func ItemBlob(index uint32, j int) string {
	return fmt.Sprintf("%s%d/%d", itemBlobPre, index, j)
}

// ---- sources ----

// L1Block is what the Capturer needs of one parent-chain block.
type L1BlockData struct {
	Number     uint64
	Hash       [32]byte
	HeaderRLP  []byte // re-encoded positionally from the provider JSON and checked to hash to Hash
	Timestamp  uint64
	TxRaw      [][]byte // every transaction, EIP-2718 consensus encoding, block order
	TxTo       [][20]byte
	TxHasTo    []bool
	TxBlobHash [][][32]byte
}

// StateProof is an eth_getProof answer reduced to its trie nodes (account proof, then each storage proof).
type StateProof struct {
	Nodes  [][]byte
	Values map[[32]byte][32]byte // the storage values the provider reported (untrusted; the verifier re-proves them)
}

// L1Source reads the parent chain. Proof must be served by a provider whose window still holds the block (near head).
type L1Source interface {
	Head(ctx context.Context) (uint64, error)
	Block(ctx context.Context, number uint64) (L1BlockData, error)
	Proof(ctx context.Context, address [20]byte, slots [][32]byte, block uint64) (StateProof, error)
}

// BeaconSource serves the blobs of a slot (the blob API); the Capturer matches them to versioned hashes by commitment.
type BeaconSource interface {
	Blobs(ctx context.Context, slot uint64) ([][]byte, error)
}

// ---- the Capturer ----

// Capturer is leg-independent (spec 2.8): on every L1 head it captures, for every block holding a batch-inbox transaction, the
// frame transactions with their trie proofs, their blobs (with commitments and proofs) and the SystemConfig proofs at that block.
type Capturer struct {
	Chain       uint64
	Pins        *Pins
	L1          L1Source
	Beacon      BeaconSource
	Store       CaptureStore
	GenesisTime uint64 // Sepolia beacon genesis_time (slot = (timestamp - genesis) / 12)
	SlotSeconds uint64
	// Record receives the named states of a capture that could not be completed; a nil Record drops nothing silently: the
	// errors are also returned.
	Record func(l1Block uint64, s *finality.StateError)
}

// CaptureBlock captures one L1 block. It returns (false, nil) for a block without batch-inbox transactions (nothing stored).
func (c *Capturer) CaptureBlock(ctx context.Context, number uint64) (bool, error) {
	blk, err := c.L1.Block(ctx, number)
	if err != nil {
		return false, &BlockFetchError{Block: number, Err: err}
	}
	var idx []uint32
	for i := range blk.TxRaw {
		if blk.TxHasTo[i] && blk.TxTo[i] == c.Pins.BatchInbox {
			idx = append(idx, uint32(i))
		}
	}
	if len(idx) == 0 {
		return false, nil
	}
	key := func(item string) CaptureKey {
		return CaptureKey{Chain: c.Chain, L1Block: blk.Number, L1Hash: blk.Hash, Item: item}
	}
	hdr, err := finality.ReadHeader(blk.HeaderRLP)
	if err != nil {
		return false, err
	}
	if hdr.Hash != blk.Hash {
		return false, errors.New("baseposted: the re-encoded header does not hash to the block hash")
	}
	// State first: it is the item that expires (the provider window), so a failure here stores nothing.
	var sc StateProof
	{
		slots := [][32]byte{batcherHashSlot, eip1967ImplSlot}
		a, err := c.L1.Proof(ctx, c.Pins.SystemConfig, slots, blk.Number)
		if err != nil {
			s := finality.NewState("batcher_state_unavailable", "l1_block", blk.Number)
			if c.Record != nil {
				c.Record(blk.Number, s)
			}
			return false, fmt.Errorf("%s: %w", s.Error(), err)
		}
		// The implementation account needs its own proof (address read from the slot value).
		impl, ok := implFromProof(a)
		if !ok {
			return false, errors.New("baseposted: the SystemConfig proof does not carry the EIP-1967 implementation")
		}
		b, err := c.L1.Proof(ctx, impl, nil, blk.Number)
		if err != nil {
			s := finality.NewState("batcher_state_unavailable", "l1_block", blk.Number)
			if c.Record != nil {
				c.Record(blk.Number, s)
			}
			return false, fmt.Errorf("%s: %w", s.Error(), err)
		}
		sc.Nodes = append(append(sc.Nodes, a.Nodes...), b.Nodes...)
	}
	var kz *kzgsetup.Context
	type blobRow struct {
		tx uint32
		j  int
		b  Blob
	}
	var blobs []blobRow
	for _, i := range idx {
		hashes := blk.TxBlobHash[i]
		if len(hashes) == 0 {
			continue
		}
		slot := (blk.Timestamp - c.GenesisTime) / c.SlotSeconds
		raws, err := c.Beacon.Blobs(ctx, slot)
		if err != nil {
			s := finality.NewState("l1_blob_unavailable", "l1_block", blk.Number, "versioned_hashes", hashesOf(hashes), "beacon_slot", slot, "http_status", uint64(0))
			if c.Record != nil {
				c.Record(blk.Number, s)
			}
			return false, fmt.Errorf("%s: %w", s.Error(), err)
		}
		if kz == nil {
			if kz, err = kzgsetup.Load(c.Pins.KZGSetupSHA256); err != nil {
				return false, err
			}
		}
		byHash := map[[32]byte]Blob{}
		for _, raw := range raws {
			if len(raw) != BlobSize {
				continue
			}
			com, err := kz.Commit(raw)
			if err != nil {
				return false, err
			}
			vh := sha256Sum(com[:])
			vh[0] = 0x01
			if _, want := hashesSet(hashes)[vh]; !want {
				continue
			}
			pr, err := kz.Prove(raw, com)
			if err != nil {
				return false, err
			}
			byHash[vh] = Blob{Raw: raw, Commitment: com, Proof: pr}
		}
		for j, h := range hashes {
			bl, ok := byHash[h]
			if !ok {
				s := finality.NewState("l1_blob_unavailable", "l1_block", blk.Number, "versioned_hashes", hashesOf(hashes), "beacon_slot", slot, "http_status", uint64(200))
				if c.Record != nil {
					c.Record(blk.Number, s)
				}
				return false, errors.New(s.Error())
			}
			blobs = append(blobs, blobRow{i, j, bl})
		}
	}
	// Transaction trie proofs.
	proofs := map[uint32][][]byte{}
	for _, i := range idx {
		p, err := ethproof.Prove(blk.TxRaw, uint64(i), common.Hash(hdr.TransactionRoot))
		if err != nil {
			return false, err
		}
		proofs[i] = p.ProofNodes
	}
	// Everything is known: insert.
	put := func(item string, b []byte) error { return c.Store.Put(ctx, key(item), b) }
	if err := put(ItemHeader, blk.HeaderRLP); err != nil {
		return false, err
	}
	var w finality.Writer
	w.Count(len(idx))
	for _, i := range idx {
		w.U32(i)
	}
	if err := put(ItemInbox, w.Bytes()); err != nil {
		return false, err
	}
	for _, i := range idx {
		if err := put(ItemTx(i), blk.TxRaw[i]); err != nil {
			return false, err
		}
		var pw finality.Writer
		pw.LPList(proofs[i])
		if err := put(ItemTxNodes(i), pw.Bytes()); err != nil {
			return false, err
		}
	}
	for _, r := range blobs {
		var bw finality.Writer
		bw.LP(r.b.Raw)
		bw.Fixed(r.b.Commitment[:])
		bw.Fixed(r.b.Proof[:])
		if err := put(ItemBlob(r.tx, r.j), bw.Bytes()); err != nil {
			return false, err
		}
	}
	var sw finality.Writer
	sw.LPList(sc.Nodes)
	if err := put(ItemSysCfg, sw.Bytes()); err != nil {
		return false, err
	}
	return true, nil
}

// CaptureRange captures blocks from..to inclusive and returns the blocks that held inbox transactions. A block that fails is
// returned in errs with its number and the scan continues: capture follows the head and never waits on one block.
func (c *Capturer) CaptureRange(ctx context.Context, from, to uint64) (captured []uint64, errs map[uint64]error) {
	errs = map[uint64]error{}
	for n := from; n <= to; n++ {
		ok, err := c.CaptureBlock(ctx, n)
		if err != nil {
			errs[n] = err
			continue
		}
		if ok {
			captured = append(captured, n)
		}
	}
	return captured, errs
}

func hashesSet(h [][32]byte) map[[32]byte]bool {
	m := map[[32]byte]bool{}
	for _, x := range h {
		m[x] = true
	}
	return m
}

func hashesOf(h [][32]byte) string {
	parts := make([]string, len(h))
	for i, x := range h {
		parts[i] = fmt.Sprintf("0x%x", x)
	}
	return strings.Join(parts, ",")
}

// implFromProof reads the EIP-1967 implementation address the provider reported for the SystemConfig proxy.
func implFromProof(p StateProof) ([20]byte, bool) {
	v, ok := p.Values[eip1967ImplSlot]
	var a [20]byte
	copy(a[:], v[12:])
	return a, ok && a != [20]byte{}
}
