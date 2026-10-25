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
	"github.com/certen/independant-validator/pkg/metrics"
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
	// The block is verified BEFORE anything is concluded from it, also when it holds no inbox transaction: "this block holds nothing to
	// capture" closes a capture gap, so it must be a verified statement and not a provider's word (RB12-GO-INT D7). The header must hash to
	// the hash the block is named by, and the transactions served must be the ones the header commits to.
	hdr, err := finality.ReadHeader(blk.HeaderRLP)
	if err != nil {
		return false, err
	}
	if hdr.Hash != blk.Hash {
		return false, errors.New("baseposted: the re-encoded header does not hash to the block hash")
	}
	// The header must be the header of the height that was ASKED for: the source names a block by the requested height while the header is
	// the provider's own, so a valid block of another height would otherwise be stored (and a gap filled) under the wrong number.
	if hdr.Number != number || blk.Number != number {
		return false, fmt.Errorf("baseposted: the block served for height %d carries a header of height %d (nothing stored)", number, hdr.Number)
	}
	if len(blk.TxTo) != len(blk.TxRaw) || len(blk.TxHasTo) != len(blk.TxRaw) || len(blk.TxBlobHash) != len(blk.TxRaw) {
		return false, errors.New("baseposted: the block's transaction columns differ in length")
	}
	if ethproof.TrieRoot(blk.TxRaw) != common.Hash(hdr.TransactionRoot) {
		return false, errors.New("baseposted: the transactions served do not hash to the header's transaction root")
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
	// AUTHENTICATION (RB12-GO-INT D2). Rows are insert-only and the providers are untrusted: what is stored is what the verifier will use,
	// so the SystemConfig proof is verified HERE under the header's own state root (the verifier's systemConfigAt: the proxy's batcherHash,
	// the EIP-1967 implementation and its pinned code hash), and only the inbox transactions whose sender is that batcher are kept (the rule
	// of verifyChannel, "Authentication"). A proof that does not verify stores nothing and leaves the gap open; a transaction another key
	// sent is skipped and counted. The live capture and the backfill are this same function.
	auth, err := authorizerAt(c.Pins, sc.Nodes, hdr.StateRoot, blk.Number)
	if err != nil {
		s := finality.NewState("batcher_state_unavailable", "l1_block", blk.Number)
		if c.Record != nil {
			c.Record(blk.Number, s)
		}
		return false, fmt.Errorf("%s: the SystemConfig proof does not verify under the state root of the header (nothing stored): %w", s.Error(), err)
	}
	kept := idx[:0:0]
	for _, i := range idx {
		if auth.sent(blk.TxRaw[i]) { // the one authorization (authorize.go), shared with the readers
			kept = append(kept, i)
			continue
		}
		metrics.IncFinalityCaptureForeignInboxTx(c.Chain)
	}
	if idx = kept; len(idx) == 0 {
		return false, nil
	}
	var kz *kzgsetup.Context
	// RB12 OPS-A2 item 1 (ledger CG-1): the blobs of the slot are fetched once for the block, and only the blobs the kept transactions name are
	// committed (a slot holds up to six and a commitment costs milliseconds), each at its sidecar position: the index of a blob is its place
	// among the blob hashes of the WHOLE block. Every kept blob is still accepted only if the commitment of its bytes hashes to the versioned
	// hash the transaction names, and is proved; a beacon that serves another order or a subset is read by the complete scan, as before.
	var slotRaws [][]byte
	slotFetched := false
	blobOffset := make([]int, len(blk.TxBlobHash)+1)
	for j, hs := range blk.TxBlobHash {
		blobOffset[j+1] = blobOffset[j] + len(hs)
	}
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
		if !slotFetched {
			raws, err := c.Beacon.Blobs(ctx, slot)
			if err != nil {
				s := finality.NewState("l1_blob_unavailable", "l1_block", blk.Number, "versioned_hashes", hashesOf(hashes), "beacon_slot", slot, "http_status", uint64(0))
				if c.Record != nil {
					c.Record(blk.Number, s)
				}
				return false, fmt.Errorf("%s: %w", s.Error(), err)
			}
			slotRaws, slotFetched = raws, true
		}
		raws := slotRaws
		var err error
		if kz == nil {
			if kz, err = kzgsetup.Load(c.Pins.KZGSetupSHA256); err != nil {
				return false, err
			}
		}
		byHash := map[[32]byte]Blob{}
		wanted := hashesSet(hashes)
		take := func(raw []byte) error { // commits raw and keeps it only if its versioned hash is one the transaction names
			if len(raw) != BlobSize {
				return nil
			}
			if kzgCommitHook != nil {
				kzgCommitHook()
			}
			com, err := kz.Commit(raw)
			if err != nil {
				return err
			}
			vh := sha256Sum(com[:])
			vh[0] = 0x01
			if !wanted[vh] {
				return nil
			}
			if _, have := byHash[vh]; have {
				return nil
			}
			pr, err := kz.Prove(raw, com)
			if err != nil {
				return err
			}
			byHash[vh] = Blob{Raw: raw, Commitment: com, Proof: pr}
			return nil
		}
		for j := range hashes { // the wanted sidecar positions first
			if pos := blobOffset[i] + j; pos < len(raws) {
				if err := take(raws[pos]); err != nil {
					return false, err
				}
			}
		}
		if len(byHash) < len(wanted) { // another order or a subset was served: the complete scan
			for _, raw := range raws {
				if err := take(raw); err != nil {
					return false, err
				}
			}
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
	// Everything is known: the rows of the block are written as ONE unit (finality.PutBlock). The inbox row names the block as
	// captured and lists its transactions, so it must never be stored without the rows it lists: a budget that does not fit the
	// whole block, or a store failure, stores nothing (RB11-DBFIX D7). The inbox row is listed LAST: a store that can only write row
	// by row (finality.PutBlock writes them in this order) is then cut at worst between rows nothing names yet.
	var rows []finality.CaptureRow
	add := func(item string, b []byte) { rows = append(rows, finality.CaptureRow{CaptureKey: key(item), Bytes: b}) }
	add(ItemHeader, blk.HeaderRLP)
	for _, i := range idx {
		add(ItemTx(i), blk.TxRaw[i])
		var pw finality.Writer
		pw.LPList(proofs[i])
		add(ItemTxNodes(i), pw.Bytes())
	}
	for _, r := range blobs {
		var bw finality.Writer
		bw.LP(r.b.Raw)
		bw.Fixed(r.b.Commitment[:])
		bw.Fixed(r.b.Proof[:])
		add(ItemBlob(r.tx, r.j), bw.Bytes())
	}
	var sw finality.Writer
	sw.LPList(sc.Nodes)
	add(ItemSysCfg, sw.Bytes())
	var w finality.Writer
	w.Count(len(idx))
	for _, i := range idx {
		w.U32(i)
	}
	add(ItemInbox, w.Bytes())
	if err := finality.PutBlock(ctx, c.Store, rows); err != nil {
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

// kzgCommitHook is called before every blob commitment of a capture (nil in production): the tests count the commitments.
var kzgCommitHook func()

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
