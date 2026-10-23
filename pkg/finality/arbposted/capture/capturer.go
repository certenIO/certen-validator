// Copyright 2026 Certen Protocol

package capture

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality"
)

// The rollup deployment the capture serves (V2_SPEC_S7 4.2; the verifier reads the same addresses from the pins).
const (
	ChainArbitrumSepolia uint64 = 421614
	// BeaconGenesisTime is the Sepolia beacon genesis (slot = (timestamp - genesis) / 12).
	BeaconGenesisTime uint64 = 1655733600
)

var (
	// SequencerInboxAddr is the Arbitrum Sepolia SequencerInbox.
	SequencerInboxAddr = common.HexToAddress("0x6c97864CE4bEf387dE0b3310A44230f7E3F1be0D")
	// BridgeAddr is the Arbitrum Sepolia Bridge (accumulators live in its storage).
	BridgeAddr = common.HexToAddress("0x38f918D0E9F1b721EDaA41302E399fa1B79333a9")

	// TopicBatchDelivered is keccak256("SequencerBatchDelivered(uint256,bytes32,bytes32,bytes32,uint256,(uint64,uint64,uint64,uint64),uint8)").
	TopicBatchDelivered = crypto.Keccak256Hash([]byte("SequencerBatchDelivered(uint256,bytes32,bytes32,bytes32,uint256,(uint64,uint64,uint64,uint64),uint8)"))
	// TopicBatchData is keccak256("SequencerBatchData(uint256,bytes)") (dataLocation 1).
	TopicBatchData = crypto.Keccak256Hash([]byte("SequencerBatchData(uint256,bytes)"))

	// ImplSlot is the EIP-1967 implementation slot.
	ImplSlot = common.HexToHash("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
)

// Storage slots of the Bridge (nitro-contracts v3.1.0 layout; the pins carry them for the verifier).
const (
	DelayedAccSlot   = 6
	SequencerAccSlot = 7
)

// ArraySlot is the storage key of element index of the dynamic array declared at slot base: keccak256(w(base)) + index.
func ArraySlot(base uint64, index uint64) [32]byte {
	var w [32]byte
	binary.BigEndian.PutUint64(w[24:], base)
	h := new(big.Int).SetBytes(crypto.Keccak256(w[:]))
	h.Add(h, new(big.Int).SetUint64(index))
	var out [32]byte
	h.FillBytes(out[:])
	return out
}

// Config tunes a Capturer. Zero values take the defaults noted.
type Config struct {
	Chain       uint64 // rollup chain id; 421614
	Inbox       [20]byte
	Bridge      [20]byte
	GenesisTime uint64 // beacon genesis; 1655733600
	// Overlap blocks of the previous scan are read again each tick so a reorg of the last blocks is seen (default 8).
	Overlap uint64
	// MaxCatchUp bounds the blocks scanned in one tick (default 400).
	MaxCatchUp uint64
	// StartBack: with no cursor in the store, scanning starts StartBack blocks below the head (default 0: at the head).
	StartBack uint64
	// ProofTries is how many blocks (head, head-1, ...) a tick tries as the proof block (default 3).
	ProofTries int
	// SlotsPerProof bounds the storage slots of one eth_getProof call (default 32).
	SlotsPerProof int
	// BlobGiveUpTicks: after this many failed blob fetches of one batch a BlobUnavailableRecord is written once (default 30);
	// the fetch is still retried afterwards.
	BlobGiveUpTicks int
	// UnavailableEvery: a batch without a proof gets an UnavailableRecord every this many ticks (default 20).
	UnavailableEvery int
	// RebuildBlocks: on the first tick, batches captured within this many L1 blocks of the head are re-examined with their blob rows read
	// and checked; EVERY older batch is re-examined too (RB12-CAPTURE-GAP), by key listing alone, and an incomplete one is a recorded gap
	// (default 7200).
	RebuildBlocks uint64
	// OldRetryEvery: an old incomplete batch (older than RebuildBlocks when found) is retried every this many ticks (default 10).
	OldRetryEvery int
	Logf          func(format string, args ...any)
}

func (c Config) withDefaults() Config {
	if c.Chain == 0 {
		c.Chain = ChainArbitrumSepolia
	}
	if c.Inbox == ([20]byte{}) {
		c.Inbox = SequencerInboxAddr
	}
	if c.Bridge == ([20]byte{}) {
		c.Bridge = BridgeAddr
	}
	if c.GenesisTime == 0 {
		c.GenesisTime = BeaconGenesisTime
	}
	if c.Overlap == 0 {
		c.Overlap = 8
	}
	if c.MaxCatchUp == 0 {
		c.MaxCatchUp = 400
	}
	if c.ProofTries == 0 {
		c.ProofTries = 3
	}
	if c.SlotsPerProof == 0 {
		c.SlotsPerProof = 32
	}
	if c.BlobGiveUpTicks == 0 {
		c.BlobGiveUpTicks = 30
	}
	if c.UnavailableEvery == 0 {
		c.UnavailableEvery = 20
	}
	if c.RebuildBlocks == 0 {
		c.RebuildBlocks = 7200
	}
	if c.OldRetryEvery == 0 {
		c.OldRetryEvery = 10
	}
	return c
}

// Capturer runs the capture phase. Tick is called on every parent-chain head (or on a timer); it is safe to call from one
// goroutine at a time.
type Capturer struct {
	Store  CaptureStore
	L1     L1Source
	Beacon BeaconSource
	Cfg    Config

	mu          sync.Mutex
	started     bool
	needBlobs   map[uint64]*pendBlob // N -> record awaiting its blobs
	needProof   map[uint64]*pendProof
	wantDelayed map[uint64]*pendProof
	ticks       int
	gaps        map[uint64]BatchRecord // batches recorded as an incomplete-capture gap and not yet closed
}

type pendBlob struct {
	rec    BatchRecord
	ts     uint64
	tries  int
	gaveUp bool
	old    bool // found incomplete beyond RebuildBlocks: retried at the bounded cadence
}
type pendProof struct {
	rec   BatchRecord
	ticks int
	old   bool
}

// NewCapturer returns a Capturer with defaults applied.
func NewCapturer(store CaptureStore, l1 L1Source, beacon BeaconSource, cfg Config) *Capturer {
	return &Capturer{Store: store, L1: l1, Beacon: beacon, Cfg: cfg.withDefaults(),
		needBlobs: map[uint64]*pendBlob{}, needProof: map[uint64]*pendProof{}, wantDelayed: map[uint64]*pendProof{}, gaps: map[uint64]BatchRecord{}}
}

// WantDelayed asks the capturer to capture the delayedInboxAccs[k] and [k-1] proofs at the next tick (k >= 1).
func (c *Capturer) WantDelayed(k uint64) error {
	if k == 0 {
		return errors.New("capture: delayedInboxAccs[k-1] does not exist for k = 0")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.wantDelayed[k]; !ok {
		c.wantDelayed[k] = &pendProof{}
	}
	return nil
}

// Report is what one tick did.
type Report struct {
	Head        uint64
	ScannedFrom uint64
	ScannedTo   uint64
	NewBatches  []uint64
	BlobsStored int
	Proofs      []uint64
	ProofBlock  uint64
	Unavailable []uint64
	Errors      []string // redacted
}

func (c *Capturer) logf(f string, a ...any) {
	if c.Cfg.Logf != nil {
		c.Cfg.Logf(f, ethrpc.RedactArgs(a)...)
	}
}

func (r *Report) fail(c *Capturer, format string, a ...any) {
	msg := ethrpc.RedactText(fmt.Sprintf(format, a...))
	r.Errors = append(r.Errors, msg)
	c.logf("capture: %s", msg)
}

func putRow(ctx context.Context, s CaptureStore, k Key, b []byte) error {
	if err := s.Put(ctx, k, b); err != nil {
		return err
	}
	return nil
}

func hdrKey(chain uint64, h Header, item string) Key {
	return Key{Chain: chain, L1Block: h.Number, L1Hash: h.Hash, Item: item}
}

// Tick runs one capture round at the current head.
func (c *Capturer) Tick(ctx context.Context) (Report, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var rep Report
	c.ticks++
	head, err := c.L1.HeadNumber(ctx)
	if err != nil {
		return rep, fmt.Errorf("capture: head: %w", ethrpc.RedactError(err))
	}
	rep.Head = head
	if !c.started {
		if err := c.rebuild(ctx, head); err != nil {
			return rep, err
		}
		c.started = true
	}
	// (a) scan
	if err := c.scan(ctx, head, &rep); err != nil {
		rep.fail(c, "scan: %v", err)
	}
	// blobs awaiting a beacon answer
	c.fetchBlobs(ctx, &rep)
	// (b) proofs near the head
	c.captureProofs(ctx, head, &rep)
	c.closeGaps(ctx, &rep)
	return rep, nil
}

// dueOld reports whether an old incomplete batch is retried at this tick: the first tick of the process and then every OldRetryEvery.
func (c *Capturer) dueOld() bool { return (c.ticks-1)%c.Cfg.OldRetryEvery == 0 }

// closeGaps records a fill for every batch that was recorded as an incomplete-capture gap and now has its blobs and its proof.
func (c *Capturer) closeGaps(ctx context.Context, rep *Report) {
	for n, rec := range c.gaps {
		if c.needBlobs[n] != nil || c.needProof[n] != nil {
			continue
		}
		if err := finality.RecordGapFill(ctx, c.Store, c.Cfg.Chain, rec.L1Block, rec.L1Hash, true); err != nil {
			rep.fail(c, "fill of the gap of batch %d: %v", n, err)
			continue
		}
		delete(c.gaps, n)
		c.logf("capture: batch %d at L1 block %d is complete (blobs and proof): its capture gap is closed", n, rec.L1Block)
	}
}

// rebuild reloads what a previous process left incomplete: batches within RebuildBlocks of the head without all their blobs
// or without a proof row.
func (c *Capturer) rebuild(ctx context.Context, head uint64) error {
	keys, err := c.Store.ListByRange(ctx, c.Cfg.Chain, 0, finality.MaxCaptureBlock, "batch/")
	if err != nil {
		return err
	}
	pk, err := c.Store.ListByRange(ctx, c.Cfg.Chain, 0, finality.MaxCaptureBlock, "proof/")
	if err != nil {
		return err
	}
	have := map[uint64]bool{}
	for _, k := range pk {
		var n uint64
		if _, e := fmt.Sscanf(k.Item, "proof/%d", &n); e == nil {
			have[n] = true
		}
	}
	// the blob rows by batch, from the keys alone: an old batch's blob rows are not read to find out whether they are all there
	bk, err := c.Store.ListByRange(ctx, c.Cfg.Chain, 0, finality.MaxCaptureBlock, "blob/")
	if err != nil {
		return err
	}
	blobRows := map[uint64]int{}
	for _, k := range bk {
		var n uint64
		var j int
		if _, e := fmt.Sscanf(k.Item, "blob/%d/%d", &n, &j); e == nil {
			blobRows[n]++
		}
	}
	for _, k := range keys {
		old := k.L1Block+c.Cfg.RebuildBlocks < head
		b, ok, err := c.Store.Get(ctx, k)
		if err != nil || !ok {
			return fmt.Errorf("capture: row %s unreadable", k)
		}
		rec, err := DecodeBatchRecord(b)
		if err != nil {
			return err
		}
		var missing []finality.GapClass
		if !have[rec.N] {
			c.needProof[rec.N] = &pendProof{rec: rec, old: old}
			missing = append(missing, finality.GapStateProofUnavailable)
		}
		if rec.DataLocation == LocBlob {
			complete := false
			if old {
				complete = blobRows[rec.N] >= len(rec.VersionedHashes)
			} else {
				blobs, err := LoadBlobs(ctx, c.Store, c.Cfg.Chain, rec)
				if err != nil {
					return err
				}
				complete = len(blobs) >= len(rec.VersionedHashes)
			}
			if !complete {
				hk := Key{Chain: c.Cfg.Chain, L1Block: rec.L1Block, L1Hash: rec.L1Hash, Item: ItemHeader}
				hb, ok, _ := c.Store.Get(ctx, hk)
				if !ok {
					return fmt.Errorf("capture: header row of batch %d missing", rec.N)
				}
				hf, err := finality.ReadHeader(hb)
				if err != nil {
					return err
				}
				c.needBlobs[rec.N] = &pendBlob{rec: rec, ts: hf.Timestamp, old: old}
				missing = append(missing, finality.GapBlobUnavailable)
			}
		}
		// an incomplete batch is a durable, named gap until it is complete (the framework's gap rows, at the batch's L1 block)
		for _, class := range missing {
			if err := finality.RecordGap(ctx, c.Store, c.Cfg.Chain, rec.L1Block, rec.L1Block, class); err != nil {
				return fmt.Errorf("capture: recording the gap of batch %d: %w", rec.N, err)
			}
		}
		if len(missing) > 0 {
			c.gaps[rec.N] = rec
			if old {
				c.logf("capture: batch %d at L1 block %d (%d blocks before the head) is incomplete after a restart: recorded as a capture gap, retried every %d ticks", rec.N, rec.L1Block, head-rec.L1Block, c.Cfg.OldRetryEvery)
			}
		}
	}
	return nil
}

func cursorBlock(ctx context.Context, s CaptureStore, chain uint64) (uint64, bool, error) {
	keys, err := s.ListByRange(ctx, chain, 0, finality.MaxCaptureBlock, ItemCursor)
	if err != nil {
		return 0, false, err
	}
	var last uint64
	found := false
	for _, k := range keys {
		if k.Item == ItemCursor && (!found || k.L1Block > last) {
			last, found = k.L1Block, true
		}
	}
	return last, found, nil
}

func (c *Capturer) scan(ctx context.Context, head uint64, rep *Report) error {
	last, ok, err := cursorBlock(ctx, c.Store, c.Cfg.Chain)
	if err != nil {
		return err
	}
	var from uint64
	switch {
	case ok && last+1 > c.Cfg.Overlap:
		from = last + 1 - c.Cfg.Overlap
	case ok:
		from = 0
	case head > c.Cfg.StartBack:
		from = head - c.Cfg.StartBack
	}
	if from > head {
		return nil
	}
	to := head
	if to-from+1 > c.Cfg.MaxCatchUp {
		to = from + c.Cfg.MaxCatchUp - 1
	}
	rep.ScannedFrom, rep.ScannedTo = from, to
	logs, err := c.L1.Logs(ctx, c.Cfg.Inbox, TopicBatchDelivered, nil, from, to)
	if err != nil {
		return err
	}
	sort.Slice(logs, func(i, j int) bool {
		if logs[i].BlockNumber != logs[j].BlockNumber {
			return logs[i].BlockNumber < logs[j].BlockNumber
		}
		return logs[i].LogIndex < logs[j].LogIndex
	})
	for _, lg := range logs {
		n, err := c.captureBatch(ctx, lg, rep)
		if err != nil {
			// an uncaptured event must not be skipped by the cursor: stop here and retry the range next tick
			return fmt.Errorf("batch event at block %d: %w", lg.BlockNumber, err)
		}
		if n != nil {
			rep.NewBatches = append(rep.NewBatches, *n)
		}
	}
	h, err := c.L1.Header(ctx, to)
	if err != nil {
		return err
	}
	if err := putRow(ctx, c.Store, hdrKey(c.Cfg.Chain, h, ItemHeader), h.RLP); err != nil {
		return err
	}
	cur := make([]byte, 0, 40)
	cur = binary.BigEndian.AppendUint64(cur, to)
	cur = append(cur, h.Hash[:]...)
	return putRow(ctx, c.Store, hdrKey(c.Cfg.Chain, h, ItemCursor), cur)
}

func word(b []byte, i int) []byte { return b[i*32 : (i+1)*32] }

func wordU64(b []byte, i int) (uint64, error) {
	w := word(b, i)
	for _, x := range w[:24] {
		if x != 0 {
			return 0, errors.New("event word exceeds 64 bits")
		}
	}
	return binary.BigEndian.Uint64(w[24:]), nil
}

// ParseBatchDelivered decodes a SequencerBatchDelivered log into a BatchRecord (L1 block fields from the log).
func ParseBatchDelivered(lg Log) (BatchRecord, error) {
	var r BatchRecord
	if len(lg.Topics) != 4 || lg.Topics[0] != [32]byte(TopicBatchDelivered) {
		return r, errors.New("not a SequencerBatchDelivered log")
	}
	if len(lg.Data) != 7*32 {
		return r, fmt.Errorf("SequencerBatchDelivered data of %d bytes, want 224", len(lg.Data))
	}
	n := new(big.Int).SetBytes(lg.Topics[1][:])
	if !n.IsUint64() {
		return r, errors.New("batch sequence number exceeds 64 bits")
	}
	r.N = n.Uint64()
	r.BeforeAcc, r.AfterAcc = lg.Topics[2], lg.Topics[3]
	copy(r.DelayedAcc[:], word(lg.Data, 0))
	var err error
	afterDelayed, err := wordU64(lg.Data, 1)
	if err != nil {
		return r, err
	}
	// header40 order (packHeader): minTimestamp, maxTimestamp, minBlockNumber, maxBlockNumber, afterDelayedMessagesRead
	for i := 0; i < 4; i++ {
		if r.Header40[i], err = wordU64(lg.Data, 2+i); err != nil {
			return r, err
		}
	}
	r.Header40[4] = afterDelayed
	loc, err := wordU64(lg.Data, 6)
	if err != nil || loc > 255 {
		return r, errors.New("bad data location")
	}
	r.DataLocation = uint8(loc)
	r.L1Block, r.L1Hash, r.TxHash, r.TxIndex = lg.BlockNumber, lg.BlockHash, lg.TxHash, lg.TxIndex
	return r, nil
}

func (c *Capturer) captureBatch(ctx context.Context, lg Log, rep *Report) (*uint64, error) {
	rec, err := ParseBatchDelivered(lg)
	if err != nil {
		return nil, err
	}
	bk := Key{Chain: c.Cfg.Chain, L1Block: rec.L1Block, L1Hash: rec.L1Hash, Item: ItemBatch(rec.N)}
	if _, exists, err := c.Store.Get(ctx, bk); err != nil {
		return nil, err
	} else if exists {
		return nil, nil
	}
	h, err := c.L1.Header(ctx, lg.BlockNumber)
	if err != nil {
		return nil, err
	}
	if h.Hash != lg.BlockHash {
		return nil, fmt.Errorf("the header of block %d is %x, the log says %x (a reorg or provider skew; retried next tick)", lg.BlockNumber, h.Hash[:4], lg.BlockHash[:4])
	}
	tx, err := c.L1.TxByHash(ctx, lg.TxHash)
	if err != nil {
		return nil, err
	}
	if tx.BlockHash != lg.BlockHash {
		return nil, errors.New("the batch transaction is not in the event's block")
	}
	rec.TxRaw, rec.TxIndex = tx.Raw, tx.Index
	var data []byte
	switch rec.DataLocation {
	case LocBlob:
		if len(tx.BlobVersionedHashes) == 0 || len(tx.BlobVersionedHashes) > maxVHashes {
			return nil, fmt.Errorf("a blob batch transaction with %d versioned hashes", len(tx.BlobVersionedHashes))
		}
		rec.VersionedHashes = tx.BlobVersionedHashes
	case LocTxInput:
		if data, err = ExtractTxInputData(tx.Input); err != nil {
			return nil, err
		}
	case LocSeparateBatchEvent:
		n := new(big.Int).SetUint64(rec.N)
		var t1 [32]byte
		n.FillBytes(t1[:])
		bl, err := c.L1.Logs(ctx, c.Cfg.Inbox, TopicBatchData, &t1, lg.BlockNumber, lg.BlockNumber)
		if err != nil {
			return nil, err
		}
		for _, l := range bl {
			if l.TxHash == lg.TxHash && l.BlockHash == lg.BlockHash {
				if data, err = decodeABIBytes(l.Data); err != nil {
					return nil, err
				}
				break
			}
		}
		if data == nil {
			return nil, errors.New("the SequencerBatchData event of a separate-event batch was not found")
		}
	case LocNoData:
	default:
		return nil, fmt.Errorf("unknown data location %d", rec.DataLocation)
	}
	if !rec.ConsistentAcc(data) {
		return nil, fmt.Errorf("batch %d: keccak256(beforeAcc || dataHash || delayedAcc) differs from the event's afterAcc (the capture cannot reproduce the accumulator)", rec.N)
	}
	if err := putRow(ctx, c.Store, hdrKey(c.Cfg.Chain, h, ItemHeader), h.RLP); err != nil {
		return nil, err
	}
	if rec.DataLocation == LocTxInput || rec.DataLocation == LocSeparateBatchEvent {
		raw := data
		if rec.DataLocation == LocTxInput {
			raw = tx.Input
		}
		if err := putRow(ctx, c.Store, Key{Chain: c.Cfg.Chain, L1Block: h.Number, L1Hash: h.Hash, Item: ItemCalldata(rec.N)}, raw); err != nil {
			return nil, err
		}
	}
	if err := putRow(ctx, c.Store, bk, rec.Encode()); err != nil {
		return nil, err
	}
	c.needProof[rec.N] = &pendProof{rec: rec}
	if rec.DataLocation == LocBlob {
		c.needBlobs[rec.N] = &pendBlob{rec: rec, ts: h.Timestamp}
	}
	n := rec.N
	return &n, nil
}

func decodeABIBytes(data []byte) ([]byte, error) {
	if len(data) < 64 {
		return nil, errors.New("short ABI bytes")
	}
	off, err := wordU64(data, 0)
	if err != nil || off+32 > uint64(len(data)) {
		return nil, errors.New("bad ABI offset")
	}
	var lw [32]byte
	copy(lw[:], data[off:off+32])
	l, err := wordU64(lw[:], 0)
	if err != nil || off+32+l > uint64(len(data)) {
		return nil, errors.New("bad ABI length")
	}
	return append([]byte{}, data[off+32:off+32+l]...), nil
}

func (c *Capturer) fetchBlobs(ctx context.Context, rep *Report) {
	if c.Beacon == nil {
		return
	}
	ns := make([]uint64, 0, len(c.needBlobs))
	for n := range c.needBlobs {
		ns = append(ns, n)
	}
	sort.Slice(ns, func(i, j int) bool { return ns[i] < ns[j] })
	for _, n := range ns {
		p := c.needBlobs[n]
		if p.old && !c.dueOld() {
			continue
		}
		slot := (p.ts - c.Cfg.GenesisTime) / 12
		scs, err := c.Beacon.Sidecars(ctx, slot, p.rec.VersionedHashes)
		if err != nil {
			p.tries++
			rep.fail(c, "blobs of batch %d: %v", n, ethrpc.RedactError(err))
			if p.tries >= c.Cfg.BlobGiveUpTicks && !p.gaveUp {
				p.gaveUp = true
				u := BlobUnavailableRecord{N: n, L1Block: p.rec.L1Block, BeaconSlot: slot, VersionedHashes: p.rec.VersionedHashes, Err: ethrpc.RedactText(err.Error())}
				var be *BeaconError
				if errors.As(err, &be) {
					u.HTTPStatus = uint32(be.Status)
				}
				if perr := putRow(ctx, c.Store, Key{Chain: c.Cfg.Chain, L1Block: p.rec.L1Block, L1Hash: p.rec.L1Hash, Item: ItemBlobUnavailable(n)}, u.Encode()); perr != nil {
					rep.fail(c, "record blob unavailability of batch %d: %v", n, perr)
				}
			}
			continue
		}
		ok := true
		for j, vh := range p.rec.VersionedHashes {
			sc, found := scs[vh]
			if !found {
				ok = false
				rep.fail(c, "blob %d of batch %d missing from the beacon answer", j, n)
				break
			}
			br := BlobRecord{Raw: sc.Blob, Commitment: sc.Commitment, Proof: sc.Proof}
			if VersionedHash(br.Commitment) != vh {
				ok = false
				rep.fail(c, "blob %d of batch %d: commitment does not hash to the versioned hash", j, n)
				break
			}
			if err := putRow(ctx, c.Store, Key{Chain: c.Cfg.Chain, L1Block: p.rec.L1Block, L1Hash: p.rec.L1Hash, Item: ItemBlob(n, j)}, br.Encode()); err != nil {
				ok = false
				rep.fail(c, "store blob %d of batch %d: %v", j, n, err)
				break
			}
			rep.BlobsStored++
		}
		if ok {
			delete(c.needBlobs, n)
		}
	}
}

// proofAcceptor verifies a Bridge proof answer against the state root of the proof block.
func bridgeAcceptor(stateRoot [32]byte, bridge [20]byte, slots [][32]byte) func(*Proof) error {
	return func(p *Proof) error {
		acct, err := ethproof.VerifyAccount(common.Hash(stateRoot), common.Address(bridge), p.AccountProof)
		if err != nil {
			return err
		}
		if !acct.HasCode() {
			return errors.New("the Bridge account has no code at the proof block")
		}
		for i, s := range p.Slots {
			v, err := ethproof.VerifySlot(acct.StorageRoot, common.Hash(slots[i]), s.Proof)
			if err != nil {
				return err
			}
			if [32]byte(v) != s.Value {
				return errors.New("a slot proof proves another value than the answer states")
			}
		}
		return nil
	}
}

func implAcceptor(stateRoot [32]byte, impl [20]byte) func(*Proof) error {
	return func(p *Proof) error {
		acct, err := ethproof.VerifyAccount(common.Hash(stateRoot), common.Address(impl), p.AccountProof)
		if err != nil {
			return err
		}
		if !acct.HasCode() {
			return errors.New("the implementation account has no code at the proof block")
		}
		return nil
	}
}

func (c *Capturer) captureProofs(ctx context.Context, head uint64, rep *Report) {
	var jobs []proofJob
	ns := make([]uint64, 0, len(c.needProof))
	for n := range c.needProof {
		ns = append(ns, n)
	}
	sort.Slice(ns, func(i, j int) bool { return ns[i] < ns[j] })
	for _, n := range ns {
		if c.needProof[n].old && !c.dueOld() {
			continue
		}
		jobs = append(jobs, proofJob{ProofBatchAcc, n, [][32]byte{ArraySlot(SequencerAccSlot, n)}, c.needProof[n]})
	}
	ks := make([]uint64, 0, len(c.wantDelayed))
	for k := range c.wantDelayed {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool { return ks[i] < ks[j] })
	for _, k := range ks {
		jobs = append(jobs, proofJob{ProofDelayedAcc, k, [][32]byte{ArraySlot(DelayedAccSlot, k), ArraySlot(DelayedAccSlot, k-1)}, c.wantDelayed[k]})
	}
	if len(jobs) == 0 {
		return
	}
	var failures []string
	for try := 0; try < c.Cfg.ProofTries && uint64(try) <= head; try++ {
		P := head - uint64(try)
		h, err := c.L1.Header(ctx, P)
		if err != nil {
			failures = append(failures, fmt.Sprintf("header %d: %s", P, ethrpc.RedactText(err.Error())))
			continue
		}
		hf, err := finality.ReadHeader(h.RLP)
		if err != nil {
			failures = append(failures, fmt.Sprintf("header %d unreadable", P))
			continue
		}
		if done := c.proveAt(ctx, h, hf.StateRoot, jobs, rep, &failures); done {
			rep.ProofBlock = P
			return
		}
	}
	// no proof block worked: record the unavailability (rate-limited per batch) keyed at the head
	hh, herr := c.L1.Header(ctx, head)
	for _, j := range jobs {
		j.rec.ticks++
		if j.rec.ticks%c.Cfg.UnavailableEvery != 1 {
			continue
		}
		if j.kind != ProofBatchAcc || herr != nil {
			continue
		}
		u := UnavailableRecord{N: j.index, EventBlock: j.rec.rec.L1Block, Head: head, Providers: failures}
		if err := putRow(ctx, c.Store, hdrKey(c.Cfg.Chain, hh, ItemUnavailable(j.index)), u.Encode()); err != nil {
			rep.fail(c, "record proof unavailability of batch %d: %v", j.index, err)
			continue
		}
		rep.Unavailable = append(rep.Unavailable, j.index)
	}
	for _, f := range failures {
		rep.fail(c, "proof: %s", f)
	}
}

type proofJob struct {
	kind  uint8
	index uint64
	slots [][32]byte // the slots proven besides the implementation slot
	rec   *pendProof
}

// proveAt captures every job at proof block h; it returns true when ALL jobs were stored (partial progress is kept and
// retried at the next tick, at a nearer block).
func (c *Capturer) proveAt(ctx context.Context, h Header, stateRoot [32]byte, jobs []proofJob, rep *Report, failures *[]string) bool {
	// the implementation slot is proven together with the first group of slots
	allOK := true
	stored := false
	for start := 0; start < len(jobs); {
		var slots [][32]byte
		var group []proofJob
		slots = append(slots, [32]byte(ImplSlot))
		end := start
		for end < len(jobs) && len(slots)+len(jobs[end].slots) <= c.Cfg.SlotsPerProof {
			slots = append(slots, jobs[end].slots...)
			group = append(group, jobs[end])
			end++
		}
		if len(group) == 0 {
			*failures = append(*failures, "a job has more slots than SlotsPerProof")
			return false
		}
		start = end
		bp, err := c.L1.GetProof(ctx, c.Cfg.Bridge, slots, h.Number, bridgeAcceptor(stateRoot, c.Cfg.Bridge, slots))
		if err != nil {
			*failures = append(*failures, fmt.Sprintf("bridge proof at %d: %s", h.Number, ethrpc.RedactText(err.Error())))
			allOK = false
			continue
		}
		var impl [20]byte
		copy(impl[:], bp.Slots[0].Value[12:])
		if impl == ([20]byte{}) {
			*failures = append(*failures, "the Bridge implementation slot is empty at the proof block")
			allOK = false
			continue
		}
		ip, err := c.L1.GetProof(ctx, impl, nil, h.Number, implAcceptor(stateRoot, impl))
		if err != nil {
			*failures = append(*failures, fmt.Sprintf("implementation proof at %d: %s", h.Number, ethrpc.RedactText(err.Error())))
			allOK = false
			continue
		}
		if !stored {
			if err := putRow(ctx, c.Store, hdrKey(c.Cfg.Chain, h, ItemHeader), h.RLP); err != nil {
				*failures = append(*failures, "store proof block header: "+err.Error())
				return false
			}
			stored = true
		}
		pos := 1
		for _, j := range group {
			nodes := append([][]byte{}, bp.AccountProof...)
			nodes = append(nodes, bp.Slots[0].Proof...)
			nodes = append(nodes, ip.AccountProof...)
			pr := ProofRecord{Kind: j.kind, Index: j.index, ProofBlock: h.Number, ProofBlockHash: h.Hash, Bridge: c.Cfg.Bridge, Implementation: impl}
			for i := range j.slots {
				nodes = append(nodes, bp.Slots[pos+i].Proof...)
			}
			pr.ValueN = bp.Slots[pos].Value
			if j.kind == ProofDelayedAcc {
				pr.ValuePrev = bp.Slots[pos+1].Value
			}
			pos += len(j.slots)
			pr.Nodes = nodes
			item := ItemProof(j.index)
			if j.kind == ProofDelayedAcc {
				item = ItemDelayedProof(j.index)
			}
			if err := putRow(ctx, c.Store, hdrKey(c.Cfg.Chain, h, item), pr.Encode()); err != nil {
				*failures = append(*failures, fmt.Sprintf("store %s: %v", item, err))
				allOK = false
				continue
			}
			if j.kind == ProofBatchAcc {
				delete(c.needProof, j.index)
				rep.Proofs = append(rep.Proofs, j.index)
			} else {
				delete(c.wantDelayed, j.index)
			}
		}
	}
	return allOK
}

// Hex helpers for logs and the runner.
func HexHash(b [32]byte) string { return "0x" + hex.EncodeToString(b[:]) }
