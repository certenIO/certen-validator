// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/baseposted/kzgsetup"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
	"github.com/certen/independant-validator/pkg/finality/l1adapt"
)

// The Base R and unavailability codes this kind raises (V2_SPEC_S7 section 7); registered in testdata/finality/states.json.
const (
	CodeL1FinalityUnproven   = "l1_finality_unproven"
	CodeBatcherSender        = "batcher_sender_mismatch"
	CodeBatcherNotToInbox    = "batcher_tx_not_to_inbox"
	CodeBlobMismatch         = "blob_commitment_mismatch"
	CodeChannelIncomplete    = "channel_incomplete"
	CodeChannelTimedOut      = "channel_timed_out"
	CodeChannelMalformed     = "channel_malformed"
	CodeBatchNotFound        = "batch_not_found"
	CodeBatchBindingMismatch = "batch_binding_mismatch"
	CodeBatchOutsideWindow   = "batch_outside_sequencing_window"
	CodeBatchFormat          = "batch_format_unsupported"
	CodeL1TxProofInvalid     = "l1_tx_proof_invalid"
	CodeL1StateProofInvalid  = "l1_state_proof_invalid"
	CodeContractIdentity     = "contract_identity_unproven"
)

// LCRefused is the reason of l1_finality_unproven when the LC part of the container is refused; the inner fault code rides in
// the `inner` field.
const LCRefused = "lc_refused"

// eip1967ImplSlot is keccak256("eip1967.proxy.implementation") - 1.
var eip1967ImplSlot = common.HexToHash("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")

// batcherHashSlot is SystemConfig.batcherHash (storage slot 103, [BASE Q2]).
var batcherHashSlot = common.BigToHash(big.NewInt(103))

// Kind is the verifier of base-sepolia/l1_posted/v1 (spec 5.4). It is pure: no I/O, no clock.
type Kind struct{}

func (Kind) Name() string          { return KindName }
func (Kind) Chain() uint64         { return uint64(Chain) }
func (Kind) Level() finality.Level { return finality.LevelL1Posted }

// Register adds the kind to a registry; there is no init().
func Register(reg *finality.Registry) error { return reg.RegisterKind(Kind{}) }

func st(code string, kv ...any) *finality.StateError { return finality.NewState(code, kv...) }

type nodeDB struct{ db *memorydb.Database }

func newNodeDB(nodes [][]byte) nodeDB {
	db := memorydb.New()
	for _, n := range nodes {
		_ = db.Put(crypto.Keccak256(n), n)
	}
	return nodeDB{db}
}

func (n nodeDB) value(root [32]byte, key []byte) ([]byte, bool) {
	v, err := trie.VerifyProof(common.Hash(root), key, n.db)
	return v, err == nil
}

// account proves an account under a state root: its storage root and code hash. A missing proof, a bad node or an absent
// account is l1_state_proof_invalid{which:"account"}.
func (n nodeDB) account(stateRoot [32]byte, addr [20]byte) (types.StateAccount, error) {
	v, ok := n.value(stateRoot, crypto.Keccak256(addr[:]))
	if !ok || len(v) == 0 {
		return types.StateAccount{}, st(CodeL1StateProofInvalid, "which", "account")
	}
	var a types.StateAccount
	if err := rlp.DecodeBytes(v, &a); err != nil {
		return types.StateAccount{}, st(CodeL1StateProofInvalid, "which", "account")
	}
	return a, nil
}

// slot proves a storage slot under a storage root; an absent slot reads zero.
func (n nodeDB) slot(storageRoot [32]byte, slot common.Hash) ([32]byte, error) {
	var out [32]byte
	v, ok := n.value(storageRoot, crypto.Keccak256(slot[:]))
	if !ok {
		return out, st(CodeL1StateProofInvalid, "which", "slot")
	}
	if len(v) == 0 {
		return out, nil
	}
	var raw []byte
	if err := rlp.DecodeBytes(v, &raw); err != nil || len(raw) > 32 {
		return out, st(CodeL1StateProofInvalid, "which", "slot")
	}
	copy(out[32-len(raw):], raw)
	return out, nil
}

// systemConfigAt proves, under stateRoot of L1 block number l1, SystemConfig.batcherHash and the implementation behind the
// pinned proxy (EIP-1967 slot), whose code hash must be a pinned syscfg_impl. It returns the batcher address.
func systemConfigAt(db nodeDB, bp *Pins, stateRoot [32]byte, l1 uint64) ([20]byte, error) {
	var zero [20]byte
	acct, err := db.account(stateRoot, bp.SystemConfig)
	if err != nil {
		return zero, err
	}
	bh, err := db.slot(acct.Root, batcherHashSlot)
	if err != nil {
		return zero, err
	}
	implWord, err := db.slot(acct.Root, eip1967ImplSlot)
	if err != nil {
		return zero, err
	}
	var impl [20]byte
	copy(impl[:], implWord[12:])
	ia, err := db.account(stateRoot, impl)
	if err != nil {
		return zero, err
	}
	var ch [32]byte
	copy(ch[:], ia.CodeHash)
	if !bp.SystemConfigImplHashes[ch] {
		return zero, st(CodeContractIdentity, "role", RoleSystemConfigImpl, "address", impl, "code_hash", ch, "judged_at", l1)
	}
	for _, c := range bh[:12] {
		if c != 0 {
			return zero, st(CodeBatcherSender)
		}
	}
	copy(zero[:], bh[12:])
	return zero, nil
}

// Verify judges the container (spec 5.4 O1-O6). The L2 header is b.HeaderRLP (the leg's Settlement.Header).
func (Kind) Verify(p *finality.Pins, b finality.BlockRef, evidence []byte) (finality.Verdict, error) {
	bp, err := ParsePins(p)
	if err != nil {
		return finality.Verdict{}, err
	}
	eth, err := p.Sepolia()
	if err != nil {
		return finality.Verdict{}, err
	}
	ep := l1adapt.Pins(eth)
	lim := finality.DefaultLimits()
	c, err := finality.DecodeContainer(evidence, lim)
	if err != nil {
		return finality.Verdict{}, err
	}
	if c.Header.Kind != KindName {
		return finality.Verdict{}, finality.EvidenceUnrecognised(c.Header.Kind, "")
	}
	if c.Header.Chain != uint64(Chain) || c.Header.Level != finality.LevelL1Posted {
		return finality.Verdict{}, finality.Malformed("header.chain", finality.ReasonDiffersFromAddendum, 0, 0)
	}
	if c.Header.BlockNumber != b.Number {
		return finality.Verdict{}, finality.BlockMismatch("blockNumber", b.Number, c.Header.BlockNumber)
	}
	if c.Header.BlockHash != b.Hash {
		return finality.Verdict{}, finality.BlockMismatch("blockHash", b.Hash, c.Header.BlockHash)
	}
	maxBlobs := bp.MaxBlobs
	if maxBlobs > lim.MaxBlobsBase {
		maxBlobs = lim.MaxBlobsBase
	}
	body, err := DecodeBody(c.Body, lim, ep, maxBlobs)
	if err != nil {
		return finality.Verdict{}, err
	}
	if !bytes.Equal(EncodeBody(body), c.Body) {
		return finality.Verdict{}, finality.Malformed("body", finality.ReasonNodesNotAscendingUnique, 0, 0)
	}
	// The leg header: raw RLP hashed as given and read positionally.
	if len(b.HeaderRLP) == 0 {
		return finality.Verdict{}, finality.Malformed("leg.header", finality.ReasonHeaderNotRLPList, 0, 0)
	}
	l2, err := finality.ReadHeader(b.HeaderRLP)
	if err != nil {
		return finality.Verdict{}, err
	}
	if l2.Hash != b.Hash {
		return finality.Verdict{}, finality.BlockMismatch("blockHash", b.Hash, l2.Hash)
	}
	if l2.Number != b.Number {
		return finality.Verdict{}, finality.BlockMismatch("blockNumber", b.Number, l2.Number)
	}
	// O6: a post-Denim block (200 ms blocks, five per timestamp second, singular batches only) is judged only under pins that carry the
	// post_denim capability row; under pins without it the refusal is the named state it always was.
	if err := bp.denimGate(l2.Timestamp); err != nil {
		return finality.Verdict{}, err
	}
	// O1: L1 finality, then the spine.
	head, err := ethl1.VerifyFinalizedHead(ep, body.LC)
	if err != nil {
		inner := ""
		if f, ok := err.(*ethl1.Fault); ok {
			inner = f.Code
		}
		return finality.Verdict{}, st(CodeL1FinalityUnproven, "reason", LCRefused, "inner", inner)
	}
	covered, err := head.Covers(body.L1Spine, ep.MaxSpineHeaders)
	if err != nil {
		return finality.Verdict{}, l1adapt.State(err)
	}
	return verifyChannel(bp, body, covered, l2, head)
}

// verifyChannel is O3-O5 over a covered L1 spine.
func verifyChannel(bp *Pins, body Body, covered []ethl1.L1Block, l2 finality.HeaderFields, head ethl1.FinalizedHead) (finality.Verdict, error) {
	db := newNodeDB(body.Nodes)
	signer := types.LatestSignerForChainID(new(big.Int).SetUint64(bp.L1ChainID))
	var kz *kzgsetup.Context
	var frames []Frame
	var frameL1 []uint64
	var frameTime []uint64 // the timestamp of the L1 block of each entry of frameL1 (selects the channel timeout, see below)
	var batcher [20]byte
	var prevL1 uint64
	var prevIdx uint32
	for i, f := range body.Frames {
		// O1: the frame L1 block is a header of the covered spine, by number.
		blk, err := ethl1.BlockAt(covered, f.L1Block)
		if err != nil {
			return finality.Verdict{}, l1adapt.State(err)
		}
		raw := body.L1Spine[covered[0].Number-f.L1Block]
		hdr, err := finality.ReadHeader(raw)
		if err != nil {
			return finality.Verdict{}, err
		}
		if i > 0 && (f.L1Block < prevL1 || (f.L1Block == prevL1 && f.TxIndex <= prevIdx)) {
			return finality.Verdict{}, st(CodeChannelIncomplete)
		}
		prevL1, prevIdx = f.L1Block, f.TxIndex
		// Inclusion: the transaction is the value at rlp(index) of the block transaction trie.
		key, _ := rlp.EncodeToBytes(uint64(f.TxIndex))
		v, ok := db.value(hdr.TransactionRoot, key)
		if !ok || !bytes.Equal(v, f.TxRaw) {
			return finality.Verdict{}, st(CodeL1TxProofInvalid)
		}
		var tx types.Transaction
		if err := tx.UnmarshalBinary(f.TxRaw); err != nil {
			return finality.Verdict{}, st(CodeL1TxProofInvalid)
		}
		if to := tx.To(); to == nil || [20]byte(*to) != bp.BatchInbox {
			return finality.Verdict{}, st(CodeBatcherNotToInbox)
		}
		// Authentication: the sender is SystemConfig.batcherHash proven at THIS frame L1 block.
		want, err := systemConfigAt(db, bp, blk.StateRoot, f.L1Block)
		if err != nil {
			return finality.Verdict{}, err
		}
		from, err := signer.Sender(&tx)
		if err != nil || [20]byte(from) != want {
			return finality.Verdict{}, st(CodeBatcherSender)
		}
		batcher = want
		var datas [][]byte
		if tx.Type() == types.BlobTxType {
			hashes := tx.BlobHashes()
			if len(f.Blobs) != len(hashes) {
				return finality.Verdict{}, st(CodeBlobMismatch)
			}
			for j, bl := range f.Blobs {
				s := sha256Sum(bl.Commitment[:])
				s[0] = 0x01
				if s != [32]byte(hashes[j]) {
					return finality.Verdict{}, st(CodeBlobMismatch)
				}
				if kz == nil {
					if kz, err = kzgsetup.Load(bp.KZGSetupSHA256); err != nil {
						return finality.Verdict{}, finality.PinsCorrupt(finality.PinsBadValue, "key", bp.KZGSetupKey)
					}
				}
				if err := kz.VerifyBlob(bl.Raw, bl.Commitment, bl.Proof); err != nil {
					return finality.Verdict{}, st(CodeBlobMismatch)
				}
				d, err := blobToData(bl.Raw)
				if err != nil {
					return finality.Verdict{}, st(CodeChannelMalformed)
				}
				datas = append(datas, d)
			}
		} else {
			if len(f.Blobs) != 0 {
				return finality.Verdict{}, st(CodeBlobMismatch)
			}
			datas = append(datas, tx.Data())
		}
		for _, d := range datas {
			fr, err := parseFrames(d)
			if err != nil {
				return finality.Verdict{}, st(CodeChannelMalformed)
			}
			for _, x := range fr {
				if x.ID == body.ChannelID {
					frames = append(frames, x)
					frameL1 = append(frameL1, f.L1Block)
					frameTime = append(frameTime, hdr.Timestamp)
				}
			}
		}
	}
	// O4: contiguous from 0, exactly one closing frame (the last), all within channel_timeout of the first.
	if len(frames) == 0 {
		return finality.Verdict{}, st(CodeChannelIncomplete)
	}
	var stream []byte
	for i, fr := range frames {
		if uint64(fr.Number) != uint64(i) || (fr.IsLast != (i == len(frames)-1)) {
			return finality.Verdict{}, st(CodeChannelIncomplete)
		}
		stream = append(stream, fr.Data...)
	}
	// op-node IngestFrame ignores a frame when `currentCh.OpenBlockNumber()+cb.spec.ChannelTimeout(origin.Time) < origin.Number`: origin
	// is the L1 block that holds the frame, so the timeout in force (50 from Granite, 300 before) is selected by that block's own
	// timestamp, frame by frame [r2:D2FIX].
	for i, l := range frameL1 {
		if l-frameL1[0] > bp.ChannelTimeoutAt(frameTime[i]) { // frameL1 is non-decreasing (the frames are in order), so this cannot wrap
			return finality.Verdict{}, st(CodeChannelTimedOut)
		}
	}
	raw, err := decompress(stream, bp.MaxRLPBytesPerChannel)
	if err != nil {
		return finality.Verdict{}, st(CodeChannelMalformed)
	}
	batches, err := decodeBatches(raw, spanParams{GenesisTime: bp.L2GenesisTime, BlockTime: bp.L2BlockTime, ChainID: bp.ChainID})
	if err != nil {
		if bf, ok := err.(*batchFormatError); ok {
			return finality.Verdict{}, st(CodeBatchFormat, "type", bf.typ)
		}
		return finality.Verdict{}, st(CodeChannelMalformed)
	}
	bt, err := selectBatch(bp, batches, l2)
	if err != nil {
		return finality.Verdict{}, err
	}
	// O5: binding.
	if !prefixEq(bt.ParentHash, bt.ParentLen, l2.ParentHash) {
		return finality.Verdict{}, st(CodeBatchBindingMismatch, "field", "parent_hash")
	}
	if len(body.Deposits) == 0 || len(body.Deposits[0]) == 0 || body.Deposits[0][0] != 0x7e {
		return finality.Verdict{}, st(CodeBatchBindingMismatch, "field", "l1_info_deposit")
	}
	// O2/O5: the block's transaction list is depositTxs followed by the batch's transactions and the two lists are told apart by
	// type alone, as OP derivation does (a batch may not embed a deposit or an empty transaction: checkSingularBatch / span
	// batch validation drop it). Without this a prover moves any block transaction the batcher never posted into depositTxs
	// and the recomputed root still matches [r2:D2FIX].
	for _, d := range body.Deposits {
		if len(d) == 0 || d[0] != 0x7e {
			return finality.Verdict{}, st(CodeBatchBindingMismatch, "field", "deposit_txs")
		}
	}
	for _, x := range bt.Txs {
		if len(x) == 0 || x[0] == 0x7e {
			return finality.Verdict{}, st(CodeBatchBindingMismatch, "field", "batch_txs")
		}
	}
	num, hash, ok := l1Info(body.Deposits[0])
	if !ok {
		return finality.Verdict{}, st(CodeBatchBindingMismatch, "field", "l1_info_deposit")
	}
	if bt.EpochNum != num {
		return finality.Verdict{}, st(CodeBatchBindingMismatch, "field", "epoch_num")
	}
	if !prefixEq(bt.EpochHash, bt.EpochLen, hash) {
		return finality.Verdict{}, st(CodeBatchBindingMismatch, "field", "epoch_hash")
	}
	// OP derivation drops a batch when `batch.epoch_num + sequence_window_size < inclusion_block_number`, the inclusion block being the one
	// whose frame COMPLETES the channel (derivation.md: "the L1 block number when batch was first fully derived"); it has no lower bound.
	// op-batcher streams the ready frames of an OPEN channel while L2 blocks are still being added (channel_builder.go outputReadyFrames:
	// "already generate frames and send them off as txs while still collecting blocks in the channel builder"; channel_manager.go
	// getReadyChannel runs outputFrames on the not-yet-full current channel), so an early frame may lie below the epoch of a later block
	// of its channel. frameL1 is non-decreasing, so its last element is the completing frame's block. See research/R12-SPEC-Q1.md.
	if last := frameL1[len(frameL1)-1]; last > bt.EpochNum && last-bt.EpochNum > bp.SeqWindowSize {
		return finality.Verdict{}, st(CodeBatchOutsideWindow)
	}
	all := make([][]byte, 0, len(body.Deposits)+len(bt.Txs))
	all = append(all, body.Deposits...)
	all = append(all, bt.Txs...)
	if root := ethproof.TrieRoot(all); [32]byte(root) != l2.TransactionRoot {
		return finality.Verdict{}, st(CodeBatchBindingMismatch, "field", "transactions_root")
	}
	return finality.Verdict{Level: finality.LevelL1Posted, Kind: KindName, Fields: map[string]any{
		"channel_id": body.ChannelID, "l1_blocks": distinctSorted(frameL1), "batcher": batcher, "batch_type": uint64(bt.Type),
		"span_index": uint64(bt.SpanIndex), "span_blocks": uint64(bt.SpanBlocks),
		"parent_hash_bits": uint64(bt.ParentLen * 8), "epoch_hash_bits": uint64(bt.EpochLen * 8),
		"finalized_slot": head.Slot, "finalized_epoch": head.Epoch,
	}}, nil
}

// denimGate is the O6 gate: a block with timestamp >= denim_time is batch_format_unsupported{post_denim} unless the pins carry the
// post_denim capability row.
func (p *Pins) denimGate(ts uint64) error {
	if ts >= p.DenimTime && p.PostDenim == nil {
		return st(CodeBatchFormat, "type", "post_denim")
	}
	return nil
}

// selectBatch is the batch of the channel that produced the block l2 (derivation takes, for a block, the first valid batch of its
// position). Before denim_time a timestamp names one block (2 s blocks), so the first batch with the block's timestamp is it and the
// parent-hash binding is O5's. From denim_time five blocks share a timestamp second (200 ms blocks), so the timestamp alone names
// five batches and the block is the one whose parent hash the batch commits in full: a singular batch (32-byte parent) with the block's
// timestamp and parent hash. A span batch with the block's timestamp would be dropped by derivation (op-node SpanBatchPostDenim), so it
// is never taken: with no singular match it is batch_format_unsupported{type:span_post_denim}; a singular batch of the second with
// another parent is batch_binding_mismatch{parent_hash}; none at all is batch_not_found.
func selectBatch(bp *Pins, batches []Batch, l2 finality.HeaderFields) (*Batch, error) {
	if l2.Timestamp < bp.DenimTime {
		for i := range batches {
			if batches[i].Timestamp == l2.Timestamp {
				return &batches[i], nil
			}
		}
		return nil, st(CodeBatchNotFound, "timestamp", l2.Timestamp, "n_batches", uint64(len(batches)))
	}
	if err := bp.denimGate(l2.Timestamp); err != nil {
		return nil, err
	}
	var sameSecond, span bool
	for i := range batches {
		b := &batches[i]
		if b.Timestamp != l2.Timestamp {
			continue
		}
		if !bp.PostDenim.allowsBatchType(b.Type) {
			span = true
			continue
		}
		sameSecond = true
		if b.ParentLen == 32 && b.ParentHash == l2.ParentHash {
			return b, nil
		}
	}
	switch {
	case span:
		return nil, st(CodeBatchFormat, "type", "span_post_denim")
	case sameSecond:
		return nil, st(CodeBatchBindingMismatch, "field", "parent_hash")
	}
	return nil, st(CodeBatchNotFound, "timestamp", l2.Timestamp, "n_batches", uint64(len(batches)))
}

func prefixEq(have [32]byte, n int, want [32]byte) bool {
	if n <= 0 || n > 32 {
		return false
	}
	return bytes.Equal(have[:n], want[:n])
}

// l1Info reads the L1-info deposit: with the 4-byte selector included, the epoch number sits at calldata [28:36] and the epoch
// hash at [100:132]; the deposit is a type-0x7e transaction whose data is the last of its eight RLP items.
func l1Info(dep []byte) (uint64, [32]byte, bool) {
	var hash [32]byte
	content, rest, err := rlp.SplitList(dep[1:])
	if err != nil || len(rest) != 0 {
		return 0, hash, false
	}
	var last []byte
	n := 0
	for len(content) > 0 {
		kind, val, tail, err := rlp.Split(content)
		if err != nil {
			return 0, hash, false
		}
		n++
		if n == 8 {
			if kind != rlp.String {
				return 0, hash, false
			}
			last = val
		}
		content = tail
	}
	if n != 8 || len(last) < 132 {
		return 0, hash, false
	}
	copy(hash[:], last[100:132])
	return binary.BigEndian.Uint64(last[28:36]), hash, true
}

func distinctSorted(in []uint64) []uint64 {
	seen := map[uint64]bool{}
	var out []uint64
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
