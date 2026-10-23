// Copyright 2026 Certen Protocol

package arbposted

import (
	"context"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted/capture"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
	"github.com/certen/independant-validator/pkg/metrics"
)

// This file is the ATTEST half of the two-phase build (spec 2.8): given the rows the leg-independent Capturer stored, the
// leg's L2 block and the L1 finality evidence, find the batch and message that hold the block, wait for the finalized head to
// cover the proof block, assemble the container, run the verifier and return the addendum, or a named pending / U state.

// L2Source reads the leg's block from the Arbitrum chain: the consensus encodings of ALL its transactions, in order.
type L2Source interface {
	BlockTxs(ctx context.Context, blockHash [32]byte) ([][]byte, error)
}

// L1Chain is the parent-chain read side of the attest phase: the beacon light-client evidence of the finalized head and the
// execution headers that connect it down to the proof block. None of it is trusted: Build runs the verifier on what it gets.
type L1Chain interface {
	// LightClient returns the LC part (spec 3.2) proving the current finalized head.
	LightClient(ctx context.Context) (ethl1.LC, error)
	// HeaderRLP returns the raw RLP header of the L1 block with this number (hash checked by the caller through Covers).
	HeaderRLP(ctx context.Context, number uint64) ([]byte, error)
	// HeaderRLPByHash returns the raw RLP header with this hash.
	HeaderRLPByHash(ctx context.Context, hash [32]byte) ([]byte, error)
}

// Pending reasons of this kind (the awaiting_* values of V2_SPEC_S7 section 7 and states.json).
const (
	PendingAwaitingBatchPost      = "awaiting_batch_post"
	PendingAwaitingL1Finality     = "awaiting_l1_finality_of_batch"
	PendingProofWindowUnavailable = "l1_proof_window_unavailable"
	codeBlobUnavailable           = "l1_blob_unavailable"
	codeL2HeaderUnavailable       = "l2_header_unavailable"
)

// Builder is the finality.Prover of chain 421614 for level 2 (l1_posted).
type Builder struct {
	Store capture.CaptureStore
	L2    L2Source
	L1    L1Chain
	Pins  *finality.Pins
	// Now is the clock for ETAs only (never used by a verifier). Nil means time.Now.
	Now func() time.Time
	// Index is the batch index (RB12-INDEX-B). With it a build locates its batch from the index rows and loads only that batch; without
	// it (CERTEN_FINALITY_ARB_INDEX=off, or a bad setting) the build reads every captured batch and decodes every window candidate, the
	// reference implementation the index is proven equal to. A build never falls back from one to the other.
	Index *IndexReader
}

func (b *Builder) Chain() uint64 { return finality.ChainArbitrumSepolia }

// Ceiling is the highest level this prover builds (the finalized level has its own prover, RB11-E3).
func (b *Builder) Ceiling() finality.Level { return finality.LevelL1Posted }

func (b *Builder) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

// l1BlockTime is the average L1 block interval used for ETAs only.
const l1BlockInterval = 12 * time.Second

func pending(chain uint64, reason string, eta time.Time, judged map[string]any) *finality.PendingState {
	return &finality.PendingState{Chain: chain, LevelReached: finality.LevelIncluded, NextLevel: finality.LevelL1Posted, Reason: reason, ETA: eta, Judged: judged}
}

// Build implements finality.Prover.
func (b *Builder) Build(ctx context.Context, s *ethproof.Settlement, have finality.LevelSet, target finality.Level) (*finality.Addendum, *finality.PendingState, error) {
	if target != finality.LevelL1Posted {
		return nil, nil, nil // finalized is the sibling prover's level (arbfinal/build)
	}
	if have.Has(finality.LevelL1Posted) {
		return nil, nil, finality.NewState(finality.CodeLevelAlreadyPresent, "chain", b.Chain(), "level", finality.LevelL1Posted)
	}
	ref, err := finality.DeriveIncluded(b.Chain(), s)
	if err != nil {
		return nil, nil, err
	}
	return b.BuildFor(ctx, ref)
}

// BuildFor is Build for a leg block already derived at level 1 (the block reference carries the L2 header).
func (b *Builder) BuildFor(ctx context.Context, ref finality.BlockRef) (*finality.Addendum, *finality.PendingState, error) {
	hdr, err := finality.ReadHeader(ref.HeaderRLP)
	if err != nil {
		return nil, nil, err
	}
	arb, err := loadArbPins(b.Pins)
	if err != nil {
		return nil, nil, err
	}
	if hdr.Number <= arb.BoldGenesisL2Block {
		return nil, nil, finality.NewState(CodePreBold, "n", hdr.Number, "bold_genesis_l2_block", arb.BoldGenesisL2Block)
	}
	txs, err := b.L2.BlockTxs(ctx, ref.Hash)
	if err != nil {
		return nil, nil, finality.NewState(codeL2HeaderUnavailable, "block", hdr.Number)
	}
	if ethproof.TrieRoot(txs) != common.Hash(hdr.TransactionRoot) {
		return nil, nil, contentNotFound(ContentBlockTxsRootMismatch)
	}

	// the batch and message that hold the block, from what the capture phase stored
	var found *located
	if b.Index != nil {
		var pend *finality.PendingState
		found, pend, err = b.Index.Locate(ctx, b, hdr, standardTxs(txs), arb)
		if err != nil {
			return nil, nil, err
		}
		if pend != nil {
			return nil, pend, nil
		}
	} else {
		batches, err := capture.LoadBatches(ctx, b.Store, b.Chain())
		if err != nil {
			return nil, nil, err
		}
		found, err = b.locate(ctx, batches, hdr, txs, arb)
		if err != nil {
			return nil, nil, err
		}
		if found == nil {
			newest := uint64(0)
			for _, r := range batches {
				if r.N > newest {
					newest = r.N
				}
			}
			return nil, pending(b.Chain(), PendingAwaitingBatchPost, b.now().Add(3*time.Minute),
				map[string]any{"l2_block": hdr.Number, "latest_captured_batch": newest}), nil
		}
	}
	rec := found.rec

	// the near-head proof the capture phase stored for this batch
	proofs, err := capture.LoadProofs(ctx, b.Store, b.Chain(), rec.N)
	if err != nil {
		return nil, nil, err
	}
	if len(proofs) == 0 {
		return nil, pending(b.Chain(), PendingProofWindowUnavailable, time.Time{},
			map[string]any{"l1_block": rec.L1Block, "providers": []string{}}), nil
	}
	proof := proofs[0]

	// the finalized head must cover the proof block (the state block S)
	lc, err := b.L1.LightClient(ctx)
	if err != nil {
		return nil, pending(b.Chain(), "finality_lc_unavailable", time.Time{}, map[string]any{"endpoints": []string{redactErr(err)}}), nil
	}
	l1p, kzgPin, err := ethl1Pins(b.Pins)
	if err != nil {
		return nil, nil, err
	}
	_ = kzgPin
	fh, ferr := ethl1.VerifyFinalizedHead(l1p, lc)
	if ferr != nil {
		return nil, nil, l1FinalityUnproven(L1FinalityLCRefused, innerCode(ferr))
	}
	topRLP, err := b.L1.HeaderRLPByHash(ctx, fh.ExecHash)
	if err != nil {
		return nil, l1StatePending(b.Chain(), 0, err), nil
	}
	top, err := finality.ReadHeader(topRLP)
	if err != nil {
		return nil, nil, err
	}
	if top.Number < proof.ProofBlock {
		blocks := proof.ProofBlock - top.Number
		return nil, pending(b.Chain(), PendingAwaitingL1Finality, b.now().Add(time.Duration(blocks)*l1BlockInterval),
			map[string]any{"l1_block": proof.ProofBlock, "finalized_exec_number": top.Number}), nil
	}
	spine := [][]byte{topRLP}
	for n := top.Number; n > proof.ProofBlock; {
		n--
		raw, err := b.L1.HeaderRLP(ctx, n)
		if err != nil {
			return nil, l1StatePending(b.Chain(), n, err), nil
		}
		spine = append(spine, raw)
	}

	blobs, err := capture.LoadBlobs(ctx, b.Store, b.Chain(), rec)
	if err != nil {
		return nil, nil, err
	}
	if rec.DataLocation == capture.LocBlob && len(blobs) != len(rec.VersionedHashes) {
		return nil, nil, b.blobUnavailable(ctx, rec)
	}
	ev := Evidence{LC: lc, L1Spine: spine, StateBlock: proof.ProofBlock, BlockTxs: txs, BatchSeq: rec.N, Header40: rec.Header40,
		BeforeAcc: rec.BeforeAcc, DelayedAcc: rec.DelayedAcc, Nodes: proof.Nodes}
	switch rec.DataLocation {
	case capture.LocBlob:
		ev.DataKind = DataBlobs
		ev.VersionedHashes = rec.VersionedHashes
		for _, bl := range blobs {
			ev.Blobs = append(ev.Blobs, Blob{Raw: bl.Raw, Commitment: bl.Commitment, Proof: bl.Proof})
		}
	case capture.LocTxInput, capture.LocSeparateBatchEvent:
		ev.DataKind = DataCalldata
		ev.Calldata = found.data
	default:
		ev.DataKind = DataNone
	}
	body := ev.Encode()
	c := finality.Container{Header: finality.ContainerHeader{Kind: KindName, Chain: b.Chain(), Level: finality.LevelL1Posted,
		BlockNumber: ref.Number, BlockHash: ref.Hash}, Body: body}
	enc, err := c.Encode()
	if err != nil {
		return nil, nil, err
	}
	// the verifier is the gate: nothing is returned that it does not accept
	if _, err := New().Verify(b.Pins, ref, enc); err != nil {
		return nil, nil, err
	}
	return &finality.Addendum{Level: finality.LevelL1Posted, Chain: b.Chain(), Kind: KindName, Evidence: enc}, nil, nil
}

func hashList(h [][32]byte) []string {
	out := make([]string, len(h))
	for i, x := range h {
		out[i] = fmt.Sprintf("0x%x", x[:])
	}
	return out
}

// located is a captured batch that holds the block, with the calldata batch bytes when the batch is not a blob batch.
type located struct {
	rec  capture.BatchRecord
	data []byte
}

// standardTxs is the block's signed standard transactions (types 0-4), in order: what a batch message must carry for the block to be in it.
func standardTxs(txs [][]byte) [][]byte {
	var std [][]byte
	for _, tx := range txs {
		if ethproof.TxType(tx) <= 4 {
			std = append(std, tx)
		}
	}
	return std
}

// candidateKind is what matchCandidate concluded about one captured batch.
type candidateKind uint8

const (
	candidateNoMatch    candidateKind = iota // the batch does not hold the block: skipped (unreadable data, a payload that does not decode, no message with these transactions)
	candidateIncomplete                      // a blob batch whose blob rows are not all stored: its content is unknown
	candidateMatch                           // a message of the batch carries exactly the block's standard transactions
)

// matchCandidate is the judgement of ONE captured batch, the body of the reference reader's loop and, unchanged, the check the indexed
// reader makes of the batch its fingerprints point to: load the data rows of the batch, decode the payload, and look for a message whose
// signed transactions are std. Both readers call it, so they cannot disagree about a batch.
func (b *Builder) matchCandidate(ctx context.Context, rec capture.BatchRecord, std [][]byte, arb *arbPins) (*located, candidateKind, error) {
	var payload, data []byte
	switch rec.DataLocation {
	case capture.LocBlob:
		bl, err := capture.LoadBlobs(ctx, b.Store, b.Chain(), rec)
		if err != nil {
			return nil, candidateNoMatch, err
		}
		if len(bl) != len(rec.VersionedHashes) {
			return nil, candidateIncomplete, nil
		}
		raws := make([][]byte, len(bl))
		for i := range bl {
			raws[i] = bl[i].Raw
		}
		payload, err = decodeBlobs(raws)
		if err != nil {
			return nil, candidateNoMatch, nil
		}
	case capture.LocTxInput, capture.LocSeparateBatchEvent:
		row, ok, err := b.Store.Get(ctx, capture.Key{Chain: b.Chain(), L1Block: rec.L1Block, L1Hash: rec.L1Hash, Item: capture.ItemCalldata(rec.N)})
		if err != nil || !ok {
			return nil, candidateNoMatch, nil
		}
		if rec.DataLocation == capture.LocTxInput {
			d, err := capture.ExtractTxInputData(row)
			if err != nil {
				return nil, candidateNoMatch, nil
			}
			row = d
		}
		payload, data = row, row
	default:
		return nil, candidateNoMatch, nil
	}
	res := decodePayload(payload, arb.MaxUncompressedBatch, arb.MaxSegments)
	if res.status != payloadOK {
		return nil, candidateNoMatch, nil
	}
	for _, m := range res.messages {
		if sameTxs(std, m.txs) {
			return &located{rec: rec, data: data}, candidateMatch, nil
		}
	}
	return nil, candidateNoMatch, nil
}

// authorized reports whether the record is a batch the Bridge holds (capture.AuthorizeBatch over the captured, verified proofs of its
// accumulator): false only for a FOREIGN record, one a verified proof contradicts. An unproven record is kept; the verifier of the leg
// decides what it can prove.
func (b *Builder) authorized(ctx context.Context, rec capture.BatchRecord, arb *arbPins) (bool, error) {
	views, err := capture.LoadProofViews(ctx, b.Store, b.Chain(), rec.N, rec.L1Block)
	if err != nil {
		return false, err
	}
	if capture.AuthorizeBatch(rec, arb.bridge, arb.Layout.AccArraySlot, views) == capture.AuthForeign {
		metrics.AddFinalityCaptureForeignTxs(b.Chain(), 1)
		return false, nil
	}
	return true, nil
}

// locate finds the captured batch whose decoded payload holds a message with the block's signed transactions: the REFERENCE reader, which
// judges every captured batch whose time bounds hold the block's timestamp, in (N, L1 block) order, and serves the first that holds the
// message and is not foreign. The time bounds only narrow the candidates (hints are never evidence); the decode decides.
func (b *Builder) locate(ctx context.Context, batches []capture.BatchRecord, hdr finality.HeaderFields, txs [][]byte, arb *arbPins) (*located, error) {
	var incomplete *capture.BatchRecord
	std := standardTxs(txs)
	if len(std) == 0 {
		return nil, nil
	}
	for _, rec := range capture.FindBatchContaining(batches, hdr.Timestamp) {
		loc, kind, err := b.matchCandidate(ctx, rec, std, arb)
		if err != nil {
			return nil, err
		}
		switch kind {
		case candidateIncomplete:
			r := rec
			incomplete = &r
		case candidateMatch:
			ok, err := b.authorized(ctx, rec, arb)
			if err != nil {
				return nil, err
			}
			if ok {
				return loc, nil
			}
		}
	}
	if incomplete != nil {
		return nil, b.blobUnavailable(ctx, *incomplete)
	}
	return nil, nil
}

// blobUnavailable is l1_blob_unavailable for a captured batch whose blobs are not all stored: the capture phase's own record of
// the beacon answer when it gave up, else the batch's L1 block and hashes with no beacon status.
func (b *Builder) blobUnavailable(ctx context.Context, rec capture.BatchRecord) error {
	slot, status := uint64(0), uint64(0)
	if raw, ok, err := b.Store.Get(ctx, capture.Key{Chain: b.Chain(), L1Block: rec.L1Block, L1Hash: rec.L1Hash, Item: capture.ItemBlobUnavailable(rec.N)}); err == nil && ok {
		if u, err := capture.DecodeBlobUnavailableRecord(raw); err == nil {
			slot, status = u.BeaconSlot, uint64(u.HTTPStatus)
		}
	}
	return finality.NewState(codeBlobUnavailable, "l1_block", rec.L1Block, "versioned_hashes", hashList(rec.VersionedHashes),
		"beacon_slot", slot, "http_status", status)
}

func redactErr(err error) string { return ethrpc.RedactText(err.Error()) }

func l1StatePending(chain uint64, block uint64, err error) *finality.PendingState {
	return pending(chain, "l1_state_unavailable", time.Time{}, map[string]any{"block": block, "providers": []string{redactErr(err)}})
}

// PayloadFromBlobs decodes the raw blobs of a batch into its payload (nitro DecodeBlobs).
func PayloadFromBlobs(raws [][]byte) ([]byte, error) { return decodeBlobs(raws) }

// MessageTxs decodes a batch payload into its L2 messages and returns, per message, its signed transactions. It is the
// verifier's decode (header byte, brotli, segments, messages) for tools that need to pick a block from a batch.
func MessageTxs(payload []byte, maxUncompressed, maxSegments int) ([][][]byte, error) {
	res := decodePayload(payload, maxUncompressed, maxSegments)
	if res.status != payloadOK {
		return nil, fmt.Errorf("arbposted: payload status %d", res.status)
	}
	out := make([][][]byte, len(res.messages))
	for i, m := range res.messages {
		out[i] = m.txs
	}
	return out, nil
}

// SegmentCount is the number of segments of a decoded batch payload (0 when it does not decode); for tools that state a batch's size.
func SegmentCount(payload []byte, maxUncompressed, maxSegments int) int {
	return decodePayload(payload, maxUncompressed, maxSegments).segments
}
