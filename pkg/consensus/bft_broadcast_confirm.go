package consensus

// Broadcast outcome = inclusion, not the RPC acknowledgement.
//
// WHAT WAS WRONG (testnet fleet, 2026-09-15)
//
// BroadcastValidatorBlockCommit treated the BroadcastTxSync reply as the verdict. When a block commit
// held the mempool lock longer than CometBFT's RPC write timeout (timeout_broadcast_tx_commit + 1 s =
// 11 s), the reply was lost as EOF even though the node admitted the transaction moments later. The
// retries (2 s and 4 s apart, three in total) landed inside the next commit and got EOF again, so the
// validator declared the intent failed. Validator-3 failed intent 770f02b8 at 15:48:39 while its
// ValidatorBlock was committed at height 2187 at 15:48:24; four of seven validators did the same, and
// quorum never formed.
//
// WHAT THIS DOES
//
// A transport error only means the reply was lost. Before retrying or failing, the transaction is looked
// up by its hash (sha256 of the payload, CometBFT's tx hash): committed -> done; in the mempool -> the
// usual inclusion poll. Retries are bounded by a time budget longer than a slow commit instead of by a
// count. A CheckTx rejection or a non-transport error is still reported at once, unchanged.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	coretypes "github.com/cometbft/cometbft/rpc/core/types"
	cmttypes "github.com/cometbft/cometbft/types"
)

// broadcastRPC is the part of the CometBFT RPC client the broadcaster uses (*cmthttp.HTTP).
//
// Status/BlockchainInfo/Block/BlockResults are here so the outcome can be read from COMMITTED BLOCKS
// rather than from the transaction index, which answers for the last copy indexed rather than for the
// copy that committed successfully — see bft_inclusion_scan.go.
type broadcastRPC interface {
	BroadcastTxSync(ctx context.Context, tx cmttypes.Tx) (*coretypes.ResultBroadcastTx, error)
	Tx(ctx context.Context, hash []byte, prove bool) (*coretypes.ResultTx, error)
	UnconfirmedTxs(ctx context.Context, limit *int) (*coretypes.ResultUnconfirmedTxs, error)
	Status(ctx context.Context) (*coretypes.ResultStatus, error)
	BlockchainInfo(ctx context.Context, minHeight, maxHeight int64) (*coretypes.ResultBlockchainInfo, error)
	Block(ctx context.Context, height *int64) (*coretypes.ResultBlock, error)
	BlockResults(ctx context.Context, height *int64) (*coretypes.ResultBlockResults, error)
}

type broadcastTiming struct {
	attemptTimeout time.Duration // one BroadcastTxSync call
	submitBudget   time.Duration // total time to get the transaction admitted
	retryBase      time.Duration // first retry delay, doubled per attempt
	retryMax       time.Duration // retry delay cap
	lookupTimeout  time.Duration // one lookup by hash, and one RPC call inside a scan
	inclusionPoll  time.Duration // how long to wait for block inclusion once admitted
	pollInterval   time.Duration
	maxScanBlocks  int // most blocks one inclusion scan will read (0 = defaultMaxScanBlocks)
}

// defaultBroadcastTiming fits the caller's 3-minute context (validator_block execution): up to 2 minutes
// to get admitted — many times a slow commit — and 15 s to observe inclusion.
var defaultBroadcastTiming = broadcastTiming{
	attemptTimeout: 30 * time.Second,
	submitBudget:   2 * time.Minute,
	retryBase:      2 * time.Second,
	retryMax:       10 * time.Second,
	lookupTimeout:  5 * time.Second,
	inclusionPoll:  15 * time.Second,
	pollInterval:   1 * time.Second,
	maxScanBlocks:  defaultMaxScanBlocks,
}

// unconfirmedLookupLimit is CometBFT's maximum page for unconfirmed_txs. A transaction beyond it is not
// found by the lookup; the next broadcast then answers "already exists in cache", which is also success.
const unconfirmedLookupLimit = 100

type txLookup int

const (
	txNotFound     txLookup = iota // both lookups answered and neither has the transaction
	txLookupFailed                 // a lookup did not answer, so absence is not established
	txInMempool
	txCommitted
)

// lookupMempoolOnly answers just the "is it queued" question, without consulting the transaction index.
//
// The index cannot be asked for a verdict: it stores by hash and the node overwrites it with the LAST
// inclusion, so after a resend it can report a rejected duplicate for a ValidatorBlock that committed
// perfectly well. When the inclusion scan is on, the blocks answer "did it commit" and this answers only
// "is another copy still pending" — the one thing the mempool genuinely knows.
//
// A lookup that does not answer is txLookupFailed, never absence: unconfirmed_txs takes the mempool lock
// and therefore blocks for as long as a commit does, which is exactly when the broadcast reply was lost.
func lookupMempoolOnly(ctx context.Context, rpc broadcastRPC, hash []byte, timeout time.Duration) txLookup {
	uctx, ucancel := context.WithTimeout(ctx, timeout)
	defer ucancel()
	limit := unconfirmedLookupLimit
	u, err := rpc.UnconfirmedTxs(uctx, &limit)
	if err != nil || u == nil {
		return txLookupFailed
	}
	for _, tx := range u.Txs {
		if bytes.Equal(tx.Hash(), hash) {
			return txInMempool
		}
	}
	return txNotFound
}

// lookupTxByHash reports whether the transaction is committed or waiting in the mempool.
//
// Each lookup gets its own timeout. unconfirmed_txs takes the mempool lock and therefore blocks for as long
// as a block commit does, exactly when the broadcast reply was lost; a lookup that does not answer is
// reported as txLookupFailed, never as absence. The caller retries the broadcast either way, which is safe
// (a duplicate is deduplicated), but only a real absence may end in "not in the mempool".
func lookupTxByHash(ctx context.Context, rpc broadcastRPC, hash []byte, timeout time.Duration) (txLookup, *coretypes.ResultTx) {
	failed := false

	tctx, tcancel := context.WithTimeout(ctx, timeout)
	res, err := rpc.Tx(tctx, hash, false)
	tcancel()
	switch {
	case err == nil && res != nil:
		return txCommitted, res
	case err != nil && !strings.Contains(err.Error(), "not found"):
		failed = true // the indexer did not answer, rather than answering "not found"
	}

	uctx, ucancel := context.WithTimeout(ctx, timeout)
	defer ucancel()
	limit := unconfirmedLookupLimit
	u, err := rpc.UnconfirmedTxs(uctx, &limit)
	if err != nil || u == nil {
		return txLookupFailed, nil
	}
	for _, tx := range u.Txs {
		if bytes.Equal(tx.Hash(), hash) {
			return txInMempool, nil
		}
	}
	if failed {
		return txLookupFailed, nil
	}
	return txNotFound, nil
}

// committedResult turns a committed transaction into the execution result, failing if the block rejected it.
func committedResult(logger *log.Logger, res *coretypes.ResultTx, since time.Time) (*BFTExecutionResult, error) {
	if res.TxResult.Code != 0 {
		logger.Printf("❌ [COMETBFT] Transaction failed in block: code=%d log=%s", res.TxResult.Code, res.TxResult.Log)
		return nil, fmt.Errorf("transaction failed in block: code=%d log=%s", res.TxResult.Code, res.TxResult.Log)
	}
	logger.Printf("🎉 [COMETBFT] ValidatorBlock COMMITTED at height=%d hash=%X (elapsed: %v)",
		res.Height, res.Hash, time.Since(since).Round(time.Millisecond))
	return &BFTExecutionResult{
		Height:      res.Height,
		TxHash:      res.Hash,
		BlockHash:   nil,
		CommittedAt: time.Now().UTC(),
	}, nil
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// submitValidatorBlock submits a marshaled ValidatorBlock and waits for it to be admitted and, within
// timing.inclusionPoll, committed.
//
// Returns Height > 0 when the block was observed committed, and Height == 0 when it was admitted to the
// mempool but not yet observed in a block (callers already treat this as pending consensus).
func submitValidatorBlock(ctx context.Context, rpc broadcastRPC, payload []byte, timing broadcastTiming, logger *log.Logger) (*BFTExecutionResult, error) {
	start := time.Now()
	sum := sha256.Sum256(payload)
	txHash := sum[:]

	// The floor for every scan in this call. Anything already committed at or below h0 belongs to an
	// earlier submission of identical bytes, not to this one.
	//
	// A Status that does not answer leaves h0 at 0, which scans the whole cap window instead: costlier,
	// but it can only add history, never hide the block this transaction is in.
	scanning := inclusionScanEnabled()
	var h0 int64
	if scanning {
		var err error
		if h0, err = statusHeight(ctx, rpc, timing.lookupTimeout); err != nil {
			logger.Printf("⚠️ [COMETBFT] Could not read the chain height before broadcasting (%v); "+
				"the inclusion scan will search its whole window", err)
		}
	}
	// One entry per attempt: the height the chain was at when that copy was offered. A failure cannot be
	// final while a copy offered at or after it may still commit.
	var admittedAt []int64
	// A block rejection observed during the submit loop, held back in case a resend still commits.
	var blockFailure *outcome

	deadline := start.Add(timing.submitBudget)
	// The last attempt may start at the deadline and then take a full attempt plus its two lookups; leave the
	// caller's context room for that and for the inclusion poll. (With the production caller's 3-minute
	// context this bound is later than the 2-minute budget, so the budget decides.)
	if dl, ok := ctx.Deadline(); ok {
		reserve := timing.inclusionPoll + timing.attemptTimeout + 2*timing.lookupTimeout
		if d := dl.Add(-reserve); d.Before(deadline) {
			deadline = d
		}
	}
	lastLookup := txNotFound

	logger.Printf("📡 [COMETBFT] Phase 1: Submitting to mempool via BroadcastTxSync...")
submit:
	for attempt := 1; ; attempt++ {
		if scanning {
			// Before the copy is offered, not after: a height read afterwards could already be past the
			// block this copy landed in, which would wrongly make an earlier failure look final.
			if h, err := statusHeight(ctx, rpc, timing.lookupTimeout); err == nil {
				admittedAt = append(admittedAt, h)
			}
		}
		attemptCtx, cancel := context.WithTimeout(ctx, timing.attemptTimeout)
		logger.Printf("📡 [COMETBFT] BroadcastTxSync attempt %d (timeout=%v)...", attempt, timing.attemptTimeout)
		res, err := rpc.BroadcastTxSync(attemptCtx, payload)
		cancel()

		if err == nil {
			logger.Printf("📡 [COMETBFT] BroadcastTxSync returned: hash=%X code=%d", res.Hash, res.Code)
			if res.Code != 0 {
				logger.Printf("❌ [COMETBFT] CheckTx failed: code=%d log=%s", res.Code, res.Log)
				return nil, fmt.Errorf("CheckTx failed: code=%d log=%s", res.Code, res.Log)
			}
			if len(res.Hash) > 0 {
				txHash = res.Hash
			}
			logger.Printf("✅ [COMETBFT] CheckTx passed - transaction in mempool: hash=%X", txHash)
			break
		}

		logger.Printf("⚠️ [COMETBFT] BroadcastTxSync attempt %d failed: %v", attempt, err)

		// A peer broadcasting the SAME canonical block first is not a failure: CometBFT's mempool
		// deduplicates by hash and answers "tx already exists in cache" — the transaction IS queued
		// (2026-09-12, intent ec656887).
		if isAlreadyInMempool(err) {
			logger.Printf("✅ [COMETBFT] Canonical block is already in the mempool (a peer broadcast it first): hash=%X — treating as submitted", txHash)
			break
		}

		if ctx.Err() != nil {
			logger.Printf("❌ [COMETBFT] Context ended, not retrying")
			return nil, fmt.Errorf("BroadcastTxSync: %w", err)
		}

		if !isTransientBroadcastError(err) {
			logger.Printf("❌ [COMETBFT] BroadcastTxSync failed with a non-retryable error: %v", err)
			return nil, fmt.Errorf("BroadcastTxSync: %w", err)
		}

		// A transport error means the REPLY was lost, not that the transaction was. The node may already
		// have admitted it (a commit held CheckTx past the RPC write timeout) or even committed it.
		//
		// The blocks are asked first. The index would answer for whichever copy was indexed last, which
		// after a resend can be a rejected duplicate of a block that committed perfectly well.
		var state txLookup
		if scanning {
			// The mempool answers only "is another copy still pending". The blocks answer everything else.
			// The INDEX answers nothing here: it stores by hash and keeps the last inclusion, so after a
			// resend it reports a rejected duplicate for a block that committed — the false failure itself.
			state = lookupMempoolOnly(ctx, rpc, txHash, timing.lookupTimeout)

			inc, complete, scanErr := scanInclusions(ctx, rpc, txHash, h0, timing)
			if scanErr == nil {
				switch out := resolveOutcome(inc, complete, admittedAt, state == txInMempool); out.kind {
				case outcomeCommittedOK:
					logger.Printf("✅ [COMETBFT] Reply lost (%v) but the ValidatorBlock is committed at height=%d: hash=%X",
						err, out.height, txHash)
					logger.Printf("🎉 [COMETBFT] ValidatorBlock COMMITTED at height=%d hash=%X (elapsed: %v)",
						out.height, txHash, time.Since(start).Round(time.Millisecond))
					return committedAtHeight(txHash, out.height), nil
				case outcomeFailedFinal:
					// REMEMBERED, NOT RETURNED. This copy is dead, but CometBFT removed it from the mempool
					// cache precisely because it was rejected, so identical bytes can be admitted again and
					// the resend may commit — which is the case this whole change exists for. Returning
					// here would reinstate the false failure in a new place. It is reported only once the
					// submit budget is out and no resend can still succeed.
					if blockFailure == nil {
						f := out
						blockFailure = &f
					}
					logger.Printf("⚠️ [COMETBFT] A copy of this ValidatorBlock was rejected in block %d (code=%d); "+
						"it has been evicted from the mempool cache, so the resend may still commit", out.height, out.code)
				}
			}
		} else {
			var committed *coretypes.ResultTx
			state, committed = lookupTxByHash(ctx, rpc, txHash, timing.lookupTimeout)
			if state == txCommitted {
				logger.Printf("✅ [COMETBFT] Reply lost (%v) but the ValidatorBlock is already committed: hash=%X", err, txHash)
				return committedResult(logger, committed, start)
			}
		}

		switch state {
		case txInMempool:
			logger.Printf("✅ [COMETBFT] Reply lost (%v) but the ValidatorBlock is in the mempool: hash=%X", err, txHash)
			break submit
		case txLookupFailed:
			logger.Printf("⚠️ [COMETBFT] Reply lost (%v) and the lookup by hash did not answer; admission unknown: hash=%X", err, txHash)
		}
		lastLookup = state

		if !time.Now().Before(deadline) {
			// The budget is out, so no further copy can be offered and the rejection observed earlier is
			// now the whole story. Report what the chain did, not the transport error that hid it.
			if blockFailure != nil {
				logger.Printf("❌ [COMETBFT] Transaction failed in block: code=%d log=%s",
					blockFailure.code, blockFailure.log)
				return nil, fmt.Errorf("transaction failed in block: code=%d log=%s",
					blockFailure.code, blockFailure.log)
			}
			if lastLookup == txLookupFailed {
				logger.Printf("❌ [COMETBFT] BroadcastTxSync failed after %d attempts over %v; whether the node admitted the transaction could not be determined: %v",
					attempt, time.Since(start).Round(time.Millisecond), err)
				return nil, fmt.Errorf("BroadcastTxSync: %w (admission could not be confirmed after %d attempts: the lookup by hash did not answer)", err, attempt)
			}
			logger.Printf("❌ [COMETBFT] BroadcastTxSync failed after %d attempts over %v; the transaction is neither committed nor in the mempool: %v",
				attempt, time.Since(start).Round(time.Millisecond), err)
			return nil, fmt.Errorf("BroadcastTxSync: %w (not committed and not in the mempool after %d attempts)", err, attempt)
		}

		delay := timing.retryBase
		for i := 1; i < attempt && delay < timing.retryMax; i++ {
			delay *= 2
		}
		if delay > timing.retryMax {
			delay = timing.retryMax
		}
		if remaining := time.Until(deadline); delay > remaining {
			delay = remaining
		}
		logger.Printf("🔄 [COMETBFT] Retrying in %v...", delay)
		if !sleepCtx(ctx, delay) {
			return nil, fmt.Errorf("BroadcastTxSync: %w", errors.Join(err, ctx.Err()))
		}
	}

	// Phase 2: poll for inclusion in a block.
	logger.Printf("⏳ [COMETBFT] Phase 2: Polling for block inclusion (max %v)...", timing.inclusionPoll)
	pollStart := time.Now()
	for {
		if scanning {
			// rpc.Tx is still called, but only as a HINT that something has been indexed; it is never the
			// verdict. The blocks decide.
			_, _ = rpc.Tx(ctx, txHash, false)

			inc, complete, scanErr := scanInclusions(ctx, rpc, txHash, h0, timing)
			if scanErr == nil {
				switch out := resolveOutcome(inc, complete, admittedAt, false); out.kind {
				case outcomeCommittedOK:
					logger.Printf("🎉 [COMETBFT] ValidatorBlock COMMITTED at height=%d hash=%X (elapsed: %v)",
						out.height, txHash, time.Since(pollStart).Round(time.Millisecond))
					return committedAtHeight(txHash, out.height), nil
				case outcomeFailedFinal:
					logger.Printf("❌ [COMETBFT] Transaction failed in block: code=%d log=%s", out.code, out.log)
					return nil, fmt.Errorf("transaction failed in block: code=%d log=%s", out.code, out.log)
				}
			}
		} else if res, err := rpc.Tx(ctx, txHash, false); err == nil && res != nil {
			return committedResult(logger, res, pollStart)
		}
		if time.Since(pollStart) > timing.inclusionPoll || !sleepCtx(ctx, timing.pollInterval) {
			logger.Printf("⚠️ [COMETBFT] Poll timeout - returning with mempool confirmation only")
			logger.Printf("✅ [COMETBFT] Transaction passed CheckTx and is in mempool - consensus will commit it")
			return &BFTExecutionResult{
				Height:      0,
				TxHash:      txHash,
				BlockHash:   nil,
				CommittedAt: time.Now().UTC(),
			}, nil
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────────
// Block-store source for the consensus persister
// ─────────────────────────────────────────────────────────────────────────────────────────────────────

// blockReader is the part of the CometBFT RPC client that reads committed blocks (*cmthttp.HTTP).
type blockReader interface {
	Block(ctx context.Context, height *int64) (*coretypes.ResultBlock, error)
	BlockResults(ctx context.Context, height *int64) (*coretypes.ResultBlockResults, error)
}

// rpcCommittedBlockSource rebuilds a committed block's accepted ValidatorBlocks from this node's block
// store: the block's transactions and time, and the FinalizeBlock result code of each transaction (a
// rejected transaction was never stored by FinalizeBlock, so it is not persisted).
type rpcCommittedBlockSource struct {
	reader  blockReader
	chainID string
}

func (s *rpcCommittedBlockSource) CommittedValidatorBlocks(ctx context.Context, height int64) (*committedBlock, error) {
	h := height
	blk, err := s.reader.Block(ctx, &h)
	if err != nil {
		return nil, classifyBlockStoreError(height, err)
	}
	if blk == nil || blk.Block == nil {
		return nil, fmt.Errorf("height %d: empty block response", height)
	}
	results, err := s.reader.BlockResults(ctx, &h)
	if err != nil {
		return nil, classifyBlockStoreError(height, err)
	}
	if results == nil || len(results.TxsResults) != len(blk.Block.Txs) {
		got := -1
		if results != nil {
			got = len(results.TxsResults)
		}
		return nil, fmt.Errorf("%w: height %d has %d transactions but %d results", errCommittedBlockUnavailable, height, len(blk.Block.Txs), got)
	}

	out := &committedBlock{height: height, time: blk.Block.Header.Time}
	for i, tx := range blk.Block.Txs {
		if results.TxsResults[i] == nil || results.TxsResults[i].Code != 0 {
			continue // rejected by FinalizeBlock
		}
		if _, ok := DecodePolicyUpdate(tx); ok {
			continue // not a ValidatorBlock
		}
		var vb ValidatorBlock
		if err := json.Unmarshal(tx, &vb); err != nil {
			continue // FinalizeBlock would have rejected it; a code-0 result makes this unreachable
		}
		applyCommitMetadata(&vb, height, blk.Block.Header.Time, s.chainID)
		out.blocks = append(out.blocks, vb)
	}
	return out, nil
}

// classifyBlockStoreError marks heights the block store can no longer serve as unavailable (not retried).
func classifyBlockStoreError(height int64, err error) error {
	msg := err.Error()
	if strings.Contains(msg, "is not available, lowest height is") ||
		strings.Contains(msg, "could not find results for height") ||
		strings.Contains(msg, "not persisting finalize block responses") {
		return fmt.Errorf("%w: height %d: %v", errCommittedBlockUnavailable, height, err)
	}
	return fmt.Errorf("height %d: %w", height, err)
}
