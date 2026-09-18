package consensus

// Decide a broadcast from committed blocks, not from the transaction index.
//
// WHY THE INDEX CANNOT DECIDE
//
// Verified against CometBFT v0.38.0:
//
//   - A committed transaction with a NON-ZERO code is REMOVED from the mempool cache unless
//     KeepInvalidTxsInCache is set (mempool/clist_mempool.go: "Allow invalid transactions to be
//     resubmitted"). It defaults to false and every engine builder here takes config.DefaultConfig(), so
//     identical bytes can be admitted a second time.
//   - The node's IndexerService indexes through TxIndex.AddBatch, which does Set(hash, …) unconditionally —
//     the source comments it "index by hash (always)". LAST INCLUSION WINS, IN BOTH DIRECTIONS.
//     (TxIndex.Index has a keep-the-successful-result rule. The node does not use that path. Do not rely
//     on it.)
//
// So within one submitValidatorBlock call, copy 1 can be rejected at height H, copy 2 admitted and
// committed OK at H+1, and a poll of rpc.Tx reads copy 1's failure — reporting a committed ValidatorBlock
// as failed. The realistic trigger is an entitlement policy activation landing between the two blocks;
// most other FinalizeBlock rejections are deterministic and cannot flip.
//
// The reverse — a false SUCCESS through the index — is not possible: an OK record can only exist if these
// exact bytes committed OK, and each attempt's bytes are unique per second because the builder stamps
// Timestamp = time.Now().
//
// WHAT THIS DOES
//
// Records the chain height before the first broadcast and scans the committed blocks above it for every
// inclusion of the hash, with its code. The first OK inclusion is the verdict, whatever a later copy did.
// A failure is final only when the scan was complete, no copy is still in the mempool, and no attempt was
// admitted at or after that failure. Anything unreadable makes the scan incomplete, which is reported as
// unknown and never as absence.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	cmttypes "github.com/cometbft/cometbft/types"
)

// inclusion is one appearance of the transaction in a committed block.
type inclusion struct {
	Height int64
	Code   uint32
	Log    string
}

// inclusionScanEnabled reports whether outcomes are decided from committed blocks.
//
// Default ON. INCLUSION_SCAN=off restores the previous index-based path for one release, because turning
// off a path that decides whether a target-chain side effect executes deserves a way back that does not
// need a rebuild. Nothing here touches ABCI, the app hash or FinalizeBlock — it changes only how a node
// observes its own submission — so a rolling deploy is safe and mixed versions are fine.
func inclusionScanEnabled() bool {
	return !strings.EqualFold(strings.TrimSpace(os.Getenv("INCLUSION_SCAN")), "off")
}

// requireBFTCommit reports whether an intent may proceed on a ValidatorBlock that was not observed
// committed.
//
// DEFAULT: NO. Until 2026-09 the default was yes — the flag was opt-in and was set on no validator in the
// fleet — so whenever the inclusion poll timed out, a target-chain side effect executed on a block that
// had only passed CheckTx. CheckTx is one node's opinion; it is not agreement. Nothing then re-checked
// whether the block ever committed.
//
// Failing closed is cheap because the failure is RETRYABLE: the intent is requeued and succeeds on the
// next pass once consensus commits. And with the inclusion scan deciding outcomes from committed blocks,
// the pending window closes far more often than it used to, so this should rarely trigger at all.
//
// REQUIRE_BFT_COMMIT=false restores the old permissive behaviour for one release.
func requireBFTCommit() bool {
	return !strings.EqualFold(strings.TrimSpace(os.Getenv("REQUIRE_BFT_COMMIT")), "false")
}

// LogConsensusSafetyMode states, once at startup, which way both switches are set.
//
// Both change whether a side effect can execute on an unproven block, and a default that is only visible
// by reading the source is a default nobody has chosen.
func LogConsensusSafetyMode(logf func(string, ...interface{})) {
	if logf == nil {
		return
	}
	if inclusionScanEnabled() {
		logf("✅ [CONSENSUS] Broadcast outcomes are decided from committed blocks (INCLUSION_SCAN on)")
	} else {
		logf("⚠️ [CONSENSUS] INCLUSION_SCAN=off — outcomes come from the transaction index, which reports " +
			"the LAST inclusion of a hash and can therefore report a committed ValidatorBlock as failed")
	}
	if requireBFTCommit() {
		logf("✅ [CONSENSUS] A ValidatorBlock must be observed committed before any target-chain side effect")
	} else {
		logf("⚠️ [CONSENSUS] REQUIRE_BFT_COMMIT=false — a side effect may execute on a ValidatorBlock that " +
			"was never proven committed")
	}
}

// blockchainInfoPageSize is CometBFT's hard limit for one BlockchainInfo call (rpc/core/blocks.go).
const blockchainInfoPageSize = 20

// defaultMaxScanBlocks bounds one scan. At ~1 block/second this is several minutes of history, far more
// than the inclusion window, and it keeps a pathological gap between h0 and the tip from running the
// caller's context out.
const defaultMaxScanBlocks = 200

// scanInclusions returns every inclusion of hash in (fromHeight, tip], oldest first.
//
// `complete` reports whether the whole range was actually read. An unreadable block, an unreadable result
// set, or a range longer than the scan cap makes it false. CALLERS MUST NOT READ ABSENCE FROM AN
// INCOMPLETE SCAN: "I could not look" and "it is not there" are different facts, and conflating them is
// the defect this file exists to remove.
func scanInclusions(
	ctx context.Context,
	rpc broadcastRPC,
	hash []byte,
	fromHeight int64,
	timing broadcastTiming,
) ([]inclusion, bool, error) {
	sctx, scancel := context.WithTimeout(ctx, timing.lookupTimeout)
	status, err := rpc.Status(sctx)
	scancel()
	if err != nil || status == nil {
		// Not knowing where the chain ends is a lookup failure, not an empty chain.
		return nil, false, fmt.Errorf("reading node status: %w", err)
	}
	tip := status.SyncInfo.LatestBlockHeight
	if tip <= fromHeight {
		// Nothing has committed since the floor. That IS a complete answer about this range.
		return nil, true, nil
	}

	first := fromHeight + 1
	complete := true
	limit := timing.maxScanBlocks
	if limit <= 0 {
		limit = defaultMaxScanBlocks
	}
	if tip-first+1 > int64(limit) {
		// Scan the MOST RECENT window: the inclusion being looked for is the one that just happened.
		// The range is truncated, so the scan is not complete and absence proves nothing.
		first = tip - int64(limit) + 1
		complete = false
	}

	var found []inclusion
	for start := first; start <= tip; start += blockchainInfoPageSize {
		end := start + blockchainInfoPageSize - 1
		if end > tip {
			end = tip
		}

		bctx, bcancel := context.WithTimeout(ctx, timing.lookupTimeout)
		info, err := rpc.BlockchainInfo(bctx, start, end)
		bcancel()
		if err != nil || info == nil {
			// This slice of the range is unknown. Keep whatever was already found — an inclusion that was
			// read is still a fact — but the scan can no longer establish absence.
			complete = false
			continue
		}

		for _, meta := range info.BlockMetas {
			if meta == nil || meta.NumTxs == 0 {
				continue // an empty block cannot contain the transaction; never fetch it
			}
			inc, ok := inclusionInBlock(ctx, rpc, hash, meta.Header.Height, timing)
			if !ok {
				complete = false
				continue
			}
			if inc != nil {
				found = append(found, *inc)
			}
		}
	}

	// BlockchainInfo returns its metas newest-first, and a partly-failed scan can leave gaps, so the
	// order is imposed here rather than assumed. Every rule below is stated in commit order.
	sortInclusionsByHeight(found)
	return found, complete, nil
}

// inclusionInBlock reads one block and reports whether the hash is in it. ok=false means the block or its
// results could not be read, which is not the same as the transaction not being there.
func inclusionInBlock(
	ctx context.Context,
	rpc broadcastRPC,
	hash []byte,
	height int64,
	timing broadcastTiming,
) (*inclusion, bool) {
	h := height
	bctx, bcancel := context.WithTimeout(ctx, timing.lookupTimeout)
	blk, err := rpc.Block(bctx, &h)
	bcancel()
	if err != nil || blk == nil || blk.Block == nil {
		return nil, false
	}

	idx := -1
	for i, tx := range blk.Block.Txs {
		if bytes.Equal(cmttypes.Tx(tx).Hash(), hash) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, true // read successfully; the transaction is genuinely not in this block
	}

	rctx, rcancel := context.WithTimeout(ctx, timing.lookupTimeout)
	results, err := rpc.BlockResults(rctx, &h)
	rcancel()
	if err != nil || results == nil || idx >= len(results.TxsResults) || results.TxsResults[idx] == nil {
		// The transaction IS in this block but its outcome is unknown. Reporting that as "not included"
		// would be a lie in the dangerous direction, so the scan is marked incomplete instead.
		return nil, false
	}
	r := results.TxsResults[idx]
	return &inclusion{Height: height, Code: r.Code, Log: r.Log}, true
}

func sortInclusionsByHeight(in []inclusion) {
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && in[j].Height < in[j-1].Height; j-- {
			in[j], in[j-1] = in[j-1], in[j]
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────────
// Deciding
// ─────────────────────────────────────────────────────────────────────────────────────────────────────

type outcomeKind int

const (
	outcomeUnknown     outcomeKind = iota // the scan could not establish what happened
	outcomePending                        // nothing committed yet, and something may still
	outcomeCommittedOK                    // an OK inclusion was observed
	outcomeFailedFinal                    // a failure that nothing can still overturn
)

type outcome struct {
	kind   outcomeKind
	height int64
	code   uint32
	log    string
}

// resolveOutcome turns observed inclusions into a verdict.
//
//   - FIRST OK WINS. Once these exact bytes committed with code 0, the ValidatorBlock is in the chain at
//     that height. A later duplicate that FinalizeBlock rejected overwrites the index entry but changes
//     nothing about the earlier block, so it must not change the verdict.
//   - A FAILURE IS FINAL ONLY IF NOTHING CAN STILL SUCCEED: the scan was complete, no copy is waiting in
//     the mempool, and no attempt was admitted at or after the failing height. Otherwise a resend is still
//     in flight and the caller keeps waiting.
//   - AN INCOMPLETE SCAN IS NEVER ABSENCE.
func resolveOutcome(inc []inclusion, complete bool, admittedAt []int64, inMempool bool) outcome {
	for _, i := range inc {
		if i.Code == 0 {
			return outcome{kind: outcomeCommittedOK, height: i.Height}
		}
	}

	if len(inc) > 0 {
		last := inc[len(inc)-1]
		if complete && !inMempool && !admittedAtOrAfter(admittedAt, last.Height) {
			return outcome{kind: outcomeFailedFinal, height: last.Height, code: last.Code, log: last.Log}
		}
		// A failure exists but a later copy may still commit: keep waiting rather than declaring defeat.
		return outcome{kind: outcomePending}
	}

	if !complete {
		return outcome{kind: outcomeUnknown}
	}
	return outcome{kind: outcomePending}
}

func admittedAtOrAfter(admittedAt []int64, height int64) bool {
	for _, h := range admittedAt {
		if h >= height {
			return true
		}
	}
	return false
}

// committedAtHeight builds the success result for an inclusion found by scanning. The scan gives the
// height and the hash; there is no ResultTx to carry.
func committedAtHeight(hash []byte, height int64) *BFTExecutionResult {
	return &BFTExecutionResult{
		Height:      height,
		TxHash:      append([]byte(nil), hash...),
		BlockHash:   nil,
		CommittedAt: time.Now().UTC(),
	}
}

// statusHeight reads the chain tip, used to floor a scan.
//
// A failure returns 0 with the error. A caller that floors at 0 scans its whole cap window rather than
// skipping history: losing the floor costs RPC calls, whereas guessing one too high would silently ignore
// the block the transaction is in.
func statusHeight(ctx context.Context, rpc broadcastRPC, timeout time.Duration) (int64, error) {
	sctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	st, err := rpc.Status(sctx)
	if err != nil || st == nil {
		return 0, fmt.Errorf("reading node status: %w", err)
	}
	return st.SyncInfo.LatestBlockHeight, nil
}
