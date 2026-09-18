package consensus

// The inclusion scan, tested against the REAL CometBFT pieces it has to agree with.
//
// The defect being fixed is a claim about CometBFT's own semantics: that a rejected transaction leaves the
// mempool cache and can be resubmitted, and that the node's indexer overwrites by hash so the LAST
// inclusion wins. A fake of those two things would only encode the assumption. So the tests below drive
// mempool.LRUTxCache and kv.TxIndex — the actual types the node uses — and assert that the scan disagrees
// with the index exactly where the index is wrong.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	dbm "github.com/cometbft/cometbft-db"
	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/mempool"
	coretypes "github.com/cometbft/cometbft/rpc/core/types"
	"github.com/cometbft/cometbft/state/txindex"
	"github.com/cometbft/cometbft/state/txindex/kv"
	cmttypes "github.com/cometbft/cometbft/types"
)

// ─────────────────────────────────────────────────────────────────────────────────────────────────────
// The four block-reading methods, derived from the state fakeCometRPC already models.
//
// Defined here rather than in bft_broadcast_confirm_test.go so that file — and the thirteen tests that
// pin the 2026-09-15 lost-reply fix — stays untouched.
// ─────────────────────────────────────────────────────────────────────────────────────────────────────

// latestHeightLocked is where the chain has got to: the commit height once the transaction has committed,
// one below it before. Callers hold f.mu.
func (f *fakeCometRPC) latestHeightLocked() int64 {
	if f.height == 0 {
		return 0
	}
	if f.committed() {
		return f.height
	}
	return f.height - 1
}

func (f *fakeCometRPC) txsAtLocked(height int64) []cmttypes.Tx {
	if f.height != 0 && height == f.height && f.committed() {
		return []cmttypes.Tx{cmttypes.Tx(testPayload)}
	}
	return nil
}

func (f *fakeCometRPC) Status(ctx context.Context) (*coretypes.ResultStatus, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return &coretypes.ResultStatus{
		SyncInfo: coretypes.SyncInfo{LatestBlockHeight: f.latestHeightLocked()},
	}, nil
}

func (f *fakeCometRPC) BlockchainInfo(ctx context.Context, minHeight, maxHeight int64) (*coretypes.ResultBlockchainInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	out := &coretypes.ResultBlockchainInfo{LastHeight: f.latestHeightLocked()}
	// CometBFT returns metas newest-first; mirror that so the scan cannot depend on receiving them sorted.
	for h := maxHeight; h >= minHeight; h-- {
		txs := f.txsAtLocked(h)
		out.BlockMetas = append(out.BlockMetas, &cmttypes.BlockMeta{
			Header: cmttypes.Header{Height: h},
			NumTxs: len(txs),
		})
	}
	return out, nil
}

func (f *fakeCometRPC) Block(ctx context.Context, height *int64) (*coretypes.ResultBlock, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	h := int64(0)
	if height != nil {
		h = *height
	}
	blk := &cmttypes.Block{Header: cmttypes.Header{Height: h}}
	blk.Data.Txs = f.txsAtLocked(h)
	return &coretypes.ResultBlock{Block: blk}, nil
}

func (f *fakeCometRPC) BlockResults(ctx context.Context, height *int64) (*coretypes.ResultBlockResults, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	h := int64(0)
	if height != nil {
		h = *height
	}
	out := &coretypes.ResultBlockResults{Height: h}
	for range f.txsAtLocked(h) {
		out.TxsResults = append(out.TxsResults, &abcitypes.ExecTxResult{Code: f.txCode, Log: "fictional"})
	}
	return out, nil
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────────
// A scriptable chain, for the scenarios the derived fake cannot express
// ─────────────────────────────────────────────────────────────────────────────────────────────────────

type scriptedTx struct {
	tx   cmttypes.Tx
	code uint32
	log  string
}

// scriptedChain is a chain written out block by block, with per-height failures so an unreadable block or
// an unreadable result set can be planted exactly where a test needs it.
type scriptedChain struct {
	tip    int64
	blocks map[int64][]scriptedTx

	statusErr  error
	infoErr    error
	blockErr   map[int64]error
	resultsErr map[int64]error

	// mempool is consulted by UnconfirmedTxs.
	mempool []cmttypes.Tx

	// indexed is what rpc.Tx answers: the node's transaction index, which stores by hash and is
	// overwritten by the LAST inclusion. Setting it to a failure while the blocks hold a success is the
	// production defect exactly, and is what stops anything from quietly trusting the index again.
	indexed *coretypes.ResultTx

	broadcastReply func(attempt int) (*coretypes.ResultBroadcastTx, error)
	broadcasts     int

	blockReads int
	infoReads  int
	txReads    int
}

func (s *scriptedChain) BroadcastTxSync(ctx context.Context, tx cmttypes.Tx) (*coretypes.ResultBroadcastTx, error) {
	s.broadcasts++
	if s.broadcastReply != nil {
		return s.broadcastReply(s.broadcasts)
	}
	return &coretypes.ResultBroadcastTx{Code: 0, Hash: tx.Hash()}, nil
}

func (s *scriptedChain) Tx(ctx context.Context, hash []byte, prove bool) (*coretypes.ResultTx, error) {
	s.txReads++
	if s.indexed != nil {
		return s.indexed, nil
	}
	return nil, fmt.Errorf("tx (%X) not found", hash)
}

func (s *scriptedChain) UnconfirmedTxs(ctx context.Context, limit *int) (*coretypes.ResultUnconfirmedTxs, error) {
	return &coretypes.ResultUnconfirmedTxs{Count: len(s.mempool), Txs: s.mempool}, nil
}

func (s *scriptedChain) Status(ctx context.Context) (*coretypes.ResultStatus, error) {
	if s.statusErr != nil {
		return nil, s.statusErr
	}
	return &coretypes.ResultStatus{SyncInfo: coretypes.SyncInfo{LatestBlockHeight: s.tip}}, nil
}

func (s *scriptedChain) BlockchainInfo(ctx context.Context, minHeight, maxHeight int64) (*coretypes.ResultBlockchainInfo, error) {
	s.infoReads++
	if s.infoErr != nil {
		return nil, s.infoErr
	}
	out := &coretypes.ResultBlockchainInfo{LastHeight: s.tip}
	for h := maxHeight; h >= minHeight; h-- {
		out.BlockMetas = append(out.BlockMetas, &cmttypes.BlockMeta{
			Header: cmttypes.Header{Height: h},
			NumTxs: len(s.blocks[h]),
		})
	}
	return out, nil
}

func (s *scriptedChain) Block(ctx context.Context, height *int64) (*coretypes.ResultBlock, error) {
	h := *height
	s.blockReads++
	if err := s.blockErr[h]; err != nil {
		return nil, err
	}
	blk := &cmttypes.Block{Header: cmttypes.Header{Height: h}}
	for _, st := range s.blocks[h] {
		blk.Data.Txs = append(blk.Data.Txs, st.tx)
	}
	return &coretypes.ResultBlock{Block: blk}, nil
}

func (s *scriptedChain) BlockResults(ctx context.Context, height *int64) (*coretypes.ResultBlockResults, error) {
	h := *height
	if err := s.resultsErr[h]; err != nil {
		return nil, err
	}
	out := &coretypes.ResultBlockResults{Height: h}
	for _, st := range s.blocks[h] {
		out.TxsResults = append(out.TxsResults, &abcitypes.ExecTxResult{Code: st.code, Log: st.log})
	}
	return out, nil
}

func scanTiming() broadcastTiming {
	t := fastTiming()
	t.maxScanBlocks = 200
	return t
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────────
// The CometBFT semantics this fix depends on — asserted against the real types
// ─────────────────────────────────────────────────────────────────────────────────────────────────────

// The premise of the whole change, part 1: a committed transaction the block REJECTED is dropped from the
// mempool cache, so identical bytes can be admitted again. If this ever stops being true, a resend could
// not produce a second copy and the defect would not exist.
func TestRejectedTxLeavesTheRealMempoolCacheAndCanBeResubmitted(t *testing.T) {
	cache := mempool.NewLRUTxCache(100)
	tx := cmttypes.Tx(testPayload)

	if !cache.Push(tx) {
		t.Fatal("the cache refused a transaction it had never seen")
	}
	if cache.Push(tx) {
		t.Fatal("the cache admitted the same transaction twice while it was still cached")
	}

	// What clist_mempool does in Update() for a non-OK result when KeepInvalidTxsInCache is false.
	cache.Remove(tx)

	if cache.Has(tx) {
		t.Fatal("a rejected transaction is still in the cache")
	}
	if !cache.Push(tx) {
		t.Fatal("identical bytes could not be admitted again after rejection — the premise of this fix is gone")
	}
}

// The premise, part 2: the node indexes through AddBatch, which sets by hash unconditionally. A FAILED
// duplicate at a later height therefore overwrites the record of the block that succeeded — which is
// exactly why rpc.Tx cannot be the verdict.
func TestRealIndexerLetsAFailedDuplicateOverwriteASuccess(t *testing.T) {
	idx := kv.NewTxIndex(dbm.NewMemDB())
	tx := cmttypes.Tx(testPayload)
	hash := tx.Hash()

	okAt := &abcitypes.TxResult{
		Height: 100, Index: 0, Tx: tx,
		Result: abcitypes.ExecTxResult{Code: abcitypes.CodeTypeOK},
	}
	failedAt := &abcitypes.TxResult{
		Height: 101, Index: 0, Tx: tx,
		Result: abcitypes.ExecTxResult{Code: 7, Log: "fictional rejection"},
	}

	// The IndexerService path: AddBatch, once per block.
	first := txindex.NewBatch(1)
	if err := first.Add(okAt); err != nil {
		t.Fatal(err)
	}
	if err := idx.AddBatch(first); err != nil {
		t.Fatal(err)
	}
	second := txindex.NewBatch(1)
	if err := second.Add(failedAt); err != nil {
		t.Fatal(err)
	}
	if err := idx.AddBatch(second); err != nil {
		t.Fatal(err)
	}

	got, err := idx.Get(hash)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("the index lost the transaction entirely")
	}
	if got.Result.Code == abcitypes.CodeTypeOK {
		t.Skip("this CometBFT build keeps the successful result in AddBatch; the scan is then belt and braces")
	}
	if got.Height != 101 || got.Result.Code != 7 {
		t.Fatalf("index returned height=%d code=%d, want the later failure (101, 7)", got.Height, got.Result.Code)
	}
	// This is the false failure: the block at 100 committed this ValidatorBlock, and the index says it
	// failed at 101. Everything below exists so the broadcaster does not believe it.
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────────
// A1–A8
// ─────────────────────────────────────────────────────────────────────────────────────────────────────

// A1 — the defect. Copy 1 is rejected at H, the resend is admitted and commits OK at H+1. The verdict is
// the success, not the rejection the index would report.
func TestA1ResendCommittedAfterARejectionIsASuccess(t *testing.T) {
	tx := cmttypes.Tx(testPayload)
	chain := &scriptedChain{
		tip: 101,
		blocks: map[int64][]scriptedTx{
			100: {{tx: tx, code: 7, log: "rejected by a policy activation"}},
			101: {{tx: tx, code: 0}},
		},
	}
	inc, complete, err := scanInclusions(context.Background(), chain, tx.Hash(), 99, scanTiming())
	if err != nil {
		t.Fatal(err)
	}
	if len(inc) != 2 || !complete {
		t.Fatalf("inclusions=%+v complete=%t, want both copies and a complete scan", inc, complete)
	}
	if inc[0].Height != 100 || inc[1].Height != 101 {
		t.Fatalf("inclusions are not in commit order: %+v", inc)
	}
	out := resolveOutcome(inc, complete, []int64{99, 100}, false)
	if out.kind != outcomeCommittedOK || out.height != 101 {
		t.Fatalf("outcome = %+v, want committed OK at 101 — this is the false failure the fix removes", out)
	}
}

// A2 — both copies rejected, nothing in flight: a real failure, citing the later height.
func TestA2BothCopiesRejectedIsAFailureAtTheLaterHeight(t *testing.T) {
	tx := cmttypes.Tx(testPayload)
	chain := &scriptedChain{
		tip: 101,
		blocks: map[int64][]scriptedTx{
			100: {{tx: tx, code: 7, log: "first"}},
			101: {{tx: tx, code: 9, log: "second"}},
		},
	}
	inc, complete, err := scanInclusions(context.Background(), chain, tx.Hash(), 99, scanTiming())
	if err != nil {
		t.Fatal(err)
	}
	out := resolveOutcome(inc, complete, []int64{99, 100}, false)
	if out.kind != outcomeFailedFinal || out.height != 101 || out.code != 9 {
		t.Fatalf("outcome = %+v, want a final failure at 101 with code 9", out)
	}
}

// A3 — OK at H, then a failed duplicate at H+1 overwrites the index. The success stands.
func TestA3AFailedDuplicateAfterASuccessDoesNotChangeTheVerdict(t *testing.T) {
	tx := cmttypes.Tx(testPayload)
	chain := &scriptedChain{
		tip: 101,
		blocks: map[int64][]scriptedTx{
			100: {{tx: tx, code: 0}},
			101: {{tx: tx, code: 7, log: "duplicate rejected"}},
		},
	}
	inc, complete, err := scanInclusions(context.Background(), chain, tx.Hash(), 99, scanTiming())
	if err != nil {
		t.Fatal(err)
	}
	out := resolveOutcome(inc, complete, nil, false)
	if out.kind != outcomeCommittedOK || out.height != 100 {
		t.Fatalf("outcome = %+v, want committed OK at 100 — the first success wins", out)
	}
}

// A4 — an inclusion at or below h0 belongs to an earlier submission and must be ignored.
func TestA4InclusionsAtOrBelowTheFloorAreNotThisSubmission(t *testing.T) {
	tx := cmttypes.Tx(testPayload)
	chain := &scriptedChain{
		tip: 100,
		blocks: map[int64][]scriptedTx{
			99:  {{tx: tx, code: 0}}, // an identical submission from before this call
			100: {},
		},
	}
	inc, complete, err := scanInclusions(context.Background(), chain, tx.Hash(), 99, scanTiming())
	if err != nil {
		t.Fatal(err)
	}
	if len(inc) != 0 {
		t.Fatalf("inclusions = %+v, want none: height 99 is at the floor", inc)
	}
	if out := resolveOutcome(inc, complete, nil, false); out.kind != outcomePending {
		t.Fatalf("outcome = %+v, want pending", out)
	}
}

// A5 — the block is readable but its results are not. The transaction IS in that block and its outcome is
// unknown, so the scan is incomplete and the verdict is unknown: never "not found".
func TestA5UnreadableResultsGiveUnknownNotAbsence(t *testing.T) {
	tx := cmttypes.Tx(testPayload)
	chain := &scriptedChain{
		tip:        100,
		blocks:     map[int64][]scriptedTx{100: {{tx: tx, code: 0}}},
		resultsErr: map[int64]error{100: errors.New("could not find results for height 100")},
	}
	inc, complete, err := scanInclusions(context.Background(), chain, tx.Hash(), 99, scanTiming())
	if err != nil {
		t.Fatal(err)
	}
	if complete {
		t.Fatal("a scan that could not read a block's results reported itself complete")
	}
	if out := resolveOutcome(inc, complete, nil, false); out.kind != outcomeUnknown {
		t.Fatalf("outcome = %+v, want unknown", out)
	}
}

// A5b — the block itself cannot be read. Same rule.
func TestA5bUnreadableBlockGivesUnknownNotAbsence(t *testing.T) {
	tx := cmttypes.Tx(testPayload)
	chain := &scriptedChain{
		tip:      100,
		blocks:   map[int64][]scriptedTx{100: {{tx: tx, code: 0}}},
		blockErr: map[int64]error{100: errors.New("height 100 is not available, lowest height is 500")},
	}
	_, complete, err := scanInclusions(context.Background(), chain, tx.Hash(), 99, scanTiming())
	if err != nil {
		t.Fatal(err)
	}
	if complete {
		t.Fatal("a scan that could not read a block reported itself complete")
	}
}

// A6 — Status errors. The scan fails cleanly; it does not crash and does not claim an empty chain.
func TestA6StatusFailureIsALookupFailureNotAnEmptyChain(t *testing.T) {
	tx := cmttypes.Tx(testPayload)
	chain := &scriptedChain{tip: 100, statusErr: errors.New("fictional: node unreachable")}
	inc, complete, err := scanInclusions(context.Background(), chain, tx.Hash(), 99, scanTiming())
	if err == nil {
		t.Fatal("a failed Status was not reported as an error")
	}
	if complete {
		t.Fatal("a scan that never learned the chain tip reported itself complete")
	}
	if len(inc) != 0 {
		t.Fatalf("inclusions = %+v, want none", inc)
	}
}

// A7 — empty blocks between inclusions are skipped without being fetched. BlockchainInfo says how many
// transactions a block holds; fetching the empty ones would multiply the RPC cost of every scan.
func TestA7EmptyBlocksAreSkippedWithoutBeingFetched(t *testing.T) {
	tx := cmttypes.Tx(testPayload)
	blocks := map[int64][]scriptedTx{}
	for h := int64(101); h <= 140; h++ {
		blocks[h] = nil // empty
	}
	blocks[140] = []scriptedTx{{tx: tx, code: 0}}
	chain := &scriptedChain{tip: 140, blocks: blocks}

	inc, complete, err := scanInclusions(context.Background(), chain, tx.Hash(), 100, scanTiming())
	if err != nil {
		t.Fatal(err)
	}
	if !complete || len(inc) != 1 || inc[0].Height != 140 {
		t.Fatalf("inclusions=%+v complete=%t, want the single inclusion at 140", inc, complete)
	}
	if chain.blockReads != 1 {
		t.Fatalf("fetched %d blocks, want 1 — the 39 empty blocks must be skipped", chain.blockReads)
	}
}

// A8 — the scan is bounded. A huge gap between the floor and the tip must not read the whole chain, and
// the truncated result must be reported as incomplete rather than as absence.
func TestA8ScanIsCappedAndReportsItselfIncomplete(t *testing.T) {
	tx := cmttypes.Tx(testPayload)
	timing := scanTiming()
	timing.maxScanBlocks = 40
	chain := &scriptedChain{tip: 100000, blocks: map[int64][]scriptedTx{}}

	start := time.Now()
	inc, complete, err := scanInclusions(context.Background(), chain, tx.Hash(), 1, timing)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if complete {
		t.Fatal("a capped scan reported itself complete; absence would then be believed")
	}
	if len(inc) != 0 {
		t.Fatalf("inclusions = %+v", inc)
	}
	// 40 blocks at 20 per BlockchainInfo call.
	if chain.infoReads != 2 {
		t.Fatalf("BlockchainInfo called %d times, want 2 — the cap is not being applied", chain.infoReads)
	}
	if out := resolveOutcome(inc, complete, nil, false); out.kind != outcomeUnknown {
		t.Fatalf("outcome = %+v, want unknown", out)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("a capped scan took %v", elapsed)
	}
}

// The cap keeps the MOST RECENT window: the inclusion being looked for is the one that just happened, so
// truncating the old end is right and truncating the new end would miss it every time.
func TestCappedScanKeepsTheMostRecentWindow(t *testing.T) {
	tx := cmttypes.Tx(testPayload)
	timing := scanTiming()
	timing.maxScanBlocks = 20
	chain := &scriptedChain{
		tip:    1000,
		blocks: map[int64][]scriptedTx{1000: {{tx: tx, code: 0}}},
	}
	inc, _, err := scanInclusions(context.Background(), chain, tx.Hash(), 1, timing)
	if err != nil {
		t.Fatal(err)
	}
	if len(inc) != 1 || inc[0].Height != 1000 {
		t.Fatalf("inclusions = %+v, want the inclusion at the tip", inc)
	}
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────────
// resolveOutcome's rules, stated directly
// ─────────────────────────────────────────────────────────────────────────────────────────────────────

// A failure is NOT final while a copy offered at or after it may still commit. Calling it final there is
// the false-failure defect in a new costume.
func TestAFailureIsNotFinalWhileALaterCopyMayStillCommit(t *testing.T) {
	inc := []inclusion{{Height: 100, Code: 7}}

	if out := resolveOutcome(inc, true, []int64{100}, false); out.kind != outcomePending {
		t.Fatalf("outcome = %+v, want pending: an attempt was offered at the failing height", out)
	}
	if out := resolveOutcome(inc, true, []int64{101}, false); out.kind != outcomePending {
		t.Fatalf("outcome = %+v, want pending: an attempt was offered after the failure", out)
	}
	if out := resolveOutcome(inc, true, []int64{99}, true); out.kind != outcomePending {
		t.Fatalf("outcome = %+v, want pending: a copy is still in the mempool", out)
	}
	if out := resolveOutcome(inc, false, []int64{99}, false); out.kind != outcomePending {
		t.Fatalf("outcome = %+v, want pending, not a final failure from an incomplete scan", out)
	}
	if out := resolveOutcome(inc, true, []int64{99}, false); out.kind != outcomeFailedFinal {
		t.Fatalf("outcome = %+v, want a final failure once nothing can still succeed", out)
	}
}

// An OK inclusion wins regardless of anything else — mempool copies, later failures, an incomplete scan.
// Once these bytes are in a block with code 0 the ValidatorBlock is in the chain.
func TestAnOKInclusionWinsUnconditionally(t *testing.T) {
	inc := []inclusion{{Height: 100, Code: 7}, {Height: 101, Code: 0}, {Height: 102, Code: 9}}
	for _, complete := range []bool{true, false} {
		for _, inMempool := range []bool{true, false} {
			out := resolveOutcome(inc, complete, []int64{99, 100, 101}, inMempool)
			if out.kind != outcomeCommittedOK || out.height != 101 {
				t.Fatalf("complete=%t inMempool=%t: outcome = %+v, want committed OK at 101",
					complete, inMempool, out)
			}
		}
	}
}

func TestNoInclusionsAndACompleteScanIsPending(t *testing.T) {
	if out := resolveOutcome(nil, true, []int64{99}, false); out.kind != outcomePending {
		t.Fatalf("outcome = %+v, want pending", out)
	}
	if out := resolveOutcome(nil, false, []int64{99}, false); out.kind != outcomeUnknown {
		t.Fatalf("outcome = %+v, want unknown from an incomplete scan", out)
	}
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────────
// End to end through submitValidatorBlock
// ─────────────────────────────────────────────────────────────────────────────────────────────────────

// The whole defect, driven through the real entry point: the reply is lost, copy 1 was rejected, the
// resend committed. The broadcaster must report success.
func TestSubmitReportsSuccessWhenAResendCommittedAfterARejection(t *testing.T) {
	tx := cmttypes.Tx(testPayload)
	chain := &scriptedChain{
		tip:    99,
		blocks: map[int64][]scriptedTx{},
	}
	chain.broadcastReply = func(n int) (*coretypes.ResultBroadcastTx, error) {
		switch n {
		case 1:
			// Copy 1 is admitted and then rejected at 100; the reply is lost.
			chain.blocks[100] = []scriptedTx{{tx: tx, code: 7, log: "rejected by a policy activation"}}
			chain.tip = 100
			return nil, eofErr
		default:
			// The resend is admitted and commits OK at 101.
			chain.blocks[101] = []scriptedTx{{tx: tx, code: 0}}
			chain.tip = 101
			return ok()
		}
	}

	res, err := submitValidatorBlock(context.Background(), chain, testPayload, scanTiming(), broadcastQuietLog)
	if err != nil {
		t.Fatalf("a committed ValidatorBlock was reported as failed: %v", err)
	}
	if res.Height != 101 {
		t.Fatalf("height = %d, want 101", res.Height)
	}
}

// THE PRODUCTION DEFECT, END TO END.
//
// The blocks say this ValidatorBlock committed OK at 100. The index says it failed at 101, because a
// rejected duplicate was indexed afterwards and AddBatch stores by hash unconditionally. Anything that
// consults rpc.Tx for the verdict returns a false failure here; only the blocks give the right answer.
//
// This is the test that catches "use the rpc.Tx result directly", which the scan-only tests cannot: they
// never see an index that answers WRONGLY, only one that answers "not found".
func TestTheIndexLyingAboutAFailureDoesNotOverrideTheBlocks(t *testing.T) {
	tx := cmttypes.Tx(testPayload)
	// The chain starts BELOW the blocks in question, as it does in production: h0 is read before the
	// first broadcast, and both inclusions happen after it.
	chain := &scriptedChain{tip: 99, blocks: map[int64][]scriptedTx{}}
	chain.broadcastReply = func(int) (*coretypes.ResultBroadcastTx, error) {
		chain.blocks[100] = []scriptedTx{{tx: tx, code: 0}}
		chain.blocks[101] = []scriptedTx{{tx: tx, code: 7, log: "duplicate rejected"}}
		chain.tip = 101
		// What kv.TxIndex.Get returns after the second AddBatch: the later FAILURE.
		chain.indexed = &coretypes.ResultTx{
			Hash:     tx.Hash(),
			Height:   101,
			TxResult: abcitypes.ExecTxResult{Code: 7, Log: "duplicate rejected"},
		}
		return ok()
	}

	res, err := submitValidatorBlock(context.Background(), chain, testPayload, scanTiming(), broadcastQuietLog)
	if err != nil {
		t.Fatalf("the index's stale failure was believed over the block that committed: %v", err)
	}
	if res.Height != 100 {
		t.Fatalf("height = %d, want 100 — the block that actually committed this ValidatorBlock", res.Height)
	}
}

// The same shape in the lost-reply path: the reply is lost, the index reports the later rejection, and
// the blocks hold the success.
func TestTheIndexLyingDuringALostReplyDoesNotOverrideTheBlocks(t *testing.T) {
	tx := cmttypes.Tx(testPayload)
	chain := &scriptedChain{tip: 99, blocks: map[int64][]scriptedTx{}}
	chain.broadcastReply = func(int) (*coretypes.ResultBroadcastTx, error) {
		chain.blocks[100] = []scriptedTx{{tx: tx, code: 0}}
		chain.blocks[101] = []scriptedTx{{tx: tx, code: 7, log: "duplicate rejected"}}
		chain.tip = 101
		chain.indexed = &coretypes.ResultTx{
			Hash:     tx.Hash(),
			Height:   101,
			TxResult: abcitypes.ExecTxResult{Code: 7, Log: "duplicate rejected"},
		}
		return nil, eofErr // the reply is lost
	}

	res, err := submitValidatorBlock(context.Background(), chain, testPayload, scanTiming(), broadcastQuietLog)
	if err != nil {
		t.Fatalf("lost reply + a lying index produced a false failure: %v", err)
	}
	if res.Height != 100 {
		t.Fatalf("height = %d, want 100", res.Height)
	}
}

// The reverse must still work: a genuine rejection with nothing in flight is still a failure.
func TestSubmitStillReportsAGenuineRejection(t *testing.T) {
	tx := cmttypes.Tx(testPayload)
	chain := &scriptedChain{tip: 99, blocks: map[int64][]scriptedTx{}}
	chain.broadcastReply = func(n int) (*coretypes.ResultBroadcastTx, error) {
		chain.blocks[100] = []scriptedTx{{tx: tx, code: 7, log: "fictional invariant violation"}}
		chain.tip = 100
		return ok()
	}
	_, err := submitValidatorBlock(context.Background(), chain, testPayload, scanTiming(), broadcastQuietLog)
	if err == nil || !strings.Contains(err.Error(), "transaction failed in block: code=7") {
		t.Fatalf("err = %v, want the block rejection", err)
	}
}

// Nothing committed within the window is still pending, not a failure: the caller treats Height 0 as
// "admitted, consensus will commit it".
func TestSubmitReturnsPendingWhenNothingCommitsInTheWindow(t *testing.T) {
	chain := &scriptedChain{tip: 99, blocks: map[int64][]scriptedTx{}}
	res, err := submitValidatorBlock(context.Background(), chain, testPayload, scanTiming(), broadcastQuietLog)
	if err != nil {
		t.Fatalf("err = %v, want a pending result", err)
	}
	if res.Height != 0 {
		t.Fatalf("height = %d, want 0 (admitted, not yet committed)", res.Height)
	}
}

// D1 — the happy path resolves quickly and cheaply.
func TestD1HappyPathIsFastAndCheap(t *testing.T) {
	tx := cmttypes.Tx(testPayload)
	chain := &scriptedChain{tip: 99, blocks: map[int64][]scriptedTx{}}
	chain.broadcastReply = func(int) (*coretypes.ResultBroadcastTx, error) {
		chain.blocks[100] = []scriptedTx{{tx: tx, code: 0}}
		chain.tip = 100
		return ok()
	}

	start := time.Now()
	res, err := submitValidatorBlock(context.Background(), chain, testPayload, scanTiming(), broadcastQuietLog)
	elapsed := time.Since(start)
	if err != nil || res.Height != 100 {
		t.Fatalf("res=%+v err=%v, want committed at 100", res, err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("took %v, want under 2s", elapsed)
	}
	if chain.blockReads > 3 {
		t.Fatalf("read %d blocks for a one-block-later commit", chain.blockReads)
	}
}

// The escape hatch has to actually work: with INCLUSION_SCAN=off nothing scans.
func TestInclusionScanCanBeTurnedOff(t *testing.T) {
	if !inclusionScanEnabled() {
		t.Fatal("the scan is not on by default")
	}
	t.Setenv("INCLUSION_SCAN", "off")
	if inclusionScanEnabled() {
		t.Fatal("INCLUSION_SCAN=off did not disable the scan")
	}
	t.Setenv("INCLUSION_SCAN", "on")
	if !inclusionScanEnabled() {
		t.Fatal("INCLUSION_SCAN=on disabled the scan")
	}
}

func TestInclusionScanOffUsesTheIndexPath(t *testing.T) {
	t.Setenv("INCLUSION_SCAN", "off")
	chain := &scriptedChain{tip: 99, blocks: map[int64][]scriptedTx{}}
	res, err := submitValidatorBlock(context.Background(), chain, testPayload, scanTiming(), broadcastQuietLog)
	if err != nil || res.Height != 0 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if chain.infoReads != 0 || chain.blockReads != 0 {
		t.Fatalf("scanned with INCLUSION_SCAN=off: info=%d blocks=%d", chain.infoReads, chain.blockReads)
	}
}
