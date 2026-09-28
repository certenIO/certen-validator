package consensus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/config"
)

// Blocks at gateNow (2027-01-15) are judged by the v9 rule; beforeV9 is before duplicateOperationRuleFrom.
var beforeV9 = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

func persistedStamp(t *testing.T, app *ValidatorApp) uint64 {
	t.Helper()
	st, err := app.ledgerStore.LoadABCIState()
	if err != nil || st == nil {
		t.Fatalf("ABCI state: %v %v", st, err)
	}
	return st.ExecutionRulesVersion
}

// RB3-F141: a validator's second ValidatorBlock for an operation its block already committed is refused
// from duplicateOperationRuleFrom - in a later block and within one block - and the first commit stays the
// indexed one. Refusing it is a decision only v9 makes, so the state is stamped v9 from that height.
func TestASecondBlockForACommittedOperationIsRefused(t *testing.T) {
	app := newPersistTestApp(t)
	at := time.Unix(gateNow, 0).UTC()
	first := persistTestBlockJSON(t, "op-dup", "G2", "validator-1")
	peer := persistTestBlockJSON(t, "op-dup", "G2", "validator-2")

	_, fb := commitBlock(t, app, nil, 1, at, first, peer)
	if fb.TxResults[0].Code != 0 || fb.TxResults[1].Code != 0 {
		t.Fatalf("each validator's own block for the operation commits: codes %d,%d", fb.TxResults[0].Code, fb.TxResults[1].Code)
	}
	if got := persistedStamp(t, app); got != executionRulesV7 {
		t.Fatalf("stamp %d after blocks every rules version accepts, want v7", got)
	}

	_, fb = commitBlock(t, app, nil, 2, at.Add(time.Second), first)
	if fb.TxResults[0].Code != codeDuplicateOperation {
		t.Fatalf("second commit of validator-1's block for op-dup: code %d, want %d (%s)", fb.TxResults[0].Code, codeDuplicateOperation, fb.TxResults[0].Log)
	}
	if !strings.Contains(fb.TxResults[0].Log, "at height 1") {
		t.Fatalf("the refusal does not name the first commit: %s", fb.TxResults[0].Log)
	}
	if got := persistedStamp(t, app); got != executionRulesV9 {
		t.Fatalf("stamp %d after a v9-only refusal, want v9", got)
	}

	// Within one block: the first is accepted, the second refused.
	other := persistTestBlockJSON(t, "op-once", "G1", "validator-3")
	_, fb = commitBlock(t, app, nil, 3, at.Add(2*time.Second), other, other)
	if fb.TxResults[0].Code != 0 || fb.TxResults[1].Code != codeDuplicateOperation {
		t.Fatalf("same block twice: codes %d,%d", fb.TxResults[0].Code, fb.TxResults[1].Code)
	}

	rec, upTo, err := app.CommittedOperation("validator-1", "op-dup")
	if err != nil || rec == nil || rec.Height != 1 || upTo != 3 || rec.BundleID != bundleOf(t, first) {
		t.Fatalf("index: %+v up to %d, %v; want height 1, covering 3", rec, upTo, err)
	}
	sum := sha256.Sum256(first)
	if rec.TxHash != strings.ToUpper(hex.EncodeToString(sum[:])) {
		t.Fatalf("indexed tx %s is not the committed transaction's hash", rec.TxHash)
	}
}

// Before duplicateOperationRuleFrom the chain accepted a second block, and replaying that history must
// accept it again: the rule changes nothing there, and the state stays stamped with the older rules.
func TestBeforeTheRuleASecondBlockIsAcceptedAsHistoryWas(t *testing.T) {
	app := newPersistTestApp(t)
	b := persistTestBlockJSON(t, "op-hist", "G2", "validator-1")
	commitBlock(t, app, nil, 1, beforeV9, b)
	_, fb := commitBlock(t, app, nil, 2, beforeV9.Add(time.Minute), b)
	if fb.TxResults[0].Code != 0 {
		t.Fatalf("a pre-v9 second commit is refused: code %d (%s)", fb.TxResults[0].Code, fb.TxResults[0].Log)
	}
	if got := persistedStamp(t, app); got != executionRulesV7 {
		t.Fatalf("stamp %d, want v7: nothing here needs v9", got)
	}
	if rec, _, err := app.CommittedOperation("validator-1", "op-hist"); err != nil || rec == nil || rec.Height != 1 {
		t.Fatalf("the first commit is the indexed one: %+v %v", rec, err)
	}
}

// A block CometBFT hands to FinalizeBlock again - a handshake replay after a crash between the index write
// and the state save - is the same commit, not a second one.
func TestAReplayedBlockIsNotItsOwnDuplicate(t *testing.T) {
	app := newPersistTestApp(t)
	at := time.Unix(gateNow, 0).UTC()
	b := persistTestBlockJSON(t, "op-replay", "G2", "validator-1")
	commitBlock(t, app, nil, 1, at, b)
	app.latestHeight = 0 // the state save did not happen; the index write did
	_, fb := commitBlock(t, app, nil, 1, at, b)
	if fb.TxResults[0].Code != 0 {
		t.Fatalf("replayed block refused as its own duplicate: code %d (%s)", fb.TxResults[0].Code, fb.TxResults[0].Log)
	}
}

// RB3-F140: a block naming no validator used to be given the chain's name before the invariants ran, which
// made "validator_id must not be empty" unreachable. It is refused, and because v8 would have accepted it,
// that is a v9 decision.
func TestABlockNamingNoValidatorIsRefused(t *testing.T) {
	app := newPersistTestApp(t)
	_, fb := commitBlock(t, app, nil, 1, time.Unix(gateNow, 0).UTC(), persistTestBlockJSON(t, "op-anon", "G2", ""))
	if fb.TxResults[0].Code != 2 || !strings.Contains(fb.TxResults[0].Log, "validator_id must not be empty") {
		t.Fatalf("code %d (%s), want 2: validator_id must not be empty", fb.TxResults[0].Code, fb.TxResults[0].Log)
	}
	if got := persistedStamp(t, app); got != executionRulesV9 {
		t.Fatalf("stamp %d, want v9: v8 accepted this block", got)
	}
}

// RB3-F144: every ABCI state write carries the rules stamp. Without it the next start adopted whatever its
// binary implemented, which is the replay the stamp exists to refuse.
func TestShutdownAndResetKeepTheRulesStamp(t *testing.T) {
	app := newPersistTestApp(t)
	commitBlock(t, app, nil, 1, time.Unix(gateNow, 0).UTC(), persistTestBlockJSON(t, "op-anon", "G2", ""))
	if err := app.Shutdown(); err != nil {
		t.Fatal(err)
	}
	if got := persistedStamp(t, app); got != executionRulesV9 {
		t.Fatalf("stamp after Shutdown %d, want v9", got)
	}
	if err := app.ForceResetState(1, []byte("reset_state")); err == nil {
		t.Fatal("a reset to an app hash CometBFT never recorded was accepted")
	}
	hash := make([]byte, 32)
	hash[0] = 7
	if err := app.ForceResetState(1, hash); err != nil {
		t.Fatal(err)
	}
	if got := persistedStamp(t, app); got != executionRulesV9 {
		t.Fatalf("stamp after ForceResetState %d, want v9", got)
	}
}

// The proposer's side (RB3-F141): asked before anything is broadcast, the index answers from committed state.
// The same bundle is the committed block at its height; a different bundle for the operation is refused by
// name; no engine start and no broadcast either way.
func TestBroadcastAnswersACommittedOperationWithoutBroadcasting(t *testing.T) {
	app := newPersistTestApp(t)
	at := time.Unix(gateNow, 0).UTC()
	tx := persistTestBlockJSON(t, "op-seen", "G2", "validator-1")
	commitBlock(t, app, nil, 1, at, tx)
	engine := &RealCometBFTEngine{app: app, logger: persistQuietLog}

	vb := decodeBlock(t, tx)
	res, err := engine.BroadcastValidatorBlockCommit(context.Background(), vb)
	if err != nil || res.Height != 1 || !res.CommittedAt.Equal(at) {
		t.Fatalf("committed block: %+v, %v; want height 1 at %s", res, err, at)
	}
	sum := sha256.Sum256(tx)
	if hex.EncodeToString(res.TxHash) != hex.EncodeToString(sum[:]) {
		t.Fatalf("tx %x is not the committed transaction", res.TxHash)
	}

	rebuilt := decodeBlock(t, persistTestBlockJSON(t, "op-seen", "G1", "validator-1"))
	if _, err := engine.BroadcastValidatorBlockCommit(context.Background(), rebuilt); !errors.Is(err, ErrOperationCommittedAsAnotherBlock) {
		t.Fatalf("a different bundle for a committed operation: %v", err)
	}
}

// The index answers only for the chain it covers.
func TestTheIndexRefusesToAnswerForHeightsItDoesNotCover(t *testing.T) {
	app := newPersistTestApp(t)
	commitBlock(t, app, nil, 1, time.Unix(gateNow, 0).UTC(), persistTestBlockJSON(t, "op-cov", "G2", "validator-1"))
	app.latestHeight = 5
	if _, _, err := app.CommittedOperation("validator-1", "op-cov"); !errors.Is(err, ErrCommittedOperationsUnavailable) {
		t.Fatalf("answered for heights 2-5 it never read: %v", err)
	}
}

func decodeBlock(t *testing.T, tx []byte) *ValidatorBlock {
	t.Helper()
	var vb ValidatorBlock
	if err := json.Unmarshal(tx, &vb); err != nil {
		t.Fatal(err)
	}
	return &vb
}

// fakeHistory is a committed chain held in memory.
type fakeHistory struct {
	base   int64
	blocks map[int64][][]byte
	times  map[int64]time.Time
	codes  map[int64][]uint32
}

func (h *fakeHistory) Base() int64 { return h.base }
func (h *fakeHistory) Height() int64 {
	top := int64(0)
	for k := range h.blocks {
		if k > top {
			top = k
		}
	}
	return top
}
func (h *fakeHistory) Block(height int64) ([][]byte, time.Time, error) {
	b, ok := h.blocks[height]
	if !ok {
		return nil, time.Time{}, fmt.Errorf("no block %d", height)
	}
	return b, h.times[height], nil
}
func (h *fakeHistory) ResultCodes(height int64) ([]uint32, error) { return h.codes[height], nil }

func historyApp(t *testing.T, height int64) *ValidatorApp {
	t.Helper()
	app := newPersistTestApp(t)
	app.latestHeight = height
	return app
}

// A node indexes the chain it committed before the index existed, and refuses to start on history v9 would
// decide differently - checked on every node, not assumed.
func TestCommittedHistoryIsIndexedAndCheckedAgainstV9(t *testing.T) {
	a := persistTestBlockJSON(t, "op-h1", "G2", "validator-1")
	b := persistTestBlockJSON(t, "op-h2", "G2", "validator-2")
	policy := []byte(fmt.Sprintf(`{"kind":%q}`, PolicyUpdateKind))
	h := &fakeHistory{base: 1,
		blocks: map[int64][][]byte{1: {a, policy}, 2: {b, a}, 3: {}},
		times:  map[int64]time.Time{1: beforeV9, 2: beforeV9.Add(time.Hour), 3: beforeV9.Add(2 * time.Hour)},
		codes:  map[int64][]uint32{1: {0, 0}, 2: {0, 0}, 3: {}},
	}
	app := historyApp(t, 3)
	if err := app.IndexCommittedHistory(h); err != nil {
		t.Fatalf("history before the rule, with its second commit: %v", err)
	}
	if rec, upTo, err := app.CommittedOperation("validator-1", "op-h1"); err != nil || rec == nil || rec.Height != 1 || upTo != 3 {
		t.Fatalf("indexed %+v up to %d, %v", rec, upTo, err)
	}
	// Indexed once: a second run reads nothing.
	h.blocks = nil
	if err := app.IndexCommittedHistory(h); err != nil {
		t.Fatalf("re-index read blocks again: %v", err)
	}

	cases := map[string]*fakeHistory{
		"a second commit after the rule": {base: 1,
			blocks: map[int64][][]byte{1: {a}, 2: {a}},
			times:  map[int64]time.Time{1: time.Unix(gateNow, 0), 2: time.Unix(gateNow+1, 0)},
			codes:  map[int64][]uint32{1: {0}, 2: {0}}},
		"a block naming no validator, accepted": {base: 1,
			blocks: map[int64][][]byte{1: {persistTestBlockJSON(t, "op-anon", "G2", "")}, 2: {}},
			times:  map[int64]time.Time{1: beforeV9, 2: beforeV9},
			codes:  map[int64][]uint32{1: {0}, 2: {}}},
	}
	for name, hist := range cases {
		if err := historyApp(t, 2).IndexCommittedHistory(hist); !errors.Is(err, ErrCommittedHistoryUnderV9) {
			t.Fatalf("%s: %v", name, err)
		}
	}

	// A block store that no longer holds the heights to index, or whose results do not match its blocks.
	if err := historyApp(t, 2).IndexCommittedHistory(&fakeHistory{base: 2, blocks: map[int64][][]byte{2: {}}}); err == nil {
		t.Fatal("indexed from a pruned block store")
	}
	if err := historyApp(t, 1).IndexCommittedHistory(&fakeHistory{base: 1, blocks: map[int64][][]byte{1: {a}},
		times: map[int64]time.Time{1: beforeV9}, codes: map[int64][]uint32{1: {}}}); err == nil {
		t.Fatal("indexed a block whose results do not match its transactions")
	}
}

// A chain whose genesis starts above height 1 has no blocks below it, and its index starts there.
func TestTheIndexStartsAtTheGenesisInitialHeight(t *testing.T) {
	app := newPersistTestApp(t)
	if _, err := app.InitChain(context.Background(), &abcitypes.RequestInitChain{InitialHeight: 100}); err != nil {
		t.Fatal(err)
	}
	commitBlock(t, app, nil, 100, time.Unix(gateNow, 0).UTC(), persistTestBlockJSON(t, "op-g", "G2", "validator-1"))
	app.latestHeight = 100
	if rec, upTo, err := app.CommittedOperation("validator-1", "op-g"); err != nil || rec == nil || upTo != 100 {
		t.Fatalf("%+v up to %d, %v", rec, upTo, err)
	}
}

// RB3-F146: v7 judged a tick (and a rotation) as a ValidatorBlock and refused it with code 2; v8 accepts a
// tick. Result codes are hashed into the next header, so a chain that committed one is not v7 history,
// rotation or not - and a history backfill that finds one records it the same way.
func TestATickMakesTheStateV8(t *testing.T) {
	app := newPersistTestApp(t)
	tick := []byte(fmt.Sprintf(`{"kind":%q,"nonce":"0011223344556677"}`, ChainTickKind))
	_, fb := commitBlock(t, app, nil, 1, beforeV9, tick)
	if fb.TxResults[0].Code != 0 {
		t.Fatalf("tick: code %d (%s)", fb.TxResults[0].Code, fb.TxResults[0].Log)
	}
	if got := persistedStamp(t, app); got != executionRulesV8 {
		t.Fatalf("stamp %d after a committed tick, want v8", got)
	}

	hist := historyApp(t, 1)
	if err := hist.IndexCommittedHistory(&fakeHistory{base: 1, blocks: map[int64][][]byte{1: {tick}},
		times: map[int64]time.Time{1: beforeV9}, codes: map[int64][]uint32{1: {0}}}); err != nil {
		t.Fatal(err)
	}
	if hist.committedRulesVersion() != executionRulesV8 {
		t.Fatalf("history with a tick is stamped v%d, want v8", hist.committedRulesVersion())
	}
}

// The mempool does not admit a block for a committed operation once the rule is in force.
func TestTheMempoolRefusesABlockForACommittedOperation(t *testing.T) {
	app := newPersistTestApp(t)
	tx := persistTestBlockJSON(t, "op-mem", "G2", "validator-1")
	commitBlock(t, app, nil, 1, time.Unix(gateNow, 0).UTC(), tx)
	defer func(c func() time.Time) { checkTxClock = c }(checkTxClock)

	checkTxClock = func() time.Time { return duplicateOperationRuleFrom.Add(-time.Hour) }
	if res, _ := app.CheckTx(context.Background(), &abcitypes.RequestCheckTx{Tx: tx}); res.Code == codeDuplicateOperation {
		t.Fatalf("refused before the rule: %s", res.Log)
	}
	checkTxClock = func() time.Time { return duplicateOperationRuleFrom }
	if res, _ := app.CheckTx(context.Background(), &abcitypes.RequestCheckTx{Tx: tx}); res.Code != codeDuplicateOperation {
		t.Fatalf("admitted: code %d (%s)", res.Code, res.Log)
	}
	if res, _ := app.CheckTx(context.Background(), &abcitypes.RequestCheckTx{Tx: persistTestBlockJSON(t, "op-mem", "G2", "validator-2")}); res.Code == codeDuplicateOperation {
		t.Fatalf("another validator's block for the operation refused: %s", res.Log)
	}
}

// RB3-F97: the node never serves CometBFT's gRPC broadcast API (GO-2026-6443 has no released fix).
func TestTheCometBFTGRPCServerIsNeverServed(t *testing.T) {
	cfg := config.DefaultConfig()
	if cfg.RPC.GRPCListenAddress != "" {
		t.Fatalf("CometBFT's default serves gRPC at %q", cfg.RPC.GRPCListenAddress)
	}
	cfg.RPC.GRPCListenAddress = "tcp://127.0.0.1:36658"
	if _, err := NewRealCometBFTEngine(cfg, newPersistTestApp(t), persistQuietLog); err == nil || !strings.Contains(err.Error(), "GO-2026-6443") {
		t.Fatalf("a gRPC listen address was accepted: %v", err)
	}
}
