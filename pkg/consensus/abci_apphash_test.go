package consensus

import (
	"bytes"
	"context"
	"testing"

	dbm "github.com/cometbft/cometbft-db"
	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/certen/independant-validator/pkg/kvdb"
	"github.com/certen/independant-validator/pkg/ledger"
)

// newInMemLedger builds a LedgerStore backed by an in-memory DB so a "restart" can be
// simulated by constructing a second ValidatorApp over the same store.
func newInMemLedger() *ledger.LedgerStore {
	return ledger.NewLedgerStore(kvdb.NewKVAdapter(dbm.NewMemDB()))
}

// TestAppHashConsistencyAcrossRestart reproduces the assertAppHashEqualsOneFromState
// crash and locks in the fix: the app-hash CometBFT records from ResponseFinalizeBlock.AppHash
// must equal what the app persists in Commit and reports from Info — both during the run and
// after a restart. Before the fix, FinalizeBlock returned an empty AppHash while Commit
// persisted generateAppHash(), so CometBFT's stored app-hash never matched the app's on restart.
func TestAppHashConsistencyAcrossRestart(t *testing.T) {
	ctx := context.Background()
	store := newInMemLedger()
	app := NewValidatorApp(store, "validator-chain-test")

	if _, err := app.InitChain(ctx, &abcitypes.RequestInitChain{ChainId: "validator-chain-test"}); err != nil {
		t.Fatalf("InitChain: %v", err)
	}

	// Height 1: an empty block (no ValidatorBlock txs) — the exact first-after-idle scenario.
	fb, err := app.FinalizeBlock(ctx, &abcitypes.RequestFinalizeBlock{Height: 1, Hash: bytes.Repeat([]byte{0xAB}, 32)})
	if err != nil {
		t.Fatalf("FinalizeBlock: %v", err)
	}
	if len(fb.AppHash) == 0 {
		t.Fatal("FinalizeBlock returned an empty AppHash: CometBFT would record empty and panic " +
			"(assertAppHashEqualsOneFromState) on restart against the app's persisted hash")
	}
	recorded := append([]byte(nil), fb.AppHash...) // what CometBFT stores for height 1

	if _, err := app.Commit(ctx, &abcitypes.RequestCommit{}); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Info during the run must report exactly what CometBFT recorded from FinalizeBlock.
	info, err := app.Info(ctx, &abcitypes.RequestInfo{})
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.LastBlockHeight != 1 {
		t.Fatalf("Info height = %d, want 1", info.LastBlockHeight)
	}
	if !bytes.Equal(info.LastBlockAppHash, recorded) {
		t.Fatalf("in-run app-hash mismatch: Info=%x FinalizeBlock=%x", info.LastBlockAppHash, recorded)
	}

	// Simulate a process RESTART: a fresh ValidatorApp over the SAME persisted ledger
	// (NewValidatorApp auto-restores). CometBFT would reload state.db at height 1 with
	// app-hash == recorded and compare it against this app's Info().
	restarted := NewValidatorApp(store, "validator-chain-test")
	info2, err := restarted.Info(ctx, &abcitypes.RequestInfo{})
	if err != nil {
		t.Fatalf("Info after restart: %v", err)
	}
	if info2.LastBlockHeight != 1 {
		t.Fatalf("post-restart height = %d, want 1", info2.LastBlockHeight)
	}
	if !bytes.Equal(info2.LastBlockAppHash, recorded) {
		t.Fatalf("post-restart app-hash mismatch: Info=%x recorded=%x -> handshake would panic",
			info2.LastBlockAppHash, recorded)
	}
}

// applyBlock stages a block's bundles then promotes (what Commit does), returning the app-hash.
func applyBlock(app *ValidatorApp, bundles []string) []byte {
	staged, seeded := app.stageAccum(bundles)
	app.committedAccum = staged
	app.committedSeeded = seeded
	return appHashFromAccum(staged, seeded)
}

var testBundles = []string{
	"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
	"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
}

// TestAppHashAccumulatorReproducibleAcrossRestart proves the app-hash a node computes after
// restarting mid-chain (seeded from its persisted hash, then folding in the blocks it missed)
// equals the app-hash a node computes having processed every block from genesis.
func TestAppHashAccumulatorReproducibleAcrossRestart(t *testing.T) {
	blocks := [][]string{
		{testBundles[0], testBundles[1]},
		{testBundles[2]},
		{testBundles[3], testBundles[4]},
	}

	// Reference node: applies every block from genesis.
	full := NewValidatorApp(newInMemLedger(), "t")
	var fullHash []byte
	for _, blk := range blocks {
		fullHash = applyBlock(full, blk)
	}

	// Node applies block 0, persists that app-hash, then "restarts": a fresh app seeded from the
	// persisted hash applies only the blocks it missed.
	part := NewValidatorApp(newInMemLedger(), "t")
	persisted := applyBlock(part, blocks[0])

	restarted := NewValidatorApp(newInMemLedger(), "t")
	restarted.seedAccumFromHash(persisted)
	var restartedHash []byte
	for _, blk := range blocks[1:] {
		restartedHash = applyBlock(restarted, blk)
	}

	if !bytes.Equal(restartedHash, fullHash) {
		t.Fatalf("restart-seeded app-hash %x != from-scratch %x", restartedHash, fullHash)
	}
}

// TestStageAccumIdempotentAndPure is the core idempotency guarantee: stageAccum never mutates
// committed state, returns the identical result when called repeatedly (rejected block / blocksync
// retry / handshake replay), and folds duplicate bundle-ids within a block only once.
func TestStageAccumIdempotentAndPure(t *testing.T) {
	app := NewValidatorApp(newInMemLedger(), "t")
	app.seedAccumFromHash(bytes.Repeat([]byte{0x11}, 32)) // non-empty committed state
	before := app.committedAccum
	beforeSeeded := app.committedSeeded

	block := []string{testBundles[0], testBundles[1], testBundles[0]} // note duplicate

	s1, seeded1 := app.stageAccum(block)

	// Purity: committed state untouched by FinalizeBlock-equivalent staging.
	if app.committedAccum != before || app.committedSeeded != beforeSeeded {
		t.Fatal("stageAccum mutated committed state")
	}
	// Idempotency: same inputs -> same output (this is what FinalizeBlock relies on under replay).
	s2, seeded2 := app.stageAccum(block)
	if s1 != s2 || seeded1 != seeded2 {
		t.Fatalf("stageAccum not idempotent: %x/%v vs %x/%v", s1, seeded1, s2, seeded2)
	}
	// Duplicate folded once: staging {a,b,a} == staging {a,b}.
	s3, _ := app.stageAccum([]string{testBundles[0], testBundles[1]})
	if s1 != s3 {
		t.Fatalf("duplicate bundle not deduped within block: %x vs %x", s1, s3)
	}
}

// TestFinalizeWithoutCommitLeavesCommittedUnchanged proves that a block finalized but never
// committed (e.g. rejected during blocksync) does not advance committed state, so the next
// FinalizeBlock for the real next block starts from the correct base (no double-count).
func TestFinalizeWithoutCommitLeavesCommittedUnchanged(t *testing.T) {
	app := NewValidatorApp(newInMemLedger(), "t")

	// Genesis committed state, then finalize a block WITHOUT committing (simulate rejection).
	base := app.committedAccum
	rejected, _ := app.stageAccum([]string{testBundles[0]})
	app.pendingAccum = rejected // FinalizeBlock stages into pending; Commit never runs
	if app.committedAccum != base {
		t.Fatal("committed advanced without Commit")
	}

	// The real next block is the SAME height retried and committed. Staging again from the
	// (still-genesis) committed base yields the correct result, and Commit promotes it once.
	staged, seeded := app.stageAccum([]string{testBundles[0]})
	app.committedAccum, app.committedSeeded = staged, seeded // Commit

	// A from-scratch node that applied exactly one block with testBundles[0] must match.
	ref := NewValidatorApp(newInMemLedger(), "t")
	refHash := applyBlock(ref, []string{testBundles[0]})
	if !bytes.Equal(app.generateAppHash(), refHash) {
		t.Fatalf("post-retry app-hash %x != single-block reference %x", app.generateAppHash(), refHash)
	}
}

// TestFinalizeBlockAppHashMatchesCommit checks byte-identity between the app-hash returned to

// TestFinalizeBlockAppHashMatchesCommit checks byte-identity between the app-hash returned to
// CometBFT in FinalizeBlock and the one persisted in Commit across several sequential blocks.
func TestFinalizeBlockAppHashMatchesCommit(t *testing.T) {
	ctx := context.Background()
	store := newInMemLedger()
	app := NewValidatorApp(store, "validator-chain-test")
	if _, err := app.InitChain(ctx, &abcitypes.RequestInitChain{ChainId: "validator-chain-test"}); err != nil {
		t.Fatalf("InitChain: %v", err)
	}

	for h := int64(1); h <= 5; h++ {
		fb, err := app.FinalizeBlock(ctx, &abcitypes.RequestFinalizeBlock{Height: h, Hash: bytes.Repeat([]byte{0xAB}, 32)})
		if err != nil {
			t.Fatalf("FinalizeBlock h=%d: %v", h, err)
		}
		if _, err := app.Commit(ctx, &abcitypes.RequestCommit{}); err != nil {
			t.Fatalf("Commit h=%d: %v", h, err)
		}
		persisted, err := store.LoadABCIState()
		if err != nil || persisted == nil {
			t.Fatalf("LoadABCIState h=%d: %v", h, err)
		}
		if persisted.LastBlockHeight != h {
			t.Fatalf("persisted height = %d, want %d", persisted.LastBlockHeight, h)
		}
		if !bytes.Equal(persisted.LastBlockAppHash, fb.AppHash) {
			t.Fatalf("h=%d: persisted app-hash %x != FinalizeBlock app-hash %x",
				h, persisted.LastBlockAppHash, fb.AppHash)
		}
	}
}
