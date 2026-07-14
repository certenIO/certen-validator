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
	// Seed a committed app-hash (as if VBs were committed earlier) so the empty block below carries a
	// non-nil hash. Empty blocks legitimately leave the app-hash UNCHANGED (see
	// TestEmptyBlockDoesNotChangeAppHash); this test checks FinalizeBlock/Commit/Info agree + survive
	// restart on that stable hash.
	app.seedAppHash(bytes.Repeat([]byte{0x22}, 32))

	if _, err := app.InitChain(ctx, &abcitypes.RequestInitChain{ChainId: "validator-chain-test"}); err != nil {
		t.Fatalf("InitChain: %v", err)
	}

	// Height 1: an empty block (no ValidatorBlock txs) — must carry the unchanged committed hash.
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
	staged := app.stageAppHash(bundles)
	app.committedAppHash = staged
	return staged
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
	restarted.seedAppHash(persisted)
	var restartedHash []byte
	for _, blk := range blocks[1:] {
		restartedHash = applyBlock(restarted, blk)
	}

	if !bytes.Equal(restartedHash, fullHash) {
		t.Fatalf("restart-seeded app-hash %x != from-scratch %x", restartedHash, fullHash)
	}
}

// TestStageAppHashIdempotentAndPure is the core idempotency guarantee: stageAppHash never mutates
// committed state, returns the identical result when called repeatedly (rejected block / blocksync
// retry / handshake replay), dedups duplicate bundle-ids within a block, and is order-independent
// within a block (bundles are sorted). Output is always a 32-byte SHA256.
func TestStageAppHashIdempotentAndPure(t *testing.T) {
	app := NewValidatorApp(newInMemLedger(), "t")
	app.seedAppHash(bytes.Repeat([]byte{0x11}, 32)) // non-empty committed head
	before := append([]byte(nil), app.committedAppHash...)

	block := []string{testBundles[0], testBundles[1], testBundles[0]} // note duplicate

	s1 := app.stageAppHash(block)
	if len(s1) != 32 {
		t.Fatalf("app-hash must be 32 bytes, got %d", len(s1))
	}
	// Purity: committed state untouched.
	if !bytes.Equal(app.committedAppHash, before) {
		t.Fatal("stageAppHash mutated committed state")
	}
	// Idempotency: same inputs -> same output (what FinalizeBlock relies on under replay).
	if s2 := app.stageAppHash(block); !bytes.Equal(s1, s2) {
		t.Fatalf("stageAppHash not idempotent: %x vs %x", s1, s2)
	}
	// Duplicate deduped: {a,b,a} == {a,b}.
	if s3 := app.stageAppHash([]string{testBundles[0], testBundles[1]}); !bytes.Equal(s1, s3) {
		t.Fatalf("duplicate not deduped: %x vs %x", s1, s3)
	}
	// Order-independent within a block (sorted): {a,b} == {b,a}.
	if s4 := app.stageAppHash([]string{testBundles[1], testBundles[0]}); !bytes.Equal(s1, s4) {
		t.Fatalf("not order-independent within block: %x vs %x", s1, s4)
	}
}

// TestFinalizeWithoutCommitLeavesCommittedUnchanged proves a block finalized but never committed
// (rejected during blocksync) does not advance committed state, so the retried+committed block
// matches a from-scratch reference (no double-count / no corruption).
func TestFinalizeWithoutCommitLeavesCommittedUnchanged(t *testing.T) {
	app := NewValidatorApp(newInMemLedger(), "t")
	base := append([]byte(nil), app.committedAppHash...) // nil at genesis

	app.pendingAppHash = app.stageAppHash([]string{testBundles[0]}) // FinalizeBlock, no Commit
	if !bytes.Equal(app.committedAppHash, base) {
		t.Fatal("committed advanced without Commit")
	}

	// Retry the same block and commit.
	staged := app.stageAppHash([]string{testBundles[0]})
	app.committedAppHash = staged // Commit

	ref := NewValidatorApp(newInMemLedger(), "t")
	refHash := applyBlock(ref, []string{testBundles[0]})
	if !bytes.Equal(app.generateAppHash(), refHash) {
		t.Fatalf("post-retry app-hash %x != single-block reference %x", app.generateAppHash(), refHash)
	}
}

// TestAppHashCommitsToOrderAndCount is the integrity improvement over XOR: the SAME bundles grouped
// into different blocks yield DIFFERENT app-hashes (the chain commits to per-block grouping / order),
// and a one-bundle block differs from an empty block. XOR-of-bundle-ids would collide in both cases.
func TestAppHashCommitsToOrderAndCount(t *testing.T) {
	// {A},{B} across two blocks vs {A,B} in one block — XOR gives base^A^B either way.
	two := NewValidatorApp(newInMemLedger(), "t")
	applyBlock(two, []string{testBundles[0]})
	twoHash := applyBlock(two, []string{testBundles[1]})

	one := NewValidatorApp(newInMemLedger(), "t")
	oneHash := applyBlock(one, []string{testBundles[0], testBundles[1]})

	if bytes.Equal(twoHash, oneHash) {
		t.Fatal("two blocks {A},{B} collided with one block {A,B} — chain must commit to grouping")
	}

	// A single-bundle block must differ from an empty block.
	nonEmpty := NewValidatorApp(newInMemLedger(), "t")
	neHash := applyBlock(nonEmpty, []string{testBundles[0]})
	empty := NewValidatorApp(newInMemLedger(), "t")
	eHash := applyBlock(empty, []string{})
	if bytes.Equal(neHash, eHash) {
		t.Fatal("single-bundle block collided with empty block")
	}
}

// TestFinalizeBlockAppHashMatchesCommit checks byte-identity between the app-hash returned to

// TestEmptyBlockDoesNotChangeAppHash is the guard against the empty/timed-block runaway: an empty
// block (no VBs) MUST leave the app-hash unchanged. If it advanced the hash, CometBFT's
// needProofBlock rule (with create_empty_blocks=false) would emit an endless stream of empty blocks.
func TestEmptyBlockDoesNotChangeAppHash(t *testing.T) {
	app := NewValidatorApp(newInMemLedger(), "t")
	applyBlock(app, []string{testBundles[0]}) // commit a real VB
	h1 := append([]byte(nil), app.committedAppHash...)

	// Several empty blocks must all yield the SAME app-hash as h1.
	for i := 0; i < 3; i++ {
		if h := applyBlock(app, []string{}); !bytes.Equal(h, h1) {
			t.Fatalf("empty block %d changed app-hash %x -> %x (would cause endless empty blocks)", i, h1, h)
		}
	}
	// A subsequent real VB must still advance the hash (chain not frozen).
	if h := applyBlock(app, []string{testBundles[1]}); bytes.Equal(h, h1) {
		t.Fatal("real VB after empty blocks did not advance the app-hash")
	}
}

// TestFinalizeBlockAppHashMatchesCommit checks byte-identity between the app-hash returned to
// CometBFT in FinalizeBlock and the one persisted in Commit across several sequential blocks.
func TestFinalizeBlockAppHashMatchesCommit(t *testing.T) {
	ctx := context.Background()
	store := newInMemLedger()
	app := NewValidatorApp(store, "validator-chain-test")
	if _, err := app.InitChain(ctx, &abcitypes.RequestInitChain{ChainId: "validator-chain-test"}); err != nil {
		t.Fatalf("InitChain: %v", err)
	}
	// Seed a committed hash so these (empty) blocks carry a stable non-nil app-hash — empty blocks
	// leave the hash unchanged; this test checks FinalizeBlock's AppHash == the value Commit persists.
	app.seedAppHash(bytes.Repeat([]byte{0x33}, 32))

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
