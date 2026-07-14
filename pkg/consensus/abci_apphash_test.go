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

// TestAppHashAccumulatorReproducibleAcrossRestart proves the app-hash a node computes after
// restarting mid-chain (seeded from its persisted hash, then folding in the blocks it missed)
// equals the app-hash a node computes having processed every block from genesis. Without the
// seeded accumulator a restarted node recomputes wrong hashes from an empty map and cannot catch up.
func TestAppHashAccumulatorReproducibleAcrossRestart(t *testing.T) {
	bundles := []string{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
	}

	// Reference: one node folds in every bundle from genesis.
	full := NewValidatorApp(newInMemLedger(), "t")
	for _, b := range bundles {
		full.xorBundleIntoAccum(b)
	}
	fullHash := full.generateAppHash()

	// Node processes the first two, persists that app-hash, then "restarts": a fresh app seeded
	// from the persisted hash folds in only the blocks it missed.
	part := NewValidatorApp(newInMemLedger(), "t")
	part.xorBundleIntoAccum(bundles[0])
	part.xorBundleIntoAccum(bundles[1])
	persisted := part.generateAppHash()

	restarted := NewValidatorApp(newInMemLedger(), "t")
	restarted.seedAccumFromHash(persisted)
	restarted.xorBundleIntoAccum(bundles[2])
	restarted.xorBundleIntoAccum(bundles[3])

	if !bytes.Equal(restarted.generateAppHash(), fullHash) {
		t.Fatalf("restart-seeded app-hash %x != from-scratch %x", restarted.generateAppHash(), fullHash)
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
