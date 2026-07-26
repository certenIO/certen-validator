package consensus

import (
	"context"
	"log"
	"os"
	"testing"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/certen/independant-validator/pkg/ledger"
)

// Info() answers CometBFT's handshake. If it reports height 0 on a node that
// has actually committed blocks, CometBFT replays from genesis — and once the
// block store has been pruned, that replay is impossible and the node can
// never start again:
//
//	error on replay: app block height (0) is too far below block store base (4)
//
// That took the entire validator set down on a routine restart. `latestHeight`
// is in-memory and always 0 in a fresh process, so Info() MUST restore it from
// the ledger, which is the durable record of what this app committed.

// memKV is the smallest thing satisfying ledger.KV, so the recovery path can
// be exercised without a real database.
type memKV struct{ m map[string][]byte }

func newMemKV() *memKV { return &memKV{m: map[string][]byte{}} }

func (k *memKV) Get(key []byte) ([]byte, error) { return k.m[string(key)], nil }
func (k *memKV) Set(key, value []byte) error {
	k.m[string(key)] = append([]byte(nil), value...)
	return nil
}

func newTestApp(t *testing.T, store *ledger.LedgerStore) *ValidatorApp {
	t.Helper()
	return &ValidatorApp{
		logger:      log.New(os.Stderr, "[test] ", 0),
		ledgerStore: store,
	}
}

func TestInfoRestoresHeightFromLedgerAfterRestart(t *testing.T) {
	store := ledger.NewLedgerStore(newMemKV())
	appHash := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}
	if err := store.SaveABCIState(&ledger.ABCIState{
		LastBlockHeight:  104,
		LastBlockAppHash: appHash,
	}); err != nil {
		t.Fatalf("seeding ledger state: %v", err)
	}

	// Fresh process: memory height is 0, exactly as after a container restart.
	app := newTestApp(t, store)

	resp, err := app.Info(context.Background(), &abcitypes.RequestInfo{})
	if err != nil {
		t.Fatalf("Info returned error: %v", err)
	}

	if resp.LastBlockHeight != 104 {
		t.Errorf("LastBlockHeight = %d, want 104 — reporting 0 forces a replay that a pruned store cannot serve",
			resp.LastBlockHeight)
	}
	if string(resp.LastBlockAppHash) != string(appHash) {
		t.Errorf("LastBlockAppHash = %x, want %x", resp.LastBlockAppHash, appHash)
	}
}

func TestInfoDoesNotRewindAheadOfMemory(t *testing.T) {
	store := ledger.NewLedgerStore(newMemKV())
	if err := store.SaveABCIState(&ledger.ABCIState{LastBlockHeight: 10}); err != nil {
		t.Fatalf("seeding ledger state: %v", err)
	}

	app := newTestApp(t, store)
	app.latestHeight = 42 // already ahead in this process

	resp, err := app.Info(context.Background(), &abcitypes.RequestInfo{})
	if err != nil {
		t.Fatalf("Info returned error: %v", err)
	}
	if resp.LastBlockHeight != 42 {
		t.Errorf("LastBlockHeight = %d, want 42 — a stale ledger read must never rewind a live app",
			resp.LastBlockHeight)
	}
}

func TestInfoOnGenuinelyFreshNodeReportsZero(t *testing.T) {
	app := newTestApp(t, ledger.NewLedgerStore(newMemKV()))

	resp, err := app.Info(context.Background(), &abcitypes.RequestInfo{})
	if err != nil {
		t.Fatalf("Info returned error: %v", err)
	}
	if resp.LastBlockHeight != 0 {
		t.Errorf("LastBlockHeight = %d, want 0 for a node that has committed nothing", resp.LastBlockHeight)
	}
}
