package consensus

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	dbm "github.com/cometbft/cometbft-db"
	abcitypes "github.com/cometbft/cometbft/abci/types"
	sm "github.com/cometbft/cometbft/state"
	"github.com/cometbft/cometbft/store"
	"github.com/cometbft/cometbft/types"

	"github.com/certen/independant-validator/pkg/ledger"
)

// BenchmarkHistoryRecheckOf2861Blocks times the one-time re-check a binary with new history checks runs at startup, on a
// ledger the size certen-testnet's was when PR #106's checks first had to run (2,861 blocks): CometBFT's block and state
// stores on disk (goleveldb, as a node opens them), seven padded ValidatorBlocks in every block, and one accepted BLS
// registry with its record. Each iteration starts from the old v12 watermark at the top, so the whole chain is read.
//
//	go test ./pkg/consensus/ -run '^$' -bench HistoryRecheckOf2861Blocks -benchtime 3x
func BenchmarkHistoryRecheckOf2861Blocks(b *testing.B) {
	const (
		top      = 2861
		perBlock = 7
		padding  = 8 << 10
	)
	dir := b.TempDir()
	blockDB, err := dbm.NewGoLevelDB("blockstore", dir)
	if err != nil {
		b.Fatal(err)
	}
	defer blockDB.Close()
	stateDB, err := dbm.NewGoLevelDB("state", dir)
	if err != nil {
		b.Fatal(err)
	}
	defer stateDB.Close()
	blocks := store.NewBlockStore(blockDB)
	results := sm.NewStore(stateDB, sm.StoreOptions{})

	t := b
	f := newRegistryFixture(t)
	reg := f.registry(1, "ops-1", "ops-2")
	regRaw := rotJSON(t, reg)
	const regHeight = 2790
	pad := bytes.Repeat([]byte("ab"), padding/2)
	var txBytes int
	for h := int64(1); h <= top; h++ {
		var txs []types.Tx
		var res []*abcitypes.ExecTxResult
		if h == regHeight {
			txs = append(txs, regRaw)
			res = append(res, &abcitypes.ExecTxResult{Code: 0})
		}
		for v := 1; v <= perBlock; v++ {
			vb := persistTestBlockJSON(t, fmt.Sprintf("op-%d", h), "G2", fmt.Sprintf("validator-%d", v))
			tx := append(append(append(vb[:len(vb)-1:len(vb)-1], []byte(`,"padding":"`)...), pad...), []byte(`"}`)...)
			txs = append(txs, tx)
			res = append(res, &abcitypes.ExecTxResult{Code: 0})
		}
		for _, tx := range txs {
			txBytes += len(tx)
		}
		block := types.MakeBlock(h, txs, &types.Commit{}, nil)
		block.Header.Time = beforeV9
		block.Header.ProposerAddress = bytes.Repeat([]byte{0x01}, 20)
		parts, err := block.MakePartSet(types.BlockPartSizeBytes)
		if err != nil {
			b.Fatal(err)
		}
		blocks.SaveBlock(block, parts, &types.Commit{Height: h, BlockID: types.BlockID{Hash: block.Hash(), PartSetHeader: parts.Header()}})
		if err := results.SaveFinalizeBlockResponse(h, &abcitypes.ResponseFinalizeBlock{TxResults: res, AppHash: bytes.Repeat([]byte{0x02}, 32)}); err != nil {
			b.Fatal(err)
		}
	}
	hist := storeHistory{blocks: blocks, results: results}
	b.Logf("%d blocks, %d transactions, %.1f MiB of transactions", top, top*perBlock+1, float64(txBytes)/(1<<20))

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		b.StopTimer()
		app, _ := legacyWatermarkLedger(t, top)
		if err := app.ledgerStore.SaveBLSRegistry(&ledger.BLSRegistryLog{Versions: []ledger.BLSRegistryRecord{
			{Version: 1, Height: regHeight, ID: reg.RegistryID()}}}); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		start := time.Now()
		if err := app.IndexCommittedHistory(hist); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		through, err := app.ledgerStore.KindsCheckedThrough(CurrentExecutionRulesVersion, CommittedHistoryCheckVersion)
		if err != nil || through != top {
			b.Fatalf("checked through %d, %v", through, err)
		}
		b.Logf("re-checked %d committed blocks in %s", top, time.Since(start).Round(time.Millisecond))
		b.StartTimer()
	}
}
