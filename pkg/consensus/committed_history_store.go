// Copyright 2026 Certen Protocol

package consensus

import (
	"fmt"
	"time"

	"github.com/cometbft/cometbft/config"
	sm "github.com/cometbft/cometbft/state"
	"github.com/cometbft/cometbft/store"
)

// storeHistory reads committed blocks and their FinalizeBlock results straight from CometBFT's block and
// state stores - the chain as this node committed it (committedHistory).
type storeHistory struct {
	blocks  *store.BlockStore
	results sm.Store
}

func (h storeHistory) Base() int64   { return h.blocks.Base() }
func (h storeHistory) Height() int64 { return h.blocks.Height() }

func (h storeHistory) Block(height int64) ([][]byte, time.Time, error) {
	b := h.blocks.LoadBlock(height)
	if b == nil {
		return nil, time.Time{}, fmt.Errorf("the block store has no block at height %d", height)
	}
	txs := make([][]byte, len(b.Txs))
	for i, tx := range b.Txs {
		txs[i] = tx
	}
	return txs, b.Header.Time, nil
}

func (h storeHistory) ResultCodes(height int64) ([]uint32, error) {
	r, err := h.results.LoadFinalizeBlockResponse(height)
	if err != nil {
		return nil, err
	}
	codes := make([]uint32, len(r.TxResults))
	for i, res := range r.TxResults {
		if res == nil {
			return nil, fmt.Errorf("height %d: result %d is missing", height, i)
		}
		codes[i] = res.Code
	}
	return codes, nil
}

// indexCommittedHistoryFromStores opens CometBFT's block and state stores - before the node does, and closes
// them before it opens them - and indexes what the app committed (ValidatorApp.IndexCommittedHistory).
func indexCommittedHistoryFromStores(cfg *config.Config, dbProvider config.DBProvider, app *ValidatorApp) error {
	blockDB, err := dbProvider(&config.DBContext{ID: "blockstore", Config: cfg})
	if err != nil {
		return fmt.Errorf("open the block store: %w", err)
	}
	defer blockDB.Close()
	stateDB, err := dbProvider(&config.DBContext{ID: "state", Config: cfg})
	if err != nil {
		return fmt.Errorf("open the state store: %w", err)
	}
	defer stateDB.Close()
	return app.IndexCommittedHistory(storeHistory{
		blocks:  store.NewBlockStore(blockDB),
		results: sm.NewStore(stateDB, sm.StoreOptions{DiscardABCIResponses: cfg.Storage.DiscardABCIResponses}),
	})
}
