// Copyright 2026 Certen Protocol

// Package genesis recomputes the Adiri genesis block hash from tn_genesis under go-ethereum. It is its own Go module so that
// importing go-ethereum core does not change the validator module's go.mod (activation freeze).
package genesis

import (
	"encoding/json"

	"github.com/ethereum/go-ethereum/core"
)

// GenesisHashFromTN recomputes the genesis block hash of tn_genesis's JSON under go-ethereum (core.Genesis.ToBlock) and
// returns it with the state root.
func GenesisHashFromTN(tnGenesis []byte) (hash, stateRoot [32]byte, err error) {
	var g core.Genesis
	if err = json.Unmarshal(tnGenesis, &g); err != nil {
		return
	}
	b := g.ToBlock()
	return [32]byte(b.Hash()), [32]byte(b.Root()), nil
}
