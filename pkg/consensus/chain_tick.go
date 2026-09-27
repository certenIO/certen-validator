package consensus

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// A chain tick is a transaction that does nothing, so an operator can make the chain produce a block
// (RB3-F95).
//
// This chain runs with empty blocks disabled: CometBFT produces a block only for a transaction (or the one
// proof block that follows an app-hash change). A validator rotation accepted at height h moves the slot to
// the new key at h+2 and is adopted only once a later block carries the new key's signature - on an idle
// chain, neither happens until someone submits work. A tick is that work, and nothing else: accepted with no
// state change, no app-hash contribution and no validator update.

// ChainTickKind identifies a tick on the wire.
const ChainTickKind = "certen.chain.tick/v1"

// ChainTickTx is a tick. The nonce makes each tick's bytes unique, so the mempool does not drop a second
// tick as a duplicate of the first.
type ChainTickTx struct {
	Kind  string `json:"kind"`
	Nonce string `json:"nonce"` // 8 to 32 bytes of hex
}

// DecodeChainTick returns the tick if these bytes are one.
func DecodeChainTick(tx []byte) (*ChainTickTx, bool) {
	var probe struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(tx, &probe); err != nil || probe.Kind != ChainTickKind {
		return nil, false
	}
	var out ChainTickTx
	if err := json.Unmarshal(tx, &out); err != nil {
		return nil, false
	}
	return &out, true
}

// CheckShape accepts only a kind and a hex nonce of 8 to 32 bytes: a tick carries nothing else.
func (t *ChainTickTx) CheckShape() error {
	if t.Kind != ChainTickKind {
		return fmt.Errorf("kind %q is not %q", t.Kind, ChainTickKind)
	}
	b, err := hex.DecodeString(t.Nonce)
	if err != nil || len(b) < 8 || len(b) > 32 {
		return fmt.Errorf("a tick's nonce is 8 to 32 bytes of hex")
	}
	return nil
}
