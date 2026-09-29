package execution

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// ReadAnchorState reads anchors(bundleId) on the anchor at the given block (nil: latest) and decodes it by the
// generation the returned data shows (contracts.DecodeAnchorsReturn). It is THE reader of anchor state: the batch path
// reads V8.2 anchors, and verification and repair also read the V8.1 anchors created before the V8.2 rollout, so no
// reader transcribes a layout of its own.
func ReadAnchorState(ctx context.Context, caller ethereum.ContractCaller, anchor common.Address, bundleID [32]byte, block *big.Int) (*contracts.AnchorState, error) {
	ret, err := caller.CallContract(ctx, ethereum.CallMsg{To: &anchor, Data: contracts.AnchorsCallData(bundleID)}, block)
	if err != nil {
		return nil, fmt.Errorf("reading anchors(0x%x) on %s: %w", bundleID[:8], anchor.Hex(), err)
	}
	return contracts.DecodeAnchorsReturn(ret)
}
