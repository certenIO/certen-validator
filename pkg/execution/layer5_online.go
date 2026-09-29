// Copyright 2026 Certen Protocol

package execution

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// createBatchAnchorSelector is CertenAnchorV8_1/V8_2 createBatchAnchor(bytes32 bundleId, bytes32 batchRoot,
// uint256 leafCount, bytes32 batchOperationID, uint256 accumulateBlockHeight).
var createBatchAnchorSelector = crypto.Keccak256([]byte("createBatchAnchor(bytes32,bytes32,uint256,bytes32,uint256)"))[:4]

// Layer5OnlineCheck is what VerifyLayer5Online read from the chain.
type Layer5OnlineCheck struct {
	AnchorContract   string // the contract the anchor-create transaction called - for the auditor to compare
	BundleID         string
	BatchRoot        string
	BatchOperationID string
}

// VerifyLayer5Online is the online half of layer 5: the anchor-create transaction the layer names mined, called
// createBatchAnchor, and carried the layer's batch root - and, when the layer carries its batch's governance, the
// batch operation id it recomputes (RB4-F66). It reads the chain at rpcURL; nothing else.
func VerifyLayer5Online(ctx context.Context, rpcURL string, l5 *Layer5) (*Layer5OnlineCheck, error) {
	if l5 == nil {
		return nil, fmt.Errorf("layer5: absent")
	}
	if !IsTransactionHash(l5.AnchorTx) {
		return nil, fmt.Errorf("layer5: anchorTx %q is not a transaction hash", l5.AnchorTx)
	}
	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", rpcURL, err)
	}
	defer client.Close()
	h := common.HexToHash(l5.AnchorTx)
	tx, _, err := client.TransactionByHash(ctx, h)
	if err != nil {
		return nil, fmt.Errorf("read anchor transaction %s: %w", l5.AnchorTx, err)
	}
	receipt, err := client.TransactionReceipt(ctx, h)
	if err != nil {
		return nil, fmt.Errorf("read anchor transaction %s's receipt: %w", l5.AnchorTx, err)
	}
	if receipt.Status != 1 {
		return nil, fmt.Errorf("anchor transaction %s reverted", l5.AnchorTx)
	}
	if receipt.BlockNumber == nil || receipt.BlockNumber.Uint64() != l5.BlockNumber {
		return nil, fmt.Errorf("anchor transaction %s mined in block %v, the layer names block %d",
			l5.AnchorTx, receipt.BlockNumber, l5.BlockNumber)
	}
	out := &Layer5OnlineCheck{}
	if tx.To() != nil {
		out.AnchorContract = strings.ToLower(tx.To().Hex())
	}
	call, err := decodeCreateBatchAnchor(tx.Data())
	if err != nil {
		return out, fmt.Errorf("anchor transaction %s: %w", l5.AnchorTx, err)
	}
	out.BundleID, out.BatchRoot, out.BatchOperationID = hexPrefixed(call.bundleID[:]), hexPrefixed(call.root[:]),
		hexPrefixed(call.batchOpID[:])
	if !strings.EqualFold(strings.TrimPrefix(l5.BatchRoot, "0x"), strings.TrimPrefix(out.BatchRoot, "0x")) {
		return out, fmt.Errorf("anchor transaction %s published root %s, the layer names %s", l5.AnchorTx, out.BatchRoot, l5.BatchRoot)
	}
	if l5.Governance != nil && !strings.EqualFold(l5.Governance.BatchOperationID, out.BatchOperationID) {
		return out, fmt.Errorf("anchor transaction %s stored batch operation id %s, the layer's members recompute %s",
			l5.AnchorTx, out.BatchOperationID, l5.Governance.BatchOperationID)
	}
	return out, nil
}

type batchAnchorCall struct {
	bundleID, root, batchOpID [32]byte
	leafCount, height         uint64
}

// decodeCreateBatchAnchor reads createBatchAnchor calldata: the selector and five 32-byte words.
func decodeCreateBatchAnchor(data []byte) (*batchAnchorCall, error) {
	if len(data) != 4+5*32 {
		return nil, fmt.Errorf("calldata is %d bytes, not a createBatchAnchor call", len(data))
	}
	if !bytes.Equal(data[:4], createBatchAnchorSelector) {
		return nil, fmt.Errorf("calldata selector %x is not createBatchAnchor", data[:4])
	}
	w := func(i int) []byte { return data[4+32*i : 4+32*(i+1)] }
	c := &batchAnchorCall{}
	copy(c.bundleID[:], w(0))
	copy(c.root[:], w(1))
	copy(c.batchOpID[:], w(3))
	for _, i := range []int{2, 4} {
		word := w(i)
		for _, b := range word[:24] {
			if b != 0 {
				return nil, fmt.Errorf("calldata word %d does not fit in 64 bits", i)
			}
		}
	}
	c.leafCount = uint64Word(w(2))
	c.height = uint64Word(w(4))
	return c, nil
}

// uint64Word is a 32-byte big-endian word whose value fits in 64 bits (checked by the caller).
func uint64Word(word []byte) uint64 {
	var v uint64
	for _, b := range word[24:] {
		v = v<<8 | uint64(b)
	}
	return v
}
