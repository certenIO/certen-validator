// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"fmt"
	"github.com/certen/independant-validator/pkg/execution/contracts"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// Layer5OnlineCheck is what VerifyLayer5Online read from the chain.
type Layer5OnlineCheck struct {
	AnchorContract   string // the contract the anchor-create transaction called - for the auditor to compare
	BundleID         string
	BatchRoot        string
	BatchOperationID string
	// AnchorVersion is the generation of the createBatchAnchor call ("v8_1", "v8_2"). On a V8.2 call the anchor also
	// committed AccumulateSetRoot and Incarnation; both are empty on a V8.1 call, which committed neither.
	AnchorVersion     string
	AccumulateSetRoot string
	Incarnation       string
	// AnchorRecordChecked is true when the anchor's own record (anchors(bundleId)) was read and matched.
	AnchorRecordChecked bool
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
	if tx.ChainId() == nil || !tx.ChainId().IsInt64() {
		return out, fmt.Errorf("anchor transaction %s names no chain id", l5.AnchorTx)
	}
	call, err := contracts.DecodeCreateBatchAnchor(tx.ChainId().Int64(), tx.Data())
	if err != nil {
		return out, fmt.Errorf("anchor transaction %s: %w", l5.AnchorTx, err)
	}
	out.BundleID, out.BatchRoot, out.BatchOperationID = hexPrefixed(call.BundleID[:]), hexPrefixed(call.Root[:]),
		hexPrefixed(call.BatchOperationID[:])
	out.AnchorVersion = string(call.Version)
	if call.Version == contracts.BatchAnchorV8_2 {
		out.AccumulateSetRoot, out.Incarnation = hexPrefixed(call.AccumulateSetRoot[:]), hexPrefixed(call.Incarnation[:])
	}
	if !strings.EqualFold(strings.TrimPrefix(l5.BatchRoot, "0x"), strings.TrimPrefix(out.BatchRoot, "0x")) {
		return out, fmt.Errorf("anchor transaction %s published root %s, the layer names %s", l5.AnchorTx, out.BatchRoot, l5.BatchRoot)
	}
	if l5.Governance != nil && !strings.EqualFold(l5.Governance.BatchOperationID, out.BatchOperationID) {
		return out, fmt.Errorf("anchor transaction %s stored batch operation id %s, the layer's members recompute %s",
			l5.AnchorTx, out.BatchOperationID, l5.Governance.BatchOperationID)
	}
	if c := l5.Commitment; c != nil {
		// The transaction created exactly the anchor the layer says was committed: its generation, bundle id and, on
		// V8.2, the Accumulate set and incarnation.
		if c.Version != out.AnchorVersion || !strings.EqualFold(strings.TrimPrefix(c.BundleID, "0x"), strings.TrimPrefix(out.BundleID, "0x")) {
			return out, fmt.Errorf("anchor transaction %s created a %s anchor %s, the layer names a %s anchor %s",
				l5.AnchorTx, out.AnchorVersion, out.BundleID, c.Version, c.BundleID)
		}
		if c.Version == string(contracts.BatchAnchorV8_2) &&
			(!strings.EqualFold(strings.TrimPrefix(c.AccumulateSetRoot, "0x"), strings.TrimPrefix(out.AccumulateSetRoot, "0x")) ||
				!strings.EqualFold(strings.TrimPrefix(c.Incarnation, "0x"), strings.TrimPrefix(out.Incarnation, "0x"))) {
			return out, fmt.Errorf("anchor transaction %s committed Accumulate set %s under incarnation %s, the layer names %s under %s",
				l5.AnchorTx, out.AccumulateSetRoot, out.Incarnation, c.AccumulateSetRoot, c.Incarnation)
		}
		// And the anchor still holds it: its own record, read from its contract.
		if tx.To() == nil {
			return out, fmt.Errorf("anchor transaction %s created no contract call", l5.AnchorTx)
		}
		st, err := ReadAnchorState(ctx, client, *tx.To(), call.BundleID, nil)
		if err != nil {
			return out, fmt.Errorf("anchor %s: %w", out.BundleID, err)
		}
		if string(st.Version) != c.Version || st.MerkleRoot != call.Root || st.AccumulateSetRoot != call.AccumulateSetRoot ||
			st.Incarnation != call.Incarnation || !st.Valid {
			return out, fmt.Errorf("anchor %s holds a %s record (root %x…, Accumulate set %x…, incarnation %x…, valid %v) that is "+
				"not what its create transaction committed", out.BundleID, st.Version, st.MerkleRoot[:8],
				st.AccumulateSetRoot[:8], st.Incarnation[:8], st.Valid)
		}
		out.AnchorRecordChecked = true
	}
	return out, nil
}
