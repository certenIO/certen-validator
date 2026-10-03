// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

// =============================================================================
// The live anchors' own record, watched on every supported chain (RB3-F72)
// =============================================================================
//
// The startup event watcher used to watch CERTEN_CONTRACT_ADDRESS - the retired CertenAnchorV5 on
// Sepolia alone - with a V3 ABI whose AnchorCreated and ProofVerificationFailed signatures the live
// anchors no longer emit. It watched nothing the validator settles through. This watches each supported
// chain's live CertenAnchorV8_1, from the same resolver the batch path settles through, for the events
// that say what became of a batch: BatchAnchorCreated (a batch root anchored), ProofExecuted (the
// anchor verified a proof) and ProofVerificationFailed (the anchor refused one - reported loudly, it
// means a settlement did not happen). The anchor quorum backfill scans ProofExecuted with the same ABI.

// anchorEventsABIJSON is the events as CertenAnchorV8_1.sol declares them.
const anchorEventsABIJSON = `[
 {"type":"event","name":"BatchAnchorCreated","anonymous":false,"inputs":[
   {"name":"bundleId","type":"bytes32","indexed":true},
   {"name":"batchRoot","type":"bytes32","indexed":true},
   {"name":"leafCount","type":"uint256","indexed":false},
   {"name":"batchOperationID","type":"bytes32","indexed":false},
   {"name":"validator","type":"address","indexed":true},
   {"name":"timestamp","type":"uint256","indexed":false}]},
 {"type":"event","name":"ProofExecuted","anonymous":false,"inputs":[
   {"name":"anchorId","type":"bytes32","indexed":true},
   {"name":"transactionHash","type":"bytes32","indexed":false},
   {"name":"merkleVerified","type":"bool","indexed":false},
   {"name":"blsVerified","type":"bool","indexed":false},
   {"name":"governanceVerified","type":"bool","indexed":false},
   {"name":"timestamp","type":"uint256","indexed":false}]},
 {"type":"event","name":"ProofVerificationFailed","anonymous":false,"inputs":[
   {"name":"anchorId","type":"bytes32","indexed":true},
   {"name":"transactionHash","type":"bytes32","indexed":false},
   {"name":"merkleVerified","type":"bool","indexed":false},
   {"name":"blsVerified","type":"bool","indexed":false},
   {"name":"governanceVerified","type":"bool","indexed":false},
   {"name":"commitmentVerified","type":"bool","indexed":false},
   {"name":"reason","type":"string","indexed":false},
   {"name":"timestamp","type":"uint256","indexed":false}]}
]`

var anchorEventsABI = func() abi.ABI {
	a, err := abi.JSON(strings.NewReader(anchorEventsABIJSON))
	if err != nil {
		panic(fmt.Sprintf("anchor events ABI: %v", err))
	}
	return a
}()

// AnchorEndpoints is what the monitor needs of the batch path's chain resolver.
type AnchorEndpoints interface {
	Chains() []int64
	Endpoint(chainID int64) (string, common.Address, error)
}

// AnchorEventMonitor polls each supported chain's live anchor for its events.
type AnchorEventMonitor struct {
	Endpoints AnchorEndpoints
	Interval  time.Duration
	// MaxRange bounds one log query; public RPCs refuse wide ranges (Base Sepolia: 1,000 blocks).
	MaxRange uint64
	Logf     func(string, ...interface{})
}

// Start dials every chain's anchor and polls it until ctx ends. A chain it cannot watch is an error:
// the validator does not start watching some anchors and not others.
func (m *AnchorEventMonitor) Start(ctx context.Context) error {
	if m.Endpoints == nil || len(m.Endpoints.Chains()) == 0 {
		return fmt.Errorf("anchor event monitor: no chains to watch")
	}
	if m.Interval <= 0 {
		m.Interval = 30 * time.Second
	}
	if m.MaxRange == 0 {
		m.MaxRange = 500
	}
	for _, chainID := range m.Endpoints.Chains() {
		rpc, anchor, err := m.Endpoints.Endpoint(chainID)
		if err != nil {
			return fmt.Errorf("anchor event monitor: chain %d: %w", chainID, err)
		}
		client, err := ethrpc.DialRetrying(ctx, rpc)
		if err != nil {
			return fmt.Errorf("anchor event monitor: chain %d: dial: %w", chainID, err)
		}
		head, err := client.BlockNumber(ctx)
		if err != nil {
			return fmt.Errorf("anchor event monitor: chain %d: head: %w", chainID, err)
		}
		go m.poll(ctx, chainID, client, anchor, head)
		m.Logf("✅ [ANCHOR-EVENTS] watching chain %d anchor %s from block %d", chainID, anchor.Hex(), head)
	}
	return nil
}

func (m *AnchorEventMonitor) poll(ctx context.Context, chainID int64, client *ethclient.Client, anchor common.Address, from uint64) {
	t := time.NewTicker(m.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		head, err := client.BlockNumber(ctx)
		if err != nil {
			m.Logf("⚠️ [ANCHOR-EVENTS] chain %d: head unreadable, retrying from block %d: %v", chainID, from, err)
			continue
		}
		for from <= head {
			to := from + m.MaxRange - 1
			if to > head {
				to = head
			}
			logs, err := client.FilterLogs(ctx, anchorEventsQuery(anchor, from, to))
			if err != nil {
				m.Logf("⚠️ [ANCHOR-EVENTS] chain %d: logs %d-%d unreadable, retrying: %v", chainID, from, to, err)
				break
			}
			for _, lg := range logs {
				m.Logf("%s", describeAnchorEvent(chainID, lg))
			}
			from = to + 1
		}
	}
}

// anchorEventsQuery selects the events from one anchor over a block range.
func anchorEventsQuery(anchor common.Address, from, to uint64) ethereum.FilterQuery {
	return ethereum.FilterQuery{
		FromBlock: new(big.Int).SetUint64(from),
		ToBlock:   new(big.Int).SetUint64(to),
		Addresses: []common.Address{anchor},
		Topics: [][]common.Hash{{
			anchorEventsABI.Events["BatchAnchorCreated"].ID,
			anchorEventsABI.Events["ProofExecuted"].ID,
			anchorEventsABI.Events["ProofVerificationFailed"].ID,
		}},
	}
}

// describeAnchorEvent is the log line for one anchor event. An event it cannot decode is reported as
// that, never skipped.
func describeAnchorEvent(chainID int64, lg types.Log) string {
	if len(lg.Topics) == 0 {
		return fmt.Sprintf("❌ [ANCHOR-EVENTS] chain %d: log with no topics in tx %s", chainID, lg.TxHash.Hex())
	}
	switch lg.Topics[0] {
	case anchorEventsABI.Events["BatchAnchorCreated"].ID:
		v := map[string]interface{}{}
		if len(lg.Topics) < 4 || anchorEventsABI.UnpackIntoMap(v, "BatchAnchorCreated", lg.Data) != nil {
			return fmt.Sprintf("❌ [ANCHOR-EVENTS] chain %d: undecodable BatchAnchorCreated in tx %s", chainID, lg.TxHash.Hex())
		}
		return fmt.Sprintf("📡 [ANCHOR-EVENTS] chain %d: BatchAnchorCreated bundle=%s root=%s leaves=%v validator=%s block=%d tx=%s",
			chainID, lg.Topics[1].Hex(), lg.Topics[2].Hex(), v["leafCount"], common.BytesToAddress(lg.Topics[3].Bytes()).Hex(), lg.BlockNumber, lg.TxHash.Hex())
	case anchorEventsABI.Events["ProofExecuted"].ID:
		v := map[string]interface{}{}
		if len(lg.Topics) < 2 || anchorEventsABI.UnpackIntoMap(v, "ProofExecuted", lg.Data) != nil {
			return fmt.Sprintf("❌ [ANCHOR-EVENTS] chain %d: undecodable ProofExecuted in tx %s", chainID, lg.TxHash.Hex())
		}
		return fmt.Sprintf("📡 [ANCHOR-EVENTS] chain %d: ProofExecuted anchor=%s merkle=%v bls=%v governance=%v block=%d tx=%s",
			chainID, lg.Topics[1].Hex(), v["merkleVerified"], v["blsVerified"], v["governanceVerified"], lg.BlockNumber, lg.TxHash.Hex())
	case anchorEventsABI.Events["ProofVerificationFailed"].ID:
		v := map[string]interface{}{}
		if len(lg.Topics) < 2 || anchorEventsABI.UnpackIntoMap(v, "ProofVerificationFailed", lg.Data) != nil {
			return fmt.Sprintf("❌ [ANCHOR-EVENTS] chain %d: undecodable ProofVerificationFailed in tx %s", chainID, lg.TxHash.Hex())
		}
		return fmt.Sprintf("❌ [ANCHOR-EVENTS] chain %d: ProofVerificationFailed anchor=%s reason=%q merkle=%v bls=%v governance=%v commitment=%v block=%d tx=%s",
			chainID, lg.Topics[1].Hex(), v["reason"], v["merkleVerified"], v["blsVerified"], v["governanceVerified"], v["commitmentVerified"], lg.BlockNumber, lg.TxHash.Hex())
	}
	return fmt.Sprintf("❌ [ANCHOR-EVENTS] chain %d: unexpected event %s in tx %s", chainID, lg.Topics[0].Hex(), lg.TxHash.Hex())
}
