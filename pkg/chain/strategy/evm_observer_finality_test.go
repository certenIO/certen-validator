package strategy

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/ethproof/ethprooftest"
)

// RB5-F49: the strategy observer reports a settlement finalized only in the chain's finalized, canonical block. It used to
// count two confirmations past whatever block the receipt named. Here the providers' index names a block the finalized
// chain does not have; the old observer called that block final. (The live event of 2026-10-02 was the converse - a fork
// header served before finality; see pkg/execution TestTheLiveForkHeaderIsWaitedOutUntilFinality.)
//
// The block is a real Sepolia block (pkg/ethproof/testdata), so the observation is also proven in it (RB5-F16).
func TestTheStrategyObserverReportsTheFinalizedCanonicalBlock(t *testing.T) {
	f := ethprooftest.Load(t, ethprooftest.Sepolia)
	orphan := common.HexToHash("0x0ff1ce00000000000000000000000000000000000000000000000000000000aa")
	staleIndex := func(method string, _ []json.RawMessage, res json.RawMessage) json.RawMessage {
		if method != "eth_getTransactionReceipt" || string(res) == "null" {
			return res
		}
		var r map[string]json.RawMessage
		_ = json.Unmarshal(res, &r)
		r["blockHash"], _ = json.Marshal(orphan)
		out, _ := json.Marshal(r)
		return out
	}
	o := fixtureObserver(t, &ethprooftest.Provider{F: f, Mutate: staleIndex}, &ethprooftest.Provider{F: f, Mutate: staleIndex})
	got, err := o.ObserveTransaction(context.Background(), f.SettlementTx)
	if err != nil {
		t.Fatalf("THE regression: a settlement the canonical block holds was not observed: %v", err)
	}
	header := f.Header(t)
	if !got.IsFinalized || got.BlockHash != f.BlockHash().Hex() || got.BlockNumber != header.Number.Uint64() || got.Status != 1 {
		t.Fatalf("observed %+v; want finalized in the canonical block %s", got, f.BlockHash().Hex())
	}

	// One block short of finality: not observed as final.
	short := func(method string, params []json.RawMessage, res json.RawMessage) json.RawMessage {
		var tag string
		if method == "eth_getBlockByNumber" && len(params) > 0 && json.Unmarshal(params[0], &tag) == nil && tag == "finalized" {
			var b map[string]json.RawMessage
			_ = json.Unmarshal(res, &b)
			b["number"], _ = json.Marshal(fmt.Sprintf("0x%x", new(big.Int).Sub(header.Number, big.NewInt(1))))
			out, _ := json.Marshal(b)
			return out
		}
		return res
	}
	o2 := fixtureObserver(t, &ethprooftest.Provider{F: f, Mutate: short}, &ethprooftest.Provider{F: f, Mutate: short})
	o2.timeout = 50 * 1e6
	if res, err := o2.ObserveTransaction(context.Background(), f.SettlementTx); err == nil {
		t.Fatalf("a block not yet finalized was observed: %+v", res)
	} else if !strings.Contains(err.Error(), "finalized") {
		t.Fatalf("refused, but not for finality: %v", err)
	}
}
