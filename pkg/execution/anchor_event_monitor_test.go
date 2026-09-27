// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// RB3-F72: the monitor watches the events the live anchors emit, as CertenAnchorV8_1.sol declares them.
// The expectations are the Solidity signatures, not the ABI under test restated.
func TestAnchorEventsAreTheLiveAnchorsSignatures(t *testing.T) {
	for name, sig := range map[string]string{
		"BatchAnchorCreated":      "BatchAnchorCreated(bytes32,bytes32,uint256,bytes32,address,uint256)",
		"ProofExecuted":           "ProofExecuted(bytes32,bytes32,bool,bool,bool,uint256)",
		"ProofVerificationFailed": "ProofVerificationFailed(bytes32,bytes32,bool,bool,bool,bool,string,uint256)",
	} {
		if got, want := anchorEventsABI.Events[name].ID, crypto.Keccak256Hash([]byte(sig)); got != want {
			t.Fatalf("%s topic %s; CertenAnchorV8_1 emits %s", name, got.Hex(), want.Hex())
		}
	}
	q := anchorEventsQuery(common.HexToAddress("0xEA9eeeE42a7971792B11Fd2f682C9c1172490272"), 10, 20)
	if len(q.Addresses) != 1 || q.FromBlock.Uint64() != 10 || q.ToBlock.Uint64() != 20 || len(q.Topics) != 1 || len(q.Topics[0]) != 3 {
		t.Fatalf("query %+v", q)
	}
}

func TestAnchorEventsAreDescribedOrReportedUndecodable(t *testing.T) {
	ev := anchorEventsABI.Events["BatchAnchorCreated"]
	data, err := ev.Inputs.NonIndexed().Pack(big.NewInt(3), [32]byte{7}, big.NewInt(1790000000))
	if err != nil {
		t.Fatal(err)
	}
	validator := common.HexToAddress("0x91C798AA00000000000000000000000000000001")
	lg := types.Log{Topics: []common.Hash{ev.ID, {1}, {2}, common.BytesToHash(validator.Bytes())}, Data: data, BlockNumber: 9}
	if d := describeAnchorEvent(84532, lg); !strings.Contains(d, "BatchAnchorCreated") || !strings.Contains(d, "leaves=3") || !strings.Contains(d, validator.Hex()) {
		t.Fatalf("batch anchor: %s", d)
	}
	pf := anchorEventsABI.Events["ProofVerificationFailed"]
	data, err = pf.Inputs.NonIndexed().Pack([32]byte{5}, true, false, true, true, "bls signature invalid", big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	if d := describeAnchorEvent(84532, types.Log{Topics: []common.Hash{pf.ID, {9}}, Data: data}); !strings.HasPrefix(d, "❌") ||
		!strings.Contains(d, "bls signature invalid") || !strings.Contains(d, "bls=false") {
		t.Fatalf("a refused proof is reported loudly with its reason: %s", d)
	}
	for _, bad := range []types.Log{{}, {Topics: []common.Hash{ev.ID}}, {Topics: []common.Hash{{0xee}}}} {
		if d := describeAnchorEvent(1, bad); !strings.HasPrefix(d, "❌") {
			t.Fatalf("an event the monitor cannot decode was not reported: %s", d)
		}
	}
}

type fakeEndpoints struct {
	chains []int64
	err    error
}

func (f fakeEndpoints) Chains() []int64 { return f.chains }
func (f fakeEndpoints) Endpoint(int64) (string, common.Address, error) {
	return "http://127.0.0.1:1", common.Address{1}, f.err
}

func TestAnchorEventMonitorWatchesEveryChainOrNone(t *testing.T) {
	logf := func(string, ...interface{}) {}
	if err := (&AnchorEventMonitor{Endpoints: fakeEndpoints{}, Logf: logf}).Start(context.Background()); err == nil {
		t.Fatal("no chains to watch")
	}
	if err := (&AnchorEventMonitor{Endpoints: fakeEndpoints{chains: []int64{84532}, err: fmt.Errorf("no anchor")}, Logf: logf}).Start(context.Background()); err == nil {
		t.Fatal("a chain without an anchor was skipped")
	}
	if err := (&AnchorEventMonitor{Endpoints: fakeEndpoints{chains: []int64{84532}}, Logf: logf}).Start(context.Background()); err == nil {
		t.Fatal("a chain whose RPC cannot be read was skipped")
	}
}
