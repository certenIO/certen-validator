package billing

import (
	"math/big"
	"testing"
)

func bi(n int64) *big.Int { return big.NewInt(n) }

// A cost is measured from a receipt, and a REVERTED transaction has a receipt
// too — gas consumed, block assigned, nothing done. Reporting the cost without
// the outcome let the gateway complete and bill intents whose execution
// reverted: 13 of them on 2026-08-11, $12.89, of which $6.50 was platform fee
// charged for enforcement that never happened.
//
// The receipt's status field was already being decoded here. It was simply
// never carried, so the gateway had nothing to look at.

func TestCostEventCarriesSucceeded(t *testing.T) {
	yes := true
	c := &ChainCost{
		Chain: "ethereum-sepolia", ChainID: 11155111, Leg: "vault_execute",
		TxHash: "0xabc", NativeSymbol: "ETH", Succeeded: &yes,
	}
	c.setGas(21000, bi(1_000_000_000))
	c.WeiPerNative = bi(1_000_000_000_000_000_000)

	ev, err := NewCostEvent("intent-1", "acc://x.acme", "accum-hash", c, nil)
	if err != nil {
		t.Fatalf("NewCostEvent: %v", err)
	}
	if ev.Succeeded == nil {
		t.Fatal("Succeeded was dropped between the measurement and the wire payload")
	}
	if !*ev.Succeeded {
		t.Fatal("Succeeded inverted")
	}
}

func TestCostEventCarriesFailure(t *testing.T) {
	no := false
	c := &ChainCost{
		Chain: "ethereum-sepolia", ChainID: 11155111, Leg: "vault_execute",
		TxHash: "0xdef", NativeSymbol: "ETH", Succeeded: &no,
	}
	c.setGas(103953, bi(1_000_000_000))
	c.WeiPerNative = bi(1_000_000_000_000_000_000)

	ev, err := NewCostEvent("intent-2", "acc://x.acme", "accum-hash", c, nil)
	if err != nil {
		t.Fatalf("NewCostEvent: %v", err)
	}
	if ev.Succeeded == nil {
		t.Fatal("a KNOWN failure must reach the gateway; nil reads as unknown and still bills")
	}
	if *ev.Succeeded {
		t.Fatal("a reverted execution was reported as successful")
	}
}

// Unknown must stay unknown. A chain whose adapter cannot determine the outcome
// leaves this nil, and the gateway treats nil as "not reported" — it still
// completes. Defaulting to false here would strand every intent on that chain;
// defaulting to true would bake the original bug back in.
func TestUnknownOutcomeIsOmitted(t *testing.T) {
	c := &ChainCost{
		Chain: "solana-devnet", Leg: "vault_execute",
		TxHash: "sig", NativeSymbol: "SOL",
	}
	c.setGas(1, bi(5000))
	c.WeiPerNative = bi(1_000_000_000)

	ev, err := NewCostEvent("intent-3", "acc://x.acme", "accum-hash", c, nil)
	if err != nil {
		t.Fatalf("NewCostEvent: %v", err)
	}
	if ev.Succeeded != nil {
		t.Fatalf("unknown outcome should stay nil, got %v", *ev.Succeeded)
	}
}
