// Copyright 2026 Certen Protocol

package execution

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/strategy"
)

// RB3-F66: a member's write-back states the calls it was actually settled by - the chain's V8 anchor with
// the batch path's createBatchAnchor and executeComprehensiveProof, and the settlement transaction as
// observed - never the retired V3 template.
func TestWriteBackStatesTheCallsTheMemberWasSettledBy(t *testing.T) {
	anchor := common.HexToAddress("0xEA9eeeE42a7971792B11Fd2f682C9c1172490272") // Base V8 anchor
	account := common.HexToAddress("0x184aeF98bEAcAF3E73Ca4a77c72e8F11E9B790A7")
	reg := strategy.NewRegistry()
	if err := reg.RegisterChainStrategy("84532", &chain.ChainConfig{Platform: chain.ChainPlatformEVM, ChainID: "84532", ContractAddress: anchor.Hex()}, &anchorChain{}); err != nil {
		t.Fatal(err)
	}
	o := &UnifiedOrchestrator{config: &UnifiedOrchestratorConfig{Registry: reg}}
	settled := &chain.ObservationResult{TxHash: "0x5a55", Status: 1, TxTo: account.Hex(), TxSelector: "d7b0e1a3"}

	steps, err := o.settlementSteps("84532", []*chain.ObservationResult{settled})
	if err != nil {
		t.Fatal(err)
	}
	if steps.anchor != anchor || steps.step3Contract != account.Hex() || steps.step3Selector != "d7b0e1a3" {
		t.Fatalf("steps %+v; want the registry's anchor and the observed settlement call", steps)
	}
	// The selectors the batch path packs its anchor calls with - not the V3 createAnchor/executeWithGovernance.
	if steps.step1Selector != hexSel("createBatchAnchor(bytes32,bytes32,uint256,bytes32,uint256)") {
		t.Fatalf("step 1 selector %s is not createBatchAnchor", steps.step1Selector)
	}
	if steps.step1Selector == hexSel("createAnchor(bytes32,bytes32,bytes32,bytes32,uint256)") ||
		steps.step2Selector == hexSel("executeWithGovernance(bytes32,address,uint256,bytes)") {
		t.Fatal("a retired V3 selector is stated")
	}

	// The write-back context carries exactly these.
	c := memberCycle("i-steps", "84532", []int64{84532}, 1, settled)
	c.Request.BundleID = [32]byte{1}
	c.Request.CommitmentData["finalTarget"], c.Request.CommitmentData["finalValue"] = "0x000000000000000000000000000000000000dEaD", "0"
	ctx := o.buildComprehensiveProofContext(c)
	if ctx.StepsError != nil || ctx.Step1Contract != anchor.Hex() || ctx.Step2Contract != anchor.Hex() ||
		ctx.Step3Contract != account.Hex() || ctx.Commitment.TargetContract != anchor {
		t.Fatalf("context steps %s/%s/%s target %s err %v", ctx.Step1Contract, ctx.Step2Contract, ctx.Step3Contract,
			ctx.Commitment.TargetContract.Hex(), ctx.StepsError)
	}

	// Nothing observed to state, or no anchor for the chain: an error, never a blank or a template.
	if _, err := o.settlementSteps("84532", []*chain.ObservationResult{{TxHash: "0x5a55", Status: 1}}); err == nil {
		t.Fatal("a settlement with no observed call must not be stated")
	}
	if _, err := o.settlementSteps("11155111", []*chain.ObservationResult{settled}); err == nil {
		t.Fatal("a chain with no registered anchor must not be stated")
	}
	if c2 := memberCycle("i-steps-2", "84532", []int64{84532}, 1, nil); o.buildComprehensiveProofContext(c2).StepsError == nil {
		t.Fatal("the context must carry why its steps could not be stated")
	}

	// The transfer was executed by the observed settlement; its events are verified only when the gate
	// proved them - never because the receipt merely had logs.
	settled.Logs = []chain.EventLog{{Topics: []string{"0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"}}}
	ctx = o.buildComprehensiveProofContext(c)
	if ctx.TransferExecutedHash != "0x5a55" || ctx.EventsVerified || ctx.EventCount != 1 {
		t.Fatalf("unproven: transfer %q verified %v count %d; want the settlement, not verified, 1 event",
			ctx.TransferExecutedHash, ctx.EventsVerified, ctx.EventCount)
	}
	c.VerifiedCalls = verifiedCallProofs{"5a55": &ExternalChainResult{}}
	if ctx = o.buildComprehensiveProofContext(c); !ctx.EventsVerified {
		t.Fatal("events the gate proved must be stated verified")
	}
}

// hexSel is a function selector, computed independently of the code under test.
func hexSel(sig string) string {
	return common.Bytes2Hex(crypto.Keccak256([]byte(sig))[:4])
}
