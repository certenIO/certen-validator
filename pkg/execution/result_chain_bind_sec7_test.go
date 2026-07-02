package execution

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// SEC-7: VerifyAgainstResult must (a) bind the observed chain to the COMMITTED chain and
// (b) never rubber-stamp a contract call — or any non-EVM leg carrying calldata — on
// confirmation alone. The pre-fix code keyed a blanket `return true` off the executor-
// reported chain string, so an executor could satisfy an EVM commitment with a result it
// labelled "solana", and non-EVM legs skipped all field/effect binding.

func sec7NativeNonEVMCommitment(chain string) *ExecutionCommitment {
	return &ExecutionCommitment{
		TargetChain:   chain,
		ExpectedValue: big.NewInt(0),
		// native: not a contract call, no committed events
	}
}

func sec7ConfirmOnlyResult(chain string) *ExternalChainResult {
	return &ExternalChainResult{Chain: chain, Status: 1} // TxTo/TxData nil — native observer
}

// A committed EVM contract call satisfied by a result labelled as a different (non-EVM)
// chain must be refused — chain identity binds first.
func TestSec7_ObservedChainMismatch_Refused(t *testing.T) {
	c := rb4CallCommitment([]ExpectedEvent{{Contract: rb4Target, Topic0: rb4Topic0}})
	c.TargetChain = "ethereum"
	res := rb4Result(c.FunctionSelector, true)
	res.Chain = "solana" // executor mislabels the chain
	if c.VerifyAgainstResult(res) {
		t.Error("must refuse when observed chain != committed chain")
	}
}

// A committed EVM contract call whose observed chain matches still passes the strict path.
func TestSec7_EVMCallMatchingChain_Passes(t *testing.T) {
	c := rb4CallCommitment([]ExpectedEvent{{Contract: rb4Target, Topic0: rb4Topic0}})
	c.TargetChain = "ethereum"
	if !c.VerifyAgainstResult(rb4Result(c.FunctionSelector, true)) {
		t.Error("EVM contract call with matching chain + committed event must verify")
	}
}

// A committed NON-EVM contract call can never be accepted on confirmation alone.
func TestSec7_NonEVMContractCall_Refused(t *testing.T) {
	c := rb4CallCommitment([]ExpectedEvent{{Contract: rb4Target, Topic0: rb4Topic0}})
	c.TargetChain = "solana"
	// non-EVM observer returns confirmation only
	if c.VerifyAgainstResult(sec7ConfirmOnlyResult("solana")) {
		t.Error("non-EVM contract call must be refused (not trustlessly effect-verifiable)")
	}
}

// A genuine non-EVM NATIVE transfer on the committed chain is accepted (scoped limitation).
func TestSec7_NonEVMNativeMatching_Passes(t *testing.T) {
	c := sec7NativeNonEVMCommitment("tron")
	if !c.VerifyAgainstResult(sec7ConfirmOnlyResult("tron")) {
		t.Error("non-EVM native transfer on the committed chain should be accepted on confirmation")
	}
}

// Even a non-EVM native transfer must match the committed chain.
func TestSec7_NonEVMNativeChainMismatch_Refused(t *testing.T) {
	c := sec7NativeNonEVMCommitment("tron")
	if c.VerifyAgainstResult(sec7ConfirmOnlyResult("near")) {
		t.Error("non-EVM native transfer on a different chain than committed must be refused")
	}
}

// An EVM commitment whose observed result has a nil TxTo (nothing to field-verify) must be
// refused — the non-EVM confirmation-only branch must not be reachable for EVM chains.
func TestSec7_EVMNilTxTo_Refused(t *testing.T) {
	c := &ExecutionCommitment{
		TargetChain:    "ethereum",
		TargetContract: common.HexToAddress("0x00000000000000000000000000000000DeaDBeef"),
		ExpectedValue:  big.NewInt(0),
	}
	if c.VerifyAgainstResult(sec7ConfirmOnlyResult("ethereum")) {
		t.Error("EVM result with nil TxTo must be refused, never accepted via the non-EVM branch")
	}
}
