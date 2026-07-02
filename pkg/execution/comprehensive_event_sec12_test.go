package execution

import (
	"math/big"
	"testing"
)

// SEC-12: the ComprehensiveData event path (verifyExpectedEvents) must FAIL a committed
// event whose topic0 is empty or malformed, instead of silently treating it as satisfied.
// Reaches the lenient path via ComprehensiveData with isContractCall unset (so the strict
// RB-4 gate is skipped) but expectedEvents present.

func sec12Commitment(events []interface{}) *ExecutionCommitment {
	sel := [4]byte{0x1a, 0x17, 0x72, 0x68}
	return &ExecutionCommitment{
		TargetChain:      "ethereum",
		TargetContract:   rb4Target,
		FunctionSelector: sel,
		ExpectedValue:    big.NewInt(0),
		ComprehensiveData: map[string]interface{}{
			"expectedEvents": events,
		},
	}
}

func TestSec12_EmptyTopic0_Refused(t *testing.T) {
	c := sec12Commitment([]interface{}{
		map[string]interface{}{"name": "Ping", "topic0": "", "contract": rb4Target.Hex()},
	})
	if c.VerifyAgainstResult(rb4Result(c.FunctionSelector, true)) {
		t.Error("a committed event with an empty topic0 must be refused, not skipped")
	}
}

func TestSec12_MalformedTopic0_Refused(t *testing.T) {
	c := sec12Commitment([]interface{}{
		map[string]interface{}{"name": "Ping", "topic0": "0xZZZZ", "contract": rb4Target.Hex()},
	})
	if c.VerifyAgainstResult(rb4Result(c.FunctionSelector, true)) {
		t.Error("a committed event with a malformed topic0 must be refused, not skipped")
	}
}

func TestSec12_ValidTopic0Present_Passes(t *testing.T) {
	c := sec12Commitment([]interface{}{
		map[string]interface{}{"name": "Completed", "topic0": rb4Topic0.Hex(), "contract": rb4Target.Hex()},
	})
	if !c.VerifyAgainstResult(rb4Result(c.FunctionSelector, true)) {
		t.Error("a committed event whose topic0 is present in logs must pass")
	}
}
