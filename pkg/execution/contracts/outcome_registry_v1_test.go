package contracts

import (
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// TestCertenOutcomeRegistryV1ABI pins the registry surface the D4 outcome path depends on (RB5).
func TestCertenOutcomeRegistryV1ABI(t *testing.T) {
	parsed, err := abi.JSON(strings.NewReader(CertenOutcomeRegistryV1ABI))
	if err != nil {
		t.Fatal(err)
	}
	if m := parsed.Methods["recordBatchOutcome"]; m.Sig != RecordBatchOutcomeSignature {
		t.Fatalf("recordBatchOutcome is %s", m.Sig)
	}
	for name, sig := range map[string]string{
		"outcomeMessage": "outcomeMessage(bytes32,bytes32)", "outcomeRoots": "outcomeRoots(bytes32)",
		"recordedInBlock": "recordedInBlock(bytes32)", "anchor": "anchor()", "DEPLOYMENT_CHAIN_ID": "DEPLOYMENT_CHAIN_ID()",
	} {
		if parsed.Methods[name].Sig != sig {
			t.Fatalf("%s is %q, want %q", name, parsed.Methods[name].Sig, sig)
		}
	}
	if e := parsed.Events["BatchOutcomeRecorded"]; e.Sig != "BatchOutcomeRecorded(bytes32,bytes32,address,bytes32)" {
		t.Fatalf("BatchOutcomeRecorded is %q", e.Sig)
	}
	for _, name := range []string{"AnchorNotAttested", "AnchorNotV8_2", "ChainIDMismatch", "OnlyRegisteredValidator",
		"OutcomeAlreadyRecorded", "OutcomeRootRequired", "QuorumAttestationInvalid"} {
		if _, ok := parsed.Errors[name]; !ok {
			t.Fatalf("error %s missing", name)
		}
	}
	// The proof tuple is the anchor's BLSProofData, which CertenAnchorV4BLSProofData packs.
	proof := CertenAnchorV4BLSProofData{AggregateSignature: []byte{1}, ValidatorAddresses: []common.Address{{1}},
		VotingPowers: []*big.Int{big.NewInt(100)}, TotalVotingPower: big.NewInt(100), SignedVotingPower: big.NewInt(100),
		ThresholdMet: true, MessageHash: [32]byte{3}}
	if _, err := parsed.Pack("recordBatchOutcome", [32]byte{1}, [32]byte{2}, proof); err != nil {
		t.Fatalf("CertenAnchorV4BLSProofData does not pack as the registry's proof: %v", err)
	}
}
