package contracts

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

// The batch path's calls exist in the embedded V8.2 ABI with exactly the shapes it packs and reads.
func TestCertenAnchorV8_2BatchABI(t *testing.T) {
	parsed, err := abi.JSON(strings.NewReader(CertenAnchorV8_2BatchABI))
	if err != nil {
		t.Fatal(err)
	}
	if m := parsed.Methods["createBatchAnchor"]; m.Sig != CreateBatchAnchorV8_2Signature || [4]byte(m.ID) != CreateBatchAnchorV8_2Selector {
		t.Fatalf("createBatchAnchor is %s", m.Sig)
	}
	want := []string{"bundleId", "merkleRoot", "adiURLHash", "operationCommitment", "crossChainCommitment", "governanceRoot",
		"executionCommitment", "operationID", "accumulateBlockHeight", "timestamp", "validator", "valid", "proofExecuted",
		"governanceExecuted", "governanceLevel", "accumulateValidatorSetRoot", "accumulateIncarnation"}
	out := parsed.Methods["anchors"].Outputs
	if len(out) != len(want) {
		t.Fatalf("anchors has %d outputs, want %d", len(out), len(want))
	}
	for i, n := range want {
		if out[i].Name != n {
			t.Fatalf("anchors output %d is %s, want %s", i, out[i].Name, n)
		}
	}
	for _, sig := range []string{"isBatchAnchor(bytes32)", "batchLeafCount(bytes32)", "verifyProof(bytes32,bytes32[],bytes32)",
		"anchorExists(bytes32)", "getExecutionCommitment(bytes32)", "currentValidatorSetRoot()"} {
		found := false
		for _, m := range parsed.Methods {
			if m.Sig == sig {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is missing", sig)
		}
	}
}
