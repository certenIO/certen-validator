package execution

import (
	"context"
	"errors"
	"testing"
)

// RB3-F124: the per-intent V6.1 submission path refuses by name before anything else - it would send an empty
// aggregate and a hardcoded governance proof - and nothing it builds leaves it.
func TestThePerIntentSubmissionPathIsRetired(t *testing.T) {
	ecm := &EthereumContractManager{}
	if _, err := ecm.SubmitCertenProofToAnchor(context.Background(), nil, nil, nil); !errors.Is(err, errPerIntentSubmissionRetired) {
		t.Fatalf("SubmitCertenProofToAnchor: %v", err)
	}
	if _, _, err := ecm.ExecuteUnifiedAnchorWorkflow(context.Background(), nil, nil, nil); !errors.Is(err, errPerIntentSubmissionRetired) {
		t.Fatalf("ExecuteUnifiedAnchorWorkflow: %v", err)
	}
	if _, _, _, err := ecm.ExecuteUnifiedAnchorWorkflowFull(context.Background(), nil, nil, nil, [20]byte{}, nil, nil); !errors.Is(err, errPerIntentSubmissionRetired) {
		t.Fatalf("ExecuteUnifiedAnchorWorkflowFull: %v", err)
	}
	if p := ecm.convertToContractProof(nil, nil, nil); p != nil {
		t.Fatalf("convertToContractProof built %+v", p)
	}
}
