package consensus

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// countingOrchestrator counts the proof cycles it is asked to start.
type countingOrchestrator struct{ cycles int }

func (r *countingOrchestrator) StartProofCycle(context.Context, string, [32]byte, common.Hash, interface{}) error {
	r.cycles++
	return nil
}
func (r *countingOrchestrator) StartProofCycleWithAllTxs(context.Context, string, string, [32]byte, interface{}, interface{}) error {
	r.cycles++
	return nil
}
func (r *countingOrchestrator) StartProofCycleWithAccumulateRef(context.Context, string, string, [32]byte, interface{}, interface{}, string, string, string) error {
	r.cycles++
	return nil
}
func (r *countingOrchestrator) StartPerChainProofCycles(context.Context, string, string, [32]byte, map[string][]string, interface{}, string, interface{}, string, string, string) error {
	r.cycles++
	return nil
}

// liveFailedIntent is intent 5a2ebba0 as it was written to Accumulate.
func liveFailedIntent(t *testing.T) *CertenIntent {
	t.Helper()
	read := func(i int) []byte {
		b, err := os.ReadFile(filepath.Join("testdata", "intent_5a2ebba0", "blob"+string(rune('0'+i))+".json"))
		if err != nil {
			t.Fatalf("blob %d: %v", i, err)
		}
		return b
	}
	return &CertenIntent{
		IntentID:        "5a2ebba0-a722-4db6-bc6b-0f9aff4036a4",
		TransactionHash: "aad58e15bd8395d6f3d7b8d5c17cc69b6a4a6190299afe0f84a5d59a696a0600",
		AccountURL:      "acc://orchid-logistics-tcl1.acme/data",
		OrganizationADI: "acc://orchid-logistics-tcl1.acme",
		IntentData:      read(0),
		CrossChainData:  read(1),
		GovernanceData:  read(2),
		ReplayData:      read(3),
	}
}

func failureTestValidator(orch ProofCycleOrchestratorInterface) *BFTValidator {
	return &BFTValidator{
		logger:                 log.New(os.Stderr, "[test] ", 0),
		proofCycleOrchestrator: orch,
	}
}

// A member reported SETTLED with no transaction is not a failure. Failover validators reported
// exactly this for every on-demand intent another validator had settled, and it was recorded as a
// failure that contradicted the chain.
func TestSettledWithoutATransactionIsNotRecordedAsAFailure(t *testing.T) {
	orch := &countingOrchestrator{}
	bv := failureTestValidator(orch)
	att := &PendingAttestation{IntentID: "x", CertenIntent: liveFailedIntent(t)}

	bv.RunBatchMemberAttestation(context.Background(), att, "", 84532, true)

	if orch.cycles != 0 {
		t.Fatalf("started %d cycle(s) for a settled member with no transaction", orch.cycles)
	}
}
