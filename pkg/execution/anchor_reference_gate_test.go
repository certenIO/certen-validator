package execution

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	chain "github.com/certen/independant-validator/pkg/chain/strategy"
)

// AGT-F11 Q5 test, written against the base (cf7f24b3) API only so it can be run there: a layer 5 that states no anchor
// block hash or time must yield no anchor reference. At cf7f24b3 writeAnchorReference goes on to the repository (here
// none, so it panics); on the fix it returns without writing.
func TestAnAnchorReferenceIsNotWrittenWithoutTheAnchorBlock(t *testing.T) {
	l5 := &Layer5{ChainID: 84532, AnchorTx: "0x43766439c30deea319debe031b6f00d90ef1cede7735b8969e3ba15212a0f1ad", BlockNumber: 60397757}
	o := &UnifiedOrchestrator{config: &UnifiedOrchestratorConfig{}}
	settled := &chain.ObservationResult{TxHash: "0x" + strings.Repeat("cd", 32), BlockNumber: 60397816, IsFinalized: true,
		BlockHash: "0x" + strings.Repeat("ef", 32), BlockTimestamp: time.Unix(1_795_000_000, 0)}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("an anchor reference was attempted without the anchor block (reached the repository): %v", r)
		}
	}()
	if err := o.writeAnchorReference(context.Background(), uuid.New(), &UnifiedProofCycleResult{ChainID: "84532"}, l5, settled); err != nil {
		t.Fatalf("error: %v", err)
	}
}
