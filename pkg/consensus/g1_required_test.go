package consensus

import (
	"testing"

	"github.com/certen/independant-validator/pkg/ledger"
)

// RB9-I item 4: the proposer-side answer the intent discovery asks per intent (intent.ProofV2G1Gate) is the activation in force for the NEXT
// block, from the same committed state certificates are built against.
func TestTheProposerAsksTheActivationInForceForTheNextBlock(t *testing.T) {
	var _ interface{ G1CrossPartitionRequired() (bool, error) } = (*ValidatorApp)(nil)
	app, store := rotationApp(t, newRotationFixture())

	app.latestHeight = 20
	if on, err := app.G1CrossPartitionRequired(); err != nil || on {
		t.Fatalf("no activation recorded: %v %v", on, err)
	}
	if err := store.SaveG1Activation(&ledger.G1ActivationLog{Activations: []ledger.G1ActivationRecord{*g1Active}}); err != nil {
		t.Fatal(err)
	}
	// g1Active was accepted at height 12: blocks above 12 carry 2.1.
	for _, c := range []struct {
		latest int64
		on     bool
	}{{10, false}, {11, false}, {12, true}, {13, true}, {200, true}} {
		app.latestHeight = c.latest
		on, err := app.G1CrossPartitionRequired()
		if err != nil || on != c.on {
			t.Fatalf("latest height %d (next block %d): %v %v, want %v", c.latest, c.latest+1, on, err, c.on)
		}
	}
}
