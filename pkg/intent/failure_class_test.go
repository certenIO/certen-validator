package intent

import (
	"errors"
	"fmt"
	"testing"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/database"
)

// RB4-F13: the class comes from the typed error, wrapped as consensus wraps it on its way back to discovery.
func TestAFailureIsClassifiedFromItsTypedError(t *testing.T) {
	back := func(err error) error { // the path from the consensus workflow to processIntent's return
		return fmt.Errorf("canonical BFT execution failed: %w", fmt.Errorf("canonical BFT workflow failed: %w", err))
	}
	for name, c := range map[string]struct {
		err  error
		want database.IntentFailureClass
	}{
		"refused by the batch path":            {back(fmt.Errorf("intent i refused: %w: %w", consensus.ErrIntentPermanentlyInvalid, errors.New("declared anchor is not live"))), database.FailureRefused},
		"not entitled":                         {back(fmt.Errorf("intent i refused: %w: principal %q has no entitlement evidence", consensus.ErrNotEntitled, "acc://x.acme")), database.FailureNotEntitled},
		"governance unsatisfied":               {back(fmt.Errorf("%w: G1 governance proof incomplete", consensus.ErrGovernanceUnsatisfied)), database.FailureGovernanceUnsatisfied},
		"governance unavailable":               {back(fmt.Errorf("%w: G0 governance proof failed: dial tcp: timeout", consensus.ErrGovernanceUnavailable)), database.FailureGovernanceUnavailable},
		"untyped":                              {back(errors.New("ValidatorBlock admitted but not committed")), database.FailureProcessingFailed},
		"proof unavailable, retries exhausted": {fmt.Errorf("intent i: %w", errChainedProofUnavailable), database.FailureProcessingFailed},
		// Its own defect first: an intent both permanently invalid and unentitled is refused.
		"permanently invalid and unentitled": {back(fmt.Errorf("%w: %w", consensus.ErrNotEntitled, consensus.ErrIntentPermanentlyInvalid)), database.FailureRefused},
	} {
		if got := failureClassOf(c.err); got != c.want {
			t.Errorf("%s: classified %s, want %s", name, got, c.want)
		}
	}
}
