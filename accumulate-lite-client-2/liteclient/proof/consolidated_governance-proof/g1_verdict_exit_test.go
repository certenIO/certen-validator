// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"errors"
	"testing"
)

// RB4-F62. An authority set that did not vote to accept is a verdict on the transaction. The verifier said so, and
// then G1, G2 and main each flattened it with %v and the CLI exited 1 - the exit every outage takes - so the validator
// recorded a governance rejection as "governance proof unavailable" and its unsatisfied branch could never be reached.
// The verdict is now a type of its own, carried to the process exit.

func unsatisfiedVerdict(t *testing.T) error {
	t.Helper()
	_, err := verdict(t, fixedEvaluator{vote: &AccountVote{Account: alphaData, Satisfied: false,
		Authorities: []AuthorityVote{{Authority: alphaBook}}}})
	if err == nil {
		t.Fatal("an unsatisfied authority set produced no error")
	}
	return err
}

func TestAuthVotes_UnsatisfiedIsANamedVerdict(t *testing.T) {
	err := unsatisfiedVerdict(t)
	var ns *AuthorizationNotSatisfied
	if !errors.As(err, &ns) {
		t.Fatalf("an unsatisfied authority set produced %v (%T), not an AuthorizationNotSatisfied verdict", err, err)
	}
	// It is still the rejection it always was.
	var ve ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("the verdict stopped being a validation failure: %v", err)
	}
}

// The verdict, through every wrap between the verifier and the process exit, exits with its own code.
func TestAnUnsatisfiedVerdictExitsAsOne(t *testing.T) {
	err := proofGenerationFailed(g1ProofFailed(authorizationEvaluationFailed(unsatisfiedVerdict(t))))
	if got := exitCodeFor(err); got != exitGovernanceNotSatisfied {
		t.Fatalf("the verdict exited %d; want %d (%v)", got, exitGovernanceNotSatisfied, err)
	}
}

// Nothing else is a verdict: an outage, incomplete evidence and any other failure exit 1, as before.
func TestOnlyTheVerdictExitsAsOne(t *testing.T) {
	incomplete := authorizationEvaluationFailed(&SignatureEvidenceIncomplete{Route: "test", Requested: 1})
	if _, ok := IsEvidenceIncomplete(incomplete); !ok {
		t.Fatalf("incomplete evidence stopped being returned as-is: %v", incomplete)
	}
	for _, err := range []error{
		proofGenerationFailed(g1ProofFailed(incomplete)),
		proofGenerationFailed(g1ProofFailed(authorizationEvaluationFailed(ValidationError{Msg: "G1 incomplete: timingValid=false"}))),
		proofGenerationFailed(errors.New("rpc: connection reset by peer")),
	} {
		if got := exitCodeFor(err); got != 1 {
			t.Errorf("%v exited %d; only the verdict exits %d", err, got, exitGovernanceNotSatisfied)
		}
	}
}
