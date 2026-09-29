package consensus

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/proof"
)

// RB4-F13: every way the governance block fails the intent says which class the failure is - a verdict on the
// intent (ErrGovernanceUnsatisfied) or a proof that could not be produced (ErrGovernanceUnavailable).
func TestEveryGovernanceFailureCarriesItsClass(t *testing.T) {
	src, err := os.ReadFile("bft_integration.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	start := strings.Index(s, "if liteClientProof != nil && bv.governanceProofGen != nil {")
	end := strings.Index(s, "certenProof.G0Result = g0Proof")
	if start < 0 || end < start {
		t.Fatal("the governance block moved; update this test to find it")
	}
	block := s[start:end]
	returns := regexp.MustCompile(`return nil, fmt\.Errorf\((?s:.*?)\)\n`).FindAllString(block, -1)
	if len(returns) < 15 {
		t.Fatalf("found %d failure returns in the governance block; expected every G0/G1/G2 failure", len(returns))
	}
	for _, r := range returns {
		if !strings.Contains(r, "ErrGovernanceUnsatisfied") && !strings.Contains(r, "ErrGovernanceUnavailable") && !strings.Contains(r, "class,") {
			t.Errorf("a governance failure carries no class:\n%s", r)
		}
	}
}

func TestAnUnentitledIntentIsTypedAsSuch(t *testing.T) {
	src, err := os.ReadFile("bft_integration.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), `Error: fmt.Errorf("intent %s refused: %w: principal %q has no entitlement evidence",`) ||
		!strings.Contains(string(src), "certenIntent.IntentID, ErrNotEntitled, principal)") {
		t.Fatal("the entitlement refusal does not carry ErrNotEntitled")
	}
}

// RB4-F62: a governance proof that failed because the transaction's authority set did not vote to accept it is a
// verdict on the intent. It was classed ErrGovernanceUnavailable with every other failure of the proof, which left
// the unsatisfied class unreachable from G1 and G2.
func TestAGovernanceProofsVerdictIsUnsatisfied(t *testing.T) {
	verdict := fmt.Errorf("%w: governance proof CLI for G1: Threshold not satisfied: 1/2", proof.ErrGovernanceNotSatisfied)
	if got := governanceProofFailureClass(verdict); got != ErrGovernanceUnsatisfied {
		t.Fatalf("a G1 verdict was classed %v", got)
	}
	if got := governanceProofFailureClass(errors.New("governance proof CLI for G1 failed: connection reset")); got != ErrGovernanceUnavailable {
		t.Fatalf("an outage was classed %v", got)
	}
}

// The G1 and G2 proofs' failures are classed by what failed, not all as unavailable.
func TestG1AndG2FailuresAreClassedByWhatFailed(t *testing.T) {
	src, err := os.ReadFile("bft_integration.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, level := range []string{"g1", "g2"} {
		want := fmt.Sprintf("governanceProofFailureClass(%sErr)", level)
		if !strings.Contains(string(src), want) {
			t.Errorf("the %s proof's failure is not classed by governanceProofFailureClass", strings.ToUpper(level))
		}
	}
}
