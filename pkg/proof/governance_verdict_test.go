package proof

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"
)

// RB4-F62. The governance proof CLI exited 1 for everything, so this adapter returned the same plain error for "the
// authority set did not vote to accept this transaction" as for an RPC outage, and the validator recorded every
// governance rejection as "governance proof unavailable". The CLI now exits with its own status for that verdict and
// the adapter names it.

const fakeGovProofExit = "CERTEN_FAKE_GOVPROOF_EXIT"

// TestMain lets this test binary stand in for the govproof CLI: run with fakeGovProofExit set, it exits with that
// status the way the CLI does, its reason on stderr.
func TestMain(m *testing.M) {
	if code := os.Getenv(fakeGovProofExit); code != "" {
		n, _ := strconv.Atoi(code)
		fmt.Fprintf(os.Stderr, "Error: proof generation failed: authorization evaluation failed: Threshold not satisfied: 1/2\n")
		os.Exit(n)
	}
	os.Exit(m.Run())
}

func fakeGovProof(t *testing.T, exit int) error {
	t.Helper()
	t.Setenv(fakeGovProofExit, strconv.Itoa(exit))
	gen, err := NewCLIGovernanceProofGenerator(os.Args[0], "http://127.0.0.1:1/v3", t.TempDir(), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = gen.GenerateAtLevel(context.Background(), GovLevelG0, &GovernanceRequest{
		AccountURL:      "acc://f62.acme/data",
		TransactionHash: "ab" + "00000000000000000000000000000000000000000000000000000000000000",
	})
	if err == nil {
		t.Fatalf("a CLI exiting %d produced no error", exit)
	}
	return err
}

func TestTheCLIsVerdictIsNamed(t *testing.T) {
	if err := fakeGovProof(t, GovProofExitNotSatisfied); !errors.Is(err, ErrGovernanceNotSatisfied) {
		t.Fatalf("the CLI's not-satisfied exit produced %v, not ErrGovernanceNotSatisfied", err)
	}
}

func TestAnyOtherCLIFailureIsNoVerdict(t *testing.T) {
	for _, exit := range []int{1, 2} {
		if err := fakeGovProof(t, exit); errors.Is(err, ErrGovernanceNotSatisfied) {
			t.Fatalf("exit %d was read as a governance verdict: %v", exit, err)
		}
	}
}

// The status is a contract between two programs: the CLI's source must say the same number.
func TestTheVerdictStatusIsTheCLIs(t *testing.T) {
	src, err := os.ReadFile("../../accumulate-lite-client-2/liteclient/proof/consolidated_governance-proof/main.go")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`const exitGovernanceNotSatisfied = (\d+)`).FindSubmatch(src)
	if m == nil {
		t.Fatal("the governance proof CLI declares no exitGovernanceNotSatisfied")
	}
	if n, _ := strconv.Atoi(string(m[1])); n != GovProofExitNotSatisfied {
		t.Fatalf("the CLI exits %d for a verdict, this adapter reads %d", n, GovProofExitNotSatisfied)
	}
}
