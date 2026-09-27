// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/proof"
)

// RB3-F89: a chained proof is built on the partition the transaction was discovered on, never a guessed
// one. An empty BVN used to be recomputed from the account URL through a hard-coded Kermit routing table,
// and defaulted to bvn1 when that failed.
func TestAProofIsNeverBuiltOnAGuessedPartition(t *testing.T) {
	gen, err := proof.NewLiteClientProofGenerator("http://127.0.0.1:1/v3", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewLiteClientProofGeneratorAdapter(gen).GenerateChainedProofForTx(context.Background(),
		"acc://harbor.acme/data", strings.Repeat("ab", 32), "")
	if err == nil || !strings.Contains(err.Error(), "no partition") {
		t.Fatalf("a proof was attempted on a guessed partition: %v", err)
	}
}

// The proof cycle is started with the partition consensus used, not "".
func TestTheProofCycleIsGivenTheDiscoveredPartition(t *testing.T) {
	raw, err := os.ReadFile("../consensus/async_attestation.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	if n := strings.Count(src, "att.CertenIntent.Partition,\n\t); err != nil {"); n != 2 {
		t.Fatalf("%d of the 2 proof-cycle starts pass the discovered partition", n)
	}
}
