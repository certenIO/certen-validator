//go:build live

// Copyright 2026 Certen Protocol

// Behind the live build tag rather than a skip (00_STANDARD §2, RB3-F83): without the tag it is not
// compiled; with it, a missing input is a failure, never a pass.

package proof

import (
	"context"
	"testing"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/execution/contracts"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
)

// End-to-end: a REAL proof built from live Kermit must commit a non-zero L4
// slot, and the two legs must be signed by different partitions.
//
// Everything above uses synthetic legs. This proves the wiring works on the
// data the fleet actually sees.
func TestP5_LiveProofCommitsNonZeroL4(t *testing.T) {
	ep := "https://kermit.accumulatenetwork.io/v3"
	const (
		account = "acc://carp-buyer-62431.acme/data"
		txHash  = "51b0ba6abf413762fd3db7bcb12a2c56ee2806fcd8405640537f92b791aedcf0"
		bvn     = "bvn1"
	)

	b := chained_proof.NewProofBuilder(jsonrpc.NewClient(ep), false)
	cp, err := b.BuildProof(context.Background(), chained_proof.ProofInput{
		Account: account, TxHash: txHash, BVN: bvn,
	})
	if err != nil {
		t.Fatalf("build live proof: %v", err)
	}

	complete := ChainedProofToCompleteProof(cp)
	if complete.ConsensusProof == nil {
		t.Fatal("CRITICAL: a complete L1-L4 proof produced no L4 payload")
	}

	p := &CertenProof{LiteClientProof: &LiteClientProofData{
		CompleteProof:  complete,
		ConsensusProof: complete.ConsensusProof,
	}}
	if err := RequireL4Committed(p); err != nil {
		t.Fatalf("CRITICAL: live L4 payload rejected by the guard: %v", err)
	}

	in := contracts.NewAccumulateGovRootInputsBuilder().
		SetL4ConsensusProofFromJSON(p.LiteClientProof.ConsensusProof).Build()
	if in.L4ConsensusProofH == ([32]byte{}) {
		t.Fatal("CRITICAL: live proof still yields a ZERO L4 slot")
	}

	c := complete.ConsensusProof
	t.Logf("live L4 committed: %x", in.L4ConsensusProofH[:16])
	t.Logf("  version = %s", c.Version)
	t.Logf("  BVN  %-10s threshold=%d signers=%d stateTreeAnchor=%s",
		c.BVN.Partition, c.BVN.Threshold, len(c.BVN.Signers), c.BVN.StateTreeAnchor[:16])
	t.Logf("  DN   %-10s threshold=%d signers=%d stateTreeAnchor=%s",
		c.DN.Partition, c.DN.Threshold, len(c.DN.Signers), c.DN.StateTreeAnchor[:16])

	// The legs must bind the layers beneath them, or L4 commits to something
	// unrelated to this transaction.
	if c.BVN.StateTreeAnchor != cp.Layer2.BVNStateTreeAnchor {
		t.Fatalf("L4 BVN leg does not bind L2: %s != %s", c.BVN.StateTreeAnchor, cp.Layer2.BVNStateTreeAnchor)
	}
	if c.DN.StateTreeAnchor != cp.Layer3.DNStateTreeAnchor {
		t.Fatalf("L4 DN leg does not bind L3: %s != %s", c.DN.StateTreeAnchor, cp.Layer3.DNStateTreeAnchor)
	}
	if c.BVN.Partition == c.DN.Partition {
		t.Fatal("both legs signed by the same partition")
	}
}
