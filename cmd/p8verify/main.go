// Copyright 2026 Certen Protocol
//
// p8verify — rebuild ONE transaction's proof through the PRODUCTION entry point
// and report what the govRoot preimage would commit to.
//
// # WHY
//
// Phase 8 item 1's claim has two halves, and they need different evidence:
//
//	the proof carries a leg per signer partition   <- checkable from the chain
//	that proof reassembles from STORAGE and verifies <- needs the proof database
//
// This is the first half, and it is the half that says whether
// ConsensusProof.BVNs — the slot that has been ABSENT from every govRoot ever
// computed in production — is populated. `BVNs` is `omitempty`, so an absent
// slot and an empty one are the same bytes; the only way to tell a
// single-partition proof from a multi-partition proof whose extra legs were
// dropped is to count them and say so.
//
// It drives GenerateChainedProof — the same entry point the validators call —
// rather than reaching for BuildMultiPartitionProof directly. A capability that
// production never invokes is the same as not having it, except that it reads
// as if you do.
//
// Read-only: it queries Kermit and submits nothing.
//
//	go run ./cmd/p8verify -account acc://certen-kermit-12.acme/data -tx <hash>
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	proofpkg "github.com/certen/independant-validator/pkg/proof"
)

func main() {
	var (
		endpoint = flag.String("endpoint", "https://kermit.accumulatenetwork.io/v3", "Accumulate v3 endpoint")
		account  = flag.String("account", "", "the transaction's principal account")
		txHash   = flag.String("tx", "", "the transaction hash (64 hex, no 0x)")
		wantLegs = flag.Int("want-legs", 0, "fail unless the proof carries exactly this many legs (0 = report only)")
	)
	flag.Parse()
	if *account == "" || *txHash == "" {
		fmt.Fprintln(os.Stderr, "usage: p8verify -account <acc://.../data> -tx <hash> [-want-legs N]")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	gen, err := proofpkg.NewLiteClientProofGenerator(*endpoint, 10*time.Minute)
	if err != nil {
		fatal("%v", err)
	}
	bvn := proofpkg.CalculateBVNFromAccountURL(*account)
	cp, err := gen.GenerateChainedProof(ctx, *account, *txHash, bvn)
	if err != nil {
		fatal("production GenerateChainedProof: %v", err)
	}

	legs := cp.Legs()
	fmt.Printf("\n== what production built ==\n")
	fmt.Printf("  account            %s (principal partition %s)\n", *account, bvn)
	fmt.Printf("  legs               %d %v\n", len(legs), cp.SignerPartitions())
	for _, l := range legs {
		n, thr := 0, uint64(0)
		if l.Layer4BVN != nil {
			n, thr = len(l.Layer4BVN.Signatures), l.Layer4BVN.Threshold
		}
		fmt.Printf("    leg %-10s L1 block %d, L4 quorum %d/%d\n",
			l.Partition, l.Layer1.BVNMinorBlockIndex, n, thr)
	}

	// Offline: no network, from the object alone.
	if err := chained_proof.NewProofVerifier(false).Verify(ctx, cp); err != nil {
		fatal("the proof does NOT verify offline: %v", err)
	}
	fmt.Printf("  offline verify     OK (all %d leg(s))\n", len(legs))

	// The govRoot preimage. This is the byte-level claim TX2 checks against.
	consensus := proofpkg.BuildL4ConsensusProofFromProof(cp)
	if consensus == nil {
		fatal("no consensus summary could be built — a leg the proof names carries no quorum " +
			"evidence, and a summary without it would commit to a smaller quorum set than the " +
			"proof claims")
	}
	fmt.Printf("\n== the govRoot preimage (L4ConsensusProofH) ==\n")
	fmt.Printf("  version            %s\n", consensus.Version)
	fmt.Printf("  bvn (principal)    %s: %d signer(s), threshold %d\n",
		consensus.BVN.Partition, len(consensus.BVN.Signers), consensus.BVN.Threshold)
	fmt.Printf("  dn                 %s: %d signer(s), threshold %d\n",
		consensus.DN.Partition, len(consensus.DN.Signers), consensus.DN.Threshold)
	if len(consensus.BVNs) == 0 {
		fmt.Printf("  bvns               ABSENT (omitempty) — this root commits to ONE signer partition\n")
	} else {
		fmt.Printf("  bvns               PRESENT, %d additional partition(s)\n", len(consensus.BVNs))
		for _, b := range consensus.BVNs {
			fmt.Printf("    bvns[] %-10s %d signer(s), threshold %d\n",
				b.Partition, len(b.Signers), b.Threshold)
		}
	}

	// FAIL CLOSED on the mismatch that matters: a root committing to one leg of
	// a multi-leg proof is perfectly well-formed and attests to less than the
	// proof carries.
	if len(legs) > 1 && len(consensus.BVNs) == 0 {
		fatal("the proof carries %d legs and the preimage commits to ONE signer partition", len(legs))
	}
	if *wantLegs > 0 && len(legs) != *wantLegs {
		fatal("expected %d leg(s), got %d", *wantLegs, len(legs))
	}
	fmt.Println()
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "p8verify: "+format+"\n", args...)
	os.Exit(1)
}
