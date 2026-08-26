package main

// Does the PRODUCTION path build a multi-partition proof on its own?
//
// Everything else proves the capability exists. This proves the pipeline
// reaches for it without being told to: the same entry point the validators
// call, given a real cross-partition transaction, must discover the signer
// partitions itself and emit a leg for each.
//
// A capability that production never invokes is the same as not having it,
// except that it reads as if you do.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	proofpkg "github.com/certen/independant-validator/pkg/proof"
)

// baselineTx is a delivered 1-of-1 transaction on the production ADI, used to
// prove the shape all existing traffic uses is unaffected.
var baselineTx = "1f25bb6ae4cad401ddede00c5711d871b02dd0bae20e027d2194fae5c7f12c5f"

func checkProductionPath(ctx context.Context, endpoint string, raw map[string]json.RawMessage) error {
	cases, err := parseCases(raw)
	if err != nil {
		return err
	}
	traces, err := readJSON[captureResult](traceFile)
	if err != nil {
		return err
	}

	check := func(name string) error {
		cs, ok := cases[name]
		if !ok && name != "A" {
			return fmt.Errorf("case %s absent", name)
		}
		var tr *trace
		for i := range traces.Traces {
			if traces.Traces[i].Case == name && traces.Traces[i].ExecStatus == "delivered" {
				tr = &traces.Traces[i]
				break
			}
		}
		if tr == nil {
			return fmt.Errorf("case %s has no delivered trace", name)
		}
		principal := cs.Principal
		if principal == "" {
			principal = cs.ADI
		}
		account := principal + "/data"

		legs, err := proofpkg.DiscoverSignerLegs(ctx, endpoint,
			"acc://"+tr.TransactionHash+"@"+strings.TrimPrefix(account, "acc://"))
		if err != nil {
			return fmt.Errorf("case %s: %w", name, err)
		}
		// The union with the PRINCIPAL's partition, which is what decides how
		// many legs the proof needs. Case F has one signer account and still
		// needs two legs, because the principal is on another partition.
		principalPart := proofpkg.CalculateBVNFromAccountURL(account)
		parts := proofpkg.DistinctPartitions(append(
			append([]chained_proof.SignerLeg{}, legs...),
			chained_proof.SignerLeg{Account: account, Partition: principalPart},
		))
		fmt.Printf("  case %-2s %-38s signers=%d principal=%s span=%v legs_needed=%d\n",
			name, shortURL(account), len(legs), principalPart, parts, len(parts))
		return nil
	}

	fmt.Println("== what the production path discovers, unaided ==")
	for _, n := range []string{"B", "D", "F"} {
		if err := check(n); err != nil {
			return err
		}
	}

	// And now drive the PRODUCTION entry point itself, on the cross-partition
	// case. Discovery being right is necessary; this is the part that shows the
	// pipeline acts on it.
	f := cases["F"]
	var fTrace *trace
	for i := range traces.Traces {
		if traces.Traces[i].Case == "F" && traces.Traces[i].ExecStatus == "delivered" {
			fTrace = &traces.Traces[i]
			break
		}
	}
	if fTrace == nil {
		return fmt.Errorf("case F has no delivered trace")
	}

	gen, err := proofpkg.NewLiteClientProofGenerator(endpoint, 10*time.Minute)
	if err != nil {
		return err
	}
	account := f.Principal + "/data"
	cp, err := gen.GenerateChainedProof(ctx, account, fTrace.TransactionHash,
		proofpkg.CalculateBVNFromAccountURL(account))
	if err != nil {
		return fmt.Errorf("production GenerateChainedProof for case F: %w", err)
	}
	fmt.Printf("\nproduction built case F with %d leg(s): %v\n",
		len(cp.Legs()), cp.SignerPartitions())
	if len(cp.Legs()) < 2 {
		return fmt.Errorf("production emitted %d leg(s) for a two-partition transaction",
			len(cp.Legs()))
	}
	if err := chained_proof.NewProofVerifier(false).Verify(ctx, cp); err != nil {
		return fmt.Errorf("production proof does not verify offline: %w", err)
	}
	fmt.Println("production's cross-partition proof VERIFIES OFFLINE")

	// The regression that matters more than any of it: the 1-of-1 shape every
	// production proof uses must be untouched. Discovery now runs in front of
	// every build, so a mistake there would break all traffic, not just the
	// cross-partition case that has none yet.
	if baselineTx != "" {
		baseAcct := "acc://certen-kermit-12.acme/data"
		bcp, err := gen.GenerateChainedProof(ctx, baseAcct, baselineTx,
			proofpkg.CalculateBVNFromAccountURL(baseAcct))
		if err != nil {
			return fmt.Errorf("production baseline (1-of-1) build: %w", err)
		}
		if len(bcp.Legs()) != 1 {
			return fmt.Errorf("the 1-of-1 baseline built %d legs; it must build exactly one",
				len(bcp.Legs()))
		}
		if err := chained_proof.NewProofVerifier(false).Verify(ctx, bcp); err != nil {
			return fmt.Errorf("production baseline proof does not verify: %w", err)
		}
		fmt.Printf("baseline 1-of-1 still builds %d leg %v and VERIFIES OFFLINE\n",
			len(bcp.Legs()), bcp.SignerPartitions())
	}
	return nil
}
