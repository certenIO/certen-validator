// vsproof builds a ValidatorSetProof from a live Accumulate network and
// verifies it offline, printing the verdict.
//
// It exists so the producer and consumer halves can be exercised end to end
// without touching the proof cycle, and so an operator can see for themselves
// what the current evidence does and does not establish.
//
//	vsproof                                   # build from Kermit, verify, report
//	vsproof -endpoint https://mainnet.accumulatenetwork.io/v3
//	vsproof -pin <hex32>                      # supply the out-of-band incarnation
//	vsproof -out proof.json                   # write the evidence
//
// Exit codes mirror cmd/proofverify:
//
//	0  verified
//	1  proven wrong - tampering or corruption
//	2  usage
//	3  a named weaker state; nothing is known to be wrong
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	certenproof "github.com/certen/independant-validator/pkg/proof"
)

const (
	exitVerified = 0
	exitFailed   = 1
	exitUsage    = 2
	exitWeaker   = 3
)

func main() {
	endpoint := flag.String("endpoint", "https://kermit.accumulatenetwork.io/v3",
		"Accumulate v3 endpoint")
	pin := flag.String("pin", "",
		"the out-of-band incarnation identity (hex32). Without it the verdict is "+
			"incarnation_unverified, because the derivation is otherwise circular.")
	bind := flag.String("bind", "",
		"a quorum-signed StateTreeAnchor to bind the BPT root to (hex32). Not "+
			"achievable today - see the note printed below.")
	out := flag.String("out", "", "write the proof as JSON to this path")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	fmt.Printf("Building a validator-set proof from %s\n\n", *endpoint)
	p, err := certenproof.BuildValidatorSetProof(ctx, certenproof.NewHTTPQuerier(*endpoint))
	if err != nil {
		fmt.Printf("COULD NOT BUILD\n  %v\n", err)
		os.Exit(exitFailed)
	}

	set, thr, err := p.DerivedSet()
	if err != nil {
		fmt.Printf("FAILED  the built proof does not decode\n  %v\n", err)
		os.Exit(exitFailed)
	}
	height, _ := p.MainChainHeight()

	fmt.Printf("  incarnation        %s\n", p.Incarnation)
	fmt.Printf("  BPT root           %s\n", p.Network.StateReceipt.Anchor)
	fmt.Printf("  derived validators %d, threshold %d/%d\n", len(set), thr.Numerator, thr.Denominator)
	for _, v := range set {
		fmt.Printf("     %s  active on %v\n", v.PublicKey[:16], v.ActiveOn)
	}
	fmt.Printf("  network main chain height %d\n", height)
	if height == 1 {
		fmt.Printf("     => only the genesis entry exists, so this set has NEVER changed,\n")
		fmt.Printf("        so it IS the genesis set of this incarnation\n")
	}
	fmt.Println()

	in := certenproof.VerifyInput{
		AssertedSet: set, AssertedThreshold: thr, BoundStateTreeAnchor: *bind,
	}
	if *pin != "" {
		in.PinnedIncarnation = pin
	}

	verdict, err := p.Verify(in)
	if err != nil {
		fmt.Printf("FAILED\n  %v\n", err)
		fmt.Printf("  The evidence is present and does not check out. This is not a capability\n")
		fmt.Printf("  limit; something is wrong with the proof.\n")
		os.Exit(exitFailed)
	}

	if *out != "" {
		b, _ := json.MarshalIndent(p, "", "  ")
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			fmt.Printf("  (could not write %s: %v)\n", *out, err)
		} else {
			fmt.Printf("  evidence written to %s (%d bytes)\n\n", *out, len(b))
		}
	}

	fmt.Printf("VERDICT: %s\n\n", verdict)
	switch verdict {
	case certenproof.VerdictVerified:
		fmt.Printf("  The validator set was DERIVED from chain bytes, bound to a quorum-signed\n")
		fmt.Printf("  anchor, and the incarnation matched the pin you supplied.\n")
		os.Exit(exitVerified)

	case certenproof.VerdictValidatorSetUnbound:
		fmt.Printf("  The set is DERIVED - it came from the account's own bytes with a merkle\n")
		fmt.Printf("  path, not from a build-time RPC. It is NOT BOUND: the BPT root it was\n")
		fmt.Printf("  proven into is not tied to a quorum-signed anchor.\n\n")
		fmt.Printf("  That is expected today and is a CAPABILITY LIMIT, not a fault. An account\n")
		fmt.Printf("  query returns a receipt against the CURRENT BPT root, and roots are\n")
		fmt.Printf("  anchored only at emission points - about 1 per 46 blocks on Kermit and 1\n")
		fmt.Printf("  per 2,524 on MainNet - so a fresh root is almost never one of them.\n")
		fmt.Printf("  Binding to a specific transaction's anchor needs a membership proof\n")
		fmt.Printf("  against a HISTORICAL root, which is what AIP-058 asks for.\n")
		os.Exit(exitWeaker)

	case certenproof.VerdictIncarnationUnverified:
		fmt.Printf("  The set is derived and bound, but you supplied no -pin, so nothing\n")
		fmt.Printf("  independent fixes WHICH chain this is. Without that the derivation is\n")
		fmt.Printf("  circular: the set authenticates the anchor and the anchor authenticates\n")
		fmt.Printf("  the set, and an adversary who fabricated a whole consistent chain would\n")
		fmt.Printf("  pass every check here.\n")
		os.Exit(exitWeaker)

	case certenproof.VerdictForeignIncarnation:
		fmt.Printf("  This proof belongs to a DIFFERENT Accumulate incarnation than the one you\n")
		fmt.Printf("  pinned. Content and timing may still hold; validator-set legitimacy does\n")
		fmt.Printf("  not carry across a network restart, and nothing can make it.\n")
		os.Exit(exitWeaker)

	default:
		fmt.Printf("  A weaker state. Nothing about this proof is known to be wrong.\n")
		os.Exit(exitWeaker)
	}
}
