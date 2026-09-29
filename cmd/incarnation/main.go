// incarnation computes the Accumulate incarnation identity that every CertenAnchorV8_2 anchor commits
// (docs/l4/INCARNATION_ANCHOR.md), from sources anyone can fetch, and prints every input.
//
//	incarnation                                        # fetch from Kermit, verify, print
//	incarnation -endpoint https://mainnet.accumulatenetwork.io/v3 -bvn bvnCyclops
//	incarnation -out kermit.json                       # also write the evidence
//	incarnation -verify kermit.json                    # re-derive offline from saved evidence, no network
//
// Exit codes: 0 derived and verified; 1 the evidence does not establish an incarnation; 2 usage.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	certenproof "github.com/certen/independant-validator/pkg/proof"
)

func main() {
	endpoint := flag.String("endpoint", "https://kermit.accumulatenetwork.io/v3", "Accumulate v3 endpoint")
	bvn := flag.String("bvn", "", "the BVN whose anchor pool the genesis anchor's signed delivery is read from "+
		"(default: the first block-validator partition of the genesis network record)")
	out := flag.String("out", "", "write the evidence as JSON to this path")
	verify := flag.String("verify", "", "re-derive offline from this evidence file (no network)")
	flag.Parse()

	var ev *certenproof.IncarnationEvidence
	if *verify != "" {
		b, err := os.ReadFile(*verify)
		if err != nil {
			fmt.Println(err)
			os.Exit(2)
		}
		ev = new(certenproof.IncarnationEvidence)
		if err := json.Unmarshal(b, ev); err != nil {
			fmt.Printf("the evidence file does not decode: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Re-deriving offline from %s (fetched from %s)\n\n", *verify, ev.Endpoint)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		fmt.Printf("Fetching from %s\n\n", *endpoint)
		var err error
		ev, err = certenproof.BuildIncarnationEvidence(ctx, certenproof.NewHTTPQuerier(*endpoint),
			certenproof.NewLiveGenesisLegBuilder(*endpoint), *endpoint, *bvn)
		if err != nil {
			fmt.Printf("COULD NOT DERIVE\n  %v\n", err)
			os.Exit(1)
		}
	}

	rep, err := ev.Verify()
	if err != nil {
		fmt.Printf("DOES NOT VERIFY\n  %v\n", err)
		os.Exit(1)
	}
	in := rep.Inputs
	fmt.Printf("  network name              %s\n", rep.NetworkName)
	fmt.Printf("  genesis block             %d\n", in.GenesisMinorBlockIndex)
	fmt.Printf("  genesis root chain anchor %x   (anchor(directory)-root[0])\n", in.GenesisRootChainAnchor)
	fmt.Printf("  genesis state tree anchor %x   (anchor(directory)-bpt[0])\n", in.GenesisStateTreeAnchor)
	fmt.Printf("  genesis time              %s   (unix %d, acc://dn.acme/ledger/1)\n", rep.GenesisTime, in.GenesisTimeUnix)
	fmt.Printf("  network record            %d bytes, sha256 %s\n", len(in.NetworkRecord), sha(in.NetworkRecord))
	fmt.Printf("  globals record            %d bytes, sha256 %s\n", len(in.GlobalsRecord), sha(in.GlobalsRecord))
	fmt.Printf("  genesis validators        %d, accept threshold %d/%d\n", len(rep.Validators), rep.Threshold.Numerator, rep.Threshold.Denominator)
	for _, v := range rep.Validators {
		fmt.Printf("      %s  active on %v\n", v.PublicKey, v.ActiveOn)
	}
	fmt.Printf("  genesis anchor quorum     %d distinct valid Directory signatures, %d required\n", rep.GenesisSigners, rep.GenesisThreshold)
	fmt.Printf("  records proven into       BPT root %s\n", rep.RecordsRoot)
	fmt.Printf("      (the serving node's current root; not certified by a quorum here - RB6 §3 certifies it)\n\n")
	fmt.Printf("INCARNATION  0x%x\n", rep.Incarnation)

	if *out != "" {
		b, _ := json.MarshalIndent(ev, "", "  ")
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			fmt.Printf("could not write %s: %v\n", *out, err)
			os.Exit(1)
		}
		fmt.Printf("evidence written to %s (%d bytes)\n", *out, len(b))
	}
}

func sha(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
