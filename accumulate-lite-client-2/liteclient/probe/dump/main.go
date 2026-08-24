package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	cp "github.com/certen/certen-protocol/services/validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
)

func main() {
	ctx := context.Background()
	b := cp.NewProofBuilder(jsonrpc.NewClient("https://kermit.accumulatenetwork.io/v3"), false)
	cases := []struct{ acct, tx, bvn, out string }{
		{"acc://carp-buyer-62431.acme/data", "51b0ba6abf413762fd3db7bcb12a2c56ee2806fcd8405640537f92b791aedcf0", "bvn1", "proof_bvn1.json"},
		{"acc://certen-panel-carp-v7.acme/data", "37e28c94ce760872db514b22ffb483dbfc288204b94b22ad1d9c1c022357c750", "bvn3", "proof_bvn3.json"},
	}
	for _, c := range cases {
		p, err := b.BuildProof(ctx, cp.ProofInput{Account: c.acct, TxHash: c.tx, BVN: c.bvn})
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", c.out, err)
			os.Exit(1)
		}
		raw, _ := json.MarshalIndent(p, "", " ")
		if err := os.WriteFile(os.Args[1]+"/"+c.out, raw, 0644); err != nil {
			panic(err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s (%d bytes)\n", c.out, len(raw))
	}
}
