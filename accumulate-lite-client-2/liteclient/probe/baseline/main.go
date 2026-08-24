package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	cp "github.com/certen/certen-protocol/services/validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
)

type row struct{ Account, TxHash string }

// L1-L3 only: BuildProof requires comet clients, which are not publicly
// reachable. The layer builders are exactly what Phase 0.4 needs to baseline.
func main() {
	rows := []row{
		{"acc://carp-buyer-62431.acme/data", "51b0ba6abf413762fd3db7bcb12a2c56ee2806fcd8405640537f92b791aedcf0"},
		{"acc://certen-panel-carp-v7.acme/data", "37e28c94ce760872db514b22ffb483dbfc288204b94b22ad1d9c1c022357c750"},
		{"acc://carp-seller-40996.acme/data", "3970b4cbc47a50e5156370dc366d1f7b14da9226b810253955d793ae7aeefce7"},
		{"acc://carp-buyer-62431.acme/data", "8cc2bbf22b91aaf8b1e24ba7792dbb6b7431c9e867db03e557a3ae202df86ec4"},
		{"acc://carp-seller-40996.acme/data", "e0d54ced7c801e816a6456296b0c6a297be487e5f8eaec8bf0780d75d7c01319"},
	}
	c := jsonrpc.NewClient("https://kermit.accumulatenetwork.io/v3")
	ctx := context.Background()
	out := map[string]any{}

	for _, r := range rows {
		l1b := &cp.Layer1Builder{Client: c}
		l1, err := l1b.Build(ctx, r.Account, r.TxHash)
		if err != nil {
			fmt.Fprintf(os.Stderr, "L1 %s: %v\n", r.TxHash[:12], err)
			continue
		}
		var l2 cp.Layer2
		var bvn string
		var l2err error
		for _, b := range []string{"bvn1", "bvn2", "bvn3"} {
			l2b := &cp.Layer2Builder{Client: c}
			l2, l2err = l2b.Build(ctx, b, l1)
			if l2err == nil {
				bvn = b
				break
			}
		}
		if bvn == "" {
			fmt.Fprintf(os.Stderr, "L2 %s: %v\n", r.TxHash[:12], l2err)
			continue
		}
		l3b := &cp.Layer3Builder{Client: c}
		l3, err := l3b.Build(ctx, l2)
		if err != nil {
			fmt.Fprintf(os.Stderr, "L3 %s: %v\n", r.TxHash[:12], err)
			continue
		}
		// Verify all five receipts recompute (V1-V3, offline)
		rv := cp.NewReceiptVerifier(false)
		for name, rc := range map[string]cp.Receipt{
			"l1": l1.Receipt, "l2root": l2.RootReceipt, "l2bpt": l2.BptReceipt,
			"l3root": l3.RootReceipt, "l3bpt": l3.BptReceipt,
		} {
			if err := rv.ValidateIntegrity(rc); err != nil {
				fmt.Fprintf(os.Stderr, "RECEIPT %s %s: %v\n", r.TxHash[:12], name, err)
				os.Exit(1)
			}
		}
		out[r.TxHash] = map[string]any{"account": r.Account, "bvn": bvn, "layer1": l1, "layer2": l2, "layer3": l3}
		fmt.Fprintf(os.Stderr, "OK %s bvn=%s L1.mbi=%d L2.dnmbi=%d L2.bvnSTA=%s L3.dnSTA=%s\n",
			r.TxHash[:12], bvn, l1.BVNMinorBlockIndex, l2.DNMinorBlockIndex,
			l2.BVNStateTreeAnchor[:12], l3.DNStateTreeAnchor[:12])
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
	if len(out) == 0 {
		fmt.Fprintln(os.Stderr, "NO BASELINE CAPTURED")
		os.Exit(1)
	}
	_ = strings.TrimSpace
}
