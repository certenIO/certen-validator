// Command proofv2xcollect runs the proof v2 cross-partition capture (pkg/proofv2shadow Collector) against a live network for one
// transaction and prints what it captured or the named state it stopped at (RB9 Phase B). It reads only; it is how the capture
// is checked against Kermit before a branch is merged. The transaction's block must still be inside the node's retention.
//
//	proofv2xcollect -account acc://x.acme/data -tx <hex> [-keybook acc://x.acme/book] [-keypage acc://x.acme/book/1] [-out capture.json]
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"github.com/certen/independant-validator/pkg/proofv2shadow"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
)

func main() {
	endpoint := flag.String("endpoint", "https://kermit.accumulatenetwork.io/v3", "Accumulate v3 endpoint")
	account := flag.String("account", "", "the transaction's principal")
	tx := flag.String("tx", "", "transaction hash, hex")
	book := flag.String("keybook", "", "the key book the intent declares")
	page := flag.String("keypage", "", "the key page the intent declares")
	out := flag.String("out", "", "write the capture as JSON")
	flag.Parse()
	if *account == "" || *tx == "" {
		fmt.Println("FAIL: -account and -tx are required")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	c := jsonrpc.NewClient(*endpoint)
	b := &proofv2.Builder{C: c, Q: proof.NewHTTPQuerier(*endpoint)}
	col, err := proofv2shadow.NewCollector(ctx, *endpoint, c, b, func(f string, a ...any) { fmt.Printf(f+"\n", a...) }, *book, *page)
	if err != nil {
		fmt.Println("FAIL:", err)
		os.Exit(1)
	}
	cp, err := col.Collect(ctx, *account, *tx)
	if cp != nil {
		fmt.Printf("principal %s on %s, block %d\n", cp.Principal, cp.Partition, cp.Block)
		for p, pc := range cp.Partitions {
			fmt.Printf("  partition %-10s block %d (anchor %d, DN %d)\n", p, pc.Block, pc.Index, pc.DNBlock)
		}
		for _, pg := range cp.Pages {
			fmt.Printf("  page %s  %s  block %d  roles %v  chains-bound=%v\n", pg.URL, pg.Partition, pg.Block, pg.Roles, len(pg.Chains) > 0)
		}
		for _, v := range cp.Votes {
			fmt.Printf("  vote of %s origin %s (%s, %d hops)\n", v.Authority, v.Origin, v.Transport.Kind, len(v.Hops))
		}
		for _, n := range cp.Notes {
			fmt.Println("  note:", n)
		}
		if *out != "" {
			raw, _ := json.MarshalIndent(cp, "", " ")
			_ = os.WriteFile(*out, raw, 0o644)
		}
	}
	if err != nil {
		fmt.Println("STOPPED:", err)
		os.Exit(1)
	}
	fmt.Println("OK")
}
