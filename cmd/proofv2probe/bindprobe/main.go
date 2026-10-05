// Command bindprobe checks whether an account's state as of a transaction's block passes through the BVN state tree
// anchor paired, in the same Directory anchor entry, with the transaction's own root chain anchor.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"time"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/proof"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
)

func main() {
	account := flag.String("account", "", "transaction's account")
	tx := flag.String("tx", "", "transaction hash")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	c := jsonrpc.NewClient("https://kermit.accumulatenetwork.io/v3")
	cp, err := chained_proof.NewProofBuilder(c, false).BuildProof(ctx, chained_proof.ProofInput{Account: *account, TxHash: *tx, BVN: "bvn1"})
	if err != nil {
		fmt.Println("legs:", err)
		return
	}
	fmt.Printf("tx at BVN block %d; paired state tree anchor %s (DN index %d)\n", cp.Layer1.BVNMinorBlockIndex, cp.Layer2.BVNStateTreeAnchor, cp.Layer2.DNIndex)
	l4 := cp.Layer4BVN
	if l4 == nil {
		fmt.Println("no L4 BVN leg")
		return
	}
	fmt.Printf("L4 BVN anchor: block %d (tx block %d) root %s (L1 %s) state %s; pool %s[%d] tx %s\n", l4.MinorBlockIndex, cp.Layer1.BVNMinorBlockIndex,
		l4.RootChainAnchor[:12], cp.Layer1.BVNRootChainAnchor[:12], l4.StateTreeAnchor[:12], l4.AnchorPool, l4.AnchorIndex, l4.AnchorTxHash[:12])
	idx := l4.AnchorIndex
	q0, err := c.Query(ctx, url.MustParse(l4.AnchorPool), &api.ChainQuery{Name: "main", Index: &idx, IncludeReceipt: &api.ReceiptOptions{ForAny: true}})
	if err != nil {
		fmt.Println("anchor tx receipt:", err)
	} else {
		ce := q0.(*api.ChainEntryRecord[api.Record])
		fmt.Printf("anchor tx on %s main[%d]: entry %x, receipt to %x at DN %d valid %v\n", l4.AnchorPool, idx, ce.Entry[:6], ce.Receipt.Anchor[:6], ce.Receipt.LocalBlock, ce.Receipt.Validate(nil))
	}
	for _, acct := range []string{*account, "acc://certen-protocol.acme/book/1", "acc://certen-protocol.acme/book/2"} {
		for _, d := range []int64{-1, 0, 1} {
			at := uint64(int64(cp.Layer1.BVNMinorBlockIndex) + d)
			q, err := c.Query(ctx, url.MustParse(acct), &api.DefaultQuery{IncludeReceipt: &api.ReceiptOptions{ForHeight: at}})
			if err != nil {
				fmt.Printf("  %s @%d: %v\n", acct, at, err)
				continue
			}
			ar := q.(*api.AccountRecord)
			body, _ := ar.Account.MarshalBinary()
			sum := sha256.Sum256(body)
			r := chained_proof.Receipt{Start: hex.EncodeToString(ar.Receipt.Start), Anchor: hex.EncodeToString(ar.Receipt.Anchor)}
			for _, e := range ar.Receipt.Entries {
				r.Entries = append(r.Entries, chained_proof.ReceiptStep{Hash: hex.EncodeToString(e.Hash), Right: e.Right})
			}
			_, hit := proof.ReceiptPrefixTo(r, cp.Layer2.BVNStateTreeAnchor)
			fmt.Printf("  %s @%d: startsAtMain %v hashOK %v passes through the paired state root: %v (receipt ends %x)\n",
				acct, at, ar.Receipt.StartsAtMainState, string(sum[:]) == string(ar.Receipt.Start), hit, ar.Receipt.Anchor[:8])
		}
	}
}
