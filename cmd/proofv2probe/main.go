// Command proofv2probe exercises the proof v2 Accumulate path against the live network (RB6 Phase A, fast test):
// one continuous receipt from a transaction to a Directory root, that root certified by walking the validator-set spine
// from genesis, and the walk's updates accounted for against the network accounts' main chains.
//
//	proofv2probe -account acc://x.acme/data -tx <hex> -bvn bvn1
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"reflect"
	"time"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/network"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

func main() {
	endpoint := flag.String("endpoint", "https://kermit.accumulatenetwork.io/v3", "Accumulate v3 endpoint")
	account := flag.String("account", "", "account the transaction is on")
	tx := flag.String("tx", "", "transaction hash, hex")
	bvn := flag.String("bvn", "bvn1", "the account's BVN")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := run(ctx, jsonrpc.NewClient(*endpoint), *account, *tx, *bvn); err != nil {
		fmt.Println("FAIL:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, c *jsonrpc.Client, account, tx, bvn string) error {
	// 1. The v1 legs, combined into one continuous receipt.
	t0 := time.Now()
	cp, err := chained_proof.NewProofBuilder(c, false).BuildProof(ctx, chained_proof.ProofInput{Account: account, TxHash: tx, BVN: bvn})
	if err != nil {
		return fmt.Errorf("build v1 legs: %w", err)
	}
	r1, err := toMerkle(cp.Layer1.Receipt)
	if err != nil {
		return err
	}
	r2, err := toMerkle(cp.Layer2.RootReceipt)
	if err != nil {
		return err
	}
	r3, err := toMerkle(cp.Layer3.RootReceipt)
	if err != nil {
		return err
	}
	cont, err := r1.Combine(r2, r3)
	if err != nil {
		return fmt.Errorf("combine: %w", err)
	}
	if !cont.Validate(nil) {
		return fmt.Errorf("continuous receipt does not validate")
	}
	fmt.Printf("continuous receipt: start %x -> anchor %x, %d steps, ends at DN block %d (%s)\n",
		cont.Start, cont.Anchor, len(cont.Entries), cp.Layer3.DNSelfAnchorRecordedAtMinorBlockIndex, time.Since(t0).Round(time.Millisecond))

	// 2. The genesis trust base and the network accounts' main chains.
	g := new(network.GlobalValues)
	getState := func(u *url.URL, target interface{}) error {
		r, err := c.Query(ctx, u, &api.DefaultQuery{})
		if err != nil {
			return err
		}
		ar, ok := r.(*api.AccountRecord)
		if !ok {
			return fmt.Errorf("%v: got %T", u, r)
		}
		tv := reflect.ValueOf(target).Elem()
		av := reflect.ValueOf(ar.Account)
		if !av.Type().AssignableTo(tv.Type()) {
			return fmt.Errorf("%v is %T, want %v", u, ar.Account, tv.Type())
		}
		tv.Set(av)
		return nil
	}
	if err := g.Load(protocol.DnUrl(), getState); err != nil {
		return fmt.Errorf("load network values: %w", err)
	}
	for _, name := range []string{protocol.Network, protocol.Globals} {
		u := protocol.DnUrl().JoinPath(name)
		r, err := c.Query(ctx, u, &api.ChainQuery{Name: "main"})
		if err != nil {
			return fmt.Errorf("%v main chain: %w", u, err)
		}
		cr, ok := r.(*api.ChainRecord)
		if !ok {
			return fmt.Errorf("%v main chain: got %T", u, r)
		}
		fmt.Printf("%v main chain height %d\n", u, cr.Count)
	}
	fmt.Printf("network version %d, %d validators, directory threshold %d\n",
		g.Network.Version, len(g.Network.Validators), g.ValidatorThreshold(protocol.Directory))

	// 3. The spine from major block 1, then minor roots up to the continuous receipt's Directory block.
	t1 := time.Now()
	sp, err := proofv2.NewSpine(g, 1)
	if err != nil {
		return err
	}
	for {
		recs, err := c.MajorHeaderRange(ctx, api.MajorHeaderRangeOptions{Partition: protocol.Directory, Start: sp.NextMajor, End: sp.NextMajor + 99})
		if err != nil {
			// The last request runs past the newest major block; ask for exactly what is left.
			recs, err = c.MajorHeaderRange(ctx, api.MajorHeaderRangeOptions{Partition: protocol.Directory, Start: sp.NextMajor, End: sp.NextMajor})
			if err != nil {
				fmt.Printf("spine: stopped at major %d: %v\n", sp.NextMajor, err)
				break
			}
		}
		for _, r := range recs {
			if err := sp.Advance(r); err != nil {
				return fmt.Errorf("spine: %w", err)
			}
		}
	}
	fmt.Printf("spine: %d majors verified to DN block %d (%s), %d updates applied\n", sp.NextMajor-1, sp.LastMinorBlock, time.Since(t1).Round(time.Millisecond), len(sp.Applied))

	target := cp.Layer3.DNSelfAnchorRecordedAtMinorBlockIndex
	mr, err := c.MinorRootRange(ctx, api.MinorRootRangeOptions{Partition: protocol.Directory, Since: sp.LastMinorBlock, Until: target})
	if err != nil {
		return fmt.Errorf("minor roots to %d: %w", target, err)
	}
	if err := sp.AdvanceEpoch(mr); err != nil {
		return fmt.Errorf("minor roots: %w", err)
	}
	fmt.Printf("minor roots: certified DN block %d, root %x\n", sp.LastMinorBlock, sp.RootChainAnchor)
	for _, a := range sp.Applied {
		fmt.Printf("  applied %s %x at DN block %d\n", a.Principal, a.TxHash, a.AnchorMinorBlock)
	}

	// The Directory leg, re-asked to end at exactly the certified root: ForHeight on a chain-entry receipt is a root
	// chain height, and the certified anchor's root covers the root chain up to the end of its RootProof.
	height := mr.RootProof.MerkleState.Count + int64(len(mr.RootProof.Elements)) - 1
	q, err := c.Query(ctx, protocol.DnUrl().JoinPath(protocol.AnchorPool), &api.ChainQuery{
		Name: "anchor(directory)-root", Entry: r2.Anchor, IncludeReceipt: &api.ReceiptOptions{ForHeight: uint64(height)}})
	if err != nil {
		return fmt.Errorf("directory leg at root height %d: %w", height, err)
	}
	ce, ok := q.(*api.ChainEntryRecord[api.Record])
	if !ok || ce.Receipt == nil {
		return fmt.Errorf("directory leg: got %T without a receipt", q)
	}
	if cont, err = r1.Combine(r2, &ce.Receipt.Receipt); err != nil {
		return fmt.Errorf("combine to the certified root: %w", err)
	}
	if !cont.Validate(nil) {
		return fmt.Errorf("receipt to the certified root does not validate")
	}
	fmt.Printf("receipt to the certified root: %x at DN block %d, %d steps\n", cont.Anchor, ce.Receipt.LocalBlock, len(cont.Entries))

	if hex.EncodeToString(cont.Anchor) == hex.EncodeToString(sp.RootChainAnchor[:]) {
		fmt.Println("PASS: the continuous receipt ends at a spine-certified Directory root")
		return nil
	}
	return fmt.Errorf("continuous receipt ends at %x (DN %d), spine certified %x (DN %d)", cont.Anchor, target, sp.RootChainAnchor, sp.LastMinorBlock)
}

func toMerkle(r chained_proof.Receipt) (*merkle.Receipt, error) {
	out := new(merkle.Receipt)
	var err error
	if out.Start, err = hex.DecodeString(r.Start); err != nil {
		return nil, err
	}
	if out.Anchor, err = hex.DecodeString(r.Anchor); err != nil {
		return nil, err
	}
	for _, e := range r.Entries {
		h, err := hex.DecodeString(e.Hash)
		if err != nil {
			return nil, err
		}
		out.Entries = append(out.Entries, &merkle.ReceiptEntry{Hash: h, Right: e.Right})
	}
	return out, nil
}
