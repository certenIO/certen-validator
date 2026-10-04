// Command proofv2probe exercises the proof v2 Accumulate path against the live network (RB6 Phase A, fast test):
// one continuous receipt from a transaction to a Directory root, that root certified by walking the validator-set spine
// from genesis, and the walk's updates accounted for against the network accounts' main chains.
//
//	proofv2probe -account acc://x.acme/data -tx <hex> -bvn bvn1
//	proofv2probe -corpus corpus.txt     # lines: "<account> <tx hex> [bvn]"; the spine is walked once
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"encoding/hex"
	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/network"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

type target struct{ account, tx, bvn string }

func main() {
	endpoint := flag.String("endpoint", "https://kermit.accumulatenetwork.io/v3", "Accumulate v3 endpoint")
	account := flag.String("account", "", "account the transaction is on")
	tx := flag.String("tx", "", "transaction hash, hex")
	bvn := flag.String("bvn", "bvn1", "the account's BVN")
	corpus := flag.String("corpus", "", "file of targets, one per line: <account> <tx hex> [bvn]")
	flag.Parse()

	var targets []target
	if *corpus != "" {
		f, err := os.Open(*corpus)
		if err != nil {
			fmt.Println("FAIL:", err)
			os.Exit(1)
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) < 2 || len(fs[1]) != 64 || strings.HasPrefix(fs[0], "#") {
				continue
			}
			t := target{account: fs[0], tx: fs[1], bvn: *bvn}
			if len(fs) > 2 {
				t.bvn = fs[2]
			}
			targets = append(targets, t)
		}
		f.Close()
	} else {
		targets = []target{{*account, *tx, *bvn}}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	c := jsonrpc.NewClient(*endpoint)

	snaps, err := walkSpine(ctx, c)
	if err != nil {
		fmt.Println("FAIL: spine:", err)
		os.Exit(1)
	}
	failed := 0
	for _, t := range targets {
		t0 := time.Now()
		if err := proveOne(ctx, c, snaps, t); err != nil {
			failed++
			fmt.Printf("FAIL %s %s: %v\n", t.account, t.tx[:12], err)
			continue
		}
		fmt.Printf("PASS %s %s (%s)\n", t.account, t.tx[:12], time.Since(t0).Round(time.Millisecond))
	}
	fmt.Printf("%d of %d proven into a spine-certified Directory root\n", len(targets)-failed, len(targets))
	if failed > 0 {
		os.Exit(1)
	}
}

// walkSpine loads the genesis trust base, checks the network accounts were never written after genesis, and walks
// every major block from 1.
func walkSpine(ctx context.Context, c *jsonrpc.Client) ([]*proofv2.Spine, error) {
	t0 := time.Now()
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
		return nil, fmt.Errorf("load network values: %w", err)
	}
	heights := map[string]int64{}
	for _, name := range []string{protocol.Network, protocol.Globals} {
		u := protocol.DnUrl().JoinPath(name)
		r, err := c.Query(ctx, u, &api.ChainQuery{Name: "main"})
		if err != nil {
			return nil, fmt.Errorf("%v main chain: %w", u, err)
		}
		cr, ok := r.(*api.ChainRecord)
		if !ok {
			return nil, fmt.Errorf("%v main chain: got %T", u, r)
		}
		heights[u.String()] = int64(cr.Count)
	}
	fmt.Printf("genesis trust base: network version %d, %d validators, directory threshold %d; main chain heights %v\n",
		g.Network.Version, len(g.Network.Validators), g.ValidatorThreshold(protocol.Directory), heights)

	sp, err := proofv2.NewSpine(g, 1)
	if err != nil {
		return nil, err
	}
	var snaps []*proofv2.Spine
	for {
		recs, err := c.MajorHeaderRange(ctx, api.MajorHeaderRangeOptions{Partition: protocol.Directory, Start: sp.NextMajor, End: sp.NextMajor + 99})
		if err != nil {
			// The last request runs past the newest major block; ask for exactly what is left.
			recs, err = c.MajorHeaderRange(ctx, api.MajorHeaderRangeOptions{Partition: protocol.Directory, Start: sp.NextMajor, End: sp.NextMajor})
			if err != nil {
				break
			}
		}
		for _, r := range recs {
			if err := sp.Advance(r); err != nil {
				return nil, err
			}
			snaps = append(snaps, sp.Clone())
		}
	}

	// Main-chain accounting. The current state was used as the genesis state, which is sound only when neither
	// account was written after genesis (main chain height 1) and the walk applied nothing.
	for u, h := range heights {
		applied := 0
		for _, a := range sp.Applied {
			if a.Principal == u {
				applied++
			}
		}
		if h != 1 || applied != 0 {
			return nil, fmt.Errorf("%s: main chain height %d, %d updates applied: genesis state must be read from genesis, not current state", u, h, applied)
		}
	}
	fmt.Printf("spine: %d majors verified to DN block %d (%s), 0 updates, accounting complete\n",
		sp.NextMajor-1, sp.LastMinorBlock, time.Since(t0).Round(time.Millisecond))

	// State cross-check: prove the network definition against a certified state root inside the node's retention window,
	// and require it to equal the set the walk derived. Walk a copy of the spine to the head, keeping each hop, certify
	// an anchor a little behind the head (the head's own anchor may not exist yet on a quiet network), then prove the
	// state at that anchor's block: the state receipt passes through the block's state tree root, which the certified
	// anchor carries, so the receipt's prefix up to that root is the proof.
	hops := []*proofv2.Spine{sp.Clone()}
	for len(hops) < 50 {
		last := hops[len(hops)-1]
		mr, err := c.MinorRootRange(ctx, api.MinorRootRangeOptions{Partition: protocol.Directory, Since: last.LastMinorBlock})
		if err != nil {
			break
		}
		next := last.Clone()
		if err := next.AdvanceEpoch(mr); err != nil {
			break
		}
		hops = append(hops, next)
	}
	if len(hops) < 2 {
		return nil, fmt.Errorf("cross-check: the walk could not reach past the last major block")
	}
	head := hops[len(hops)-1].LastMinorBlock
	want := head - 100
	var base *proofv2.Spine
	for _, h := range hops {
		if h.LastMinorBlock < want {
			base = h
		}
	}
	now := base.Clone()
	mr, err := c.MinorRootRange(ctx, api.MinorRootRangeOptions{Partition: protocol.Directory, Since: now.LastMinorBlock, Until: want})
	if err != nil {
		return nil, fmt.Errorf("certify DN %d: %w", want, err)
	}
	if err := now.AdvanceEpoch(mr); err != nil {
		return nil, fmt.Errorf("certify DN %d: %w", want, err)
	}
	if len(now.Applied) != 0 {
		return nil, fmt.Errorf("cross-check: %d network updates after the last major block; main-chain accounting must cover them", len(now.Applied))
	}

	q, err := c.Query(ctx, protocol.DnUrl().JoinPath(protocol.Network), &api.DefaultQuery{IncludeReceipt: &api.ReceiptOptions{ForHeight: now.LastMinorBlock}})
	if err != nil {
		return nil, fmt.Errorf("network definition at DN %d: %w", now.LastMinorBlock, err)
	}
	ar, ok := q.(*api.AccountRecord)
	if !ok || ar.Receipt == nil {
		return nil, fmt.Errorf("network definition at DN %d: got %T without a receipt", now.LastMinorBlock, q)
	}
	body, err := ar.Account.MarshalBinary()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	if !ar.Receipt.StartsAtMainState || !bytes.Equal(ar.Receipt.Start, sum[:]) || !ar.Receipt.Validate(nil) {
		return nil, fmt.Errorf("network definition receipt does not start at the served state or does not validate")
	}
	prefix := receiptPrefixTo(&ar.Receipt.Receipt, now.StateTreeAnchor[:])
	if prefix == nil {
		return nil, fmt.Errorf("network definition receipt (to DN %d) never passes through the state root %x certified at DN %d",
			ar.Receipt.LocalBlock, now.StateTreeAnchor, now.LastMinorBlock)
	}
	fmt.Printf("cross-check: network definition proven in %d steps to the state root certified at DN %d\n", len(prefix.Entries), now.LastMinorBlock)
	def, ok := ar.Account.(*protocol.DataAccount)
	if !ok || def.Entry == nil || len(def.Entry.GetData()) != 1 {
		return nil, fmt.Errorf("network account is %T, not a one-entry data account", ar.Account)
	}
	derived, err := sp.Globals().Network.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(def.Entry.GetData()[0], derived) {
		return nil, fmt.Errorf("the proven network definition at DN %d differs from the set the walk derived", now.LastMinorBlock)
	}
	fmt.Printf("cross-check: PASS - the network definition proven at certified DN %d equals the set the walk derived\n", now.LastMinorBlock)
	return snaps, nil
}

// proveOne builds one transaction's continuous receipt to a Directory root and certifies that root from the spine.
func proveOne(ctx context.Context, c *jsonrpc.Client, snaps []*proofv2.Spine, t target) error {
	cp, err := chained_proof.NewProofBuilder(c, false).BuildProof(ctx, chained_proof.ProofInput{Account: t.account, TxHash: t.tx, BVN: t.bvn})
	if err != nil {
		return fmt.Errorf("v1 legs: %w", err)
	}
	r1, err := toMerkle(cp.Layer1.Receipt)
	if err != nil {
		return err
	}
	r2, err := toMerkle(cp.Layer2.RootReceipt)
	if err != nil {
		return err
	}

	// Certify from the last major block that closed before the target: minor roots extend forward only.
	var base *proofv2.Spine
	for _, s := range snaps {
		if s.LastMinorBlock < cp.Layer3.DNSelfAnchorRecordedAtMinorBlockIndex {
			base = s
		}
	}
	if base == nil {
		return fmt.Errorf("DN block %d precedes the first major block", cp.Layer3.DNSelfAnchorRecordedAtMinorBlockIndex)
	}
	sp := base.Clone()
	mr, err := c.MinorRootRange(ctx, api.MinorRootRangeOptions{Partition: protocol.Directory, Since: sp.LastMinorBlock, Until: cp.Layer3.DNSelfAnchorRecordedAtMinorBlockIndex})
	if err != nil {
		return fmt.Errorf("minor roots: %w", err)
	}
	if err := sp.AdvanceEpoch(mr); err != nil {
		return fmt.Errorf("minor roots: %w", err)
	}
	if len(sp.Applied) != 0 {
		return fmt.Errorf("%d network updates in the minor-root run: accounting needs the accounts' state at the certified block", len(sp.Applied))
	}

	// The Directory leg, asked to end at exactly the certified root: ForHeight on a chain-entry receipt is a root
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
	cont, err := r1.Combine(r2, &ce.Receipt.Receipt)
	if err != nil {
		return fmt.Errorf("combine: %w", err)
	}
	if !cont.Validate(nil) {
		return fmt.Errorf("receipt does not validate")
	}
	if !bytes.Equal(cont.Start, mustHex(t.tx)) {
		return fmt.Errorf("receipt starts at %x, not the transaction", cont.Start)
	}
	if !bytes.Equal(cont.Anchor, sp.RootChainAnchor[:]) {
		return fmt.Errorf("receipt ends at %x, spine certified %x (DN %d)", cont.Anchor, sp.RootChainAnchor, sp.LastMinorBlock)
	}
	return nil
}

// receiptPrefixTo returns the leading part of r that ends at value, or nil when no intermediate value of r equals it.
func receiptPrefixTo(r *merkle.Receipt, value []byte) *merkle.Receipt {
	h := append([]byte(nil), r.Start...)
	for i := 0; ; i++ {
		if bytes.Equal(h, value) {
			p := &merkle.Receipt{Start: r.Start, Anchor: append([]byte(nil), h...), Entries: r.Entries[:i]}
			if p.Validate(nil) {
				return p
			}
			return nil
		}
		if i == len(r.Entries) {
			return nil
		}
		e := r.Entries[i]
		var s [32]byte
		if e.Right {
			s = sha256.Sum256(append(append([]byte(nil), h...), e.Hash...))
		} else {
			s = sha256.Sum256(append(append([]byte(nil), e.Hash...), h...))
		}
		h = s[:]
	}
}

func mustHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
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
