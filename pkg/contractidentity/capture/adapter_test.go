// Copyright 2026 Certen Protocol

package capture_test

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/certen/independant-validator/pkg/contractidentity/capture"
	"github.com/certen/independant-validator/pkg/ethrpc"
)

// fakeAgreed is an AgreedReader over the world: what independent providers would agree on.
type fakeAgreed struct {
	fc       *fakeChain
	locs     []ethrpc.LocatorClient
	reorder  bool // serve the transactions of every block rotated by one: no longer the header's transactionsRoot
	receipts bool // serve one receipt too few
	index    bool // the receipt names another index than the transaction's own
}

func (f fakeAgreed) src() *fakeSource { return &fakeSource{fc: f.fc} }
func (f fakeAgreed) TransactionReceipt(ctx context.Context, h common.Hash) (*types.Receipt, error) {
	rc, err := f.src().TransactionReceipt(ctx, h)
	if err == nil && f.index {
		rc.TransactionIndex ^= 1
	}
	return rc, err
}
func (f fakeAgreed) HeaderByNumber(ctx context.Context, n *big.Int) (*types.Header, error) {
	return f.src().HeaderByNumber(ctx, n)
}
func (f fakeAgreed) HeaderByHash(ctx context.Context, h common.Hash) (*types.Header, error) {
	return f.src().HeaderByHash(ctx, h)
}
func (f fakeAgreed) Locators() []ethrpc.LocatorClient { return f.locs }
func (f fakeAgreed) AgreedLists(_ context.Context, what string, _ func(context.Context, *rpc.Client) ([][]byte, error)) ([][]byte, error) {
	i := strings.LastIndex(what, "0x")
	if i < 0 {
		return nil, errors.New("no block named")
	}
	name, ok := f.fc.named[common.HexToHash(what[i:])]
	if !ok {
		return nil, errors.New("unknown block")
	}
	txs, rcs, err := f.fc.w.BlockLists(name)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(what, "receipts") {
		if f.receipts && len(rcs) > 0 {
			rcs = rcs[:len(rcs)-1]
		}
		return rcs, nil
	}
	if f.reorder && len(txs) > 1 {
		txs = append(txs[1:], txs[0])
	}
	return txs, nil
}

func TestReaderSourceServesTheAgreedBlockAndTransaction(t *testing.T) {
	fc := newFakeChain(t, 11155111, "h0")
	if _, err := capture.NewReaderSource(nil); err == nil {
		t.Fatal("a nil reader was adapted")
	}
	src, err := capture.NewReaderSource(fakeAgreed{fc: fc})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	bh := fc.w.BlockHashes["attest"]
	blk, err := src.Block(ctx, bh)
	if err != nil || blk.Header.Hash() != bh {
		t.Fatalf("Block: %v", err)
	}
	wantTxs, wantRcs, _ := fc.w.BlockLists("attest")
	for i := range wantTxs {
		if !bytes.Equal(blk.Txs[i], wantTxs[i]) || !bytes.Equal(blk.Receipts[i], wantRcs[i]) {
			t.Fatalf("entry %d differs from the world's", i)
		}
	}
	if _, err := src.Block(ctx, common.Hash{1}); err == nil {
		t.Fatal("an unknown block was served")
	}
	for _, h := range []common.Hash{fc.tx.Hash(), fc.attTx} {
		tx, found, err := src.TransactionByHash(ctx, h)
		if err != nil || !found || tx.Hash() != h {
			t.Fatalf("TransactionByHash(%x): %v %v", h[:4], found, err)
		}
	}
	if _, found, _ := src.TransactionByHash(ctx, common.Hash{9}); found {
		t.Fatal("an unknown transaction was found")
	}
	// providers that disagree with the header's roots are refused by name, not served
	for name, bad := range map[string]fakeAgreed{"transactions out of order": {fc: fc, reorder: true}, "a receipt missing": {fc: fc, receipts: true}} {
		bsrc, _ := capture.NewReaderSource(bad)
		if _, err := bsrc.Block(ctx, bh); err == nil {
			t.Fatalf("%s: the block was accepted", name)
		}
		if _, found, err := bsrc.TransactionByHash(ctx, fc.attTx); found || err == nil {
			t.Fatalf("%s: the transaction was accepted: %v %v", name, found, err)
		}
	}
	// a receipt that names another index than the transaction's: the agreed block is sound and does not hold the transaction there
	isrc, _ := capture.NewReaderSource(fakeAgreed{fc: fc, index: true})
	if _, found, err := isrc.TransactionByHash(ctx, fc.attTx); found || err == nil || !strings.Contains(err.Error(), "does not hold") {
		t.Fatalf("a wrong receipt index was accepted: %v %v", found, err)
	}
	// the providers are the reader's locators; a locator without a client cannot serve code
	psrc, _ := capture.NewReaderSource(fakeAgreed{fc: fc, locs: []ethrpc.LocatorClient{{Host: "https://a.example"}, {Host: "https://b.example"}}})
	ps := psrc.Providers()
	if len(ps) != 2 || ps[0].Name() != "https://a.example" || ps[1].Name() != "https://b.example" {
		t.Fatalf("providers = %v", ps)
	}
	if _, err := ps[0].GetCode(ctx, common.Address{1}, "0x1"); err == nil {
		t.Fatal("a provider without a client served code")
	}
}

// hybrid is the adapter's agreed reads with fake providers: E1, E2 and the link run over the production read path.
type hybrid struct {
	capture.AttestSource
	ps []capture.Provider
}

func (h hybrid) Providers() []capture.Provider { return h.ps }

func TestWholeLegOverTheAdapterEqualsTheWorldContainer(t *testing.T) {
	fc := newFakeChain(t, 84532, "h0")
	agreed, _ := capture.NewReaderSource(fakeAgreed{fc: fc})
	inner, _ := fc.source(honest, honest)
	src := hybrid{AttestSource: agreed, ps: inner.providers}
	cfg := fc.config(src)
	att, err := capture.CaptureAttest(context.Background(), cfg, capture.AttestRequest{TxHash: fc.attTx})
	if err != nil || att.Stated != nil {
		t.Fatalf("%v %+v", err, att)
	}
	set, err := capture.CaptureSettle(context.Background(), cfg, fc.request())
	if err != nil || set.Stated != nil {
		t.Fatalf("%v %+v", err, set)
	}
	plan, _ := capture.ChooseLink(fc.w.Manifest, 84532, att.Block.Number, set.Block.Number, 0)
	part, err := capture.BuildAttestPart(context.Background(), src, att, fc.headers[set.Block.Number], plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, got, err := capture.Assemble(capture.Parts{Chain: 84532, Leg: set.Block, Facts: fc.facts(t), Settle: set, Attest: part})
	if err != nil || !bytes.Equal(got, fc.w.ContainerBytes) {
		t.Fatalf("container over the adapter: %v", err)
	}
}
