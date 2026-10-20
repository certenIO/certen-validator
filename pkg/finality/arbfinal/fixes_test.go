// Copyright 2026 Certen Protocol

package arbfinal_test

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbfinal"
	sw "github.com/certen/independant-validator/pkg/finality/arbfinal/synthworld"
)

// The three LOW findings of the completeness review V-E1-A1 (RB11-E1-FIX). Each test is the reviewer's accepting probe turned into
// an assertion: it ACCEPTED at d4cf095.

func canon(t *testing.T, v finality.Verdict, err error) string {
	t.Helper()
	if err != nil {
		s, ok := finality.AsNamed(err)
		if !ok {
			t.Fatalf("an unnamed error: %v", err)
		}
		return string(s.Canonical())
	}
	return "ACCEPTED " + string(finality.NewState("finalized", "route", v.Fields["confirmation_route"]).Canonical())
}

// L1: a contract-creation transaction carries init code, not calldata; the first four bytes of the init code are not an entry
// point. The wallet route must not be taken for it.
func TestFixCreationTxWalletRoute(t *testing.T) {
	p := sw.NewParts("fix-create")
	p.TxCreate = true
	p.TxInput = sw.WalletInput(sw.SelWalletTx, [][]byte{sw.ConfirmCall(sw.SelConfirm)}, []common.Address{sw.Rollup})
	w := sw.Assemble(p)
	v, err := w.Judge()
	want := string(finality.NewState(arbfinal.CodeConfirmationUnproof, "reason", arbfinal.ConfirmIndirect, "tx", w.TxHash, "l1_block", w.K.Number).Canonical())
	if got := canon(t, v, err); got != want {
		t.Fatalf("a contract creation took the wallet route:\n got:  %s\n want: %s", got, want)
	}
}

// L2: Kind.Verify judges the leg's own chain, exactly as the registry's JudgeAddendum does.
func TestFixBlockRefChain(t *testing.T) {
	w := sw.Assemble(sw.NewParts("fix-chain"))
	pins, err := finality.ParsePinsOverride(w.Pins)
	if err != nil {
		t.Fatal(err)
	}
	for _, chain := range []uint64{0, 1, 11155111, 8453} {
		leg := w.Leg
		leg.Chain = chain
		v, err := arbfinal.New().Verify(pins, leg, w.Container)
		want := string(finality.NewState(finality.CodeBlockMismatch, "field", "chain", "want", chain, "got", finality.ChainArbitrumSepolia).Canonical())
		if got := canon(t, v, err); got != want {
			t.Errorf("a leg on chain %d:\n got:  %s\n want: %s", chain, got, want)
		}
	}
}

func nodesIndex(t *testing.T, e arbfinal.Evidence, filler []byte) int {
	t.Helper()
	for i, n := range finality.EncodeNodes(e.Nodes) {
		if bytes.Equal(n, filler) {
			return i
		}
	}
	t.Fatal("the filler is not in the NODES set")
	return -1
}

func withFiller(w *sw.World, filler []byte) *sw.World {
	c := *w
	c.Evidence.Nodes = append(append([][]byte(nil), w.Evidence.Nodes...), filler)
	if err := c.Rebuild(); err != nil {
		panic(err)
	}
	return &c
}

// L3: a node that is not on the transaction or receipt proof path is a state or storage node, bounded by max_node_bytes (4096);
// a node of the transaction or receipt proof path keeps max_tx_leaf_bytes.
func TestFixOversizedStateNode(t *testing.T) {
	valid := sw.Assemble(sw.NewParts("fix-nodes"))
	for _, size := range []int{4096 + 1, 4096 + 1000, 100000} {
		filler := bytes.Repeat([]byte{0x5a}, size)
		w := withFiller(valid, filler)
		v, err := w.Judge()
		idx := nodesIndex(t, w.Evidence, filler)
		want := string(finality.NewState(finality.CodeEvidenceTooLarge, "part", "nodes", "count", uint64(size), "limit", uint64(4096), "index", uint64(idx)).Canonical())
		if got := canon(t, v, err); got != want {
			t.Errorf("a %d-byte node outside the tx/receipt proof paths:\n got:  %s\n want: %s", size, got, want)
		}
	}
	// the bound is inclusive: a node of exactly max_node_bytes is carried
	if v, err := withFiller(valid, bytes.Repeat([]byte{0x5a}, 4096)).Judge(); err != nil || v.Fields["confirmation_route"] != "direct" {
		t.Errorf("a 4096-byte node outside the proof paths was refused: %v", err)
	}
}

// The larger bound stays for the nodes that really are on the transaction and receipt proof paths: a calldata-mode batcher
// transaction (spec 8.2 r2:D8) is far above 4096 bytes.
func TestFixLargeTxAndReceiptLeavesKeepTheLargeBound(t *testing.T) {
	for _, c := range []struct {
		name string
		mod  func(*sw.Parts)
	}{
		{"tx leaf", func(p *sw.Parts) {
			p.TxInput = append(append([]byte(nil), sw.SelConfirm[:]...), bytes.Repeat([]byte{0x33}, 5000)...)
		}},
		{"receipt leaf", func(p *sw.Parts) { p.LogDataBytes = 6000 }},
	} {
		p := sw.NewParts("fix-large-" + c.name)
		c.mod(&p)
		w := sw.Assemble(p)
		if v, err := w.Judge(); err != nil || v.Fields["confirmation_route"] != "direct" {
			t.Errorf("%s over 4096 bytes on the proof path was refused: %v", c.name, err)
		}
		filler := bytes.Repeat([]byte{0x5a}, 4097)
		f := withFiller(w, filler)
		v, err := f.Judge()
		want := string(finality.NewState(finality.CodeEvidenceTooLarge, "part", "nodes", "count", uint64(4097), "limit", uint64(4096), "index", uint64(nodesIndex(t, f.Evidence, filler))).Canonical())
		if got := canon(t, v, err); got != want {
			t.Errorf("a 4097-byte filler beside a large %s:\n got:  %s\n want: %s", c.name, got, want)
		}
	}
}
