// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/basefinal"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// judgeCmd runs the 5.5 judgement (everything but the LC and the L1 spine) on every recorded case against the live header of the
// capture's A: it shows the verdict the finished container will get, long before A is final.
func judgeCmd(ctx context.Context, dir, legs string) error {
	pins, err := finality.EmbeddedPins()
	if err != nil {
		return err
	}
	bp, err := basefinal.ParsePins(pins)
	if err != nil {
		return err
	}
	store := basefinal.DirStore{Dir: dir}
	rpc := liveRPC()
	files, _ := filepath.Glob(filepath.Join(legs, "*.json"))
	for i := 0; i < len(files); i++ {
		if filepath.Base(files[i]) == "l1spine.json" {
			files = append(files[:i], files[i+1:]...)
			i--
		}
	}
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		var lf legFile
		if err := json.Unmarshal(raw, &lf); err != nil {
			return err
		}
		rows, err := store.Rows(ctx, uint64(basefinal.Chain), basefinal.ItemGame(addr20(lf.Game)))
		if err != nil || len(rows) == 0 {
			fmt.Printf("%s: no capture\n", lf.Name)
			continue
		}
		gc, err := basefinal.DecodeGameCapture(rows[0].Data)
		if err != nil {
			return err
		}
		h, err := rpc.L1HeaderByNumber(ctx, gc.L1Block)
		if err != nil {
			return err
		}
		if h.Hash != gc.L1Hash {
			fmt.Printf("%s: capture A=%d hash differs from the canonical block (reorg): recapture\n", lf.Name, gc.L1Block)
			continue
		}
		var l2 [][]byte
		for _, x := range lf.L2Headers {
			b, _ := hex.DecodeString(x)
			l2 = append(l2, b)
		}
		leg := finality.BlockRef{Chain: uint64(basefinal.Chain), Number: lf.LegBlock}
		last, err := finality.ReadHeader(l2[len(l2)-1])
		if err != nil {
			return err
		}
		leg.Hash, leg.HeaderRLP = last.Hash, l2[len(l2)-1]
		body := basefinal.Body{StateBlock: gc.L1Block, GameProxy: gc.Game, GameCode: gc.GameCode, OutputRootIndex: lf.OutputRoot, L2Spine: l2, Nodes: gc.Nodes}
		a := ethl1.L1Block{Hash: h.Hash, Number: h.Number, StateRoot: h.StateRoot, Timestamp: h.Timestamp}
		fields, err := basefinal.Judge(bp, a, body, leg, ethl1.FinalizedHead{})
		if err != nil {
			fmt.Printf("%s: REFUSED/STATE %v\n", lf.Name, err)
			continue
		}
		b, _ := json.Marshal(fields)
		fmt.Printf("%s: OK %s\n", lf.Name, b)
	}
	return nil
}
