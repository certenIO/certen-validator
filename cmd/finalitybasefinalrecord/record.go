// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/basefinal"
)

// legCase is one recorded case: a captured game and the L2 block (the "leg") whose finality is judged against it.
type legCase struct {
	Name     string `json:"name"`
	Game     string `json:"game"`
	LegBlock uint64 `json:"leg_block"` // 0: start+7 of the game
}

// the cases recorded from live Base Sepolia (R11-legs.md legs with RESOLVED 0.2.0 covering games, the unresolved 0.3.0 game
// 28495, and the in-progress 0.2.0 game 28494)
var recordedCases = []legCase{
	{"leg_47604755", "0x3b91948aafcc00cf76aecd837169e4cee0389815", 47604755},
	{"leg_47898494", "0xe8a6d478f72edb9573a898f68779cac391e1c88e", 47898494},
	{"g030_28495", "0x468258dccc0cdc699599ee0b8b0375536a67c346", 0},
	{"g020_28494_inprogress", "0xd5fa1a9005235f17cc11d6b6c4770c4c4aa90d31", 0},
}

// legFile is the recorded raw material of one case.
type legFile struct {
	Name       string   `json:"name"`
	Game       string   `json:"game"`
	LegBlock   uint64   `json:"leg_block"`
	OutputRoot uint32   `json:"output_root_index"`
	OutBlock   uint64   `json:"output_root_block"`
	L2Headers  []string `json:"l2_headers"` // hex, descending from the output-root block to the leg block
}

// recordCmd records, for every case with a capture in dir, the L2 headers from the nearest intermediate root >= the leg block
// down to the leg block (Base RPC, not windowed) into out/<name>.json. It is idempotent.
func recordCmd(ctx context.Context, dir, raw, out string) error {
	if dir == "" || out == "" {
		return fmt.Errorf("-dir and -out are required")
	}
	pins, err := finality.EmbeddedPins()
	if err != nil {
		return err
	}
	bp, err := basefinal.ParsePins(pins)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	store := basefinal.DirStore{Dir: dir}
	rpc := liveRPC()
	for _, c := range recordedCases {
		rows, err := store.Rows(ctx, uint64(basefinal.Chain), basefinal.ItemGame(addr20(c.Game)))
		if err != nil || len(rows) == 0 {
			fmt.Printf("%s: no capture (%v)\n", c.Name, err)
			continue
		}
		gc, err := basefinal.DecodeGameCapture(rows[0].Data)
		if err != nil {
			return err
		}
		lay := bp.Layouts[basefinal.LayoutAggregateV1]
		tmplLen := len(lay.CloneHead) + 2 + len(lay.CloneMid) + 20 + len(lay.CloneTail)
		args := gc.GameCode[tmplLen : len(gc.GameCode)-2]
		l2seq := binary.BigEndian.Uint64(args[84+24 : 84+32])
		start := l2seq - 600
		leg := c.LegBlock
		if leg == 0 {
			leg = start + 7
		}
		if leg <= start || leg > l2seq {
			fmt.Printf("%s: leg block %d is outside the game's range (%d,%d]\n", c.Name, leg, start, l2seq)
			continue
		}
		k := uint32((leg - start + 29) / 30) // nearest intermediate root >= leg (interval 30)
		outBlock := start + 30*uint64(k)
		lf := legFile{Name: c.Name, Game: c.Game, LegBlock: leg, OutputRoot: k, OutBlock: outBlock}
		for n := outBlock; ; n-- {
			h, err := rpc.L2HeaderByNumber(ctx, n)
			if err != nil {
				return fmt.Errorf("%s: L2 header %d: %w", c.Name, n, err)
			}
			lf.L2Headers = append(lf.L2Headers, hex.EncodeToString(h.Raw))
			if n == leg {
				break
			}
		}
		b, _ := json.MarshalIndent(lf, "", "  ")
		if err := os.WriteFile(filepath.Join(out, c.Name+".json"), append(b, '\n'), 0o644); err != nil {
			return err
		}
		fmt.Printf("%s: game %s leg %d k=%d outBlock=%d headers=%d (capture A=%d)\n", c.Name, c.Game, leg, k, outBlock, len(lf.L2Headers), gc.L1Block)
	}
	if raw != "" {
		return recordSpine(ctx, dir, raw, out)
	}
	return nil
}

// spineFile is the recorded L1 execution spine: raw headers descending from the finalized execution head of the recorded
// light-client finality update to the lowest captured L1 block.
type spineFile struct {
	ExecHash string   `json:"exec_hash"`
	Headers  []string `json:"headers"` // hex, descending
	Numbers  []uint64 `json:"numbers"`
}

// recordSpine reads the finalized execution hash out of the recorded Gloas finality update and walks the parents by hash down to
// the lowest captured block.
func recordSpine(ctx context.Context, dir, raw, out string) error {
	fu, err := os.ReadFile(filepath.Join(raw, "finality_update.ssz"))
	if err != nil {
		return err
	}
	if len(fu) != 1448 {
		return fmt.Errorf("finality_update.ssz is %d bytes, want 1448 (Gloas)", len(fu))
	}
	var exec [32]byte
	copy(exec[:], fu[496+112:496+144])
	store := basefinal.DirStore{Dir: dir}
	low := uint64(1<<63 - 1)
	for _, c := range recordedCases {
		rows, _ := store.Rows(ctx, uint64(basefinal.Chain), basefinal.ItemGame(addr20(c.Game)))
		for _, r := range rows {
			if r.L1Block < low {
				low = r.L1Block
			}
		}
	}
	rpc := liveRPC()
	sf := spineFile{ExecHash: "0x" + hex.EncodeToString(exec[:])}
	cur := exec
	for {
		h, err := rpc.L1HeaderByHash(ctx, cur)
		if err != nil {
			return fmt.Errorf("spine header %x: %w", cur[:4], err)
		}
		sf.Headers = append(sf.Headers, hex.EncodeToString(h.Raw))
		sf.Numbers = append(sf.Numbers, h.Number)
		if h.Number <= low {
			break
		}
		cur = h.Parent
	}
	b, _ := json.MarshalIndent(sf, "", "  ")
	fmt.Printf("L1 spine: %d headers, %d down to %d\n", len(sf.Headers), sf.Numbers[0], sf.Numbers[len(sf.Numbers)-1])
	return os.WriteFile(filepath.Join(out, "l1spine.json"), append(b, '\n'), 0o644)
}
