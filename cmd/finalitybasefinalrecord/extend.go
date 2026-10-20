// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/basefinal"
)

// round2Games are captured later than the first set (they name games of other types and the oldest type-621 game); their cases
// are appended to the published set with the light-client evidence of the later finalized head. No existing file changes.
var round2Games = []struct{ id, desc, game string }{
	{"other_type_0_resolved_before_the_cutover", "live: a type-0 (FaultDisputeGame) game, DEFENDER_WINS, created before the retirement timestamp: not a type-621 game, so its implementation is not pinned", "0x7e12e92b9ec79f1ffcee431edb436107e1ed6def"},
	{"other_type_0_resolved_2024", "live: a type-0 game created in 2024 with the older clone shape", "0x5358416beb7230095213462c5523de7f242fcf2f"},
	{"other_type_0_2026_02", "live: a type-0 game of 2026-03", "0x3138cf2769d390e69d7f11921ffb75f6a22c9d4e"},
	{"oldest_type_621_game", "live: the oldest type-621 game of the factory (index 15114)", "0xe22a96d3cd353c8876cec8b94be10d08c916255c"},
}

// extendCmd appends the round-2 cases to an existing set directory and rewrites its manifest.
func extendCmd(ctx context.Context, dir, rawLC, legsDir, out string) error {
	g := &gen{out: out, files: map[string][]byte{}}
	mraw, err := os.ReadFile(filepath.Join(out, "manifest.json"))
	if err != nil {
		return err
	}
	var m struct {
		Cases []string          `json:"cases"`
		Judge []string          `json:"judge_cases"`
		Files map[string]string `json:"files"`
	}
	if err := json.Unmarshal(mraw, &m); err != nil {
		return err
	}
	for n := range m.Files {
		b, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(n)))
		if err != nil {
			return err
		}
		g.files[n] = b
	}
	g.cases, g.judgeIDs = m.Cases, m.Judge
	pinsMain, lc, err := composePins(rawLC)
	if err != nil {
		return err
	}
	pb, _ := json.MarshalIndent(pinsMain, "", "  ")
	if string(append(pb, '\n')) != string(g.files["pins/main.json"]) {
		return fmt.Errorf("the later light-client anchor changes pins/main.json: a new pins file is needed")
	}
	var sf spineFile
	sb, err := os.ReadFile(filepath.Join(legsDir, "l1spine.json"))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(sb, &sf); err != nil {
		return err
	}
	// the template: the first live case's L2 data
	mainLeg, err := os.ReadFile(filepath.Join(out, "legs", "leg_47604755.json"))
	if err != nil {
		return err
	}
	_ = mainLeg
	var lf legFile
	lb, err := os.ReadFile(filepath.Join(legsDir, "leg_47604755.json"))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(lb, &lf); err != nil {
		return err
	}
	var l2 [][]byte
	for _, x := range lf.L2Headers {
		b, _ := hex.DecodeString(x)
		l2 = append(l2, b)
	}
	lh, err := finality.ReadHeader(l2[len(l2)-1])
	if err != nil {
		return err
	}
	store := basefinal.DirStore{Dir: dir}
	rpc := liveRPC()
	for _, r := range round2Games {
		rows, _ := store.Rows(ctx, uint64(basefinal.Chain), basefinal.ItemGame(addr20(r.game)))
		if len(rows) == 0 {
			return fmt.Errorf("%s: no capture", r.id)
		}
		var gc basefinal.GameCapture
		for _, row := range rows {
			c, err := basefinal.DecodeGameCapture(row.Data)
			if err != nil {
				return err
			}
			if c.L1Block >= 11954232 {
				gc = c
				break
			}
		}
		if gc.L1Block == 0 {
			return fmt.Errorf("%s: no round-2 capture", r.id)
		}
		var l1 [][]byte
		for i, n := range sf.Numbers {
			raw, _ := hex.DecodeString(sf.Headers[i])
			l1 = append(l1, raw)
			if n == gc.L1Block {
				break
			}
		}
		var implAddr [20]byte
		copy(implAddr[:], gc.GameCode[65:85])
		code, err := rpc.CodeLatest(ctx, implAddr)
		if err != nil || len(code) == 0 {
			return fmt.Errorf("%s: the embedded implementation %x has no code: %v", r.id, implAddr[:], err)
		}
		chash := crypto.Keccak256Hash(code)
		body := basefinal.Body{LC: lc, L1Spine: l1, StateBlock: gc.L1Block, GameProxy: gc.Game, GameCode: gc.GameCode, OutputRootIndex: lf.OutputRoot, L2Spine: l2, Nodes: gc.Nodes}
		want := `{"code":"contract_identity_unproven","fields":{"address":` + hexq(implAddr[:]) + `,"code_hash":` + h32(chash) + `,"judged_at":` + dec(gc.L1Block) + `,"role":"game_impl"}}`
		if strings.EqualFold(hex.EncodeToString(implAddr[:]), "d702aae6221f36dfe7e8ebc4315d64344a9db4cb") {
			continue // a 0.2.0 game would need its own L2 data: not a refusal case
		}
		legName := "legs/leg_47604755.json"
		if err := g.add(bcase{id: r.id, desc: r.desc, pins: "pins/main.json", ev: container(body, lh), leg: legName, want: want}); err != nil {
			return err
		}
	}
	return g.writeManifest()
}
