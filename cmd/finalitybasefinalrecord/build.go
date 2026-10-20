// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/basefinal"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

func hx(b []byte) string { return "0x" + hex.EncodeToString(b) }

func writeJSON(path string, v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	b = append(b, '\n')
	return b, os.WriteFile(path, b, 0o644)
}

func deepCopy(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	_ = dec.Decode(&out)
	return out
}

// composePins writes the finality-pins override of the set: the embedded pins plus a Sepolia ledger whose one anchor is the
// committee of the signature period of the recorded light-client finality update (the next_sync_committee of the recorded update
// of the period before it). It is a vector-set pin, not a published ledger entry (single source).
func composePins(rawDir string) (map[string]any, ethl1.LC, error) {
	var lc ethl1.LC
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(finality.EmbeddedPinsBytes()))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, lc, err
	}
	var capt struct {
		SigPeriod uint64 `json:"final_signature_period"`
	}
	cb, err := os.ReadFile(filepath.Join(rawDir, "capture.json"))
	if err != nil {
		return nil, lc, err
	}
	if err := json.Unmarshal(cb, &capt); err != nil {
		return nil, lc, err
	}
	P := capt.SigPeriod
	fu, err := os.ReadFile(filepath.Join(rawDir, "finality_update.ssz"))
	if err != nil {
		return nil, lc, err
	}
	linkRaw, err := os.ReadFile(filepath.Join(rawDir, "updates", fmt.Sprintf("%d.ssz", P-1)))
	if err != nil {
		return nil, lc, err
	}
	const offNext, committeeLen = 496, 24624
	comm := linkRaw[offNext : offNext+committeeLen]
	root, err := ethl1.HashTreeRootSyncCommittee(comm)
	if err != nil {
		return nil, lc, err
	}
	ls := sha256.Sum256(linkRaw)
	eth := m["eth_sepolia"].(map[string]any)
	eth["anchors"] = []any{map[string]any{"period": P, "committee_root": hx(root[:]), "wsp_epochs": 279, "link_sha256": hex.EncodeToString(ls[:]),
		"derived_by": []any{"vector-set pin: next_sync_committee of the Lodestar light_client update of period " + strconv.FormatUint(P-1, 10) + " captured " + time.Now().UTC().Format("2006-01-02") + " (single source; not a published ledger entry)"}}}
	lc = ethl1.LC{Profile: ethl1.ProfileLC, AnchorKind: 1, AnchorPeriod: P, AnchorRoot: root, AnchorBody: ethl1.LB{Layout: ethl1.LayoutNone, SSZ: append([]byte(nil), comm...)},
		FinalUpdate: ethl1.LB{Layout: ethl1.LayoutGloas, SSZ: fu}}
	return m, lc, nil
}

type bcase struct {
	id, desc, pins string
	ev             []byte
	base           []byte // nil: the evidence is stored whole
	baseFile       string
	leg            string
	want           string // the hand-written canonical expected verdict
}

type gen struct {
	out      string
	files    map[string][]byte
	cases    []string
	judgeIDs []string
}

func (g *gen) put(name string, b []byte) {
	g.files[name] = b
	p := filepath.Join(g.out, filepath.FromSlash(name))
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		panic(err)
	}
}

func (g *gen) add(c bcase) error {
	g.cases = append(g.cases, c.id)
	var e basefinal.Expect
	var wantRaw struct {
		Code   string          `json:"code"`
		Fields json.RawMessage `json:"fields"`
		Result string          `json:"result"`
	}
	if err := json.Unmarshal([]byte(c.want), &wantRaw); err != nil {
		return fmt.Errorf("%s: %w", c.id, err)
	}
	e = basefinal.Expect{Result: wantRaw.Result, Code: wantRaw.Code, Fields: wantRaw.Fields}
	if e.Result == "" {
		e.Result = "state"
	}
	evFile := "evidence/" + c.id + ".bin"
	cs := basefinal.Case{Format: "certen-finality-vectors/1", ID: c.id, Description: c.desc, Pins: c.pins, Leg: c.leg, Expect: json.RawMessage(basefinal.ExpectBytes(e))}
	if c.base != nil {
		cs.Base = c.baseFile
		cs.Splice = basefinal.Diff(c.base, c.ev)
	} else {
		cs.Base = evFile
		g.put(evFile, c.ev)
	}
	b, _ := json.MarshalIndent(cs, "", "  ")
	g.put("cases/"+c.id+".json", append(b, '\n'))
	return nil
}

func buildCmd(ctx context.Context, dir, rawLC, legsDir, out string) error {
	if dir == "" || rawLC == "" || legsDir == "" || out == "" {
		return fmt.Errorf("-dir, -raw, -legs and -out are required")
	}
	g := &gen{out: out, files: map[string][]byte{}}
	pinsMain, lc, err := composePins(rawLC)
	if err != nil {
		return err
	}
	pb, _ := json.MarshalIndent(pinsMain, "", "  ")
	g.put("pins/main.json", append(pb, '\n'))
	pins, err := finality.ParsePinsOverride(g.files["pins/main.json"])
	if err != nil {
		return fmt.Errorf("the composed pins do not parse: %w", err)
	}
	bp, err := basefinal.ParsePins(pins)
	if err != nil {
		return err
	}
	var sf spineFile
	sb, err := os.ReadFile(filepath.Join(legsDir, "l1spine.json"))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(sb, &sf); err != nil {
		return err
	}
	store := basefinal.DirStore{Dir: dir}
	ev := map[string][]byte{}
	legOf := map[string]string{}
	bodies := map[string]basefinal.Body{}
	legBlocks := map[string]finality.BlockRef{}
	for _, c := range recordedCases {
		rows, _ := basefinal.Rows(ctx, store, uint64(basefinal.Chain), basefinal.ItemGame(addr20(c.Game)))
		lb, lerr := os.ReadFile(filepath.Join(legsDir, c.Name+".json"))
		if len(rows) == 0 || lerr != nil {
			return fmt.Errorf("%s: no capture or leg file", c.Name)
		}
		gc, err := basefinal.DecodeGameCapture(rows[0].Data)
		if err != nil {
			return err
		}
		var lf legFile
		if err := json.Unmarshal(lb, &lf); err != nil {
			return err
		}
		// L1 spine from the finalized head down to this capture's A
		var l1 [][]byte
		for i, n := range sf.Numbers {
			raw, _ := hex.DecodeString(sf.Headers[i])
			l1 = append(l1, raw)
			if n == gc.L1Block {
				break
			}
		}
		if sf.Numbers[len(l1)-1] != gc.L1Block {
			return fmt.Errorf("%s: the recorded spine does not reach the capture block %d", c.Name, gc.L1Block)
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
		body := basefinal.Body{LC: lc, L1Spine: l1, StateBlock: gc.L1Block, GameProxy: gc.Game, GameCode: gc.GameCode, OutputRootIndex: lf.OutputRoot, L2Spine: l2, Nodes: gc.Nodes}
		bodies[c.Name] = body
		legBlocks[c.Name] = finality.BlockRef{Chain: uint64(basefinal.Chain), Number: lh.Number, Hash: lh.Hash, HeaderRLP: l2[len(l2)-1]}
		legName := "legs/" + c.Name + ".json"
		legOf[c.Name] = legName
		lj, _ := json.MarshalIndent(basefinal.Leg{Chain: "84532", Number: strconv.FormatUint(lh.Number, 10), Hash: hx(lh.Hash[:]), Header: hx(l2[len(l2)-1])}, "", "  ")
		g.put(legName, append(lj, '\n'))
		ev[c.Name] = container(basefinal.Body(body), lh)
	}
	return g.finish(ctx, bp, pins, ev, legOf, bodies, legBlocks, lc)
}

func container(body basefinal.Body, leg finality.HeaderFields) []byte {
	c := finality.Container{Header: finality.ContainerHeader{Kind: basefinal.KindName, Chain: uint64(basefinal.Chain), Level: finality.LevelFinalized, BlockNumber: leg.Number, BlockHash: leg.Hash}, Body: basefinal.EncodeBody(body)}
	b, err := c.Encode()
	if err != nil {
		panic(err)
	}
	return b
}

func (g *gen) writeManifest() error {
	names := make([]string, 0, len(g.files))
	for n := range g.files {
		names = append(names, n)
	}
	sort.Strings(names)
	files := map[string]string{}
	for _, n := range names {
		files[n] = basefinal.FileSHA256(g.files[n])
	}
	sort.Strings(g.cases)
	sort.Strings(g.judgeIDs)
	g.cases = uniq(g.cases)
	g.judgeIDs = uniq(g.judgeIDs)
	m := map[string]any{"format": "certen-finality-vectors-manifest/1", "set": basefinal.SetName, "cases": g.cases, "judge_cases": g.judgeIDs, "files": files}
	b, err := writeJSON(filepath.Join(g.out, "manifest.json"), m)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(g.out, "MANIFEST.sha256"), []byte(basefinal.FileSHA256(b)+"\n"), 0o644)
}

var _ = binary.BigEndian
var _ = crypto.Keccak256

func uniq(s []string) []string {
	var out []string
	for i, x := range s {
		if i == 0 || x != s[i-1] {
			out = append(out, x)
		}
	}
	return out
}
