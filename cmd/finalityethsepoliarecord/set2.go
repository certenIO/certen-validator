// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
	"github.com/certen/independant-validator/pkg/finality/ethsepolia"
	"github.com/certen/independant-validator/pkg/finality/lcssz"
)

const setName2 = "finality_eth_sepolia2"

const readme2 = `# finality_eth_sepolia2 - eth-sepolia/finalized/v1 anchored at the EMBEDDED root pin

Spec: V2_SPEC_S7 r2 sections 3.2, 4.3, 5.2 and 8.2. Same case shapes and canonical verdict form as finality_eth_sepolia1 (see its README);
that set is never edited.

## Why a second set

finality_eth_sepolia1 is judged under VECTOR pins: a 14-entry ledger (1378..1391) whose entries 1379..1390 were derived by verified
light-client links only (spec 4.3(b), the two-client rule, cannot be met for them: no public beacon client serves those historical
states, RB11-C2-F1). The pins EMBEDDED in the verifiers hold the root pin 1378 only. Evidence anchored at 1380 or 1391 is therefore
refused under the embedded pins as finality_ledger_behind, although nothing in it is wrong. This set is the production shape under the
embedded pins: the evidence is ANCHORED AT THE ROOT PIN and carries the best light-client update of every period from 1378 to the
signature period as in-evidence LINKS (spec 3.2), at most max_links (64) of them. Each case is judged under pins/main.json, which is
byte-identical to pkg/finality/pins/finality-pins.json at generation; the Go test also judges the valid cases under the pins embedded in
the running verifier.

## Contents

| path | content |
|---|---|
| raw/<leg>/evidence.bin | the CFE1 container built by the production Prover (ethsepolia.Prover.BuildLeg) against the embedded pins from the answers recorded for finality_eth_sepolia1 (final update, spine headers, the best update of every period 1378..1390), and accepted by the verifier. gloas_latest: block 11,950,125, 13 links; gloas_period: block 11,862,203; legacy: block 11,845,679 (electra layout, anchored at 1378, 0 links) |
| raw/gloas_latest_kind2/evidence.bin | the same evidence with a kind-2 anchor: the Fulu bootstrap of the pinned checkpoint block root instead of the bare committee (what the runtime light-client source builds for the rollup kinds) |
| raw/<leg>/leg.json, capture.json | the leg block; sizes and times |
| raw/links/<period>.ssz | the ledger link files (1378 = the root bootstrap, q = the best update of period q-1) |
| pins/main.json | the embedded pins file |
| cases/<id>.json | one verification case |

## Cases

valid_gloas_latest, valid_gloas_period, valid_legacy, valid_gloas_latest_kind2 (accepted, verdict fields as in set 1);
adv_link_signature_flipped (one signature byte of link 5: finality_signature_invalid{index 5}), adv_link_removed (link 5 removed:
finality_link_invalid{period_skip}), adv_links_removed_all (no links although the final update is 13 periods past the anchor:
finality_period_gap), adv_links_over_bound (link count 65: finality_evidence_too_large), adv_kind2_anchor_root_altered (kind-2
anchorRoot differs from the pinned block root: finality_pin_mismatch).

## Regenerating

    finalityethsepoliarecord build2 -set1 pkg/finality/ethsepolia/testdata/finality_eth_sepolia1 -out pkg/finality/ethsepolia/testdata/finality_eth_sepolia2    # offline
`

// replaySource serves the answers recorded for set 1: one finality update and the best update of every period 1378..1390.
type replaySource struct {
	final []byte
	links map[uint64][]byte // links[q] is the update that derived period q (the best update of period q-1); links[root] the bootstrap
	slot  uint64
}

func (r *replaySource) Name() string { return "replay" }
func (r *replaySource) FinalityUpdate(context.Context) ([]byte, error) {
	return r.final, nil
}
func (r *replaySource) HeadSlot(context.Context) (uint64, error) { return r.slot, nil }
func (r *replaySource) Bootstrap(context.Context, [32]byte) ([]byte, error) {
	return r.links[1378], nil
}
func (r *replaySource) Updates(_ context.Context, start uint64, count int) ([][]byte, error) {
	var out [][]byte
	for i := 0; i < count; i++ {
		u, ok := r.links[start+uint64(i)+1]
		if !ok {
			return nil, fmt.Errorf("the recording holds no update for period %d", start+uint64(i))
		}
		out = append(out, u)
	}
	return out, nil
}

type replayHeaders struct {
	byHash map[[32]byte][]byte
	byNum  map[uint64][]byte
}

func (r *replayHeaders) HeaderByHash(_ context.Context, h [32]byte) ([]byte, error) {
	if b, ok := r.byHash[h]; ok {
		return b, nil
	}
	return nil, fmt.Errorf("the recording holds no header %x", h[:4])
}

func (r *replayHeaders) HeadersByNumber(_ context.Context, from, to uint64) ([][]byte, error) {
	var out [][]byte
	for n := from; n <= to; n++ {
		b, ok := r.byNum[n]
		if !ok {
			return nil, fmt.Errorf("the recording holds no header %d", n)
		}
		out = append(out, b)
	}
	return out, nil
}

func build2Cmd(args []string) error {
	fs := flag.NewFlagSet("build2", flag.ExitOnError)
	set1 := fs.String("set1", "", "directory of finality_eth_sepolia1")
	out := fs.String("out", "", "directory of finality_eth_sepolia2")
	pinsFile := fs.String("pins", "", "pins/main.json of the committed set 2: a published set is reproduced from its own committed pins, never from the live embedded ones; empty: the live embedded pins (how a NEW set is made)")
	_ = fs.Parse(args)
	if *set1 == "" || *out == "" {
		return fmt.Errorf("-set1 and -out are required")
	}
	embRaw := finality.EmbeddedPinsBytes()
	emb, err := finality.EmbeddedPins()
	if *pinsFile != "" {
		if embRaw, err = os.ReadFile(*pinsFile); err == nil {
			emb, err = finality.LoadPins(embRaw, sha256.Sum256(embRaw)) // the same source label as the embedded file
		}
	}
	if err != nil {
		return err
	}
	links, err := finality.EmbeddedLedgerLinks()
	if err != nil {
		return err
	}
	e, _ := emb.Sepolia()
	if len(e.Anchors) != 1 || e.Anchors[0].BlockRoot == "" {
		return fmt.Errorf("set 2 is the root-only shape: the embedded ledger has %d anchors", len(e.Anchors))
	}
	// the full recorded link set of set 1 (14 files) supplies the best updates of 1378..1390; the root bootstrap must be the embedded one
	all := map[uint64][]byte{}
	ents, err := os.ReadDir(filepath.Join(*set1, "raw", "links"))
	if err != nil {
		return err
	}
	for _, en := range ents {
		p, _ := strconv.ParseUint(strings.TrimSuffix(en.Name(), ".ssz"), 10, 64)
		if all[p], err = os.ReadFile(filepath.Join(*set1, "raw", "links", en.Name())); err != nil {
			return err
		}
	}
	if string(all[1378]) != string(links[1378]) {
		return fmt.Errorf("the recorded root bootstrap is not the embedded one")
	}
	b := &builder{set: setName2, readme: readme2, out: *out, files: map[string][]byte{}, pinsN: map[string]*finality.Pins{}}
	main, err := finality.ParsePinsOverride(embRaw)
	if err != nil {
		return err
	}
	b.pinsN["main"] = main
	b.addFile("pins/main.json", embRaw)
	for p, d := range all {
		b.addFile(fmt.Sprintf("raw/links/%d.ssz", p), d)
	}

	ctx := context.Background()
	for _, lg := range legs {
		old, err := loadLeg(filepath.Join(*set1, "raw"), lg.id)
		if err != nil {
			return err
		}
		rs := &replaySource{final: old.body.LC.FinalUpdate.SSZ, links: all}
		_, _, rs.slot, _ = lcssz.FinalityUpdateSlots(lcssz.LayoutOfFinalityUpdate(rs.final), rs.final)
		rh := &replayHeaders{byHash: map[[32]byte][]byte{}, byNum: map[uint64][]byte{}}
		for _, h := range old.body.Spine {
			hi := readHdr(h)
			rh.byHash[hi.hash] = h
			rh.byNum[hi.number] = h
		}
		pv := &ethsepolia.Prover{Source: rs, Exec: rh, Pins: emb, Verifier: ethsepolia.New(), ExtraLinks: all, Now: func() time.Time { return time.Unix(0, 0) }}
		t0 := time.Now()
		add, pend, err := pv.BuildLeg(ctx, old.ref)
		if err != nil || add == nil {
			return fmt.Errorf("%s: the Prover built nothing (%v %v)", lg.id, err, pend)
		}
		buildMs := time.Since(t0).Milliseconds()
		t1 := time.Now()
		if _, err := ethsepolia.New().Verify(emb, old.ref, add.Evidence); err != nil {
			return fmt.Errorf("%s: the verifier refuses the Prover's evidence under the embedded pins: %v", lg.id, err)
		}
		verMs := time.Since(t1).Milliseconds()
		c, _ := finality.DecodeContainer(add.Evidence, finality.DefaultLimits())
		body, _ := ethsepolia.DecodeBody(c.Body, finality.DefaultLimits(), 64, 16384)
		b.addFile("raw/"+lg.id+"/evidence.bin", add.Evidence)
		b.addFile("raw/"+lg.id+"/leg.json", mustJSON(legOf(old.ref)))
		b.addFile("raw/"+lg.id+"/capture.json", mustJSON(capture{BuiltUTC: "replayed from finality_eth_sepolia1 raw answers", BuildMillis: buildMs, VerifyMillis: verMs,
			EvidenceBytes: len(add.Evidence), SpineHeaders: len(body.Spine), Links: len(body.LC.Links), Lodestar: "replay", Exec: "replay",
			LCLayout: map[ethl1.Layout]string{ethl1.LayoutElectra: "electra", ethl1.LayoutGloas: "gloas"}[body.LC.FinalUpdate.Layout]}))
		fmt.Printf("%s: block %d, %d bytes, %d links, %d headers (set 1 evidence %d bytes), verify under the embedded pins %d ms\n",
			lg.id, old.ref.Number, len(add.Evidence), len(body.LC.Links), len(body.Spine), len(old.ev), verMs)
	}
	// kind-2 variant of gloas_latest: the bootstrap of the pinned checkpoint instead of the bare committee
	g, err := b.loadFromFiles("gloas_latest")
	if err != nil {
		return err
	}
	k2 := g.body
	k2.LC.AnchorKind = 2
	root := rootBytes(e.Anchors[0].BlockRoot)
	copy(k2.LC.AnchorRoot[:], root)
	k2.LC.AnchorBody = ethl1.LB{Layout: ethl1.LayoutElectra, SSZ: all[1378]}
	k2ev, err := ethsepolia.BuildContainer(g.ref, k2)
	if err != nil {
		return err
	}
	b.addFile("raw/gloas_latest_kind2/evidence.bin", k2ev)
	b.addFile("raw/gloas_latest_kind2/leg.json", mustJSON(legOf(g.ref)))
	if _, err := ethsepolia.New().Verify(main, g.ref, k2ev); err != nil {
		return fmt.Errorf("the kind-2 variant is refused under the embedded pins: %v", err)
	}

	// write the raw files first (loadLeg reads a directory), then the cases
	for rel, d := range b.files {
		if err := writeFile(filepath.Join(*out, filepath.FromSlash(rel)), d); err != nil {
			return err
		}
	}
	rawDir := filepath.Join(*out, "raw")
	L := map[string]*rawLeg{}
	for _, id := range []string{"gloas_latest", "gloas_period", "legacy", "gloas_latest_kind2"} {
		if L[id], err = loadLeg(rawDir, id); err != nil {
			return err
		}
	}
	if err := b.cases2(L, e.Anchors[0]); err != nil {
		return err
	}
	return b.write()
}

func mustJSON(v any) []byte {
	b, err := jsonIndent(v)
	if err != nil {
		panic(err)
	}
	return b
}

func rootBytes(h string) []byte {
	b := make([]byte, 32)
	for i := 0; i < 32; i++ {
		v, _ := strconv.ParseUint(h[2+2*i:4+2*i], 16, 8)
		b[i] = byte(v)
	}
	return b
}

// loadFromFiles reads a leg back from the builder's staged files.
func (b *builder) loadFromFiles(id string) (*rawLeg, error) {
	dir, err := os.MkdirTemp("", "ethsepolia2-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	for _, n := range []string{"evidence.bin", "leg.json", "capture.json"} {
		if err := writeFile(filepath.Join(dir, id, n), b.files["raw/"+id+"/"+n]); err != nil {
			return nil, err
		}
	}
	return loadLeg(dir, id)
}

// linkOffsets returns, for each link, the offset of its SSZ bytes in the evidence (after its layout byte and length prefix).
func linkOffsets(l *rawLeg) []int {
	var out []int
	p := l.linksAt + 4
	for _, lk := range l.body.LC.Links {
		out = append(out, p+5)
		p += 5 + len(lk.SSZ)
	}
	return out
}

func (b *builder) cases2(L map[string]*rawLeg, root finality.AnchorPin) error {
	G := L["gloas_latest"]
	K := L["gloas_latest_kind2"]
	add := func(id, desc string, base *rawLeg, patches []patch, expect string) error {
		return b.add(vecCase{ID: id, Description: desc, Pins: "pins/main.json", Leg: legOf(base.ref), Patches: patches, Expect: expect}, base, verifyWith)
	}
	for _, c := range []struct {
		id, desc string
		l        *rawLeg
	}{
		{"valid_gloas_latest", "post-Gloas block 11,950,125, anchored at the root pin 1378 with 13 in-evidence links", G},
		{"valid_gloas_period", "post-Gloas block 11,862,203, anchored at the root pin 1378 with its in-evidence links", L["gloas_period"]},
		{"valid_legacy", "pre-Gloas block 11,845,679 (electra layout), anchored at the root pin 1378", L["legacy"]},
		{"valid_gloas_latest_kind2", "block 11,950,125 with a kind-2 anchor: the Fulu bootstrap of the pinned checkpoint block root", K},
	} {
		if err := add(c.id, c.desc, c.l, nil, validExpect(c.l)); err != nil {
			return err
		}
	}
	nl := len(G.body.LC.Links)
	if nl < 8 {
		return fmt.Errorf("gloas_latest carries %d links, the link cases need at least 8", nl)
	}
	offs := linkOffsets(G)
	const li = 5
	lk := G.body.LC.Links[li].SSZ
	if len(lk) != lcssz.GloasUpdateSize {
		return fmt.Errorf("link %d is %d bytes, not a Gloas update", li, len(lk))
	}
	_, _, sig, err := lcssz.UpdateSlots(lcssz.Gloas, lk)
	if err != nil {
		return err
	}
	pop := 0
	for _, x := range lk[26256:26320] {
		for ; x != 0; x &= x - 1 {
			pop++
		}
	}
	flipAt := offs[li] + 26320 + 20
	if err := add("adv_link_signature_flipped", "one byte of the aggregate signature of link 5 flipped", G, []patch{replaceAt(flipAt, []byte{G.ev[flipAt] ^ 0x01})},
		canonState("finality_signature_invalid", "index", li, "signature_slot", sig, "fork_version", "0x90000076", "participants", pop)); err != nil {
		return err
	}
	next := G.body.LC.Links[li+1].SSZ
	att, _, nsig, _ := lcssz.UpdateSlots(lcssz.LayoutOfUpdate(next), next)
	linkStart := func(i int) int { return offs[i] - 5 }
	rmStart, rmEnd := linkStart(li), linkStart(li+1)
	if err := add("adv_link_removed", "link 5 removed (count adjusted): the next link skips a sync-committee period", G,
		[]patch{{At: G.linksAt, Del: 4, Ins: u32(nl - 1)}, {At: rmStart, Del: rmEnd - rmStart, Ins: "0x"}},
		canonState("finality_link_invalid", "index", li, "check", "period_skip", "attested_slot", att, "signature_slot", nsig, "period", nsig/8192)); err != nil {
		return err
	}
	_, _, finSig, _ := lcssz.FinalityUpdateSlots(lcssz.LayoutOfFinalityUpdate(G.body.LC.FinalUpdate.SSZ), G.body.LC.FinalUpdate.SSZ)
	if err := add("adv_links_removed_all", "no links although the final update is signed 13 periods after the anchor", G,
		[]patch{{At: G.linksAt, Del: 4, Ins: u32(0)}, {At: linkStart(0), Del: G.finalAt - linkStart(0), Ins: "0x"}},
		canonState("finality_period_gap", "signature_period", finSig/8192, "store_period", G.body.LC.AnchorPeriod)); err != nil {
		return err
	}
	if err := add("adv_links_over_bound", "the link count is 65, one over max_links", G, []patch{{At: G.linksAt, Del: 4, Ins: u32(65)}},
		canonState("finality_evidence_too_large", "part", "lc.links", "count", uint64(65), "limit", uint64(64))); err != nil {
		return err
	}
	altered := K.body.LC.AnchorRoot
	altered[0] ^= 0xff
	return add("adv_kind2_anchor_root_altered", "the kind-2 anchorRoot differs from the pinned block root", K, []patch{replaceAt(102, []byte{K.ev[102] ^ 0xff})},
		canonState("finality_pin_mismatch", "period", root.Period, "want_root", root.BlockRoot, "got_root", hx(altered[:])))
}

func jsonIndent(v any) ([]byte, error) { return json.MarshalIndent(v, "", " ") }
