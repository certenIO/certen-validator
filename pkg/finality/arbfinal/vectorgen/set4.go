// Copyright 2026 Certen Protocol

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/certen/independant-validator/pkg/finality"
)

// generate4 publishes the fourth set, finality_arb_final4 (RB12-OPS-A1, BETA finding B-ARB-2): eight worlds in which an L1 header has
// an item that the light-client spine reader (parent, state root, number, timestamp) accepts and the framework's positional header
// reader (parent, state root, transactions root, receipts root, number, timestamp, withdrawals root from 17 items) refuses. The
// verifier applies the framework reader to K's header ONLY, so an odd header at the finalized head, at S, or anywhere but K is judged and an
// odd header at K is finality_block_not_covered{block_number: K, finalized_exec_number: F}.
//
// The worlds are read from dir from (vectors.json, evidence/, pins/ in the layout of every set): they were built in the BETA session by
// a throwaway Go program (a six-line hook in synthworld.header that edits the items of an L1 header before it is encoded) at pv2/rb11-e1-raise
// cbb6373 and carried by certen-sdk as the TS-held supplement arb_final_x. This function does what every generator of this package does with
// a world it is given: it judges EVERY vector with the verifier of this checkout, refuses to write a vector whose expected literal differs
// from the verdict, and writes the set in the published layout with its manifest. Run on the published set itself it reproduces it byte for
// byte (gen4_test.go).
func generate4(out, from string) error {
	mismatches = nil
	g := newGen()
	raw, err := os.ReadFile(filepath.Join(from, "vectors.json"))
	if err != nil {
		return err
	}
	var f struct {
		Vectors []vec `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return err
	}
	if len(f.Vectors) == 0 {
		return fmt.Errorf("%s holds no vectors", from)
	}
	for _, v := range f.Vectors {
		if v.Base != "" || len(v.Edits) != 0 || v.Evidence != v.Name+".bin" {
			return fmt.Errorf("%s: this set stores one whole evidence file per vector, named after it (evidence %q, base %q)", v.Name, v.Evidence, v.Base)
		}
		ev, err := os.ReadFile(filepath.Join(from, "evidence", v.Evidence))
		if err != nil {
			return err
		}
		pins, err := os.ReadFile(filepath.Join(from, "pins", v.Pins))
		if err != nil {
			return err
		}
		hash, err := hex.DecodeString(strings.TrimPrefix(v.Leg.Hash, "0x"))
		if err != nil || len(hash) != 32 {
			return fmt.Errorf("%s: leg hash %q", v.Name, v.Leg.Hash)
		}
		header, err := hex.DecodeString(v.Leg.HeaderHex)
		if err != nil {
			return fmt.Errorf("%s: header_hex: %v", v.Name, err)
		}
		g.add(v.Name, v.Group, v.Note, finality.BlockRef{Chain: v.Leg.Chain, Number: v.Leg.Number, Hash: [32]byte(hash), HeaderRLP: header}, v.Pins, pins, ev, v.Expect)
	}
	if len(mismatches) > 0 {
		return fmt.Errorf("%d vectors disagree with the verifier:\n%s", len(mismatches), strings.Join(mismatches, "\n"))
	}
	return g.write4(out)
}

// write4 writes the set in the layout of write3 with the format tags of the fourth set.
func (g *gen) write4(out string) error {
	for _, d := range []string{"evidence", "pins"} {
		if err := os.MkdirAll(filepath.Join(out, d), 0o755); err != nil {
			return err
		}
	}
	files := map[string]string{}
	put := func(rel string, b []byte) error {
		files[rel] = fmt.Sprintf("%x", sha256.Sum256(b))
		return os.WriteFile(filepath.Join(out, filepath.FromSlash(rel)), b, 0o644)
	}
	for _, kind := range []struct {
		dir, ext string
		m        map[string][]byte
	}{{"evidence", ".bin", g.evidence}, {"pins", "", g.pins}} {
		var names []string
		for k := range kind.m {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			if err := put(kind.dir+"/"+k+kind.ext, kind.m[k]); err != nil {
				return err
			}
		}
	}
	vj, err := json.MarshalIndent(map[string]any{"format": "finality_arb_final4/1", "vectors": g.vecs}, "", " ")
	if err != nil {
		return err
	}
	if err := put("vectors.json", append(vj, '\n')); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "README.md"), []byte(readme4Text), 0o644); err != nil {
		return err
	}
	mj, _ := json.MarshalIndent(map[string]any{"format": "finality_arb_final4/manifest/1", "files": files}, "", " ")
	mj = append(mj, '\n')
	if err := os.WriteFile(filepath.Join(out, "MANIFEST.json"), mj, 0o644); err != nil {
		return err
	}
	sum := sha256.Sum256(mj)
	if err := os.WriteFile(filepath.Join(out, "MANIFEST.json.sha256"), []byte(hex.EncodeToString(sum[:])+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %d vectors, %d evidence files, %d pins files; MANIFEST sha256 %x\n", len(g.vecs), len(g.evidence), len(g.pins), sum)
	return nil
}
