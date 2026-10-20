// Copyright 2026 Certen Protocol

// Command vectorgen writes the published conformance set finality_arb_final1 for arb-sepolia/finalized/v1 (V2_SPEC_S7 5.7):
// every vector's expected verdict is a canonical literal written here (the generator refuses to write a vector whose
// recomputed verdict differs), the synthetic worlds come from pkg/finality/arbfinal/synthworld, and the REAL vectors are
// derived from the live capture of cmd/finalityarbfinalrecord when -live is given.
//
//	go run ./pkg/finality/arbfinal/vectorgen -out pkg/finality/arbfinal/testdata/finality_arb_final1 [-live <dir>]
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbfinal"
)

type vLeg struct {
	Chain     uint64 `json:"chain"`
	Number    uint64 `json:"number"`
	Hash      string `json:"hash"`
	HeaderHex string `json:"header_hex"`
}

type vEdit struct {
	Offset int    `json:"offset"`
	Delete int    `json:"delete"`
	Insert string `json:"insert"`
}

type vec struct {
	Name     string  `json:"name"`
	Group    string  `json:"group"`
	Note     string  `json:"note"`
	Leg      vLeg    `json:"leg"`
	Pins     string  `json:"pins"`
	Evidence string  `json:"evidence,omitempty"`
	Base     string  `json:"base,omitempty"`
	Edits    []vEdit `json:"edits,omitempty"`
	Expect   string  `json:"expect"`
}

var mismatches []string

type gen struct {
	evidence map[string][]byte
	pins     map[string][]byte
	vecs     []vec
	byName   map[string]vec
	raw      map[string][]byte // name -> full evidence of every vector (for patching)
}

func newGen() *gen {
	return &gen{evidence: map[string][]byte{}, pins: map[string][]byte{}, byName: map[string]vec{}, raw: map[string][]byte{}}
}

func hx(b []byte) string { return hex.EncodeToString(b) }

// st is the canonical text of a named state: the literal a vector expects.
func st(code string, kv ...any) string { return string(finality.NewState(code, kv...).Canonical()) }

// okText is the canonical text of an accepted verdict (code "finalized") with the given fields.
func okText(fields map[string]any) string {
	var kv []any
	for k, v := range fields {
		kv = append(kv, k, v)
	}
	return st("finalized", kv...)
}

func outcome(v finality.Verdict, err error) string {
	if err != nil {
		if s, ok := finality.AsNamed(err); ok {
			return string(s.Canonical())
		}
		return "ERROR: " + err.Error()
	}
	var kv []any
	for k, val := range v.Fields {
		kv = append(kv, k, val)
	}
	return st("finalized", kv...)
}

// add records one vector. pinsRaw is the pins file the vector is judged against (stored once per distinct content under
// pins/); "embedded" means the repository's embedded pins. The expected literal is checked against the verifier before it is
// written: a generator whose literal disagrees with the verifier is a bug in one of them and stops here.
func (g *gen) add(name, group, note string, leg finality.BlockRef, pinsName string, pinsRaw []byte, evidence []byte, expect string) {
	var pins *finality.Pins
	var err error
	if pinsName == "embedded" {
		pins, err = finality.EmbeddedPins()
	} else {
		g.pins[pinsName] = pinsRaw
		pins, err = finality.ParsePinsOverride(pinsRaw)
	}
	if err != nil {
		panic(fmt.Sprintf("%s: pins: %v", name, err))
	}
	v, verr := arbfinal.New().Verify(pins, leg, evidence)
	if got := outcome(v, verr); got != expect {
		mismatches = append(mismatches, fmt.Sprintf("%s:\n got:  %s\n want: %s", name, got, expect))
	}
	e := vec{Name: name, Group: group, Note: note, Pins: pinsName, Expect: expect,
		Leg: vLeg{Chain: leg.Chain, Number: leg.Number, Hash: "0x" + hx(leg.Hash[:]), HeaderHex: hx(leg.HeaderRLP)}}
	g.raw[name] = evidence
	// A vector close to an earlier one with the same leg is stored as a patch of it.
	patched := false
	for _, bn := range []string{"synth_valid_direct", "real_valid"} {
		base, ok := g.raw[bn]
		if !ok || bn == name || !g.sameFamily(bn, name) {
			continue
		}
		pre := 0
		for pre < len(base) && pre < len(evidence) && base[pre] == evidence[pre] {
			pre++
		}
		suf := 0
		for suf < len(base)-pre && suf < len(evidence)-pre && base[len(base)-1-suf] == evidence[len(evidence)-1-suf] {
			suf++
		}
		ins := evidence[pre : len(evidence)-suf]
		if len(ins) <= 8192 {
			e.Base = bn
			e.Edits = []vEdit{{Offset: pre, Delete: len(base) - pre - suf, Insert: hx(ins)}}
			patched = true
			break
		}
	}
	if !patched {
		g.evidence[name] = evidence
		e.Evidence = name + ".bin"
	}
	g.vecs = append(g.vecs, e)
	g.byName[name] = e
}

func (g *gen) sameFamily(base, name string) bool {
	real := len(name) >= 4 && (name[:4] == "real" || (len(name) >= 8 && name[:8] == "adv_real"))
	return real == (base == "real_valid")
}

func (g *gen) write(out string) error {
	if err := os.MkdirAll(filepath.Join(out, "evidence"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(out, "pins"), 0o755); err != nil {
		return err
	}
	files := map[string]string{}
	put := func(rel string, b []byte) error {
		files[rel] = fmt.Sprintf("%x", sha256.Sum256(b))
		return os.WriteFile(filepath.Join(out, filepath.FromSlash(rel)), b, 0o644)
	}
	var names []string
	for k := range g.evidence {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if err := put("evidence/"+k+".bin", g.evidence[k]); err != nil {
			return err
		}
	}
	names = nil
	for k := range g.pins {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if err := put("pins/"+k, g.pins[k]); err != nil {
			return err
		}
	}
	if err := put("README.md", []byte(readmeText)); err != nil {
		return err
	}
	vj, err := json.MarshalIndent(map[string]any{"format": "finality_arb_final1/1", "vectors": g.vecs}, "", " ")
	if err != nil {
		return err
	}
	vj = append(vj, '\n')
	if err := put("vectors.json", vj); err != nil {
		return err
	}
	mj, _ := json.MarshalIndent(map[string]any{"format": "finality_arb_final1/manifest/1", "files": files}, "", " ")
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

func main() {
	out := flag.String("out", "pkg/finality/arbfinal/testdata/finality_arb_final1", "output directory")
	live := flag.String("live", "", "directory written by cmd/finalityarbfinalrecord (adds the real vectors)")
	flag.Parse()
	if err := generate(*out, *live); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// generate builds the set and writes it to out. A vector whose expected literal differs from the verifier is an error (all
// mismatches are listed).
func generate(out, live string) error {
	mismatches = nil
	g := newGen()
	synthetic(g)
	synthetic2(g)
	if live != "" {
		if err := realVectors(g, live); err != nil {
			return err
		}
	}
	if len(mismatches) > 0 {
		return fmt.Errorf("%d vectors disagree with the verifier:\n%s", len(mismatches), strings.Join(mismatches, "\n"))
	}
	return g.write(out)
}

var _ = bytes.Equal
var _ = common.Hash{}
