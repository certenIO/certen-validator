// Copyright 2026 Certen Protocol

// finalityethsepoliarecord records the real Sepolia legs of the published vector set finality_eth_sepolia1 and builds the set.
//
//	finalityethsepoliarecord record -vecpins <dir with pins.json and links/> -raw <dir>        (network: Lodestar + Sepolia RPC)
//	finalityethsepoliarecord build  -raw <dir> -out pkg/finality/ethsepolia/testdata/finality_eth_sepolia1   (offline, deterministic)
//
// record builds, with the production Prover, the evidence of three real legs (a post-Gloas leg served by the latest finality
// update, a post-Gloas leg served by its period's best update, the legacy pre-Gloas leg in the electra layout) and replays-
// captures one pending leg (a block newer than the latest finalized head). build mutates the real bytes into the adversarial
// cases and writes the manifest. Every expected verdict is a canonical literal computed in this file from the recorded bytes by
// small independent readers (RLP, SSZ offsets), never by the verifier under test; build refuses a case whose verdict differs.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
	"github.com/certen/independant-validator/pkg/finality/ethsepolia"
	"github.com/certen/independant-validator/pkg/finality/lcssz"
)

const (
	setName  = "finality_eth_sepolia1"
	lodestar = "https://lodestar-sepolia.chainsafe.io"
	execRPC1 = "https://ethereum-sepolia-rpc.publicnode.com"
	execRPC2 = "https://1rpc.io/sepolia"
	chain    = finality.ChainSepolia
)

var legs = []struct {
	id     string
	number uint64
}{{"gloas_latest", 11950125}, {"gloas_period", 11862203}, {"legacy", 11845679}}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: finalityethsepoliarecord record|build [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "record":
		err = recordCmd(os.Args[2:])
	case "build":
		err = buildCmd(os.Args[2:])
	case "build2":
		err = build2Cmd(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAILED:", ethrpc.RedactText(err.Error()))
		os.Exit(1)
	}
}

func hx(b []byte) string { return "0x" + hex.EncodeToString(b) }

func writeFile(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

type legJSON struct {
	Chain     string `json:"chain"`
	Number    string `json:"number"`
	Hash      string `json:"hash"`
	HeaderRLP string `json:"header_rlp"`
}

func legOf(ref finality.BlockRef) legJSON {
	return legJSON{Chain: strconv.FormatUint(ref.Chain, 10), Number: strconv.FormatUint(ref.Number, 10), Hash: hx(ref.Hash[:]), HeaderRLP: hx(ref.HeaderRLP)}
}

func refOf(l legJSON) (finality.BlockRef, error) {
	n, err := strconv.ParseUint(l.Number, 10, 64)
	if err != nil {
		return finality.BlockRef{}, err
	}
	h, err := hex.DecodeString(strings.TrimPrefix(l.Hash, "0x"))
	if err != nil || len(h) != 32 {
		return finality.BlockRef{}, fmt.Errorf("bad hash")
	}
	hr, err := hex.DecodeString(strings.TrimPrefix(l.HeaderRLP, "0x"))
	if err != nil {
		return finality.BlockRef{}, err
	}
	ref := finality.BlockRef{Chain: chain, Number: n, HeaderRLP: hr}
	copy(ref.Hash[:], h)
	return ref, nil
}

// ---- record ----

// recSource records what an LCSource served so a pending build can be replayed offline.
type recSource struct {
	ethsepolia.LCSource
	finality []byte
	head     uint64
}

func (r *recSource) FinalityUpdate(ctx context.Context) ([]byte, error) {
	b, err := r.LCSource.FinalityUpdate(ctx)
	if err == nil {
		r.finality = append([]byte(nil), b...)
	}
	return b, err
}

func (r *recSource) HeadSlot(ctx context.Context) (uint64, error) {
	h, err := r.LCSource.HeadSlot(ctx)
	if err == nil {
		r.head = h
	}
	return h, err
}

type recHeaders struct {
	ethsepolia.HeaderSource
	byHash map[string][]byte
}

func (r *recHeaders) HeaderByHash(ctx context.Context, h [32]byte) ([]byte, error) {
	b, err := r.HeaderSource.HeaderByHash(ctx, h)
	if err == nil {
		r.byHash[hx(h[:])] = b
	}
	return b, err
}

type capture struct {
	BuiltUTC      string `json:"built_utc"`
	BuildMillis   int64  `json:"build_ms"`
	VerifyMillis  int64  `json:"verify_ms"`
	EvidenceBytes int    `json:"evidence_bytes"`
	SpineHeaders  int    `json:"spine_headers"`
	Links         int    `json:"links"`
	LCLayout      string `json:"final_update_layout"`
	Lodestar      string `json:"lc_source"`
	Exec          string `json:"exec_source"`
}

func recordCmd(args []string) error {
	fs := flag.NewFlagSet("record", flag.ExitOnError)
	vecpins := fs.String("vecpins", "", "directory with pins.json and links/ (finalitypins derive-sepolia -out-pins/-links-dir output)")
	raw := fs.String("raw", "", "output directory")
	_ = fs.Parse(args)
	if *vecpins == "" || *raw == "" {
		return fmt.Errorf("-vecpins and -raw are required")
	}
	ctx := context.Background()
	pinsRaw, err := os.ReadFile(filepath.Join(*vecpins, "pins.json"))
	if err != nil {
		return err
	}
	pins, err := finality.ParsePinsOverride(pinsRaw)
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(*raw, "pins.json"), pinsRaw); err != nil {
		return err
	}
	links := map[uint64][]byte{}
	ents, err := os.ReadDir(filepath.Join(*vecpins, "links"))
	if err != nil {
		return err
	}
	for _, en := range ents {
		p, err := strconv.ParseUint(strings.TrimSuffix(en.Name(), ".ssz"), 10, 64)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(filepath.Join(*vecpins, "links", en.Name()))
		if err != nil {
			return err
		}
		links[p] = b
		if err := writeFile(filepath.Join(*raw, "links", en.Name()), b); err != nil {
			return err
		}
	}
	if err := pins.VerifyLedger(links); err != nil {
		return fmt.Errorf("the vector pins do not re-derive: %v", err)
	}
	src := &recSource{LCSource: ethsepolia.Multi{ethsepolia.NewHTTPSource(lodestar)}}
	hdrs := &recHeaders{HeaderSource: &ethsepolia.RPCHeaders{Endpoints: []string{execRPC1, execRPC2}}, byHash: map[string][]byte{}}
	prover := &ethsepolia.Prover{Source: src, Exec: hdrs, Pins: pins, Verifier: ethsepolia.New(), ExtraLinks: links}

	for _, lg := range legs {
		hs, err := hdrs.HeadersByNumber(ctx, lg.number, lg.number)
		if err != nil {
			return err
		}
		h := crypto.Keccak256Hash(hs[0])
		ref := finality.BlockRef{Chain: chain, Number: lg.number, Hash: h, HeaderRLP: hs[0]}
		t0 := time.Now()
		add, pend, err := prover.BuildLeg(ctx, ref)
		if err != nil {
			return fmt.Errorf("%s: %v", lg.id, err)
		}
		if add == nil {
			return fmt.Errorf("%s: pending: %v", lg.id, pend)
		}
		built := time.Since(t0)
		t1 := time.Now()
		if _, err := ethsepolia.New().Verify(pins, ref, add.Evidence); err != nil {
			return fmt.Errorf("%s: the verifier refuses what the builder built: %v", lg.id, err)
		}
		c, _ := finality.DecodeContainer(add.Evidence, finality.DefaultLimits())
		body, _ := ethsepolia.DecodeBody(c.Body, finality.DefaultLimits(), 64, 16384)
		cap := capture{BuiltUTC: time.Now().UTC().Format(time.RFC3339), BuildMillis: built.Milliseconds(), VerifyMillis: time.Since(t1).Milliseconds(),
			EvidenceBytes: len(add.Evidence), SpineHeaders: len(body.Spine), Links: len(body.LC.Links), Lodestar: lodestar, Exec: execRPC1,
			LCLayout: map[ethl1.Layout]string{ethl1.LayoutElectra: "electra", ethl1.LayoutGloas: "gloas"}[body.LC.FinalUpdate.Layout]}
		cj, _ := json.MarshalIndent(cap, "", " ")
		lj, _ := json.MarshalIndent(legOf(ref), "", " ")
		for name, b := range map[string][]byte{"evidence.bin": add.Evidence, "capture.json": cj, "leg.json": lj} {
			if err := writeFile(filepath.Join(*raw, lg.id, name), b); err != nil {
				return err
			}
		}
		fmt.Printf("%s: block %d built in %v, verified in %v, %d bytes, %d headers, %d links, final layout %s\n",
			lg.id, lg.number, built, time.Since(t1), len(add.Evidence), len(body.Spine), len(body.LC.Links), cap.LCLayout)
	}

	// pending: a block three above the latest finalized execution head, built against the recorded answers
	fu, err := src.LCSource.FinalityUpdate(ctx)
	if err != nil {
		return err
	}
	hash, num, has, err := lcssz.FinalizedExec(lcssz.LayoutOfFinalityUpdate(fu), fu)
	if err != nil {
		return err
	}
	if !has {
		h0, err := hdrs.HeaderByHash(ctx, hash)
		if err != nil {
			return err
		}
		f, err := finality.ReadHeader(h0)
		if err != nil {
			return err
		}
		num = f.Number
	}
	hs, err := hdrs.HeadersByNumber(ctx, num+3, num+3)
	if err != nil {
		return err
	}
	ref := finality.BlockRef{Chain: chain, Number: num + 3, Hash: crypto.Keccak256Hash(hs[0]), HeaderRLP: hs[0]}
	rec := &recSource{LCSource: ethsepolia.Multi{ethsepolia.NewHTTPSource(lodestar)}}
	pv := &ethsepolia.Prover{Source: rec, Exec: hdrs, Pins: pins, Verifier: ethsepolia.New(), ExtraLinks: links}
	add, pend, err := pv.BuildLeg(ctx, ref)
	if err != nil || add != nil || pend == nil {
		return fmt.Errorf("the leg three blocks above the finalized head was not pending (%v %v %v)", err, add != nil, pend)
	}
	lj, _ := json.MarshalIndent(legOf(ref), "", " ")
	meta, _ := json.MarshalIndent(map[string]any{"observed_head_slot": rec.head, "now_unix": time.Now().Unix(), "finalized_header_hash": hx(hash[:])}, "", " ")
	hj := map[string]string{}
	for k, v := range hdrs.byHash {
		hj[k] = hx(v)
	}
	hjb, _ := json.MarshalIndent(hj, "", " ")
	for name, b := range map[string][]byte{"leg.json": lj, "finality_update.ssz": rec.finality, "meta.json": meta, "headers_by_hash.json": hjb} {
		if err := writeFile(filepath.Join(*raw, "pending", name), b); err != nil {
			return err
		}
	}
	fmt.Printf("pending: block %d, latest finalized exec %d: %s\n", ref.Number, num, pend.State().Canonical())
	return nil
}

// ---- build ----

type patch struct {
	At  int    `json:"at"`
	Del int    `json:"del"`
	Ins string `json:"ins"`
}

type vecCase struct {
	Format      string  `json:"format"`
	ID          string  `json:"id"`
	Description string  `json:"description"`
	Pins        string  `json:"pins"`
	Leg         legJSON `json:"leg"`
	Base        string  `json:"evidence_base"`
	Patches     []patch `json:"evidence_patches"`
	Expect      string  `json:"expect_canonical"`
}

func applyPatches(base []byte, ps []patch) []byte {
	idx := make([]int, len(ps))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool { return ps[idx[a]].At > ps[idx[b]].At })
	out := append([]byte(nil), base...)
	for _, i := range idx {
		p := ps[i]
		ins, _ := hex.DecodeString(strings.TrimPrefix(p.Ins, "0x"))
		out = append(append(append([]byte(nil), out[:p.At]...), ins...), out[p.At+p.Del:]...)
	}
	return out
}

func canonState(code string, kv ...any) string {
	s := finality.NewState(code, kv...)
	return string(s.Canonical())
}

type rawLeg struct {
	id       string
	ev       []byte
	ref      finality.BlockRef
	body     ethsepolia.Body
	cap      capture
	spineAt  int // offset of the spine count
	elemAt   []int
	anchorAt int // offset of the anchor body's layout byte
	linksAt  int
	finalAt  int // offset of the final update's layout byte
}

func loadLeg(rawDir, id string) (*rawLeg, error) {
	ev, err := os.ReadFile(filepath.Join(rawDir, id, "evidence.bin"))
	if err != nil {
		return nil, err
	}
	var lj legJSON
	b, err := os.ReadFile(filepath.Join(rawDir, id, "leg.json"))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &lj); err != nil {
		return nil, err
	}
	ref, err := refOf(lj)
	if err != nil {
		return nil, err
	}
	l := &rawLeg{id: id, ev: ev, ref: ref}
	if b, err = os.ReadFile(filepath.Join(rawDir, id, "capture.json")); err == nil {
		_ = json.Unmarshal(b, &l.cap)
	}
	c, err := finality.DecodeContainer(ev, finality.DefaultLimits())
	if err != nil {
		return nil, err
	}
	if l.body, err = ethsepolia.DecodeBody(c.Body, finality.DefaultLimits(), 64, 16384); err != nil {
		return nil, err
	}
	// offsets by re-walking the encoding
	hdr := 81
	l.anchorAt = hdr + 4 + len(l.body.LC.Profile) + 1 + 8 + 32
	p := l.anchorAt + 5 + len(l.body.LC.AnchorBody.SSZ)
	l.linksAt = p
	p += 4
	for _, lk := range l.body.LC.Links {
		p += 5 + len(lk.SSZ)
	}
	l.finalAt = p
	p += 5 + len(l.body.LC.FinalUpdate.SSZ)
	l.spineAt = p
	p += 4
	for _, h := range l.body.Spine {
		l.elemAt = append(l.elemAt, p)
		p += 4 + len(h)
	}
	if p != len(ev) {
		return nil, fmt.Errorf("%s: offsets walk ends at %d, evidence is %d bytes", id, p, len(ev))
	}
	return l, nil
}

type hdrInfo struct {
	hash, parent, stateRoot [32]byte
	number                  uint64
}

func readHdr(raw []byte) hdrInfo {
	var items []rlp.RawValue
	if err := rlp.DecodeBytes(raw, &items); err != nil {
		panic(err)
	}
	var h hdrInfo
	h.hash = crypto.Keccak256Hash(raw)
	copy(h.parent[:], mustBytes(items[0]))
	copy(h.stateRoot[:], mustBytes(items[3]))
	n := mustBytes(items[8])
	for _, b := range n {
		h.number = h.number<<8 | uint64(b)
	}
	return h
}

func mustBytes(v rlp.RawValue) []byte {
	var b []byte
	if err := rlp.DecodeBytes(v, &b); err != nil {
		panic(err)
	}
	return b
}

func u32(v int) string    { var b [4]byte; binary.BigEndian.PutUint32(b[:], uint32(v)); return hx(b[:]) }
func u64(v uint64) string { var b [8]byte; binary.BigEndian.PutUint64(b[:], v); return hx(b[:]) }

func replaceAt(at int, b []byte) patch { return patch{At: at, Del: len(b), Ins: hx(b)} }

type builder struct {
	set    string // manifest set name (setName when empty)
	readme string // README text (the set 1 text when empty)
	out    string
	cases  []vecCase
	extend []extendCase
	files  map[string][]byte
	pinsN  map[string]*finality.Pins
}

func (b *builder) addFile(rel string, data []byte) { b.files[rel] = data }

func (b *builder) pins(name string) *finality.Pins { return b.pinsN[name] }

func (b *builder) add(c vecCase, base *rawLeg, verdict func(*finality.Pins, finality.BlockRef, []byte) (finality.Verdict, error)) error {
	c.Format = "certen-finality-ethsepolia-case/1"
	c.Base = "raw/" + base.id + "/evidence.bin"
	ev := applyPatches(base.ev, c.Patches)
	ref, err := refOf(c.Leg)
	if err != nil {
		return err
	}
	v, verr := verdict(b.pins(strings.TrimSuffix(strings.TrimPrefix(c.Pins, "pins/"), ".json")), ref, ev)
	got := canonOf(v, verr)
	if got != c.Expect {
		return fmt.Errorf("case %s: the verifier says\n  %s\nthe generator's literal is\n  %s", c.ID, got, c.Expect)
	}
	b.cases = append(b.cases, c)
	return nil
}

func canonOf(v finality.Verdict, err error) string {
	if err != nil {
		if s, ok := finality.AsNamed(err); ok {
			return string(s.Canonical())
		}
		return "unnamed: " + err.Error()
	}
	f := map[string]any{}
	for k, x := range v.Fields {
		f[k] = x
	}
	f["kind"] = v.Kind
	f["level"] = v.Level
	return string((&finality.StateError{Code: "verified", Fields: f}).Canonical())
}

func verifyWith(pins *finality.Pins, ref finality.BlockRef, ev []byte) (finality.Verdict, error) {
	return ethsepolia.New().Verify(pins, ref, ev)
}

// validExpect is the canonical literal of an accepted leg, computed from the recorded bytes by small independent readers.
func validExpect(l *rawLeg) string {
	fu := l.body.LC.FinalUpdate.SSZ
	lay := lcssz.LayoutOfFinalityUpdate(fu)
	_, fin, sig, err := lcssz.FinalityUpdateSlots(lay, fu)
	if err != nil {
		panic(err)
	}
	part, _ := lcssz.FinalityUpdateParticipants(lay, fu)
	top := readHdr(l.body.Spine[0])
	f := map[string]any{
		"finalized_slot": fin, "finalized_exec_number": top.number, "participants": uint64(part),
		"periods_crossed": sig/8192 - l.body.LC.AnchorPeriod, "headers_walked": uint64(len(l.body.Spine)), "anchor_period": l.body.LC.AnchorPeriod,
		"kind": ethsepolia.Name, "level": finality.LevelFinalized,
	}
	return string((&finality.StateError{Code: "verified", Fields: f}).Canonical())
}

func buildCmd(args []string) error {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	rawDir := fs.String("raw", "", "raw directory written by record")
	out := fs.String("out", "", "set directory")
	_ = fs.Parse(args)
	if *rawDir == "" || *out == "" {
		return fmt.Errorf("-raw and -out are required")
	}
	pinsRaw, err := os.ReadFile(filepath.Join(*rawDir, "pins.json"))
	if err != nil {
		return err
	}
	b := &builder{out: *out, files: map[string][]byte{}, pinsN: map[string]*finality.Pins{}}
	if err := b.pinVariants(pinsRaw); err != nil {
		return err
	}
	legsLoaded := map[string]*rawLeg{}
	for _, lg := range legs {
		l, err := loadLeg(*rawDir, lg.id)
		if err != nil {
			return err
		}
		legsLoaded[lg.id] = l
		for _, n := range []string{"evidence.bin", "leg.json", "capture.json"} {
			d, err := os.ReadFile(filepath.Join(*rawDir, lg.id, n))
			if err != nil {
				return err
			}
			b.addFile("raw/"+lg.id+"/"+n, d)
		}
	}
	ents, err := os.ReadDir(filepath.Join(*rawDir, "links"))
	if err != nil {
		return err
	}
	links := map[uint64][]byte{}
	for _, en := range ents {
		d, err := os.ReadFile(filepath.Join(*rawDir, "links", en.Name()))
		if err != nil {
			return err
		}
		p, _ := strconv.ParseUint(strings.TrimSuffix(en.Name(), ".ssz"), 10, 64)
		links[p] = d
		b.addFile("raw/links/"+en.Name(), d)
	}
	for _, n := range []string{"leg.json", "finality_update.ssz", "meta.json", "headers_by_hash.json"} {
		d, err := os.ReadFile(filepath.Join(*rawDir, "pending", n))
		if err != nil {
			return err
		}
		b.addFile("raw/pending/"+n, d)
	}
	if err := b.verifyCases(legsLoaded); err != nil {
		return err
	}
	if err := b.extendCases(pinsRaw, links); err != nil {
		return err
	}
	return b.write()
}

// pinVariants writes pins/main.json (the recorded vector pins) and the variants that alter exactly one thing.
func (b *builder) pinVariants(raw []byte) error {
	set := func(name string, data []byte) error {
		p, err := finality.ParsePinsOverride(data)
		if err != nil {
			return fmt.Errorf("pins %s: %v", name, err)
		}
		b.pinsN[name] = p
		b.addFile("pins/"+name+".json", data)
		return nil
	}
	if err := set("main", raw); err != nil {
		return err
	}
	edit := func(f func(m map[string]any, es map[string]any)) []byte {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			panic(err)
		}
		f(m, m["eth_sepolia"].(map[string]any))
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		_ = enc.Encode(m)
		return buf.Bytes()
	}
	if err := set("ledger_ends_1385", edit(func(_ map[string]any, es map[string]any) {
		var keep []any
		for _, a := range es["anchors"].([]any) {
			if p, _ := a.(map[string]any)["period"].(json.Number).Int64(); p <= 1385 {
				keep = append(keep, a)
			}
		}
		es["anchors"] = keep
	})); err != nil {
		return err
	}
	if err := set("ledger_empty", edit(func(_ map[string]any, es map[string]any) { es["anchors"] = []any{} })); err != nil {
		return err
	}
	return set("gvr_other", edit(func(_ map[string]any, es map[string]any) {
		es["genesis_validators_root"] = "0x00" + es["genesis_validators_root"].(string)[4:]
	}))
}

func (b *builder) write() error {
	for _, c := range b.cases {
		j, _ := json.MarshalIndent(c, "", " ")
		b.files["cases/"+c.ID+".json"] = append(j, '\n')
	}
	sums := map[string]string{}
	for rel, d := range b.files {
		s := sha256.Sum256(d)
		sums[rel] = hex.EncodeToString(s[:])
	}
	var ids []string
	for _, c := range b.cases {
		ids = append(ids, c.ID)
	}
	for _, c := range b.extend { // in generation order: the manifest is deterministic
		ids = append(ids, c.ID)
	}
	name := b.set
	if name == "" {
		name = setName
	}
	m := map[string]any{"format": "certen-finality-manifest/1", "set": name, "cases": ids, "files": sums}
	mj, _ := json.MarshalIndent(m, "", " ")
	mj = append(mj, '\n')
	b.files["MANIFEST.json"] = mj
	ms := sha256.Sum256(mj)
	b.files["MANIFEST.json.sha256"] = []byte(hex.EncodeToString(ms[:]) + "\n")
	if b.readme != "" {
		b.files["README.md"] = []byte(b.readme)
	} else {
		b.files["README.md"] = []byte(readme)
	}
	for rel, d := range b.files {
		if err := writeFile(filepath.Join(b.out, filepath.FromSlash(rel)), d); err != nil {
			return err
		}
	}
	fmt.Printf("%s: %d verify cases, %d extend cases, MANIFEST sha256 %x\n", name, len(b.cases), len(b.extend), ms)
	return nil
}
