// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/adiri"
)

// ---- the vector file format (consumed byte-identically by the TypeScript port) ----

type edit struct {
	Offset int    `json:"offset"` // in the BASE evidence
	Delete int    `json:"delete"`
	Insert string `json:"insert"` // hex
}

type legJSON struct {
	Chain     uint64 `json:"chain"`
	Number    uint64 `json:"number"`
	Hash      string `json:"hash"`
	HeaderHex string `json:"header_hex,omitempty"` // the leg's Settlement.Header (raw RLP) when held
}

type vec struct {
	Name     string  `json:"name"`
	Group    string  `json:"group"` // live | adversarial | synthetic
	Note     string  `json:"note"`
	Leg      legJSON `json:"leg"`
	Pins     any     `json:"pins"`               // "embedded" or the adiri pins section object
	Evidence string  `json:"evidence,omitempty"` // file under evidence/
	Base     string  `json:"base,omitempty"`     // a vector name whose evidence the edits apply to
	Edits    []edit  `json:"edits,omitempty"`    // applied from the highest offset to the lowest
	Expect   string  `json:"expect"`             // canonical {code, fields} text, written here as a literal
}

// canon renders {"code":...,"fields":{...}} independently of finality.StateError.Canonical: sorted keys, every unsigned
// integer as a decimal string, byte arrays as lowercase hex, lists of strings as JSON arrays.
func canon(code string, kv ...any) string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i].(string)] = canonVal(kv[i+1])
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(`{"code":` + jsonStr(code) + `,"fields":{`)
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(jsonStr(k) + ":" + m[k])
	}
	b.WriteString("}}")
	return b.String()
}

func jsonStr(s string) string {
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimRight(sb.String(), "\n")
}

func canonVal(v any) string {
	switch x := v.(type) {
	case string:
		return jsonStr(x)
	case bool:
		return strconv.FormatBool(x)
	case int:
		return jsonStr(strconv.Itoa(x))
	case uint64:
		return jsonStr(strconv.FormatUint(x, 10))
	case [32]byte:
		return jsonStr(hex.EncodeToString(x[:]))
	case []string:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = jsonStr(e)
		}
		return "[" + strings.Join(parts, ",") + "]"
	}
	panic(fmt.Sprintf("canonVal: %T", v))
}

// ---- edits ----

func hexOf(b []byte) string { return hex.EncodeToString(b) }

// diffEdits turns base into mut with a few local edits: common bytes are skipped, and after a difference the next point at which
// 32 bytes agree again (within a 2 KiB window on each side) ends the edit. The result is exact by construction (asserted).
func diffEdits(base, mut []byte) []edit {
	const win, sync = 2048, 32
	var out []edit
	i, j := 0, 0
	for i < len(base) || j < len(mut) {
		if i < len(base) && j < len(mut) && base[i] == mut[j] {
			i++
			j++
			continue
		}
		i2, j2, found := i, j, false
		for d := 0; d <= 2*win && !found; d++ {
			for di := 0; di <= d && di <= win; di++ {
				dj := d - di
				if dj > win {
					continue
				}
				a, b := i+di, j+dj
				if a > len(base) || b > len(mut) {
					continue
				}
				if a == len(base) && b == len(mut) {
					i2, j2, found = a, b, true
					break
				}
				if a+sync <= len(base) && b+sync <= len(mut) && string(base[a:a+sync]) == string(mut[b:b+sync]) {
					i2, j2, found = a, b, true
					break
				}
			}
		}
		if !found {
			i2, j2 = len(base), len(mut)
		}
		out = append(out, edit{Offset: i, Delete: i2 - i, Insert: hexOf(mut[j:j2])})
		i, j = i2, j2
	}
	if string(applyEdits(base, out)) != string(mut) {
		panic("diffEdits: the edits do not reproduce the mutant")
	}
	return out
}

func applyEdits(base []byte, edits []edit) []byte {
	out := append([]byte(nil), base...)
	es := append([]edit(nil), edits...)
	sort.Slice(es, func(i, j int) bool { return es[i].Offset > es[j].Offset })
	for _, e := range es {
		ins, _ := hex.DecodeString(e.Insert)
		out = append(append(append([]byte(nil), out[:e.Offset]...), ins...), out[e.Offset+e.Delete:]...)
	}
	return out
}

// ---- the live base ----

type parsed struct {
	c    finality.Container
	body *adiri.Body
	cf   *adiri.CFA1
}

func parse(ev []byte) parsed {
	lim := finality.DefaultLimits()
	c, err := finality.DecodeContainer(ev, lim)
	must(err)
	b, err := adiri.DecodeBody(c.Body, lim, 0)
	must(err)
	cf, err := adiri.DecodeCFA1(b.CFA1, lim)
	must(err)
	return parsed{c, b, cf}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func (p parsed) encode() []byte {
	enc, err := p.cf.Encode()
	must(err)
	p.body.CFA1 = enc
	out, err := finality.Container{Header: p.c.Header, Body: p.body.Encode()}.Encode()
	must(err)
	return out
}

type liveLeg struct {
	name   string
	number uint64
	hash   string
}

// The live subjects of research/R11-legs.md (the Adiri section): the settlement blocks of epochs 600, 602 and 651.
var liveLegs = []liveLeg{
	{"live-513643-epoch651", 513643, "0xd156a3a26a0fcd49bd4016630c9e66cfa3fa6f51e0625e1b1a2982a46ac1fb38"},
	{"live-500749-epoch600", 500749, "0x5831c82ec0a8024f5628340764103480fb1402a24d7d8626bb283ea0f6b276ee"},
	{"live-500980-epoch602", 500980, "0x7085a3bac0a80065d8e948afc6b0d87a5e0413ca4e9e9460f0eb2b1a23429419"},
}

func hash32(s string) [32]byte {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != 32 {
		panic("bad hash " + s)
	}
	return [32]byte(b)
}

// cacheFacts are the facts about the chain read straight from the fetched JSON (not from the verifier).
type cacheFacts struct {
	finalNumber []uint64
	finalHash   [][32]byte
	signers     []int
}

func loadFacts(cache string) cacheFacts {
	raw, err := os.ReadFile(filepath.Join(cache, "epoch_records.json"))
	must(err)
	var recs []json.RawMessage
	must(json.Unmarshal(raw, &recs))
	var f cacheFacts
	for _, r := range recs {
		_, _, _, _, rec, err := adiri.DecodeEpochRecord(r)
		must(err)
		f.finalNumber = append(f.finalNumber, rec.FinalState.Number)
		f.finalHash = append(f.finalHash, rec.FinalState.Hash)
		f.signers = append(f.signers, len(rec.Signers))
	}
	return f
}

func (f cacheFacts) epochOf(n uint64) int {
	for e, fn := range f.finalNumber {
		if fn >= n {
			return e
		}
	}
	panic("block above the sealed chain")
}

func okExpect(epoch int, f cacheFacts, n uint64, kind int, signers, size int, shrunk []string) string {
	return canon("finalized",
		"epoch", uint64(epoch), "chain_len", uint64(epoch+1), "committee_size", uint64(size), "signers", uint64(signers),
		"final_number", f.finalNumber[epoch], "final_hash", f.finalHash[epoch], "distance", f.finalNumber[epoch]-n,
		"link_kind", uint64(kind), "consensus_root_matches", true, "committee_shrunk", shrunk)
}

// recordLive builds the live vectors with the Prover against the public endpoint and returns them with the base evidence.
func recordLive(rpc, cache, out string, facts cacheFacts) (map[string][]byte, []vec) {
	pins, err := finality.EmbeddedPins()
	must(err)
	p := &adiri.Prover{Endpoints: []string{rpc}, Pins: pins}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	evidence := map[string][]byte{}
	var vs []vec
	for _, l := range liveLegs {
		hs, err := p.ReadHeaders(ctx, l.number, l.number)
		must(err)
		leg := finality.BlockRef{Chain: finality.ChainAdiri, Number: l.number, Hash: hash32(l.hash), HeaderRLP: hs[0]}
		if [32]byte(crypto.Keccak256Hash(hs[0])) != leg.Hash {
			panic("leg header does not hash to the leg hash: " + l.name)
		}
		t0 := time.Now()
		add, pend, err := p.BuildLeg(ctx, leg)
		if err != nil || pend != nil {
			panic(fmt.Sprintf("%s: build: %v %v", l.name, err, pend))
		}
		fmt.Printf("%s: built %d B evidence in %s\n", l.name, len(add.Evidence), time.Since(t0).Round(time.Millisecond))
		e := facts.epochOf(l.number)
		evidence[l.name] = add.Evidence
		vs = append(vs, vec{
			Name: l.name, Group: "live", Pins: "embedded", Evidence: l.name + ".bin",
			Note:   fmt.Sprintf("real epoch-record chain 0..%d for the settlement block %d of R11-legs, linkKind 1, built by the Prover from the public endpoint", e, l.number),
			Leg:    legJSON{finality.ChainAdiri, l.number, l.hash, hexOf(hs[0])},
			Expect: okExpect(e, facts, l.number, 1, facts.signers[e], 5, []string{}),
		})
	}
	return evidence, vs
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
