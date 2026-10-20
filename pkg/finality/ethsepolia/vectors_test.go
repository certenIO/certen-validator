// Copyright 2026 Certen Protocol

package ethsepolia

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/lcssz"
)

const vectorDir = "testdata/finality_eth_sepolia1"

type vecLeg struct {
	Chain     string `json:"chain"`
	Number    string `json:"number"`
	Hash      string `json:"hash"`
	HeaderRLP string `json:"header_rlp"`
}

type vecPatch struct {
	At  int    `json:"at"`
	Del int    `json:"del"`
	Ins string `json:"ins"`
}

type vecCase struct {
	ID      string     `json:"id"`
	Pins    string     `json:"pins"`
	Leg     vecLeg     `json:"leg"`
	Base    string     `json:"evidence_base"`
	Patches []vecPatch `json:"evidence_patches"`
	Expect  string     `json:"expect_canonical"`
}

type extCase struct {
	ID           string            `json:"id"`
	Base         string            `json:"base"`
	Extension    string            `json:"extension"`
	LinksDir     string            `json:"links_dir"`
	LinksReplace map[string]string `json:"links_replace"`
	LinksDrop    []uint64          `json:"links_drop"`
	Expect       string            `json:"expect_canonical"`
}

func readVec(t testing.TB, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectorDir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func unhexVec(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func loadManifest(t testing.TB) (cases []string, files map[string]string) {
	t.Helper()
	raw := readVec(t, "MANIFEST.json")
	sum := sha256.Sum256(raw)
	if got := strings.TrimSpace(string(readVec(t, "MANIFEST.json.sha256"))); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("MANIFEST.json.sha256 %s, manifest hashes to %x", got, sum)
	}
	var m struct {
		Format string            `json:"format"`
		Set    string            `json:"set"`
		Files  map[string]string `json:"files"`
		Cases  []string          `json:"cases"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.Format != "certen-finality-manifest/1" || m.Set != "finality_eth_sepolia1" {
		t.Fatalf("manifest format %q set %q", m.Format, m.Set)
	}
	for p, want := range m.Files {
		s := sha256.Sum256(readVec(t, p))
		if hex.EncodeToString(s[:]) != want {
			t.Errorf("%s: sha256 %x, manifest %s", p, s, want)
		}
	}
	return m.Cases, m.Files
}

func evidenceOf(t testing.TB, c vecCase) []byte {
	t.Helper()
	out := append([]byte(nil), readVec(t, c.Base)...)
	ps := append([]vecPatch(nil), c.Patches...)
	sort.Slice(ps, func(i, j int) bool { return ps[i].At > ps[j].At })
	for _, p := range ps {
		out = append(append(append([]byte(nil), out[:p.At]...), unhexVec(t, p.Ins)...), out[p.At+p.Del:]...)
	}
	return out
}

func refOf(t testing.TB, l vecLeg) finality.BlockRef {
	t.Helper()
	num, _ := strconv.ParseUint(l.Number, 10, 64)
	var hash [32]byte
	copy(hash[:], unhexVec(t, l.Hash))
	return finality.BlockRef{Chain: finality.ChainSepolia, Number: num, Hash: hash, HeaderRLP: unhexVec(t, l.HeaderRLP)}
}

func verdictCanon(v finality.Verdict, err error) string {
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

// Every published verification case is judged by Verifier.Verify and must produce exactly the canonical verdict the generator
// wrote as a literal.
func TestPublishedVectorsFinalityEthSepolia1(t *testing.T) {
	cases, files := loadManifest(t)
	if len(cases) < 40 {
		t.Fatalf("only %d cases", len(cases))
	}
	verify := 0
	for _, id := range cases {
		if _, ok := files["cases/"+id+".json"]; !ok {
			continue // an extend case, judged below
		}
		verify++
		var c vecCase
		if err := json.Unmarshal(readVec(t, "cases/"+id+".json"), &c); err != nil {
			t.Fatal(err)
		}
		pins, err := finality.ParsePinsOverride(readVec(t, c.Pins))
		if err != nil {
			t.Fatalf("%s: pins: %v", id, err)
		}
		v, verr := New().Verify(pins, refOf(t, c.Leg), evidenceOf(t, c))
		if got := verdictCanon(v, verr); got != c.Expect {
			t.Errorf("%s:\n got  %s\n want %s", id, got, c.Expect)
		}
	}
	if verify < 35 {
		t.Fatalf("only %d verification cases", verify)
	}
}

func extendLinks(t testing.TB, c extCase) map[uint64][]byte {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(vectorDir, filepath.FromSlash(c.LinksDir)))
	if err != nil {
		t.Fatal(err)
	}
	links := map[uint64][]byte{}
	for _, en := range ents {
		p, err := strconv.ParseUint(strings.TrimSuffix(en.Name(), ".ssz"), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		links[p] = readVec(t, c.LinksDir+"/"+en.Name())
	}
	for p, rel := range c.LinksReplace {
		n, _ := strconv.ParseUint(p, 10, 64)
		links[n] = readVec(t, rel)
	}
	for _, p := range c.LinksDrop {
		delete(links, p)
	}
	return links
}

// Every Pins.Extend case: the same extension judged by the framework, with the verdict the generator wrote.
func TestPublishedExtendVectorsFinalityEthSepolia1(t *testing.T) {
	cases, files := loadManifest(t)
	n := 0
	for _, id := range cases {
		if _, ok := files["extend/"+id+".json"]; !ok {
			continue
		}
		n++
		var c extCase
		if err := json.Unmarshal(readVec(t, "extend/"+id+".json"), &c); err != nil {
			t.Fatal(err)
		}
		base, err := finality.ParsePinsOverride(readVec(t, c.Base))
		if err != nil {
			t.Fatal(err)
		}
		ext := readVec(t, c.Extension)
		p, err := base.Extend(ext, extendLinks(t, c))
		var got string
		if err != nil {
			got = verdictCanon(finality.Verdict{}, err)
		} else {
			e, _ := p.Sepolia()
			_, src := p.Identity()
			got = string((&finality.StateError{Code: "verified", Fields: map[string]any{"anchors": uint64(len(e.Anchors)), "pins_source": src}}).Canonical())
		}
		if got != c.Expect {
			t.Errorf("%s:\n got  %s\n want %s", id, got, c.Expect)
		}
	}
	if n < 9 {
		t.Fatalf("only %d extend cases", n)
	}
}

// The valid vectors also pass the registry's whole path: container header against the addendum and the leg, then the kind.
func TestTheValidVectorsPassTheRegistryJudgement(t *testing.T) {
	reg := finality.NewRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	if err := Register(reg); err == nil {
		t.Fatal("a second registration of the kind was accepted")
	}
	for _, id := range []string{"valid_gloas_latest", "valid_gloas_period", "valid_legacy"} {
		var c vecCase
		if err := json.Unmarshal(readVec(t, "cases/"+id+".json"), &c); err != nil {
			t.Fatal(err)
		}
		pins, err := finality.ParsePinsOverride(readVec(t, c.Pins))
		if err != nil {
			t.Fatal(err)
		}
		ref := refOf(t, c.Leg)
		add := finality.Addendum{Level: finality.LevelFinalized, Chain: finality.ChainSepolia, Kind: Name, Evidence: evidenceOf(t, c)}
		v, err := reg.JudgeAddendum(ref, add, pins)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if v.Level != finality.LevelFinalized || v.Kind != Name {
			t.Fatalf("%s: verdict %+v", id, v)
		}
		other := ref
		other.Number++
		if _, err := reg.JudgeAddendum(other, add, pins); err == nil {
			t.Fatalf("%s: evidence about another block was accepted", id)
		}
	}
}

// ---- the builder, offline, against the recorded pending answers ----

type fakeSource struct {
	fu   []byte
	head uint64
}

func (f fakeSource) Name() string                                      { return "fake" }
func (f fakeSource) FinalityUpdate(context.Context) ([]byte, error)    { return f.fu, nil }
func (f fakeSource) HeadSlot(context.Context) (uint64, error)          { return f.head, nil }
func (fakeSource) Bootstrap(context.Context, [32]byte) ([]byte, error) { return nil, &SourceError{} }
func (fakeSource) Updates(context.Context, uint64, int) ([][]byte, error) {
	return nil, &SourceError{}
}

type fakeHeaders struct{ byHash map[string][]byte }

func (f fakeHeaders) HeaderByHash(_ context.Context, h [32]byte) ([]byte, error) {
	if b, ok := f.byHash["0x"+hex.EncodeToString(h[:])]; ok {
		return b, nil
	}
	return nil, &SourceError{Failures: []EndpointFailure{{Endpoint: "fake", Op: "headers", Reason: "no such header"}}}
}
func (fakeHeaders) HeadersByNumber(context.Context, uint64, uint64) ([][]byte, error) {
	return nil, &SourceError{}
}

// A leg three blocks above the latest finalized head is pending with the numbers the finality update itself states, never a
// weaker level; the replayed answers are the ones recorded live.
func TestARealLegAboveTheFinalizedHeadIsPendingWithTheLatestFinalizedNumbers(t *testing.T) {
	var lj vecLeg
	if err := json.Unmarshal(readVec(t, "raw/pending/leg.json"), &lj); err != nil {
		t.Fatal(err)
	}
	var meta struct {
		Head uint64 `json:"observed_head_slot"`
		Now  int64  `json:"now_unix"`
	}
	if err := json.Unmarshal(readVec(t, "raw/pending/meta.json"), &meta); err != nil {
		t.Fatal(err)
	}
	hj := map[string]string{}
	if err := json.Unmarshal(readVec(t, "raw/pending/headers_by_hash.json"), &hj); err != nil {
		t.Fatal(err)
	}
	hdrs := fakeHeaders{byHash: map[string][]byte{}}
	for k, v := range hj {
		hdrs.byHash[k] = unhexVec(t, v)
	}
	fu := readVec(t, "raw/pending/finality_update.ssz")
	pins, err := finality.ParsePinsOverride(readVec(t, "pins/main.json"))
	if err != nil {
		t.Fatal(err)
	}
	p := &Prover{Source: fakeSource{fu: fu, head: meta.Head}, Exec: hdrs, Pins: pins, Now: func() time.Time { return time.Unix(meta.Now, 0) }}
	ref := refOf(t, lj)
	add, pend, err := p.BuildLeg(context.Background(), ref)
	if err != nil || add != nil || pend == nil {
		t.Fatalf("add %v pend %v err %v", add != nil, pend, err)
	}
	lay := lcssz.LayoutOfFinalityUpdate(fu)
	_, finSlot, _, _ := lcssz.FinalityUpdateSlots(lay, fu)
	hash, _, _, _ := lcssz.FinalizedExec(lay, fu)
	fh, err := finality.ReadHeader(hdrs.byHash["0x"+hex.EncodeToString(hash[:])])
	if err != nil {
		t.Fatal(err)
	}
	if crypto.Keccak256Hash(ref.HeaderRLP) != ref.Hash || ref.Number != fh.Number+3 {
		t.Fatalf("the recorded leg is not three blocks above the finalized head")
	}
	ts, _ := finality.ReadHeader(ref.HeaderRLP)
	eta := time.Unix(int64(ts.Timestamp), 0).Add(19 * time.Minute)
	if !eta.After(time.Unix(meta.Now, 0)) {
		eta = time.Unix(meta.Now, 0).Add(6*time.Minute + 24*time.Second)
	}
	want := (&finality.PendingState{Chain: finality.ChainSepolia, LevelReached: finality.LevelIncluded, NextLevel: finality.LevelFinalized,
		Reason: "block_not_yet_covered", ETA: eta, Judged: map[string]any{"latest_finalized_exec_number": fh.Number, "latest_finalized_slot": finSlot, "observed_head_slot": meta.Head}}).State()
	if got := pend.State(); string(got.Canonical()) != string(want.Canonical()) {
		t.Fatalf("\n got  %s\n want %s", got.Canonical(), want.Canonical())
	}
}

// With no light-client endpoint answering, the builder reports finality_lc_unavailable per endpoint and builds nothing.
func TestAnUnreachableLCSourceIsPendingPerEndpointNeverALowerLevel(t *testing.T) {
	pins, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	src := Multi{&HTTPSource{Base: "http://127.0.0.1:1"}, &HTTPSource{Base: "http://127.0.0.1:2"}}
	p := &Prover{Source: src, Exec: fakeHeaders{}, Pins: pins}
	var lj vecLeg
	if err := json.Unmarshal(readVec(t, "raw/pending/leg.json"), &lj); err != nil {
		t.Fatal(err)
	}
	add, pend, err := p.BuildLeg(context.Background(), refOf(t, lj))
	if err != nil || add != nil || pend == nil || pend.Reason != PendingLCUnavailable {
		t.Fatalf("add %v pend %v err %v", add != nil, pend, err)
	}
	eps, _ := pend.Judged["endpoints"].([]string)
	if len(eps) != 2 || !strings.Contains(eps[0], "127.0.0.1:1") || !strings.Contains(eps[1], "127.0.0.1:2") {
		t.Fatalf("endpoints %v", eps)
	}
}
