// Copyright 2026 Certen Protocol

package arbfinal_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbfinal"
	"github.com/certen/independant-validator/pkg/finality/arbfinal/synthworld"
)

// vectorDir is the published set. It is never edited: a change is a new set (finality_arb_final2) with a SUPERSEDED note.
const vectorDir = "testdata/finality_arb_final1"

type vEdit struct {
	Offset int    `json:"offset"`
	Delete int    `json:"delete"`
	Insert string `json:"insert"`
}

type vLeg struct {
	Chain     uint64 `json:"chain"`
	Number    uint64 `json:"number"`
	Hash      string `json:"hash"`
	HeaderHex string `json:"header_hex"`
}

type vVec struct {
	Name     string  `json:"name"`
	Group    string  `json:"group"`
	Note     string  `json:"note"`
	Leg      vLeg    `json:"leg"`
	Pins     string  `json:"pins"`
	Evidence string  `json:"evidence"`
	Base     string  `json:"base"`
	Edits    []vEdit `json:"edits"`
	Expect   string  `json:"expect"`
}

type vFile struct {
	dir string
	// walletPins: the set predates the wallet pins (RB11-E1-RAISE) and stores its pins files without them; the harness adds them to each
	// stored pins file (synthworld.WithWalletPins) so the unedited set is judged by the verifier that requires them.
	walletPins bool
	Format     string `json:"format"`
	Vectors    []vVec `json:"vectors"`
}

func loadSet(t testing.TB, dir string) vFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f vFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	f.dir = dir
	f.walletPins = dir == vectorDir || dir == vectorDir2
	return f
}

// evidenceOf resolves a vector's evidence bytes: its own file, or its base's with the edits applied (highest offset first).
func evidenceOf(t testing.TB, f vFile, v vVec) []byte {
	t.Helper()
	if v.Evidence != "" {
		b, err := os.ReadFile(filepath.Join(f.dir, "evidence", v.Evidence))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var base *vVec
	for i := range f.Vectors {
		if f.Vectors[i].Name == v.Base {
			base = &f.Vectors[i]
		}
	}
	if base == nil {
		t.Fatalf("%s: base %q not found", v.Name, v.Base)
	}
	out := append([]byte(nil), evidenceOf(t, f, *base)...)
	es := append([]vEdit(nil), v.Edits...)
	sort.Slice(es, func(i, j int) bool { return es[i].Offset > es[j].Offset })
	for _, e := range es {
		ins, err := hex.DecodeString(e.Insert)
		if err != nil {
			t.Fatal(err)
		}
		out = append(append(append([]byte(nil), out[:e.Offset]...), ins...), out[e.Offset+e.Delete:]...)
	}
	return out
}

// pinsOf resolves a vector's pins: "embedded", or the name of a full pins file of the set's pins/ directory.
func pinsOf(t testing.TB, f vFile, v vVec) *finality.Pins {
	t.Helper()
	if v.Pins == "embedded" {
		p, err := finality.EmbeddedPins()
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	raw, err := os.ReadFile(filepath.Join(f.dir, "pins", v.Pins))
	if err != nil {
		t.Fatal(err)
	}
	if f.walletPins {
		raw = synthworld.WithWalletPins(raw)
	}
	p, err := finality.ParsePinsOverride(raw)
	if err != nil {
		t.Fatalf("%s: pins %s: %v", v.Name, v.Pins, err)
	}
	return p
}

func legOf(t testing.TB, v vVec) finality.BlockRef {
	t.Helper()
	h, err := hex.DecodeString(strings.TrimPrefix(v.Leg.Hash, "0x"))
	if err != nil || len(h) != 32 {
		t.Fatalf("%s: leg hash", v.Name)
	}
	b := finality.BlockRef{Chain: v.Leg.Chain, Number: v.Leg.Number, Hash: [32]byte(h)}
	if v.Leg.HeaderHex != "" {
		if b.HeaderRLP, err = hex.DecodeString(v.Leg.HeaderHex); err != nil {
			t.Fatal(err)
		}
	}
	return b
}

// outcome is the canonical {code, fields} text of a verification: a verdict is code "finalized".
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
	return string(finality.NewState("finalized", kv...).Canonical())
}

func TestManifestHashesEveryVectorFile(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorDir, "MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	want, err := os.ReadFile(filepath.Join(vectorDir, "MANIFEST.json.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(want)) != hex.EncodeToString(sum[:]) {
		t.Fatalf("MANIFEST.json hashes to %x, MANIFEST.json.sha256 says %s", sum, want)
	}
	var m struct {
		Files map[string]string `json:"files"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Files) < 4 {
		t.Fatalf("manifest lists %d files", len(m.Files))
	}
	for p, h := range m.Files {
		b, err := os.ReadFile(filepath.Join(vectorDir, filepath.FromSlash(p)))
		if err != nil {
			t.Fatal(err)
		}
		s := sha256.Sum256(b)
		if hex.EncodeToString(s[:]) != h {
			t.Errorf("%s hashes to %x, manifest says %s", p, s, h)
		}
	}
}

// Every vector yields exactly its literal expected verdict.
func TestEveryVectorVerdict(t *testing.T) {
	f := loadSet(t, vectorDir)
	groups := map[string]int{}
	for _, v := range f.Vectors {
		groups[v.Group]++
		got := outcome(arbfinal.New().Verify(pinsOf(t, f, v), legOf(t, v), evidenceOf(t, f, v)))
		want := v.Expect
		if w, ok := supersededInSet3[v.Name]; ok {
			want = w
		}
		if got != want {
			t.Errorf("%s (%s):\n got:  %s\n want: %s", v.Name, v.Note, got, want)
		}
	}
	if len(f.Vectors) < 80 {
		t.Fatalf("only %d vectors", len(f.Vectors))
	}
	for _, g := range []string{"synthetic", "adversarial"} {
		if groups[g] == 0 {
			t.Errorf("no %s vectors", g)
		}
	}
}

// The valid vectors go through the registry exactly as the dispatcher does, and a second registration is refused.
func TestValidVectorsThroughTheRegistry(t *testing.T) {
	f := loadSet(t, vectorDir)
	reg := finality.NewRegistry()
	if err := arbfinal.Register(reg); err != nil {
		t.Fatal(err)
	}
	if err := arbfinal.Register(reg); err == nil {
		t.Fatal("a second registration of the kind must be refused")
	}
	seen := 0
	for _, v := range f.Vectors {
		if _, ok := supersededInSet3[v.Name]; ok || !strings.Contains(v.Expect, `"code":"finalized"`) {
			continue // a superseded case answers indirect now (its SUPERSEDED.md): TestEveryVectorVerdict judges it, the registry path is for the accepted ones
		}
		seen++
		a := finality.Addendum{Level: finality.LevelFinalized, Chain: finality.ChainArbitrumSepolia, Kind: arbfinal.KindName, Evidence: evidenceOf(t, f, v)}
		got, err := reg.JudgeAddendum(legOf(t, v), a, pinsOf(t, f, v))
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if got.Level != finality.LevelFinalized || got.Kind != arbfinal.KindName {
			t.Fatalf("%s: %+v", v.Name, got)
		}
	}
	if seen < 8 {
		t.Fatalf("%d valid vectors", seen)
	}
}

// supersededInSet3 are the cases of finality_arb_final1 whose recorded expectation described a verifier that took the wallet route on
// the calldata alone (RB11-E1-RAISE): the route is now taken only for a callee proven to be a ValidatorWallet, and these worlds carry no
// proof of one. The set is not edited; testdata/finality_arb_final1/SUPERSEDED.md records the change and finality_arb_final3 carries every
// case again with the wallet proof, under its recorded expectation. A consumer of the set judges them by this column.
var supersededInSet3 = map[string]string{
	"synth_valid_wallet_execute_transaction":                    indirectNow("0x5f9a2bef6769850abfa377006e84753eec4627d560fe7c557c8daf30ba564f2b"),
	"synth_valid_wallet_execute_transactions":                   indirectNow("0x77173d1eb1ecb3d3c81b5c2fb565d3f389bad9bdec4719b128ae89f8b54d1a39"),
	"synth_valid_wallet_execute_transaction_with_gas_refunder":  indirectNow("0x338d892032735a065ac51b55158a9fb3c2f607293f33c56b73af41c1cec09337"),
	"synth_valid_wallet_execute_transactions_with_gas_refunder": indirectNow("0x7bf80577fe61ea4ef37f5e6fa9cf68aace22fd6ca3fbd748cb71576d68bedf84"),
	"adv_conf_wallet_call_targets_other_contract":               indirectNow("0x6376b7f7118925c2a4e2ad89f6de24b67460500d0cbcbe6cbf3b5eccebb8247b"),
	"adv_conf_wallet_call_other_selector":                       indirectNow("0x62001c4cfe884b267fe8e1c055b1c60d2da9c0408741c4744286f6eebe553f1d"),
	"adv_conf_wallet_fast_call":                                 indirectNow("0x7f173f2c88f247718c011b585ca10e334bb114c3446e3f7e71d552a745af9e95"),
	"adv_conf_wallet_force_call":                                indirectNow("0x07d6bfa77b6309da6bb20ece74fd59f96b26ad473cfe19a23ccb1a8ed3fa6b85"),
	"adv_conf_wallet_fast_confirmer_nonzero":                    indirectNow("0x9a1986f61c5a411165fd921c1a3cd49749e4af6588ab645342c5de9500bf753e"),
	"synth_valid_wallet_call_is_the_bare_selector":              indirectNow("0x935873569c9c16b1c4f3b6e8d8a69a60f35034c77a2cf5c1722b5db86454270d"),
	"adv_conf_wallet_call_data_three_bytes":                     indirectNow("0x2116c8fb4d1ce9d2fbcec55912daedf84ed1f0aa4963493286f030042ca906c0"),
	"adv_conf_wallet_fast_confirmer_slot_unproven":              indirectNow("0x5df460c5b7e0980fe14237fa7ef2db6ab8891b1a544e8a7e75c72084a08ef2b6"),
}

// indirectNow is the verdict of the worlds above under the wallet identity rule: the callee is not proven to be a ValidatorWallet, so
// the confirmation path is confirmation_path_unproven{indirect}, judged at K (11,999,995 in the synthetic worlds).
func indirectNow(tx string) string {
	return `{"code":"confirmation_path_unproven","fields":{"l1_block":"11999995","reason":"indirect","tx":"` + tx + `"}}`
}
