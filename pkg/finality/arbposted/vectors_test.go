// Copyright 2026 Certen Protocol

package arbposted

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// vectorDir is the set the helpers read; the set-2 test points it at its own directory for its duration.
var vectorDir = "testdata/finality_arb_posted1"

type vecLeg struct {
	Chain     string `json:"chain"`
	Number    string `json:"number"`
	Hash      string `json:"hash"`
	HeaderRLP string `json:"header_rlp"`
}

type vecCase struct {
	Format      string `json:"format"`
	ID          string `json:"id"`
	Description string `json:"description"`
	Pins        string `json:"pins"`
	Leg         vecLeg `json:"leg"`
	Base        string `json:"evidence_base"`
	Patch       struct {
		At  int    `json:"at"`
		Del int    `json:"del"`
		Ins string `json:"ins"`
	} `json:"evidence_patch"`
	Expect string `json:"expect_canonical"`
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
	if m.Format != "certen-finality-manifest/1" || m.Set != filepath.Base(vectorDir) {
		t.Fatalf("manifest format %q set %q", m.Format, m.Set)
	}
	for p, want := range m.Files {
		b := readVec(t, p)
		s := sha256.Sum256(b)
		if hex.EncodeToString(s[:]) != want {
			t.Errorf("%s: sha256 %x, manifest %s", p, s, want)
		}
	}
	return m.Cases, m.Files
}

func evidenceOf(t testing.TB, c vecCase) []byte {
	t.Helper()
	var base []byte
	if c.Base != "" {
		base = readVec(t, c.Base)
	}
	ins := unhexVec(t, c.Patch.Ins)
	out := append([]byte(nil), base[:c.Patch.At]...)
	out = append(out, ins...)
	return append(out, base[c.Patch.At+c.Patch.Del:]...)
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

func refOf(t testing.TB, l vecLeg) finality.BlockRef {
	t.Helper()
	num, _ := strconv.ParseUint(l.Number, 10, 64)
	var hash [32]byte
	copy(hash[:], unhexVec(t, l.Hash))
	return finality.BlockRef{Chain: finality.ChainArbitrumSepolia, Number: num, Hash: hash, HeaderRLP: unhexVec(t, l.HeaderRLP)}
}

// Every published case is judged by Kind.Verify and must produce exactly the canonical verdict the generator wrote as a literal.
func TestPublishedVectorsFinalityArbPosted1(t *testing.T) {
	cases, files := loadManifest(t)
	if len(cases) < 60 {
		t.Fatalf("only %d cases", len(cases))
	}
	for _, id := range cases {
		if _, ok := files["cases/"+id+".json"]; !ok {
			t.Errorf("case %s is not in the manifest's files", id)
		}
		var c vecCase
		if err := json.Unmarshal(readVec(t, "cases/"+id+".json"), &c); err != nil {
			t.Fatal(err)
		}
		pins, err := finality.ParsePinsOverride(readVec(t, c.Pins))
		if err != nil {
			t.Fatalf("%s: pins: %v", id, err)
		}
		v, verr := New().Verify(pins, refOf(t, c.Leg), evidenceOf(t, c))
		want := c.Expect
		if w, ok := supersededInSet2[id]; ok {
			want = w
		}
		if w, ok := supersededInSet4[id]; ok {
			want = w
		}
		if got := verdictCanon(v, verr); got != want {
			t.Errorf("%s:\n got  %s\n want %s", id, got, want)
		}
	}
}

// supersededInSet2 are the two cases of finality_arb_posted1 whose recorded expectation described a verifier that did not decode the
// zero-heavy layer (flag 0x20 over bytes that are not a zero-heavy payload gave byte 32). Nitro decodes that layer once, so the same
// bytes now decode to garbage whose first byte (77) is not the Brotli header: the verdict is l1_batch_header_unknown{byte:77}. The
// set is not edited; testdata/finality_arb_posted1/SUPERSEDED.md records the change and finality_arb_posted2 carries the cases.
var supersededInSet2 = map[string]string{
	"adv_synth_calldata_flag_zeroheavy": `{"code":"l1_batch_header_unknown","fields":{"batch":"77","byte":"77"}}`,
	"adv_synth_blob_payload_zeroheavy":  `{"code":"l1_batch_header_unknown","fields":{"batch":"77","byte":"77"}}`,
}

// supersededInSet4 are the seven cases of finality_arb_posted1 that hand Kind.Verify a synthetic leg (the live block's header with its
// transactionsRoot replaced, so another hash) next to the RECORDED container, whose header carries the live block's hash. Kind.Verify
// now binds the BlockRef to the container header (RB11-E2-FIX, review V-E2-A1), so these refuse with finality_block_mismatch{blockHash}
// (want = the synthetic leg's hash, got = the recorded block's hash) before the match logic they were written for runs. The set is not
// edited; testdata/finality_arb_posted1/SUPERSEDED.md records the change and finality_arb_posted4 carries each case again with the
// container header re-bound to its leg (suffix _container_bound), under its recorded expectation.
var supersededInSet4 = map[string]string{
	"adv_tx_altered":                   liveHashMismatch("0x051307b3a477cf0b336b5dde6f044f3cd32be61872fe7fbb8a1f9027181eb2e3"),
	"adv_tx_order_swapped":             liveHashMismatch("0x19a0efee390b8519ae885b8a045fc363dea85b059b25080e73a1478c1af5badc"),
	"adv_tx_missing":                   liveHashMismatch("0x324c892e5293309b4c7550fdd526c53057c04cf43319cfd513f6481ad1a07f5b"),
	"adv_tx_extra":                     liveHashMismatch("0xaabed1854d210a115872480a10b953870d1430d72e874fd92a0b72e25ee3796e"),
	"adv_no_standard_transactions":     liveHashMismatch("0x55ce73fa225c341b51740cefdadfbd33856ddfd15da8a6336199e120b5670ab4"),
	"adv_unsupported_tx_type":          liveHashMismatch("0xb45075a1c3c86368270bc66b00dba3c75a8bb7e96272ea8705689de893daeb60"),
	"adv_delayed_origin_without_proof": liveHashMismatch("0xe9be37ad6eb86d61c053a03e9661c179f0f40453777420851267bd65520f9127"),
}

func liveHashMismatch(legHash string) string {
	return `{"code":"finality_block_mismatch","fields":{"field":"blockHash","got":"0x83d81943ea8f2f51d14bb50594d8d0ae12cd576e8891816e26a9c17fdca0c9f4","want":"` + legHash + `"}}`
}

// The valid vector also passes the registry's whole path: container header against the addendum and the leg, then the kind.
func TestTheValidVectorPassesTheRegistryJudgement(t *testing.T) {
	var c vecCase
	if err := json.Unmarshal(readVec(t, "cases/valid_live.json"), &c); err != nil {
		t.Fatal(err)
	}
	pins, err := finality.ParsePinsOverride(readVec(t, c.Pins))
	if err != nil {
		t.Fatal(err)
	}
	reg := finality.NewRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	if err := Register(reg); err == nil {
		t.Fatal("a second registration of the kind was accepted")
	}
	ref := refOf(t, c.Leg)
	add := finality.Addendum{Level: finality.LevelL1Posted, Chain: finality.ChainArbitrumSepolia, Kind: KindName, Evidence: evidenceOf(t, c)}
	v, err := reg.JudgeAddendum(ref, add, pins)
	if err != nil {
		t.Fatal(err)
	}
	if v.Level != finality.LevelL1Posted || v.Kind != KindName {
		t.Fatalf("verdict %+v", v)
	}
	other := ref
	other.Number++
	if _, err := reg.JudgeAddendum(other, add, pins); err == nil {
		t.Fatal("evidence about another block was accepted")
	}
}
