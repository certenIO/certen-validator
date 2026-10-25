// Copyright 2026 Certen Protocol

package contractidentity

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
)

// RB12 EPSILON stage 2, part A: the input readers of inputs.go. A file that carries one malformed member must be refused, never read as if
// the member were zero; each corruption below names the member it breaks.

func TestMutKill4HexAndDecimalReaders(t *testing.T) {
	for _, s := range []string{"zz", "0xAB", "0xabc", "ab", "0x0g", ""} {
		if b, err := unhex(s); err == nil {
			t.Errorf("unhex(%q) = %x", s, b)
		}
	}
	if b, err := unhex("0x"); err != nil || len(b) != 0 {
		t.Errorf("unhex(0x): %x %v", b, err)
	}
	if b, err := unhex("0xab01"); err != nil || len(b) != 2 || b[0] != 0xab || b[1] != 1 {
		t.Errorf("unhex(0xab01): %x %v", b, err)
	}
	for _, s := range []string{"0x00", "zz", "0x", "0x" + strings.Repeat("00", 31), "0x" + strings.Repeat("00", 33)} {
		if _, err := unhex32(s); err == nil {
			t.Errorf("unhex32(%q) accepted", s)
		}
	}
	if v, err := unhex32("0x" + strings.Repeat("ab", 32)); err != nil || v != bytes32(0xab) {
		t.Errorf("unhex32: %x %v", v, err)
	}
	for _, s := range []string{"", "01", "00", "007", "-1", "1.5", "x", "18446744073709551616"} {
		if v, err := undec(s); err == nil {
			t.Errorf("undec(%q) = %d", s, v)
		}
	}
	if _, err := undec(""); err == nil || err.Error() != `"" is not a canonical decimal string` {
		t.Errorf("undec(\"\"): %v", err)
	}
	for s, want := range map[string]uint64{"0": 0, "7": 7, "10": 10, "18446744073709551615": ^uint64(0)} {
		if v, err := undec(s); err != nil || v != want {
			t.Errorf("undec(%q) = %d %v", s, v, err)
		}
	}
}

func mk4HexOf(b [32]byte) string { return hx(b[:]) }

// mk4ContextFile is a complete, valid context file: every optional member present, every list non-empty.
func mk4ContextFile(t *testing.T) ContextFile {
	t.Helper()
	c := validContext()
	c.Receipt = &ethproof.ReceiptLeaf{Type: 2, PostStateOrStatus: []byte{1}, CumulativeGasUsed: 21000,
		Logs: []*types.Log{{Address: common.Address{9}, Topics: []common.Hash{common.Hash(bytes32(0x21)), common.Hash(bytes32(0x22))}, Data: []byte{1, 2}}}}
	c.Registry9 = &Registry9{Members: []RegistryMember{{Address: common.Address{3}, Power: 5, BLSKey: strings.Repeat("0f", 96)}}, Num: 2, Den: 3,
		CertenSetRoot: bytes32(7), SignerCommitment: bytes32(8)}
	f, err := ContextToFile(c)
	if err != nil {
		t.Fatal(err)
	}
	f.S7 = &S7File{
		Block:    BlockFile{Chain: "11155111", Number: "9", Hash: mk4HexOf(bytes32(0x31))},
		Headline: finality.LevelFinalized.String(),
		Levels: map[string]S7Level{
			finality.LevelIncluded.String():  {Status: "verified"},
			finality.LevelFinalized.String(): {Status: "unproven", Code: "finality_pending"},
		},
		FinalizedBlock: &S7FinalizedBlock{Number: "8", Hash: mk4HexOf(bytes32(0x32)), StateRoot: mk4HexOf(bytes32(0x33))},
	}
	return f
}

func mk4Clone(t *testing.T, f ContextFile) ContextFile {
	t.Helper()
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var out ContextFile
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestMutKill4ContextFromFileReadsEveryMember(t *testing.T) {
	c, err := ContextFromFile(mk4ContextFile(t))
	if err != nil {
		t.Fatal(err)
	}
	if c.Receipt.Type != 2 || c.Receipt.CumulativeGasUsed != 21000 || len(c.Receipt.PostStateOrStatus) != 1 || len(c.Receipt.Logs) != 1 ||
		c.Receipt.Logs[0].Address != (common.Address{9}) || len(c.Receipt.Logs[0].Topics) != 2 || c.Receipt.Logs[0].Topics[1] != common.Hash(bytes32(0x22)) ||
		len(c.Receipt.Logs[0].Data) != 2 {
		t.Fatalf("receipt: %+v", c.Receipt)
	}
	r := c.Registry9
	if r.Num != 2 || r.Den != 3 || r.CertenSetRoot != bytes32(7) || r.SignerCommitment != bytes32(8) || len(r.Members) != 1 || r.Members[0].Address != (common.Address{3}) || r.Members[0].Power != 5 {
		t.Fatalf("registry9: %+v", r)
	}
	s := c.S7
	if s.Block.Chain != 11155111 || s.Block.Number != 9 || s.Block.Hash != bytes32(0x31) || s.Headline != finality.LevelFinalized ||
		s.Levels[finality.LevelIncluded].Status != "verified" || s.Levels[finality.LevelFinalized].State == nil || s.Levels[finality.LevelFinalized].State.Code != "finality_pending" ||
		s.FinalizedBlock == nil || s.FinalizedBlock.Number != 8 || s.FinalizedBlock.Hash != bytes32(0x32) || s.FinalizedBlock.StateRoot != bytes32(0x33) {
		t.Fatalf("s7: %+v", s)
	}
	if c.S6 == nil || c.S6.SettlementBlock.Number != 5 || c.Batch.Incarnation != bytes32(8) || c.Settlement == nil || c.Tx == nil {
		t.Fatalf("members: %+v", c)
	}
}

func TestMutKill4ContextFromFileSettlementFraming(t *testing.T) {
	base := mk4ContextFile(t)
	for _, raw := range []json.RawMessage{nil, json.RawMessage("null")} {
		f := mk4Clone(t, base)
		f.Settlement = raw
		c, err := ContextFromFile(f)
		if err != nil || c.Settlement != nil {
			t.Errorf("settlement %q: %v %v", raw, c.Settlement, err)
		}
	}
	for _, raw := range []json.RawMessage{json.RawMessage("5"), json.RawMessage("[1]"), json.RawMessage(`"x"`)} {
		f := mk4Clone(t, base)
		f.Settlement = raw
		if _, err := ContextFromFile(f); err == nil {
			t.Errorf("settlement %q accepted", raw)
		}
	}
}

func TestMutKill4ContextFromFileRefusesEachMalformedMember(t *testing.T) {
	short := "0x00"
	bad := "zz"
	lead := "01"
	base := mk4ContextFile(t)
	for name, mut := range map[string]func(f *ContextFile){
		"tx not hex":                    func(f *ContextFile) { f.Tx = &bad },
		"tx not a transaction":          func(f *ContextFile) { s := "0x01"; f.Tx = &s },
		"receipt type":                  func(f *ContextFile) { f.Receipt.Type = lead },
		"receipt post state":            func(f *ContextFile) { f.Receipt.PostStateOrStatus = bad },
		"receipt gas":                   func(f *ContextFile) { f.Receipt.CumulativeGasUsed = lead },
		"receipt bloom short":           func(f *ContextFile) { f.Receipt.Bloom = short },
		"receipt bloom not hex":         func(f *ContextFile) { f.Receipt.Bloom = bad },
		"log address short":             func(f *ContextFile) { f.Receipt.Logs[0].Address = short },
		"log address not hex":           func(f *ContextFile) { f.Receipt.Logs[0].Address = bad },
		"log topic short":               func(f *ContextFile) { f.Receipt.Logs[0].Topics[0] = short },
		"log data":                      func(f *ContextFile) { f.Receipt.Logs[0].Data = bad },
		"s6 contract short":             func(f *ContextFile) { f.S6.Contract = short },
		"s6 contract not hex":           func(f *ContextFile) { f.S6.Contract = bad },
		"s6 leaf key":                   func(f *ContextFile) { f.S6.LeafKey = short },
		"s6 settlement block number":    func(f *ContextFile) { f.S6.SettlementBlock.Number = lead },
		"s6 settlement block hash":      func(f *ContextFile) { f.S6.SettlementBlock.Hash = short },
		"s6 proven at number":           func(f *ContextFile) { f.S6.ProvenAt.Number = lead },
		"s6 proven at hash":             func(f *ContextFile) { f.S6.ProvenAt.Hash = short },
		"s6 code hash":                  func(f *ContextFile) { f.S6.CodeHash = short },
		"batch root":                    func(f *ContextFile) { f.Batch.BatchRoot = short },
		"batch operation id":            func(f *ContextFile) { f.Batch.OperationID = short },
		"batch acc set root":            func(f *ContextFile) { f.Batch.AccSetRoot = short },
		"batch incarnation":             func(f *ContextFile) { f.Batch.Incarnation = short },
		"registry num":                  func(f *ContextFile) { f.Registry9.Num = lead },
		"registry den":                  func(f *ContextFile) { f.Registry9.Den = lead },
		"registry certen set root":      func(f *ContextFile) { f.Registry9.CertenSetRoot = short },
		"registry signer commitment":    func(f *ContextFile) { f.Registry9.SignerCommitment = short },
		"registry member short addr":    func(f *ContextFile) { f.Registry9.Members[0].Address = short },
		"registry member bad addr":      func(f *ContextFile) { f.Registry9.Members[0].Address = bad },
		"registry member power":         func(f *ContextFile) { f.Registry9.Members[0].Power = lead },
		"s7 block chain":                func(f *ContextFile) { f.S7.Block.Chain = lead },
		"s7 block number":               func(f *ContextFile) { f.S7.Block.Number = lead },
		"s7 block hash":                 func(f *ContextFile) { f.S7.Block.Hash = short },
		"s7 headline":                   func(f *ContextFile) { f.S7.Headline = "bogus" },
		"s7 level name":                 func(f *ContextFile) { f.S7.Levels["bogus"] = S7Level{Status: "verified"} },
		"s7 finalized block number":     func(f *ContextFile) { f.S7.FinalizedBlock.Number = lead },
		"s7 finalized block hash":       func(f *ContextFile) { f.S7.FinalizedBlock.Hash = short },
		"s7 finalized block state root": func(f *ContextFile) { f.S7.FinalizedBlock.StateRoot = short },
	} {
		f := mk4Clone(t, base)
		mut(&f)
		if c, err := ContextFromFile(f); err == nil {
			t.Errorf("%s: accepted (%+v)", name, c)
		}
	}
	// the refusal of a transaction that is not hex is the hex refusal, not the later decode refusal of an empty byte string
	f := mk4Clone(t, base)
	f.Tx = &bad
	if _, err := ContextFromFile(f); err == nil || !strings.Contains(err.Error(), "context.tx") || !strings.Contains(err.Error(), "not 0x-prefixed lowercase hex") {
		t.Errorf("tx not hex: %v", err)
	}
}

func TestMutKill4ContextToFileAndMaterialiseRefuseAnUnencodableTransaction(t *testing.T) {
	c := validContext()
	c.Tx = types.NewTx(&types.LegacyTx{Value: big.NewInt(-1)})
	if f, err := ContextToFile(c); err == nil {
		t.Fatalf("a transaction that cannot be encoded was rendered: %+v", f)
	}
	if files, err := Materialise("VS8-X", Inputs{Ctx: c, ManifestRaw: EmbeddedManifestBytes()}, Expected{Headline: HeadlineVerified}); err == nil {
		t.Fatalf("materialised over an unrenderable context: %d files", len(files))
	}
	if files, err := Materialise("VS8-X", Inputs{Ctx: validContext(), ManifestRaw: EmbeddedManifestBytes()}, Expected{Headline: HeadlineVerified, Registry: json.RawMessage("{")}); err == nil {
		t.Fatalf("materialised an expectation that is not JSON: %d files", len(files))
	}
}

func TestMutKill4LoadMaterialisedRefusals(t *testing.T) {
	cont, err := Encode(g1Container(), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	files, err := Materialise("VS8-X", Inputs{Ctx: validContext(), Container: cont, ManifestRaw: EmbeddedManifestBytes()}, Expected{Headline: HeadlineVerified})
	if err != nil {
		t.Fatal(err)
	}
	set := func() map[string][]byte {
		m := map[string][]byte{}
		for k, v := range files {
			m[k] = v
		}
		return m
	}
	if in, err := LoadMaterialised(files["VS8-X.inputs.json"], set()); err != nil || len(in.Container) != len(cont) || in.ManifestPin == nil || in.ExtensionRaw != nil {
		t.Fatalf("the unmodified set: %v", err)
	}
	// edit applies a change to the parsed inputs file and the set, and loads the result
	load := func(edit func(f *InputsFile, m map[string][]byte)) error {
		var f InputsFile
		if err := json.Unmarshal(files["VS8-X.inputs.json"], &f); err != nil {
			t.Fatal(err)
		}
		m := set()
		edit(&f, m)
		b, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		_, err = LoadMaterialised(b, m)
		return err
	}
	emptyHash := sha256Hex(nil)
	if err := load(func(f *InputsFile, m map[string][]byte) {
		delete(m, f.Container.File)
		f.Container.SHA256 = emptyHash // a missing file must not pass as an empty one
	}); err == nil || !strings.Contains(err.Error(), "is not in the set") {
		t.Errorf("missing container file: %v", err)
	}
	if err := load(func(f *InputsFile, m map[string][]byte) {
		m[f.Container.File] = []byte("zz\n")
		f.Container.SHA256 = sha256Hex(m[f.Container.File])
	}); err == nil || !strings.Contains(err.Error(), "container") {
		t.Errorf("container not hex: %v", err)
	}
	if err := load(func(f *InputsFile, m map[string][]byte) { f.Manifest = nil }); err == nil || !strings.Contains(err.Error(), "no manifest reference") {
		t.Errorf("no manifest: %v", err)
	}
	if err := load(func(f *InputsFile, m map[string][]byte) { delete(m, f.Manifest.File) }); err == nil || !strings.Contains(err.Error(), "is not in the set") {
		t.Errorf("missing manifest file: %v", err)
	}
	if err := load(func(f *InputsFile, m map[string][]byte) {
		f.Extension = &FileRef{File: "extension.absent.json", SHA256: emptyHash}
	}); err == nil ||
		!strings.Contains(err.Error(), "is not in the set") {
		t.Errorf("missing extension file: %v", err)
	}
	if err := load(func(f *InputsFile, m map[string][]byte) { f.Manifest.Pin = "0x00" }); err == nil || !strings.Contains(err.Error(), "manifest pin") {
		t.Errorf("short pin: %v", err)
	}
}
