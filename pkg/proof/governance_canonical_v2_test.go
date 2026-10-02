package proof

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The fixtures are the G0/G1/G2 each of the 7 production validators committed for two operations whose govRoot
// disagreed across the fleet (RUNLOG_RB5 2026-09-29 22:40Z, read from CERTEN's own CometBFT blocks):
//   - 0x34b9c023: G1 validation.totalEntries 5 (validators 3, 5) vs 6 (the rest);
//   - 0x43372539: the G2 receipt majorBlock null (validator 7) vs 464 (the rest).

func loadG(t *testing.T, op, level string) map[string]json.RawMessage {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join("testdata", "govroot_v2", op+"_validator-*_"+level+".json"))
	if len(files) != 7 {
		t.Fatalf("%s %s: want 7 validators' results, found %d", op, level, len(files))
	}
	out := map[string]json.RawMessage{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.Base(f)] = b
	}
	return out
}

func distinct(m map[string][]byte) int {
	seen := map[string]bool{}
	for _, b := range m {
		seen[string(b)] = true
	}
	return len(seen)
}

// The production divergences: v1 (the raw result, what govRoot v1 hashes) disagrees across the fleet; the v2
// canonical form agrees.
func TestCanonicalV2_ProductionDivergencesAgree(t *testing.T) {
	type tc struct {
		op, level string
		canon     func(json.RawMessage) ([]byte, error)
	}
	g1 := func(raw json.RawMessage) ([]byte, error) {
		var g G1Result
		if err := json.Unmarshal(raw, &g); err != nil {
			return nil, err
		}
		return CanonicalG1JSONV2(&g)
	}
	g2 := func(raw json.RawMessage) ([]byte, error) {
		var g G2Result
		if err := json.Unmarshal(raw, &g); err != nil {
			return nil, err
		}
		return CanonicalG2JSONV2(&g)
	}
	g0 := func(raw json.RawMessage) ([]byte, error) {
		var g G0Result
		if err := json.Unmarshal(raw, &g); err != nil {
			return nil, err
		}
		return CanonicalG0JSONV2(&g)
	}
	v1 := func(level string, raw json.RawMessage) []byte {
		var v interface{}
		switch level {
		case "g0":
			v = new(G0Result)
		case "g1":
			v = new(G1Result)
		default:
			v = new(G2Result)
		}
		if err := json.Unmarshal(raw, v); err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(v)
		return b
	}
	for _, c := range []tc{
		{"0x34b9c023", "g1", g1}, {"0x43372539", "g2", g2},
		{"0x34b9c023", "g0", g0}, {"0x34b9c023", "g2", g2}, {"0x43372539", "g0", g0}, {"0x43372539", "g1", g1},
	} {
		raws := loadG(t, c.op, c.level)
		old, now := map[string][]byte{}, map[string][]byte{}
		for name, raw := range raws {
			old[name] = v1(c.level, raw)
			b, err := c.canon(raw)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			now[name] = b
		}
		if d := distinct(now); d != 1 {
			t.Errorf("%s %s: the v2 canonical form still differs across validators (%d distinct)", c.op, c.level, d)
		}
		t.Logf("%s %s: v1 distinct across the fleet = %d, v2 = %d", c.op, c.level, distinct(old), distinct(now))
	}
	// The two measured divergences really were divergences under v1.
	for _, c := range []struct{ op, level string }{{"0x34b9c023", "g1"}, {"0x43372539", "g2"}} {
		old := map[string][]byte{}
		for name, raw := range loadG(t, c.op, c.level) {
			old[name] = v1(c.level, raw)
		}
		if distinct(old) < 2 {
			t.Fatalf("%s %s: expected the recorded v1 divergence", c.op, c.level)
		}
	}
}

func firstG2(t *testing.T) *G2Result {
	t.Helper()
	raws := loadG(t, "0x34b9c023", "g2")
	names := make([]string, 0, len(raws))
	for n := range raws {
		names = append(names, n)
	}
	sort.Strings(names)
	g := new(G2Result)
	if err := json.Unmarshal(raws[names[0]], g); err != nil {
		t.Fatal(err)
	}
	if len(g.ValidatedSignatures) < 2 {
		t.Fatalf("fixture needs at least two signatures, has %d", len(g.ValidatedSignatures))
	}
	return g
}

// Order, messageID spelling and build-time reads do not move the canonical form; the stored result is not modified.
func TestCanonicalV2_BuildTimeReadsDoNotBind(t *testing.T) {
	base := firstG2(t)
	want, err := CanonicalG2JSONV2(base)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(base)

	mb := int64(999)
	variants := map[string]func(g *G2Result){
		"signatures reversed": func(g *G2Result) {
			s := g.ValidatedSignatures
			for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
				s[i], s[j] = s[j], s[i]
			}
		},
		"secondary-route messageID spelling": func(g *G2Result) {
			for i := range g.ValidatedSignatures {
				s := &g.ValidatedSignatures[i]
				s.MessageID = "acc://" + strings.ToUpper(s.MessageHash) + "@" + strings.ToUpper(strings.TrimPrefix(s.Signature.Signer, "acc://"))
			}
		},
		"majorBlock assigned later": func(g *G2Result) {
			g.Receipt.MajorBlock = &mb
			for i := range g.ValidatedSignatures {
				g.ValidatedSignatures[i].Receipt.MajorBlock = &mb
			}
			g.AuthoritySnapshot.Genesis.Receipt.MajorBlock = &mb
		},
		"key page grew after execution": func(g *G2Result) { g.AuthoritySnapshot.Validation.TotalEntries += 3 },
		"another txhash binary":         func(g *G2Result) { g.OutcomeLeaf.PayloadBinding.GoVerifierOutput = "hash=... (v2)" },
	}
	for name, mut := range variants {
		var g G2Result
		if err := deepCopyJSON(base, &g); err != nil {
			t.Fatal(err)
		}
		mut(&g)
		got, err := CanonicalG2JSONV2(&g)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: the canonical form moved", name)
		}
	}
	after, _ := json.Marshal(base)
	if !bytes.Equal(before, after) {
		t.Error("canonicalization modified the stored result")
	}
}

// Every execution-fixed fact still binds.
func TestCanonicalV2_ExecutionFactsBind(t *testing.T) {
	base := firstG2(t)
	want, err := CanonicalG2JSONV2(base)
	if err != nil {
		t.Fatal(err)
	}
	facts := map[string]func(g *G2Result){
		"execution block":       func(g *G2Result) { g.ExecMBI++ },
		"execution witness":     func(g *G2Result) { g.ExecWitness = strings.Repeat("0", 64) },
		"receipt anchor":        func(g *G2Result) { g.Receipt.Anchor = strings.Repeat("1", 64) },
		"a signature's bytes":   func(g *G2Result) { g.ValidatedSignatures[0].Signature.Signature = strings.Repeat("2", 128) },
		"a signer":              func(g *G2Result) { g.ValidatedSignatures[0].Signature.Signer = "acc://other.acme/book/1" },
		"a signature dropped":   func(g *G2Result) { g.ValidatedSignatures = g.ValidatedSignatures[1:] },
		"threshold":             func(g *G2Result) { g.RequiredThreshold++ },
		"state at execution":    func(g *G2Result) { g.AuthoritySnapshot.StateExec.Threshold++ },
		"mutations applied":     func(g *G2Result) { g.AuthoritySnapshot.Validation.MutationsApplied++ },
		"unique valid keys":     func(g *G2Result) { g.UniqueValidKeys++ },
		"computed payload hash": func(g *G2Result) { g.OutcomeLeaf.PayloadBinding.ComputedTxHash = strings.Repeat("3", 64) },
		"tx hash":               func(g *G2Result) { g.TxHash = strings.Repeat("4", 64) },
	}
	for name, mut := range facts {
		var g G2Result
		if err := deepCopyJSON(base, &g); err != nil {
			t.Fatal(err)
		}
		mut(&g)
		got, err := CanonicalG2JSONV2(&g)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if bytes.Equal(got, want) {
			t.Errorf("%s: an execution fact did not change the canonical form", name)
		}
	}
}

func TestCanonicalV2_RefusesMalformedSignatures(t *testing.T) {
	for name, mut := range map[string]func(g *G2Result){
		"duplicate signature": func(g *G2Result) { g.ValidatedSignatures[1] = g.ValidatedSignatures[0] },
		"no message hash":     func(g *G2Result) { g.ValidatedSignatures[0].MessageHash = "" },
		"no signer page":      func(g *G2Result) { g.ValidatedSignatures[0].Signature.Signer = "" },
	} {
		g := firstG2(t)
		mut(g)
		if _, err := CanonicalG2JSONV2(g); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := CanonicalG1JSONV2(nil); err == nil {
		t.Error("a missing G1 was accepted")
	}
}
