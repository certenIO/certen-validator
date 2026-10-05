package consensus

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/ledger"
	govproof "github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// The production proof 6c831fec-fe86-4b0f-bdf1-36accc8040d3 (intent 4e0fc602, base-sepolia, 2026-10-05), as
// cmd/prooffixture wrote it from a read-only copy of its rows: its L1-L4 chained proof, G0-G2 and vote record as in
// proof_e1e34338.json, and the proof v2 the shadow built for it (six governing pages) with the Directory's major
// records it builds on, verified from Kermit's genesis on extraction.
type intentFixtureV3 struct {
	intentFixture
	ProofV2 json.RawMessage `json:"proof_v2"`
	Archive json.RawMessage `json:"archive"`
}

func loadIntentFixtureV3(t *testing.T) *intentFixtureV3 {
	t.Helper()
	gz, err := os.ReadFile("testdata/intent_cert/proof_6c831fec_v3.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	r, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	f := new(intentFixtureV3)
	if err := json.Unmarshal(b, f); err != nil {
		t.Fatal(err)
	}
	if len(f.ProofV2) == 0 || len(f.Archive) == 0 {
		t.Fatal("the fixture carries no proof v2")
	}
	return f
}

// v3Spine is the spine the chain would hold after verifying the fixture's major records from Kermit's genesis.
func v3Spine(t *testing.T, f *intentFixtureV3) *ledger.AccumulateSpineLog {
	t.Helper()
	ar, err := proofv2.UnmarshalArchive(f.Archive)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../proof/testdata/incarnation/kermit.json")
	if err != nil {
		t.Fatal(err)
	}
	var inc govproof.IncarnationEvidence
	if err := json.Unmarshal(raw, &inc); err != nil {
		t.Fatal(err)
	}
	ir, err := inc.Verify()
	if err != nil {
		t.Fatal(err)
	}
	gen, set, err := proofv2.AcceptSpineGenesis(ir.Inputs, ir.Incarnation, 5)
	if err != nil {
		t.Fatal(err)
	}
	l := &ledger.AccumulateSpineLog{Genesis: gen, Sets: []ledger.AccumulateSpineSet{set}}
	cps, sets, err := proofv2.ExtendSpine(l, ar.Majors, 6)
	if err != nil {
		t.Fatal(err)
	}
	l.Checkpoints, l.Sets = cps, append(l.Sets, sets...)
	return l
}

func v3Block(t *testing.T, f *intentFixtureV3, validatorID string) *ValidatorBlock {
	t.Helper()
	vb := &ValidatorBlock{ValidatorID: validatorID}
	vb.CrossChainProof.OperationID = "0x" + strings.Repeat("07", 32)
	vb.LiteClientProof = govproof.ChainedProofToCompleteProof(f.ChainedProof)
	gp := &vb.GovernanceProof
	gp.G0Proof, gp.G1Proof, gp.G2Proof = new(govproof.G0Result), new(govproof.G1Result), new(govproof.G2Result)
	for _, l := range []struct {
		raw json.RawMessage
		v   interface{}
	}{{f.G0, gp.G0Proof}, {f.G1, gp.G1Proof}, {f.G2, gp.G2Proof}} {
		if err := json.Unmarshal(l.raw, l.v); err != nil {
			t.Fatal(err)
		}
	}
	return vb
}

func v3Evidence(t *testing.T, f *intentFixtureV3) *proofv2.Evidence {
	t.Helper()
	ev := new(proofv2.Evidence)
	if err := json.Unmarshal(f.ProofV2, ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

func buildV3(t *testing.T, f *intentFixtureV3, vb *ValidatorBlock, reg *ledger.BLSRegistryRecord, rf *registryFixture,
	spine *ledger.AccumulateSpineLog, ev *proofv2.Evidence) error {
	t.Helper()
	return BuildIntentCertificate(vb, intentChain, reg, rf.keys[0], intentKeyPage, intentKeyBook, f.record(t), f.VoteEvidence,
		f.ChainedProof, spine, ev)
}

// A live intent certified under v3: consensus judges its proof v2 against the chain's spine, binds it to the block's
// G0 and G1, and signs govRoot v3 over the v3 message; the evidence survives the block's JSON. The same block judged
// before the spine exists is refused as v3-not-in-force, and a v2 block once the spine exists is refused as missing
// its proof v2.
func TestAV3IntentCertificateIsJudgedAgainstTheChainSpine(t *testing.T) {
	f := loadIntentFixtureV3(t)
	rf, reg := intentRegistry(t)
	spine := v3Spine(t, f)
	if !ProofV3Required(spine, reg) {
		t.Fatal("a spine of the registry's incarnation does not require v3")
	}

	vb := v3Block(t, f, "validator-1")
	if err := buildV3(t, f, vb, reg, rf, spine, v3Evidence(t, f)); err != nil {
		t.Fatalf("building the v3 certificate: %v", err)
	}
	ev := vb.IntentCertificate
	if ev.ProofV2 == nil || ev.GovRootV3 == "" || ev.GovRootV2 != "" {
		t.Fatalf("not a v3 certificate: proof v2 %v, govRoot v3 %q, govRoot v2 %q", ev.ProofV2 != nil, ev.GovRootV3, ev.GovRootV2)
	}
	b, err := json.Marshal(vb)
	if err != nil {
		t.Fatal(err)
	}
	var back ValidatorBlock
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyIntentCertificate(&back, intentChain, reg, spine); err != nil {
		t.Fatalf("after a JSON round trip: %v", err)
	}
	t.Logf("v3 block: %d bytes of JSON, govRoot v3 %s", len(b), ev.GovRootV3)

	// The same block before any spine: v3 is not in force.
	if _, err := VerifyIntentCertificate(&back, intentChain, reg, nil); !errors.Is(err, ErrIntentProofV3NotInForce) {
		t.Fatalf("a v3 certificate before the spine: %v", err)
	}
	// A v2 block once the spine exists: refused for its missing proof v2.
	v2 := v3Block(t, f, "validator-1")
	if err := buildV3(t, f, v2, reg, rf, nil, nil); err != nil {
		t.Fatalf("building the v2 certificate: %v", err)
	}
	if _, err := VerifyIntentCertificate(v2, intentChain, reg, spine); !errors.Is(err, ErrIntentProofV2Missing) {
		t.Fatalf("a v2 certificate once the spine exists: %v", err)
	}
	// A spine of another incarnation does not require v3, so the v2 block verifies again.
	other := *spine
	g := *spine.Genesis
	g.Incarnation = "0x" + strings.Repeat("ab", 32)
	other.Genesis = &g
	if _, err := VerifyIntentCertificate(v2, intentChain, reg, &other); err != nil {
		t.Fatalf("a v2 certificate under another incarnation's spine: %v", err)
	}
}

// Everything v3 adds is recomputed from the block: a tampered proof v2, levels about another transaction, a key page
// the proof did not prove, a claimed govRoot v3 or set root that is not the recomputed one - each refused by name. And
// a proof that builds past the major blocks the chain has verified is refused, however valid from genesis.
func TestAV3IntentCertificateRefusesWhatItDoesNotProve(t *testing.T) {
	f := loadIntentFixtureV3(t)
	rf, reg := intentRegistry(t)
	spine := v3Spine(t, f)
	built := func(t *testing.T) *ValidatorBlock {
		vb := v3Block(t, f, "validator-1")
		if err := buildV3(t, f, vb, reg, rf, spine, v3Evidence(t, f)); err != nil {
			t.Fatal(err)
		}
		return vb
	}
	for _, c := range []struct {
		name string
		edit func(vb *ValidatorBlock)
		want error
	}{
		{"a dropped proof v2", func(vb *ValidatorBlock) { vb.IntentCertificate.ProofV2 = nil }, ErrIntentProofV2Missing},
		{"a tampered receipt", func(vb *ValidatorBlock) {
			r := []byte(vb.IntentCertificate.ProofV2.Receipt)
			r[len(r)-3] ^= 1
			vb.IntentCertificate.ProofV2.Receipt = string(r)
		}, ErrIntentProofV2Invalid},
		{"G0 of another block", func(vb *ValidatorBlock) { vb.GovernanceProof.G0Proof.ExecMBI++ }, ErrIntentProofV2Invalid},
		{"a key page the proof did not prove", func(vb *ValidatorBlock) {
			vb.IntentCertificate.KeyPageURL = "acc://someone-else.acme/book/1"
		}, ErrIntentProofV2Invalid},
		{"a claimed govRoot v3", func(vb *ValidatorBlock) {
			vb.IntentCertificate.GovRootV3 = "0x" + strings.Repeat("11", 32)
		}, ErrIntentGovRootMismatch},
		{"a claimed govRoot v2 beside v3", func(vb *ValidatorBlock) {
			vb.IntentCertificate.GovRootV2 = "0x" + strings.Repeat("11", 32)
		}, ErrIntentGovRootMismatch},
		{"a claimed set root", func(vb *ValidatorBlock) {
			vb.IntentCertificate.AccumulateSetRoot = "0x" + strings.Repeat("11", 32)
		}, ErrIntentAccumulateSetMismatch},
	} {
		t.Run(c.name, func(t *testing.T) {
			vb := built(t)
			c.edit(vb)
			if _, err := VerifyIntentCertificate(vb, intentChain, reg, spine); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}

	// The chain has verified fewer major blocks than the proof builds on.
	ev := v3Evidence(t, f)
	short := *spine
	short.Checkpoints = spine.Checkpoints[:ev.Majors-1]
	vb := built(t)
	if _, err := VerifyIntentCertificate(vb, intentChain, reg, &short); !errors.Is(err, ErrIntentProofV2Invalid) ||
		!strings.Contains(err.Error(), "the chain has verified") {
		t.Fatalf("a proof past the chain's spine: %v", err)
	}
}
