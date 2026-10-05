package consensus

import (
	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/crypto/bls"
	abcitypes "github.com/cometbft/cometbft/abci/types"

	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/ledger"
	govproof "github.com/certen/independant-validator/pkg/proof"
)

const intentChain = "certen-testnet"

// The production proof e1e34338-901f-4644-a23d-246f02bb6ec8 (RB4 acceptance e2e, base-sepolia, 2026-09-29), as
// cmd/prooffixture wrote it from storage through a read-only session: its L1-L4 chained proof (verified on extraction),
// its stored G0-G2, and the G1 level's vote record and evidence (evaluated again on extraction).
type intentFixture struct {
	ProofID       string                      `json:"proof_id"`
	ChainedProof  *chained_proof.ChainedProof `json:"chained_proof"`
	G0            json.RawMessage             `json:"g0"`
	G1            json.RawMessage             `json:"g1"`
	G2            json.RawMessage             `json:"g2"`
	Authorization json.RawMessage             `json:"authorization"`
	VoteEvidence  json.RawMessage             `json:"vote_evidence"`
}

func loadIntentFixture(t *testing.T) *intentFixture {
	t.Helper()
	b, err := os.ReadFile("testdata/intent_cert/proof_e1e34338.json")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	f := new(intentFixture)
	if err := json.Unmarshal(b, f); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *intentFixture) record(t *testing.T) *govproof.AuthorizationRecord {
	t.Helper()
	rec := new(govproof.AuthorizationRecord)
	if err := json.Unmarshal(f.Authorization, rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

const (
	intentKeyPage = "acc://rb4-phase-c-09282125.acme/book/1"
	intentKeyBook = "acc://rb4-phase-c-09282125.acme/book"
)

// intentBlock is a ValidatorBlock carrying the production proof: its lite_client_proof is the projection of the
// fixture's chained proof, and its G0-G2 are the stored results.
func intentBlock(t *testing.T, validatorID string) *ValidatorBlock {
	t.Helper()
	f := loadIntentFixture(t)
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

func buildCert(t *testing.T, vb *ValidatorBlock, reg *ledger.BLSRegistryRecord, sk *bls.PrivateKey) error {
	t.Helper()
	f := loadIntentFixture(t)
	return BuildIntentCertificate(vb, intentChain, reg, sk, intentKeyPage, intentKeyBook, f.record(t), f.VoteEvidence, f.ChainedProof, nil, nil)
}

func intentRegistry(t *testing.T) (*registryFixture, *ledger.BLSRegistryRecord) {
	t.Helper()
	f := newRegistryFixture(t)
	reg, err := VerifyBLSRegistry(f.registry(1, "ops-1", "ops-2"), rotChain, f.policy, &ledger.BLSRegistryLog{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	return f, reg
}

func builtIntentBlock(t *testing.T) (*registryFixture, *ledger.BLSRegistryRecord, *ValidatorBlock) {
	t.Helper()
	f, reg := intentRegistry(t)
	vb := intentBlock(t, "validator-1")
	if err := buildCert(t, vb, reg, f.keys[0]); err != nil {
		t.Fatalf("building the intent certificate: %v", err)
	}
	return f, reg, vb
}

func TestAnIntentCertificateIsRecomputedFromTheBlockAndVerified(t *testing.T) {
	_, reg, vb := builtIntentBlock(t)
	msg, err := VerifyIntentCertificate(vb, intentChain, reg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hexEquals(vb.IntentCertificate.Message, msg) {
		t.Fatal("the verified message is not the block's")
	}
	// The evidence round-trips through the block's JSON, as consensus receives it.
	b, err := json.Marshal(vb)
	if err != nil {
		t.Fatal(err)
	}
	var back ValidatorBlock
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyIntentCertificate(&back, intentChain, reg, nil); err != nil {
		t.Fatalf("after a JSON round trip: %v", err)
	}
}

// Every input is recomputed from the block, so a block cannot carry a signature over anything but what it proves;
// each refusal is by name.
func TestAnIntentCertificateRefusesWhatItDoesNotProve(t *testing.T) {
	f, reg, _ := builtIntentBlock(t)
	cases := map[string]struct {
		mut  func(vb *ValidatorBlock, reg *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string)
		want error
	}{
		"no certificate": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			vb.IntentCertificate = nil
			return vb, r, intentChain
		}, ErrIntentCertificateMissing},
		"a validator the registry does not hold (RB5-F25)": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			vb.ValidatorID = "validator-99"
			return vb, r, intentChain
		}, ErrIntentSignerNotRegistered},
		"another validator's name on validator-1's signature (RB5-F25)": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			vb.ValidatorID = "validator-2"
			return vb, r, intentChain
		}, ErrIntentSignatureInvalid},
		"a registry no longer in force": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			next := *r
			next.Version = 2
			return vb, &next, intentChain
		}, ErrIntentRegistryVersion},
		"another CERTEN chain": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			return vb, r, "certen-mainnet"
		}, ErrIntentMessageMismatch},
		"another operation": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			vb.CrossChainProof.OperationID = "0x" + strings.Repeat("08", 32)
			return vb, r, intentChain
		}, ErrIntentGovRootMismatch},
		"another key page": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			vb.IntentCertificate.KeyPageURL = "acc://rb4-phase-c-09282125.acme/book/2"
			return vb, r, intentChain
		}, ErrIntentProofInvalid},
		"a key book that is not the page's": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			vb.IntentCertificate.KeyBookURL = "acc://rb4-phase-c-09282125.acme/other-book"
			return vb, r, intentChain
		}, ErrIntentProofInvalid},
		"a changed G1 that G2 does not carry": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			vb.GovernanceProof.G1Proof.RequiredThreshold++
			return vb, r, intentChain
		}, ErrIntentProofInvalid},
		"a changed G1 carried by G2 too": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			vb.GovernanceProof.G1Proof.RequiredThreshold++
			vb.GovernanceProof.G2Proof.G1Result.RequiredThreshold++
			return vb, r, intentChain
		}, ErrIntentGovRootMismatch},
		"a substituted Accumulate validator": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			dn := *vb.LiteClientProof.Layer4DN
			dn.ValidatorSet = append(dn.ValidatorSet[:0:0], dn.ValidatorSet...)
			dn.ValidatorSet[0].PublicKey = "aa" + dn.ValidatorSet[0].PublicKey[2:]
			lp := *vb.LiteClientProof
			lp.Layer4DN = &dn
			vb.LiteClientProof = &lp
			return vb, r, intentChain
		}, ErrIntentProofInvalid},
		"another incarnation in the registry": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			other := *r
			other.AccumulateIncarnation = "0x" + strings.Repeat("11", 32)
			return vb, &other, intentChain
		}, ErrIntentAccumulateSetMismatch},
		"another CERTEN set": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			other := *r
			other.CertenSetRoot = "0x" + strings.Repeat("22", 32)
			return vb, &other, intentChain
		}, ErrIntentMessageMismatch},
		"a vote record for another account": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			rec := loadIntentFixture(t).record(t)
			rec.Account = "acc://someone-else.acme"
			vb.IntentCertificate.AuthorizationRecord, _ = json.Marshal(rec)
			return vb, r, intentChain
		}, ErrIntentGovernanceUnderivable},
		"a vote record its evidence does not reach": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			rec := loadIntentFixture(t).record(t)
			rec.Authorities[0].Vote.Pages[0].Threshold++
			vb.IntentCertificate.AuthorizationRecord, _ = json.Marshal(rec)
			return vb, r, intentChain
		}, ErrIntentProofInvalid},
		"no vote evidence": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			vb.IntentCertificate.VoteEvidence = nil
			return vb, r, intentChain
		}, ErrIntentProofInvalid},
		"no chained proof": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			vb.IntentCertificate.ChainedProof = nil
			return vb, r, intentChain
		}, ErrIntentProofInvalid},
		"a chained proof that does not verify": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			cp := *vb.IntentCertificate.ChainedProof
			dn := *cp.Layer4DN
			dn.Signatures = dn.Signatures[:0]
			cp.Layer4DN = &dn
			vb.IntentCertificate.ChainedProof = &cp
			return vb, r, intentChain
		}, ErrIntentProofInvalid},
		"a lite proof that is not the chained proof's": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			// Another transaction's verified proof, beside this block's lite proof.
			vb.IntentCertificate.ChainedProof = loadLiteFixture(t, "proof_bvn1.json")
			return vb, r, intentChain
		}, ErrIntentProofInvalid},
		"G2 carrying another G1": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			vb.GovernanceProof.G2Proof.G1Result.RequiredThreshold++
			return vb, r, intentChain
		}, ErrIntentProofInvalid},
		"G1 carrying another G0": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			vb.GovernanceProof.G1Proof.G0Result.ExecMBI++
			return vb, r, intentChain
		}, ErrIntentProofInvalid},
		"no vote record": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			vb.IntentCertificate.AuthorizationRecord = nil
			return vb, r, intentChain
		}, ErrIntentGovernanceUnderivable},
		"no G2": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			vb.GovernanceProof.G2Proof = nil
			return vb, r, intentChain
		}, ErrIntentInputsMissing},
		"a claimed govRoot that is not the block's": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			vb.IntentCertificate.GovRootV2 = "0x" + strings.Repeat("33", 32)
			return vb, r, intentChain
		}, ErrIntentGovRootMismatch},
		"a signature over another message": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			other := intentBlock(t, "validator-1")
			other.CrossChainProof.OperationID = "0x" + strings.Repeat("09", 32)
			if err := buildCert(t, other, r, f.keys[0]); err != nil {
				t.Fatal(err)
			}
			vb.IntentCertificate.Signature = other.IntentCertificate.Signature
			return vb, r, intentChain
		}, ErrIntentSignatureInvalid},
		"a signature that is not a G1 point": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			vb.IntentCertificate.Signature = strings.Repeat("ff", 48)
			return vb, r, intentChain
		}, ErrIntentSignatureInvalid},
	}
	for name, c := range cases {
		_, reg2, vb := builtIntentBlock(t)
		_ = reg
		vb, r, chain := c.mut(vb, reg2)
		if _, err := VerifyIntentCertificate(vb, chain, r, nil); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
}

// A node never builds a block it would refuse: the builder checks its own result.
func TestTheBuilderRefusesToBuildWhatItWouldRefuse(t *testing.T) {
	f, reg := intentRegistry(t)
	vb := intentBlock(t, "validator-1")
	// validator-2's key under validator-1's name.
	if err := buildCert(t, vb, reg, f.keys[1]); !errors.Is(err, ErrIntentSignatureInvalid) || vb.IntentCertificate != nil {
		t.Fatalf("built with another validator's key: %v", err)
	}
	if err := buildCert(t, vb, nil, f.keys[0]); err == nil {
		t.Fatal("built without a registry")
	}
}

// The rule FinalizeBlock applies: unchanged before a registry is in force (a block with no certificate passes, a
// certificate nothing can verify is refused); once one is, every block needs a certificate that verifies.
func TestFinalizeBlockJudgesIntentCertificatesFromTheRegistryInForce(t *testing.T) {
	f, reg, certified := builtIntentBlock(t)
	app, store := rotationApp(t, f.rotationFixture)
	app.cometChainID = intentChain
	plain := intentBlock(t, "validator-1")
	judge := func(height uint64, vb *ValidatorBlock) *abcitypes.ExecTxResult {
		app.currentBlockHeight = height
		app.blockRulesV10Verdict = false
		return app.judgeIntentCertificate(vb)
	}

	// No registry recorded.
	if r := judge(11, plain); r != nil {
		t.Fatalf("a block without a certificate, before any registry: %v", r.Log)
	}
	if r := judge(11, certified); r == nil || r.Code != codeIntentCertificateRefused || !app.blockRulesV10Verdict {
		t.Fatal("a certificate with no registry to verify it was not refused as a v10 verdict")
	}

	// The registry accepted at height 10 is in force from height 11.
	if err := store.SaveBLSRegistry(&ledger.BLSRegistryLog{Versions: []ledger.BLSRegistryRecord{*reg}}); err != nil {
		t.Fatal(err)
	}
	if r := judge(10, plain); r != nil {
		t.Fatalf("at the accepting height the registry is not yet in force: %v", r.Log)
	}
	if r := judge(11, certified); r != nil {
		t.Fatalf("a valid certificate under the registry in force: %v", r.Log)
	}
	if r := judge(11, plain); r == nil || r.Code != codeIntentCertificateRefused || !app.blockRulesV10Verdict {
		t.Fatal("a block without a certificate under a registry in force was not refused")
	}
	forged := *certified
	ev := *certified.IntentCertificate
	forged.IntentCertificate = &ev
	forged.ValidatorID = "validator-2"
	if r := judge(11, &forged); r == nil || !strings.Contains(r.Log, ErrIntentSignatureInvalid.Error()) {
		t.Fatalf("validator-1's signature under validator-2's name: %+v", r)
	}
}

// The invariants: a block with a certificate carries no V6.1 solo signature; one without needs it, as before.
func TestTheSoloSignatureIsReplacedNotDropped(t *testing.T) {
	_, _, certified := builtIntentBlock(t)
	inv := func(vb *ValidatorBlock) error { return VerifyValidatorBlockInvariants(vb) }
	certified.GovernanceProof.BLSAggregateSignature = "aa"
	if err := inv(certified); err == nil || !strings.Contains(err.Error(), "carries no V6.1 solo signature") {
		t.Fatalf("a certified block carrying the solo signature: %v", err)
	}
	certified.GovernanceProof.BLSAggregateSignature = ""
	if err := inv(certified); err != nil && strings.Contains(err.Error(), "bls_aggregate_signature") {
		t.Fatalf("a certified block was asked for the solo signature: %v", err)
	}
	certified.IntentCertificate = nil
	if err := inv(certified); err == nil || !strings.Contains(err.Error(), "bls_aggregate_signature must not be empty") {
		t.Fatalf("an uncertified block without the solo signature: %v", err)
	}
}

// Accumulate URLs are case-insensitive: one page named two ways is one page, one govRoot and one message.
func TestOnePageNamedTwoWaysIsOneMessage(t *testing.T) {
	_, reg, vb := builtIntentBlock(t)
	vb.IntentCertificate.KeyPageURL = "acc://RB4-Phase-C-09282125.acme/book/1/"
	vb.IntentCertificate.KeyBookURL = "ACC://rb4-phase-c-09282125.ACME/book"
	if _, err := VerifyIntentCertificate(vb, intentChain, reg, nil); err != nil {
		t.Fatalf("the same page spelled differently: %v", err)
	}
}
