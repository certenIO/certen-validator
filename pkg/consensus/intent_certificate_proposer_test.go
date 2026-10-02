package consensus

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/ledger"
	govproof "github.com/certen/independant-validator/pkg/proof"
)

// The proposer builds against what the chain judges by: its genesis chain id and the registry in force for the
// next block - not configuration.
func TestAProposerBuildsAgainstTheChainsOwnState(t *testing.T) {
	f, reg := intentRegistry(t)
	app, store := rotationApp(t, f.rotationFixture)
	chain, got, err := app.IntentCertificateContext()
	if err != nil || chain != rotChain || got != nil {
		t.Fatalf("before any registry: (%q, %v, %v)", chain, got, err)
	}
	if err := store.SaveBLSRegistry(&ledger.BLSRegistryLog{Versions: []ledger.BLSRegistryRecord{*reg}}); err != nil {
		t.Fatal(err)
	}
	app.latestHeight = reg.Height - 1 // the next block is the accepting one: not yet in force
	if _, got, _ = app.IntentCertificateContext(); got != nil {
		t.Fatal("a registry was in force at the height that accepts it")
	}
	app.latestHeight = reg.Height
	if _, got, _ = app.IntentCertificateContext(); got == nil || got.Version != reg.Version {
		t.Fatalf("the registry accepted at %d is not in force for %d", reg.Height, reg.Height+1)
	}
}

// certifyIntent signs with this validator's own BLS key - the key manager main initialises - and what it builds is
// what FinalizeBlock accepts; it refuses what it cannot prove.
func TestTheProposerCertifiesWithItsOwnKey(t *testing.T) {
	secret := bytes.Repeat([]byte{0x5a}, 32)
	km, err := bls.InitializeValidatorBLSKey("validator-1", filepath.Join(t.TempDir(), "bls_key_validator-1.hex"), secret)
	if err != nil {
		t.Fatal(err)
	}
	f := newRegistryFixture(t)
	f.keys[0] = km.PrivateKey() // the registry holds this validator's real key
	reg, err := VerifyBLSRegistry(f.registry(1, "ops-1", "ops-2"), rotChain, f.policy, &ledger.BLSRegistryLog{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	fx := loadIntentFixture(t)
	cert := &govproof.CertenProof{LiteClientProof: &govproof.LiteClientProofData{
		CompleteProof: govproof.ChainedProofToCompleteProof(fx.ChainedProof), ChainedProof: fx.ChainedProof}}
	vote, err := govproof.DecodeVoteEvidence(fx.VoteEvidence)
	if err != nil {
		t.Fatal(err)
	}
	bv := &BFTValidator{validatorID: "validator-1"}

	vb := intentBlock(t, "validator-1")
	if err := bv.certifyIntent(vb, intentChain, reg, cert, intentKeyPage, intentKeyBook, fx.record(t), vote); err != nil {
		t.Fatalf("certifying: %v", err)
	}
	if _, err := VerifyIntentCertificate(vb, intentChain, reg); err != nil {
		t.Fatalf("FinalizeBlock refuses what the proposer built: %v", err)
	}
	if b, _ := json.Marshal(vb); !bytes.Contains(b, []byte(`"intent_certificate"`)) {
		t.Fatal("the certificate does not travel with the block")
	}

	for name, c := range map[string]*govproof.CertenProof{
		"no chained proof": {LiteClientProof: &govproof.LiteClientProofData{CompleteProof: cert.LiteClientProof.CompleteProof}},
		"no lite proof":    {},
	} {
		vb := intentBlock(t, "validator-1")
		if err := bv.certifyIntent(vb, intentChain, reg, c, intentKeyPage, intentKeyBook, fx.record(t), vote); err == nil ||
			!strings.Contains(err.Error(), "chained proof") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := bv.certifyIntent(intentBlock(t, "validator-1"), intentChain, reg, cert, intentKeyPage, intentKeyBook,
		fx.record(t), nil); err == nil || !strings.Contains(err.Error(), "vote evidence") {
		t.Errorf("no vote evidence: %v", err)
	}
	// Under validator-2's name the same key is not the registered one.
	if err := bv.certifyIntent(intentBlock(t, "validator-2"), intentChain, reg, cert, intentKeyPage, intentKeyBook,
		fx.record(t), vote); err == nil {
		t.Error("certified under another validator's name")
	}
}
