package consensus

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/ledger"
	govproof "github.com/certen/independant-validator/pkg/proof"
)

const intentChain = "certen-testnet"

// intentRecord is a vote record for the fixture transaction's principal: harbor-mfg-tcl1.acme's book accepted
// through page 1, in the block G0 proved the transaction executed in.
func intentRecord() *govproof.AuthorizationRecord {
	page := govproof.AuthorizationPage{Page: "acc://harbor-mfg-tcl1.acme/book/1", Voted: true, Vote: "accept", Version: 1,
		Threshold: 1, DecidedAt: 11925688, Counted: []govproof.AuthorizationEntry{{Entry: "key:" + strings.Repeat("ab", 32),
			Vote: "accept", By: "acc://" + strings.Repeat("cd", 32) + "@harbor-mfg-tcl1.acme", Block: 11925688}}}
	return &govproof.AuthorizationRecord{Account: "acc://harbor-mfg-tcl1.acme", Satisfied: true,
		Authorities: []govproof.AuthorizationAuthority{{Authority: "acc://harbor-mfg-tcl1.acme/book",
			Vote: govproof.AuthorizationBook{Book: "acc://harbor-mfg-tcl1.acme/book", Voted: true, Vote: "accept",
				By: page.Page, Pages: []govproof.AuthorizationPage{page}}}}}
}

// intentBlock is a ValidatorBlock carrying a production proof: the Kermit L1-L4 fixture (with its Directory leg)
// and validator-1's production G0-G2 for operation 0x34b9c023.
func intentBlock(t *testing.T, validatorID string) *ValidatorBlock {
	t.Helper()
	vb := &ValidatorBlock{ValidatorID: validatorID}
	vb.CrossChainProof.OperationID = "0x" + strings.Repeat("07", 32)
	vb.LiteClientProof = govproof.ChainedProofToCompleteProof(loadLiteFixture(t, "proof_bvn1.json"))
	read := func(level string, v interface{}) {
		b, err := os.ReadFile("../proof/testdata/govroot_v2/0x34b9c023_validator-1_2152_" + level + ".json")
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, v); err != nil {
			t.Fatal(err)
		}
	}
	gp := &vb.GovernanceProof
	gp.G0Proof, gp.G1Proof, gp.G2Proof = new(govproof.G0Result), new(govproof.G1Result), new(govproof.G2Result)
	read("g0", gp.G0Proof)
	read("g1", gp.G1Proof)
	read("g2", gp.G2Proof)
	return vb
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
	if err := BuildIntentCertificate(vb, intentChain, reg, f.keys[0], "acc://harbor-mfg-tcl1.acme/book/1",
		"acc://harbor-mfg-tcl1.acme/book", intentRecord()); err != nil {
		t.Fatalf("building the intent certificate: %v", err)
	}
	return f, reg, vb
}

func TestAnIntentCertificateIsRecomputedFromTheBlockAndVerified(t *testing.T) {
	_, reg, vb := builtIntentBlock(t)
	msg, err := VerifyIntentCertificate(vb, intentChain, reg)
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
	if _, err := VerifyIntentCertificate(&back, intentChain, reg); err != nil {
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
			vb.IntentCertificate.KeyPageURL = "acc://harbor-mfg-tcl1.acme/book/2"
			return vb, r, intentChain
		}, ErrIntentGovRootMismatch},
		"a changed G1": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			vb.GovernanceProof.G1Proof.ThresholdSatisfied = !vb.GovernanceProof.G1Proof.ThresholdSatisfied
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
		}, ErrIntentAccumulateSetMismatch},
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
			rec := intentRecord()
			rec.Account = "acc://someone-else.acme"
			vb.IntentCertificate.AuthorizationRecord, _ = json.Marshal(rec)
			return vb, r, intentChain
		}, ErrIntentGovernanceUnderivable},
		"a different vote record": {func(vb *ValidatorBlock, r *ledger.BLSRegistryRecord) (*ValidatorBlock, *ledger.BLSRegistryRecord, string) {
			rec := intentRecord()
			rec.Authorities[0].Vote.Pages[0].Threshold = 2
			vb.IntentCertificate.AuthorizationRecord, _ = json.Marshal(rec)
			return vb, r, intentChain
		}, ErrIntentMessageMismatch},
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
			if err := BuildIntentCertificate(other, intentChain, r, f.keys[0], "acc://harbor-mfg-tcl1.acme/book/1",
				"acc://harbor-mfg-tcl1.acme/book", intentRecord()); err != nil {
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
		if _, err := VerifyIntentCertificate(vb, chain, r); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
}

// A node never builds a block it would refuse: the builder checks its own result.
func TestTheBuilderRefusesToBuildWhatItWouldRefuse(t *testing.T) {
	f, reg := intentRegistry(t)
	vb := intentBlock(t, "validator-1")
	// validator-2's key under validator-1's name.
	if err := BuildIntentCertificate(vb, intentChain, reg, f.keys[1], "acc://harbor-mfg-tcl1.acme/book/1",
		"acc://harbor-mfg-tcl1.acme/book", intentRecord()); !errors.Is(err, ErrIntentSignatureInvalid) || vb.IntentCertificate != nil {
		t.Fatalf("built with another validator's key: %v", err)
	}
	if err := BuildIntentCertificate(vb, intentChain, nil, f.keys[0], "p", "b", intentRecord()); err == nil {
		t.Fatal("built without a registry")
	}
}
