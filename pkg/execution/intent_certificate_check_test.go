package execution

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/accumulateset"
	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/crypto/bls_zkp"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/intentcert"
	"github.com/certen/independant-validator/pkg/ledger"
	certenproof "github.com/certen/independant-validator/pkg/proof"
)

const kermitIncarnation = "0xcac6698ed49a286ad8a3de94540a3354dfe964f366a439f4fdfb34533059fda0"

// storedIntentCase is production proof e1e34338 as storage holds it, with a certificate its seven-validator quorum
// would record for it: five of seven signatures over the message the proof computes.
type storedIntentCase struct {
	row    *database.IntentQuorumCertificateRow
	cp     *chained_proof.ChainedProof
	levels []certenproof.StoredGovernanceLevel
	l5     *Layer5
}

func newStoredIntentCase(t *testing.T) *storedIntentCase {
	t.Helper()
	b, err := os.ReadFile("../consensus/testdata/intent_cert/proof_e1e34338.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		ChainedProof  *chained_proof.ChainedProof `json:"chained_proof"`
		G0            json.RawMessage             `json:"g0"`
		G1            json.RawMessage             `json:"g1"`
		G2            json.RawMessage             `json:"g2"`
		Authorization json.RawMessage             `json:"authorization"`
	}
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatal(err)
	}
	c := &storedIntentCase{cp: fx.ChainedProof, levels: []certenproof.StoredGovernanceLevel{
		{Level: "G0", Result: fx.G0},
		{Level: "G1", Result: fx.G1, Flags: map[string]json.RawMessage{GovLevelAuthorizationKey: fx.Authorization}},
		{Level: "G2", Result: fx.G2},
	}}

	// The registry: seven members, power 100, 2/3, under Kermit's incarnation.
	var keys []*bls.PrivateKey
	reg := ledger.BLSRegistryRecord{Version: 1, Height: 10, ThresholdNumerator: 2, ThresholdDenominator: 3,
		AccumulateIncarnation: kermitIncarnation}
	for i := 0; i < 7; i++ {
		seed := make([]byte, 32)
		seed[0], seed[31] = 0xC3, byte(i+1)
		sk, _, err := bls.GenerateKeyPairFromSeed(seed)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, sk)
		reg.Members = append(reg.Members, ledger.BLSRegistryMember{ValidatorID: fmt.Sprintf("validator-%d", i+1),
			EVMAddress: fmt.Sprintf("0x%040x", 0x1000+i), BLSPubKey: sk.PublicKey().Hex(), Power: 100})
	}
	root, err := consensus.RegistryCertenSetRoot(reg.Members, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	reg.CertenSetRoot = "0x" + hex.EncodeToString(root[:])

	// The message the stored proof computes.
	var g0 certenproof.G0Result
	var g1 certenproof.G1Result
	var g2 certenproof.G2Result
	var rec certenproof.AuthorizationRecord
	for _, x := range []struct {
		raw json.RawMessage
		v   interface{}
	}{{fx.G0, &g0}, {fx.G1, &g1}, {fx.G2, &g2}, {fx.Authorization, &rec}} {
		if err := json.Unmarshal(x.raw, x.v); err != nil {
			t.Fatal(err)
		}
	}
	op := [32]byte{0x07}
	opHex := "0x" + hex.EncodeToString(op[:])
	page, book := g1.AuthoritySnapshot.Page, "acc://rb4-phase-c-09282125.acme/book"
	govRoot, _, err := intentcert.GovRootV2(intentcert.GovRootV2Inputs{Lite: certenproof.ChainedProofToCompleteProof(fx.ChainedProof),
		G0: &g0, G1: &g1, G2: &g2, KeyPageURL: page, KeyBookURL: book, OperationID: op})
	if err != nil {
		t.Fatal(err)
	}
	inc, _ := hex32Of(kermitIncarnation)
	acc, err := accumulateset.CommittedAccumulateSetRoot(fx.ChainedProof.Layer4DN, inc)
	if err != nil {
		t.Fatal(err)
	}
	gdr, err := certenproof.GovernanceDecisionRecord(&g0, &rec)
	if err != nil {
		t.Fatal(err)
	}
	mi := intentcert.MessageInputs{CertenChainID: "certen-testnet", OperationID: op, GovRootV2: govRoot, AccumulateSetRoot: acc,
		Incarnation: inc, GovernanceCommitment: certenproof.GovernanceCommitment(gdr), CertenSetRoot: root}
	msg, err := intentcert.Message(mi)
	if err != nil {
		t.Fatal(err)
	}

	// Five signatures, aggregated as consensus aggregates them.
	quorumReg := map[string]consensus.ValidatorRegistryEntry{}
	for _, m := range reg.Members {
		quorumReg[m.EVMAddress] = consensus.ValidatorRegistryEntry{EVMAddress: m.EVMAddress, PublicKeyHex: m.BLSPubKey, VotingPower: big.NewInt(100)}
	}
	var atts []consensus.BatchAttestationEntry
	for i := 0; i < 5; i++ {
		atts = append(atts, consensus.BatchAttestationEntry{ValidatorID: reg.Members[i].ValidatorID, EVMAddress: reg.Members[i].EVMAddress,
			SignatureHex: bls_zkp.SignV6_1PreExec(keys[i], msg).Hex(), PublicKeyHex: reg.Members[i].BLSPubKey})
	}
	agg, err := consensus.AggregateBatchAttestations(atts, quorumReg, msg, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, m := range reg.Members {
		ids[m.EVMAddress] = m.ValidatorID
	}
	var signers []string
	for _, a := range agg.Signers {
		signers = append(signers, ids[a])
	}
	cert := ledger.IntentQuorumCertificate{OperationID: opHex, Message: "0x" + hex.EncodeToString(msg[:]), RegistryVersion: 1,
		CertenSetRoot: reg.CertenSetRoot, Height: 12, Signers: signers, SignerAddresses: agg.Signers,
		AggregateSignature: agg.AggregateSignatureHex, AggregatePublicKey: agg.AggregatePublicKeyHex,
		SignedPower: agg.SignedVotingPower.String(), TotalPower: agg.TotalVotingPower.String(), ThresholdNumerator: 2, ThresholdDenominator: 3}
	h := func(v [32]byte) string { return "0x" + hex.EncodeToString(v[:]) }
	inputs := consensus.IntentMessageInputs{CertenChainID: "certen-testnet", OperationID: opHex, GovRootV2: h(govRoot),
		AccumulateSetRoot: h(acc), Incarnation: kermitIncarnation, GovernanceCommitment: h(mi.GovernanceCommitment),
		CertenSetRoot: reg.CertenSetRoot, KeyPageURL: page, KeyBookURL: book}
	cb, _ := json.Marshal(cert)
	rb, _ := json.Marshal(reg)
	ib, _ := json.Marshal(inputs)
	c.row = &database.IntentQuorumCertificateRow{OperationID: opHex, Message: cert.Message, RegistryVersion: 1,
		CertenChainID: "certen-testnet", Certificate: cb, Registry: rb, MessageInputs: ib, CertifiedHeight: 12}
	c.l5 = &Layer5{Governance: &BatchGovernance{OperationID: opHex},
		Commitment: &AnchorCommitment{Version: "v8_2", CertenSetRoot: reg.CertenSetRoot, Incarnation: kermitIncarnation}}
	return c
}

func TestAStoredProofsIntentCertificateIsCheckedOffline(t *testing.T) {
	c := newStoredIntentCase(t)
	pin, _ := hex32Of(kermitIncarnation)
	got, err := CheckIntentCertificate(c.row, c.cp, c.levels, c.l5, &pin)
	if err != nil {
		t.Fatal(err)
	}
	if got.Signers != 5 || got.SignedPower != "500" || got.TotalPower != "700" || !got.IncarnationPinned {
		t.Fatalf("check: %+v", got)
	}
	if _, err := CheckIntentCertificate(nil, c.cp, c.levels, c.l5, &pin); !errors.Is(err, ErrNoIntentCertificate) {
		t.Fatalf("no certificate: %v", err)
	}
}

func TestAStoredIntentCertificateThatIsNotTheProofsIsRefused(t *testing.T) {
	other := "0x" + strings.Repeat("ee", 32)
	for name, mut := range map[string]func(c *storedIntentCase) *[32]byte{
		"another anchor quorum": func(c *storedIntentCase) *[32]byte { c.l5.Commitment.CertenSetRoot = other; return nil },
		"another anchored incarnation": func(c *storedIntentCase) *[32]byte {
			c.l5.Commitment.Incarnation = other
			return nil
		},
		"another pinned incarnation":   func(c *storedIntentCase) *[32]byte { p := [32]byte{0xee}; return &p },
		"another operation in layer 5": func(c *storedIntentCase) *[32]byte { c.l5.Governance.OperationID = other; return nil },
		"no layer 5":                   func(c *storedIntentCase) *[32]byte { c.l5 = nil; return nil },
		"another stored G1": func(c *storedIntentCase) *[32]byte {
			var g map[string]interface{}
			_ = json.Unmarshal(c.levels[1].Result, &g)
			g["required_threshold"] = 99.0
			c.levels[1].Result, _ = json.Marshal(g)
			return nil
		},
		"another stored vote record": func(c *storedIntentCase) *[32]byte {
			var r certenproof.AuthorizationRecord
			_ = json.Unmarshal(c.levels[1].Flags[GovLevelAuthorizationKey], &r)
			r.Authorities[0].Vote.Pages[0].Threshold++
			c.levels[1].Flags[GovLevelAuthorizationKey], _ = json.Marshal(r)
			return nil
		},
		"another Directory leg": func(c *storedIntentCase) *[32]byte {
			dn := *c.cp.Layer4DN
			dn.ValidatorSet = append(dn.ValidatorSet[:0:0], dn.ValidatorSet...)
			dn.ValidatorSet[0].PublicKey = "aa" + dn.ValidatorSet[0].PublicKey[2:]
			cp := *c.cp
			cp.Layer4DN = &dn
			c.cp = &cp
			return nil
		},
		"another certified key page": func(c *storedIntentCase) *[32]byte {
			var in consensus.IntentMessageInputs
			_ = json.Unmarshal(c.row.MessageInputs, &in)
			in.KeyPageURL = "acc://rb4-phase-c-09282125.acme/book/2"
			c.row.MessageInputs, _ = json.Marshal(in)
			return nil
		},
		"a certified message the proof does not compute": func(c *storedIntentCase) *[32]byte {
			var in consensus.IntentMessageInputs
			_ = json.Unmarshal(c.row.MessageInputs, &in)
			in.CertenChainID = "certen-mainnet"
			c.row.MessageInputs, _ = json.Marshal(in)
			c.row.CertenChainID = "certen-mainnet"
			return nil
		},
		"an inflated certificate": func(c *storedIntentCase) *[32]byte {
			var cert ledger.IntentQuorumCertificate
			_ = json.Unmarshal(c.row.Certificate, &cert)
			cert.SignedPower = "700"
			c.row.Certificate, _ = json.Marshal(cert)
			return nil
		},
	} {
		c := newStoredIntentCase(t)
		pin := mut(c)
		if _, err := CheckIntentCertificate(c.row, c.cp, c.levels, c.l5, pin); err == nil || errors.Is(err, ErrNoIntentCertificate) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// On a v3 batch the anchored operation id commits the member's certified message: the certificate must be over it.
func TestTheAnchoredBatchCommitsTheCertificate(t *testing.T) {
	c := newStoredIntentCase(t)
	var cert ledger.IntentQuorumCertificate
	if err := json.Unmarshal(c.row.Certificate, &cert); err != nil {
		t.Fatal(err)
	}
	c.l5.Governance.Version = BatchOperationIDV3
	c.l5.Governance.CertifiedIntentMessage = cert.Message
	got, err := CheckIntentCertificate(c.row, c.cp, c.levels, c.l5, nil)
	if err != nil || !got.AnchoredInBatch {
		t.Fatalf("anchored: %+v %v", got, err)
	}
	c.l5.Governance.CertifiedIntentMessage = "0x" + strings.Repeat("ee", 32)
	if _, err := CheckIntentCertificate(c.row, c.cp, c.levels, c.l5, nil); err == nil {
		t.Fatal("a certificate over another message than the batch anchored was accepted")
	}
	c.l5.Governance.Version = BatchOperationIDV2
	if got, err := CheckIntentCertificate(c.row, c.cp, c.levels, c.l5, nil); err != nil || got.AnchoredInBatch {
		t.Fatalf("a pre-v3 batch: %+v %v", got, err)
	}
}
