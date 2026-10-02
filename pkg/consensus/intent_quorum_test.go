package consensus

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/ledger"
)

// Seven validators each certify the same production intent; the fifth committed signature (500 of 700, at 2/3)
// completes the quorum, and the certificate verifies offline against the registry.
func TestSevenValidatorsCertifyOneIntent(t *testing.T) {
	f, reg := intentRegistry(t)
	app, store := rotationApp(t, f.rotationFixture)
	if err := store.SaveBLSRegistry(&ledger.BLSRegistryLog{Versions: []ledger.BLSRegistryRecord{*reg}}); err != nil {
		t.Fatal(err)
	}
	blocks := make([]ValidatorBlock, 7)
	for i := range blocks {
		vb := intentBlock(t, fmt.Sprintf("validator-%d", i+1))
		if err := buildCert(t, vb, reg, f.keys[i]); err != nil {
			t.Fatalf("validator-%d: %v", i+1, err)
		}
		blocks[i] = *vb
	}
	op := strings.ToLower(blocks[0].CrossChainProof.OperationID)
	cert := func() *ledger.IntentQuorumCertificate {
		ql, err := store.LoadIntentQuorum(op)
		if err != nil || len(ql.Groups) != 1 {
			t.Fatalf("intent quorum: %+v %v", ql, err)
		}
		return ql.Groups[0].Certificate
	}

	app.recordIntentSignatures(11, blocks[:4])
	if cert() != nil {
		t.Fatal("certified with 400 of 700")
	}
	app.recordIntentSignatures(11, blocks[:4]) // replay of the same block
	if ql, _ := store.LoadIntentQuorum(op); len(ql.Groups[0].Partials) != 4 {
		t.Fatalf("replay recorded %d partials", len(ql.Groups[0].Partials))
	}
	app.recordIntentSignatures(12, blocks[4:5])
	c := cert()
	if c == nil || len(c.Signers) != 5 || c.SignedPower != "500" || c.TotalPower != "700" || c.Height != 12 {
		t.Fatalf("certificate at the fifth signature: %+v", c)
	}
	if err := VerifyIntentQuorumCertificate(c, reg); err != nil {
		t.Fatalf("the certificate does not verify offline: %v", err)
	}
	app.recordIntentSignatures(13, blocks[5:])
	if again := cert(); again.Height != 12 || len(again.Signers) != 5 {
		t.Fatal("a recorded certificate was replaced")
	}

	for name, mut := range map[string]func(c *ledger.IntentQuorumCertificate, r *ledger.BLSRegistryRecord) *ledger.BLSRegistryRecord{
		"another message": func(c *ledger.IntentQuorumCertificate, r *ledger.BLSRegistryRecord) *ledger.BLSRegistryRecord {
			c.Message = "0x" + strings.Repeat("ab", 32)
			return r
		},
		"a signer dropped from the list": func(c *ledger.IntentQuorumCertificate, r *ledger.BLSRegistryRecord) *ledger.BLSRegistryRecord {
			c.Signers, c.SignerAddresses = c.Signers[1:], c.SignerAddresses[1:]
			return r
		},
		"inflated power": func(c *ledger.IntentQuorumCertificate, r *ledger.BLSRegistryRecord) *ledger.BLSRegistryRecord {
			c.SignedPower = "700"
			return r
		},
		"another registry": func(c *ledger.IntentQuorumCertificate, r *ledger.BLSRegistryRecord) *ledger.BLSRegistryRecord {
			o := *r
			o.Version = 2
			return &o
		},
		"a higher threshold": func(c *ledger.IntentQuorumCertificate, r *ledger.BLSRegistryRecord) *ledger.BLSRegistryRecord {
			o := *r
			o.ThresholdNumerator, o.ThresholdDenominator = 6, 7
			c.ThresholdNumerator, c.ThresholdDenominator = 6, 7
			return &o
		},
		"another aggregate key": func(c *ledger.IntentQuorumCertificate, r *ledger.BLSRegistryRecord) *ledger.BLSRegistryRecord {
			c.AggregatePublicKey = r.Members[6].BLSPubKey
			return r
		},
		"a signer not in the registry": func(c *ledger.IntentQuorumCertificate, r *ledger.BLSRegistryRecord) *ledger.BLSRegistryRecord {
			c.Signers[0] = "validator-99"
			return r
		},
	} {
		cc := *c
		cc.Signers = append([]string(nil), c.Signers...)
		cc.SignerAddresses = append([]string(nil), c.SignerAddresses...)
		r := mut(&cc, reg)
		if err := VerifyIntentQuorumCertificate(&cc, r); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

// The persister's certificate source yields an operation's certificate at the height whose commit completed it, with
// the inputs of its message, and nothing at any other height; a persister built without a source writes nothing.
func TestTheCompletingBlockCarriesItsCertificateToTheDatabase(t *testing.T) {
	f, reg := intentRegistry(t)
	app, store := rotationApp(t, f.rotationFixture)
	app.cometChainID = intentChain
	if err := store.SaveBLSRegistry(&ledger.BLSRegistryLog{Versions: []ledger.BLSRegistryRecord{*reg}}); err != nil {
		t.Fatal(err)
	}
	blocks := make([]ValidatorBlock, 6)
	for i := range blocks {
		vb := intentBlock(t, fmt.Sprintf("validator-%d", i+1))
		if err := buildCert(t, vb, reg, f.keys[i]); err != nil {
			t.Fatal(err)
		}
		blocks[i] = *vb
	}
	app.recordIntentSignatures(11, blocks[:4])
	app.recordIntentSignatures(12, blocks[4:5])
	app.recordIntentSignatures(13, blocks[5:6])

	if rows, err := app.intentCertificateRows(11, blocks[:4]); err != nil || len(rows) != 0 {
		t.Fatalf("height 11 completed nothing: %v %v", rows, err)
	}
	rows, err := app.intentCertificateRows(12, blocks[4:5])
	if err != nil || len(rows) != 1 {
		t.Fatalf("height 12 completed the certificate: %v %v", rows, err)
	}
	r := rows[0]
	if r.CertifiedHeight != 12 || r.CertenChainID != intentChain || r.RegistryVersion != 1 ||
		!strings.EqualFold(r.Message, blocks[4].IntentCertificate.Message) {
		t.Fatalf("row: %+v", r)
	}
	var in IntentMessageInputs
	if err := json.Unmarshal(r.MessageInputs, &in); err != nil || !strings.EqualFold(in.GovRootV2, blocks[4].IntentCertificate.GovRootV2) ||
		in.KeyPageURL != intentKeyPage || in.CertenSetRoot != reg.CertenSetRoot {
		t.Fatalf("message inputs: %+v %v", in, err)
	}
	var c ledger.IntentQuorumCertificate
	if err := json.Unmarshal(r.Certificate, &c); err != nil || VerifyIntentQuorumCertificate(&c, reg) != nil {
		t.Fatalf("the stored certificate does not verify: %v", err)
	}
	if rows, _ := app.intentCertificateRows(13, blocks[5:6]); len(rows) != 0 {
		t.Fatal("a later signature re-emitted the certificate")
	}

	p := newConsensusPersister(nil, "validator-test", persistQuietLog, nil)
	if p.write(context.Background(), &committedBlock{height: 12}) {
		t.Fatal("a persister without a certificate source wrote a height")
	}
}
