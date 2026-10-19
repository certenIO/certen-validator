// Copyright 2026 Certen Protocol

package govvote

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig/sigfixture"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// RB8-B: the offline vote evidence applies the same rule as the online proof, for every accepted type: Accumulate's own
// Verify, the type's own key hash, typedData's chain id, and the executor-version gate at the partition and block the
// fact names.

func rb8Fact(t *testing.T, sig protocol.Signature, partition string, block int64) SigFact {
	t.Helper()
	inner := sigfixture.Inner(sig).(protocol.KeySignature)
	var path []string
	for s := sig; ; {
		d, ok := s.(*protocol.DelegatedSignature)
		if !ok {
			break
		}
		path = append(path, normalizeAccURL(d.Delegator.String()))
		s = d.Signature
	}
	return SigFact{ID: "acc://" + strings.Repeat("ab", 32) + "@probe.acme/book/1", Signer: normalizeAccURL(inner.GetSigner().String()),
		Path: path, Version: inner.GetSignerVersion(), KeyHash: hex.EncodeToString(inner.GetPublicKeyHash()),
		Vote: sig.GetVote(), Block: block, Partition: partition}
}

func rb8AfterKourou(part string) int64 { return govsig.KermitActivations()[part].Block + 1 }

func TestRB8_OfflineEvidenceChecksEveryAcceptedType(t *testing.T) {
	deleg := [][]string{nil, {"acc://a.acme/book/1"}, {"acc://a.acme/book/1", "acc://b.acme/book/1"}}
	for _, ty := range govsig.AcceptedKeyTypes() {
		k, err := sigfixture.NewKey(ty, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range deleg {
			txn := sigfixture.Txn("acc://probe.acme/data", "offline")
			sig, err := sigfixture.Sign(k, txn, sigfixture.Opts{Delegators: d})
			if err != nil {
				t.Fatal(err)
			}
			f := rb8Fact(t, sig, "bvn2", rb8AfterKourou("bvn2"))
			if err := checkSignatureFact(txn, sig, f, "DevNet"); err != nil {
				t.Errorf("%v with %d delegators: %v", ty, len(d), err)
			}
		}
	}
}

// The vote fact's key hash is the type's own. sha256(key) - what the online layer used to write - is refused for the
// five types whose page entry is another hash.
func TestRB8_OfflineKeyHashIsTheTypesOwn(t *testing.T) {
	for _, ty := range []protocol.SignatureType{protocol.SignatureTypeRCD1, protocol.SignatureTypeBTC,
		protocol.SignatureTypeBTCLegacy, protocol.SignatureTypeETH, protocol.SignatureTypeTypedData} {
		k, _ := sigfixture.NewKey(ty, rand.Reader)
		txn := sigfixture.Txn("acc://probe.acme/data", "keyhash")
		sig, _ := sigfixture.Sign(k, txn, sigfixture.Opts{})
		f := rb8Fact(t, sig, "bvn1", rb8AfterKourou("bvn1"))
		inner := sigfixture.Inner(sig).(protocol.KeySignature)
		sum := sha256.Sum256(inner.GetPublicKey())
		f.KeyHash = hex.EncodeToString(sum[:])
		if err := checkSignatureFact(txn, sig, f, "DevNet"); err == nil || !strings.Contains(err.Error(), "key hash") {
			t.Errorf("%v: sha256(key) is not this type's page entry and must be refused, got %v", ty, err)
		}
	}
}

// typedData signed under another chain id verifies cryptographically (R8 E12); the executor refuses it, so the
// evidence must.
func TestRB8_OfflineTypedDataChainID(t *testing.T) {
	k, _ := sigfixture.NewKey(protocol.SignatureTypeTypedData, rand.Reader)
	txn := sigfixture.Txn("acc://probe.acme/data", "chain")
	wrong, _ := sigfixture.Sign(k, txn, sigfixture.Opts{ChainID: big.NewInt(1)})
	good, _ := sigfixture.Sign(k, txn, sigfixture.Opts{})
	blk := rb8AfterKourou("bvn1")
	if err := checkSignatureFact(txn, wrong, rb8Fact(t, wrong, "bvn1", blk), "DevNet"); err == nil || !strings.Contains(err.Error(), "invalid chain ID") {
		t.Errorf("a chain-id-1 typedData signature must be refused for its chain id, got %v", err)
	}
	if err := checkSignatureFact(txn, good, rb8Fact(t, good, "bvn1", blk), ""); err == nil || !strings.Contains(err.Error(), "network_name") && !strings.Contains(err.Error(), "name") {
		t.Errorf("no network name must be the named state, got %v", err)
	}
	if err := checkSignatureFact(txn, good, rb8Fact(t, good, "bvn1", blk), "DevNet"); err != nil {
		t.Errorf("a DevNet typedData signature: %v", err)
	}
}

// The gate, offline: a gated type before the proven activation, or with no partition, is the named state.
func TestRB8_OfflineExecutorGate(t *testing.T) {
	for _, ty := range []protocol.SignatureType{protocol.SignatureTypeRsaSha256, protocol.SignatureTypeEcdsaSha256, protocol.SignatureTypeTypedData, protocol.SignatureTypeETH} {
		k, _ := sigfixture.NewKey(ty, rand.Reader)
		txn := sigfixture.Txn("acc://probe.acme/data", "gate")
		sig, _ := sigfixture.Sign(k, txn, sigfixture.Opts{})
		act := govsig.KermitActivations()["bvn3"].Block
		for name, f := range map[string]SigFact{
			"before":       rb8Fact(t, sig, "bvn3", act-1),
			"no partition": rb8Fact(t, sig, "", act+1),
			"no block":     rb8Fact(t, sig, "bvn3", 0),
		} {
			err := checkSignatureFact(txn, sig, f, "DevNet")
			if err == nil || !strings.Contains(err.Error(), "g1_executor_version_unproven") {
				t.Errorf("%v %s: must be g1_executor_version_unproven, got %v", ty, name, err)
			}
		}
		if err := checkSignatureFact(txn, sig, rb8Fact(t, sig, "bvn3", act+1), "DevNet"); err != nil {
			t.Errorf("%v after the activation: %v", ty, err)
		}
	}
	// the always-registered types need neither partition nor block
	for _, ty := range []protocol.SignatureType{protocol.SignatureTypeED25519, protocol.SignatureTypeLegacyED25519, protocol.SignatureTypeRCD1, protocol.SignatureTypeBTC, protocol.SignatureTypeBTCLegacy} {
		k, _ := sigfixture.NewKey(ty, rand.Reader)
		txn := sigfixture.Txn("acc://probe.acme/data", "nogate")
		sig, _ := sigfixture.Sign(k, txn, sigfixture.Opts{})
		if err := checkSignatureFact(txn, sig, rb8Fact(t, sig, "", 5), ""); err != nil {
			t.Errorf("%v needs no gate: %v", ty, err)
		}
	}
}

// A non-key value is refused and a signature over another transaction is "does not sign the transaction".
func TestRB8_OfflineRefusals(t *testing.T) {
	txn := sigfixture.Txn("acc://probe.acme/data", "one")
	other := sigfixture.Txn("acc://probe.acme/data", "two")
	k, _ := sigfixture.NewKey(protocol.SignatureTypeEcdsaSha256, rand.Reader)
	sig, _ := sigfixture.Sign(k, txn, sigfixture.Opts{})
	if err := checkSignatureFact(other, sig, rb8Fact(t, sig, "bvn1", rb8AfterKourou("bvn1")), "DevNet"); err == nil || !strings.Contains(err.Error(), "does not sign the transaction") {
		t.Errorf("wrong transaction: %v", err)
	}
	auth, _ := protocol.NewSignature(protocol.SignatureTypeAuthority)
	if err := checkSignatureFact(txn, auth, SigFact{}, "DevNet"); err == nil {
		t.Error("an authority signature is not a key's vote")
	}
}

// Facts and evidence recorded before RB8-B carry neither field: their JSON is unchanged.
func TestRB8_NewEvidenceFieldsAreOmittedWhenEmpty(t *testing.T) {
	b, err := json.Marshal(SigFact{ID: "x", KeyHash: "ab"})
	if err != nil || strings.Contains(string(b), "Partition") {
		t.Fatalf("a fact with no partition must serialise without the field: %s %v", b, err)
	}
	e, err := json.Marshal(Evidence{Version: EvidenceVersion})
	if err != nil || strings.Contains(string(e), "networkName") {
		t.Fatalf("evidence with no network name must serialise without the field: %s %v", e, err)
	}
}
