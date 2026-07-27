package consensus

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/certen/independant-validator/pkg/ledger"
)

// The operator tool signs a transaction; the chain verifies it. If those two
// disagree about a single byte of the signing preimage, every update is refused
// and the mechanism is unusable at exactly the moment it is needed.
//
// These tests exercise the transaction the way `cmd/policy-update` produces it:
// marshalled to JSON, transported, decoded, verified.

func TestToolProducedTransactionSurvivesTheWire(t *testing.T) {
	adminPub, adminPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	epochPub, _, _ := ed25519.GenerateKey(rand.Reader)

	sealed := &ledger.EntitlementPolicyState{
		Mode:           string(EntitlementObserve),
		Keys:           map[string]string{"entitlement-v1": hex.EncodeToString(epochPub)},
		Version:        1,
		AdminKeys:      map[string]string{"ops-1": hex.EncodeToString(adminPub)},
		AdminThreshold: 1,
	}

	// Exactly what `propose` builds.
	tx := &PolicyUpdateTx{
		Kind:             PolicyUpdateKind,
		Mode:             string(EntitlementEnforce),
		Keys:             sealed.Keys,
		ActivationHeight: 5000,
		Version:          2,
	}
	tx.Signatures = []PolicySignature{{
		KeyID:     "ops-1",
		Signature: hex.EncodeToString(ed25519.Sign(adminPriv, tx.SigningBytes())),
	}}

	// Marshal -> transport -> decode, as submission does.
	wire, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	decoded, ok := DecodePolicyUpdate(wire)
	if !ok {
		t.Fatal("the chain did not recognise a tool-produced transaction")
	}

	if err := VerifyPolicyUpdate(decoded, sealed, 100); err != nil {
		t.Fatalf("a correctly signed update was refused after transport: %v", err)
	}
}

// Map iteration order is random in Go, so a signing preimage that depended on
// it would verify only sometimes — the worst possible failure mode, since it
// would pass review and testing and fail in production at random.
func TestSigningBytesAreStableAcrossMapOrdering(t *testing.T) {
	keys := map[string]string{}
	for i := 0; i < 12; i++ {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		keys[string(rune('a'+i))] = hex.EncodeToString(pub)
	}
	base := &PolicyUpdateTx{
		Kind: PolicyUpdateKind, Mode: "enforce",
		Keys: keys, ActivationHeight: 900, Version: 4,
	}
	want := hex.EncodeToString(base.SigningBytes())

	// Rebuilding the same map repeatedly gives Go fresh iteration orders.
	for i := 0; i < 200; i++ {
		copyKeys := map[string]string{}
		for k, v := range keys {
			copyKeys[k] = v
		}
		other := &PolicyUpdateTx{
			Kind: PolicyUpdateKind, Mode: "enforce",
			Keys: copyKeys, ActivationHeight: 900, Version: 4,
		}
		if got := hex.EncodeToString(other.SigningBytes()); got != want {
			t.Fatalf("signing bytes changed with map ordering on attempt %d", i)
		}
	}
}

// A ValidatorBlock must never be mistaken for a policy update, or it would be
// judged by entirely the wrong rules.
func TestValidatorBlockIsNotDecodedAsAPolicyUpdate(t *testing.T) {
	vb := invariantValidBlockJSON(t, "bundle-A", "acc://payer.acme/data")
	if _, ok := DecodePolicyUpdate(vb); ok {
		t.Fatal("a ValidatorBlock was decoded as a policy update")
	}
	for _, junk := range [][]byte{
		[]byte(`{}`),
		[]byte(`{"kind":"something.else/v1"}`),
		[]byte(`not json`),
		[]byte(`{"kind":"certen.policy.update/v2"}`), // a future format
		nil,
	} {
		if _, ok := DecodePolicyUpdate(junk); ok {
			t.Fatalf("non-update payload was decoded as an update: %s", junk)
		}
	}
}

// m-of-n: signatures accumulate across separate `sign` invocations, and each
// signer's endorsement covers the same content.
func TestSignaturesAccumulateToQuorum(t *testing.T) {
	epochPub, _, _ := ed25519.GenerateKey(rand.Reader)
	adminKeys := map[string]string{}
	privs := map[string]ed25519.PrivateKey{}
	for _, id := range []string{"ops-1", "ops-2", "ops-3"} {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		adminKeys[id] = hex.EncodeToString(pub)
		privs[id] = priv
	}
	sealed := &ledger.EntitlementPolicyState{
		Mode:    string(EntitlementObserve),
		Keys:    map[string]string{"entitlement-v1": hex.EncodeToString(epochPub)},
		Version: 1, AdminKeys: adminKeys, AdminThreshold: 2,
	}

	tx := &PolicyUpdateTx{
		Kind: PolicyUpdateKind, Mode: string(EntitlementEnforce),
		Keys: sealed.Keys, ActivationHeight: 5000, Version: 2,
	}

	// First operator signs and passes the file on.
	tx.Signatures = append(tx.Signatures, PolicySignature{
		KeyID: "ops-1", Signature: hex.EncodeToString(ed25519.Sign(privs["ops-1"], tx.SigningBytes())),
	})
	wire, _ := json.Marshal(tx)
	if err := VerifyPolicyUpdate(mustDecode(t, wire), sealed, 100); err == nil {
		t.Fatal("one signature met a threshold of two")
	}

	// Second operator adds theirs to the received file.
	relayed := mustDecode(t, wire)
	relayed.Signatures = append(relayed.Signatures, PolicySignature{
		KeyID: "ops-2", Signature: hex.EncodeToString(ed25519.Sign(privs["ops-2"], relayed.SigningBytes())),
	})
	final, _ := json.Marshal(relayed)
	if err := VerifyPolicyUpdate(mustDecode(t, final), sealed, 100); err != nil {
		t.Fatalf("two independently added signatures did not reach quorum: %v", err)
	}
}

func mustDecode(t *testing.T, b []byte) *PolicyUpdateTx {
	t.Helper()
	tx, ok := DecodePolicyUpdate(b)
	if !ok {
		t.Fatal("failed to decode a policy update")
	}
	return tx
}
