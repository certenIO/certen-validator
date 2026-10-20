// Copyright 2026 Certen Protocol

package proof

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig/sigfixture"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// RB8-B: the validator's own leg discovery and key-page naming apply Accumulate's rule, not an ed25519-only list.

const rb8Hash = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"

// rb8Endpoint serves a signature set whose records are of the given signature types, and a two-route network-status.
func rb8Endpoint(t *testing.T, types ...string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		switch req.Method {
		case "network-status":
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"network":{"networkName":"DevNet"},"routing":{"routes":[`+
				`{"length":1,"value":0,"partition":"BVN1"},{"length":1,"value":1,"partition":"BVN2"}]}}}`)
		default:
			var recs []string
			for i, ty := range types {
				recs = append(recs, fmt.Sprintf(`{"id":"acc://%s@signer%d.acme/book/1","message":{"type":"signature","txID":"acc://%s@probe.acme/data","signature":{"type":%q}}}`,
					strings.Repeat(fmt.Sprintf("%02x", i+1), 32), i, rb8Hash, ty))
			}
			var sets []string
			for i := range types {
				sets = append(sets, fmt.Sprintf(`{"account":{"type":"keyPage","url":"acc://signer%d.acme/book/1"},"signatures":{"records":[%s]}}`, i, recs[i]))
			}
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"signatures":{"records":[`+strings.Join(sets, ",")+`]}}}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// Every signature type Accumulate accepts on a key page - and a delegation - gets its leg. This silently `continue`d on
// all but ed25519 and delegated, so a signer holding only an ECDSA vote had no inclusion proof for its partition and no
// refusal recorded.
func TestRB8_LegDiscoveryCoversEveryAcceptedType(t *testing.T) {
	names := append(govsig.AcceptedKeyTypeNames(), "delegated")
	legs, err := DiscoverSignerLegs(context.Background(), rb8Endpoint(t, names...), "acc://"+rb8Hash+"@probe.acme/data")
	if err != nil {
		t.Fatal(err)
	}
	if len(legs) != len(names) {
		t.Fatalf("%d legs for %d signer pages (%v): a signer's leg was dropped", len(legs), len(names), names)
	}
}

// Routine chain entries are not votes and get no leg; a name Accumulate defines no signature type for is refused by
// name - never dropped - with the real rule in the message.
func TestRB8_LegDiscoveryRefusesWhatAccumulateDoesNotDefine(t *testing.T) {
	legs, err := DiscoverSignerLegs(context.Background(), rb8Endpoint(t, "authority", "signatureRequest", "creditPayment", "ecdsaSha256"), "acc://"+rb8Hash+"@probe.acme/data")
	if err != nil || len(legs) != 1 {
		t.Fatalf("routine entries must be skipped and the ecdsa vote kept: %d legs, %v", len(legs), err)
	}
	_, err = DiscoverSignerLegs(context.Background(), rb8Endpoint(t, "blsSignature"), "acc://"+rb8Hash+"@probe.acme/data")
	if err == nil || !strings.Contains(err.Error(), "leg_dropped") || !strings.Contains(err.Error(), "ecdsaSha256") {
		t.Fatalf("an undefined signature type must be refused by name with the real rule, got %v", err)
	}
}

func TestRB8_VoteSignatureAndKeyHashAreAccumulates(t *testing.T) {
	for _, name := range append(govsig.AcceptedKeyTypeNames(), "delegated") {
		if !isVoteSignature(name) {
			t.Errorf("%s is a vote", name)
		}
	}
	for _, name := range []string{"authority", "partition", "receipt", "remote", "internal", "set", "signatureRequest", "creditPayment", "unknown", ""} {
		if isVoteSignature(name) {
			t.Errorf("%q is not a vote", name)
		}
	}
	for _, ty := range govsig.AcceptedKeyTypes() {
		k, err := sigfixture.NewKey(ty, crand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub, _ := sigfixture.PublicKey(k)
		got, ok := keyHashOfSignature(ty.String(), hex.EncodeToString(pub))
		want, _ := protocol.PublicKeyHash(pub, ty)
		if !ok || got != hex.EncodeToString(want) {
			t.Errorf("%v: key hash %q ok=%v, protocol says %x", ty, got, ok, want)
		}
	}
	if _, ok := keyHashOfSignature("delegated", "00"); ok {
		t.Error("a delegated record carries no key of its own")
	}
	if _, ok := keyHashOfSignature("eth", "zz"); ok {
		t.Error("an unparseable key has no hash")
	}
}

// The mirror of SignatureData that is hashed into the govRoot: a record that existed before RB8-B serialises exactly as
// before (no raw, no innerType); a record that needs them carries them.
func TestRB8_MirrorSerialisationIsUnchangedForExistingRecords(t *testing.T) {
	ts := int64(5)
	old := SignatureData{Type: "ed25519", PublicKey: "aa", Signature: "bb", Signer: "acc://x.acme/book/1", SignerVersion: 1, Timestamp: &ts}
	b, _ := json.Marshal(old)
	if strings.Contains(string(b), "raw") || strings.Contains(string(b), "innerType") {
		t.Fatalf("an ed25519 record gained fields: %s", b)
	}
	n, _ := json.Marshal(SignatureData{Type: "delegated", InnerType: "ecdsasha256", Raw: "0102"})
	if !strings.Contains(string(n), `"innerType":"ecdsasha256"`) || !strings.Contains(string(n), `"raw":"0102"`) {
		t.Fatalf("a non-ed25519 record must carry both: %s", n)
	}
}
