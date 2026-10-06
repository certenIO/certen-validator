package entitlement

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The cross-language round trip for header v3 (RB7 Task 4 follow-up): a document the gateway publisher ACTUALLY
// EMITTED with per-chain native rates (testdata/gateway_roundtrip_v3.json, produced by the gateway's
// headerSigningBytes + serializeDocument) parses, its signature verifies under Go's v3 preimage, and evidence built
// from it passes the consensus gate. A validator that predates v3 fails this signature - which is why validators ship
// before the gateway turns BILLING_ENTITLEMENT_PUBLISH_NATIVE_RATES on.
func loadV3RoundTrip(t *testing.T) (Document, KeySet) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "gateway_roundtrip_v3.json"))
	if err != nil {
		t.Fatalf("a committed test input is missing: no v3 round-trip fixture: %v", err)
	}
	var fx struct {
		PubKey string `json:"pubkey"`
		Doc    string `json:"doc"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	pub, err := hex.DecodeString(fx.PubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatal("bad pubkey in fixture")
	}
	var doc Document
	if err := json.Unmarshal([]byte(fx.Doc), &doc); err != nil {
		t.Fatalf("Go cannot parse the v3 document the gateway emitted: %v", err)
	}
	return doc, KeySet{"xk": ed25519.PublicKey(pub)}
}

func TestGatewayProducedV3DocumentVerifiesInGo(t *testing.T) {
	doc, keys := loadV3RoundTrip(t)
	if err := verifyHeaderSignature(doc.Header, keys); err != nil {
		t.Fatalf("the gateway's v3 signature does not verify in Go: %v", err)
	}
	if got, _ := doc.Set.SetHash(); got != doc.Header.SetHash || doc.Set.Root() != doc.Header.Root {
		t.Fatal("set hash or root disagreement on the v3 document")
	}
	proof, leaf, ok := doc.Set.BuildProof("acc://payer.acme/data")
	if !ok {
		t.Fatal("could not build a proof against the gateway's v3 set")
	}
	if err := Verify(&Evidence{Header: doc.Header, Leaf: leaf, Proof: proof}, "acc://payer.acme/data",
		doc.Header.IssuedAtUnix+1, keys); err != nil {
		t.Fatalf("evidence built from a gateway v3 document failed the gate: %v", err)
	}
}
