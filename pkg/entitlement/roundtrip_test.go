package entitlement

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// End-to-end cross-language round trip.
//
// The fixture in entitlement_vectors.json proves the two implementations agree
// on hashing. This proves something stronger and more useful: that a document
// the TypeScript publisher ACTUALLY EMITTED can be parsed, verified, and used to
// build a working inclusion proof by the Go validator.
//
// Regenerate: run api-gateway/xlgen.ts and copy its output here.
type roundTripFixture struct {
	PubKey string `json:"pubkey"`
	Doc    string `json:"doc"`
}

func TestGatewayProducedDocumentVerifiesInGo(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "gateway_roundtrip.json"))
	if err != nil {
		t.Skipf("no round-trip fixture: %v", err)
	}
	var fx roundTripFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	pub, err := hex.DecodeString(fx.PubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("bad pubkey in fixture")
	}
	keys := KeySet{"xk": ed25519.PublicKey(pub)}

	// Parse exactly as the Store would.
	var doc Document
	if err := json.Unmarshal([]byte(fx.Doc), &doc); err != nil {
		t.Fatalf("Go cannot parse the document the gateway emitted: %v", err)
	}

	// 1. The signature the gateway produced must verify under Go's signing bytes.
	if err := verifyHeaderSignature(doc.Header, keys); err != nil {
		t.Fatalf("gateway signature does not verify in Go: %v", err)
	}

	// 2. Go must recompute the same set hash and root from the gateway's leaves.
	gotHash, err := doc.Set.SetHash()
	if err != nil {
		t.Fatal(err)
	}
	if gotHash != doc.Header.SetHash {
		t.Fatalf("set hash disagreement:\n Go   %s\n gateway %s", gotHash, doc.Header.SetHash)
	}
	if gotRoot := doc.Set.Root(); gotRoot != doc.Header.Root {
		t.Fatalf("root disagreement:\n Go   %s\n gateway %s", gotRoot, doc.Header.Root)
	}

	// 3. The int64 above 2^53 must have survived JSON in both directions.
	payer, ok := doc.Set.Lookup("acc://payer.acme/data")
	if !ok {
		t.Fatal("payer missing from the gateway's set")
	}
	if payer.EpochCeilingMicroUSD != 9007199254740993 {
		t.Fatalf("int64 precision lost crossing the wire: got %d, want 9007199254740993",
			payer.EpochCeilingMicroUSD)
	}

	// 4. A proof built by Go against the gateway's set must verify — this is the
	//    property the whole fee gate rests on.
	proof, leaf, ok := doc.Set.BuildProof("acc://payer.acme/data")
	if !ok {
		t.Fatal("could not build a proof against the gateway's set")
	}
	ev := &Evidence{Header: doc.Header, Leaf: leaf, Proof: proof}
	if err := Verify(ev, "acc://payer.acme/data", doc.Header.IssuedAtUnix+1, keys); err != nil {
		t.Fatalf("evidence built from a gateway document failed verification: %v", err)
	}

	// 5. And a suspended account in that same document must be refused.
	sProof, sLeaf, ok := doc.Set.BuildProof("acc://broke.acme/data")
	if !ok {
		t.Fatal("suspended account missing; it must be published, not omitted")
	}
	sEv := &Evidence{Header: doc.Header, Leaf: sLeaf, Proof: sProof}
	err = Verify(sEv, "acc://broke.acme/data", doc.Header.IssuedAtUnix+1, keys)
	if err == nil {
		t.Fatal("a suspended account must be refused")
	}
	var ve *VerifyError
	if !asVerifyErr(err, &ve) || ve.Reason != ReasonNotEntitled {
		t.Fatalf("expected NOT_ENTITLED, got %v", err)
	}
}

func asVerifyErr(err error, target **VerifyError) bool {
	if ve, ok := err.(*VerifyError); ok {
		*target = ve
		return true
	}
	return false
}
